#!/usr/bin/env python3
import sys
import json
import argparse
import requests
import urllib3
from typing import Tuple, Optional
from dataclasses import dataclass
from enum import Enum

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class VulnStatus(Enum):
    VULNERABLE = "VULNERABLE"
    NOT_VULNERABLE = "NOT_VULNERABLE"
    UNKNOWN = "UNKNOWN"

@dataclass
class CheckResult:
    status: VulnStatus
    confidence: str  # HIGH, MEDIUM, LOW
    evidence: str
    details: str

# Vulnerability signatures - these error messages are unique to the vulnerable code path
VULN_SIGNATURES = {
    # $F type - loadServerReference path
    "workers": {
        "pattern": "workers",
        "confidence": "HIGH",
        "description": "Server reached loadServerReference (Flight $F deserialization bypass)"
    },
    # $L type - arrayBuffer path  
    "arraybuffer": {
        "pattern": "arraybuffer",
        "confidence": "HIGH", 
        "description": "Server reached $L type handler (Flight deserialization bypass)"
    },
    # $F type - null id
    "null_id": {
        "pattern": "cannot read properties of null (reading 'id')",
        "confidence": "HIGH",
        "description": "Server reached loadServerReference with null metadata"
    },
    # Type confusion (action invoked with wrong type)
    "entries": {
        "pattern": "entries",
        "confidence": "MEDIUM",
        "description": "Server Action received deserialized object instead of FormData"
    },
    # Temporary reference error
    "temporary_client": {
        "pattern": "temporary client reference",
        "confidence": "MEDIUM",
        "description": "Server processed $T type reference"
    }
}

# Patched signatures - indicate the server is not vulnerable
PATCHED_SIGNATURES = [
    "could not find the module",           # Patched: React Server Manifest validation
    "in the react server manifest",        # Patched: Clean error message
    "_formdata.get",                       # Patched: $L test uses proper FormData handling
    "response._formdata",                  # Patched: $L test uses response._formData
    "Invalid server reference",
    "Server reference not found",
    "Unexpected token",                    # JSON parse error = payload rejected early
    "is probably a bug in the react server components bundler",  # Patched error suffix
]


def create_check_payload_f_type(action_id: str) -> Tuple[str, str]:
    """
    Create payload using $F (Server Reference) type.
    This triggers loadServerReference with a fake ID.
    """
    boundary = "---------------------------vuln-check-boundary"
    
    parts = []
    
    # Action ID field
    parts.append(f'--{boundary}')
    parts.append(f'Content-Disposition: form-data; name="1_$ACTION_ID_{action_id}"')
    parts.append('')
    parts.append('')
    
    parts.append(f'--{boundary}')
    parts.append('Content-Disposition: form-data; name="1_data"')
    parts.append('')
    parts.append('check')
    
    # Chunk 1: Server reference with SAFE fake ID
    parts.append(f'--{boundary}')
    parts.append('Content-Disposition: form-data; name="1"')
    parts.append('')
    parts.append(json.dumps({
        "id": "cve-2025-55182-check#verify",  # Safe fake ID
        "bound": None
    }))
    
    # Chunk 0: Direct reference to trigger $F handling
    parts.append(f'--{boundary}')
    parts.append('Content-Disposition: form-data; name="0"')
    parts.append('')
    parts.append('"$F1"')
    
    parts.append(f'--{boundary}--')
    
    body = '\r\n'.join(parts)
    content_type = f'multipart/form-data; boundary={boundary}'
    
    return body, content_type


def create_check_payload_l_type(action_id: str) -> Tuple[str, str]:
    """
    Create payload using $L (Lazy) type.
    This triggers the arrayBuffer code path.
    Vulnerable servers will try to call .arrayBuffer() on our object.
    """
    boundary = "---------------------------vuln-check-boundary"
    
    parts = []
    
    parts.append(f'--{boundary}')
    parts.append(f'Content-Disposition: form-data; name="1_$ACTION_ID_{action_id}"')
    parts.append('')
    parts.append('')
    
    parts.append(f'--{boundary}')
    parts.append('Content-Disposition: form-data; name="1_data"')
    parts.append('')
    parts.append('check')
    
    # Chunk 1: Plain object (will fail arrayBuffer call)
    parts.append(f'--{boundary}')
    parts.append('Content-Disposition: form-data; name="1"')
    parts.append('')
    parts.append('{"check": "cve-2025-55182"}')
    
    # Chunk 0: Lazy reference to chunk 1
    parts.append(f'--{boundary}')
    parts.append('Content-Disposition: form-data; name="0"')
    parts.append('')
    parts.append('"$L1"')
    
    parts.append(f'--{boundary}--')
    
    body = '\r\n'.join(parts)
    content_type = f'multipart/form-data; boundary={boundary}'
    
    return body, content_type


def analyze_response(response_text: str, status_code: int) -> CheckResult:
    text_lower = response_text.lower()
    
    # Check for patched signatures first
    for sig in PATCHED_SIGNATURES:
        if sig.lower() in text_lower:
            return CheckResult(
                status=VulnStatus.NOT_VULNERABLE,
                confidence="HIGH",
                evidence=sig,
                details="Server rejected payload with security error (patched)"
            )
    
    # Check for vulnerability signatures in response body
    for sig_name, sig_info in VULN_SIGNATURES.items():
        if sig_info["pattern"].lower() in text_lower:
            return CheckResult(
                status=VulnStatus.VULNERABLE,
                confidence=sig_info["confidence"],
                evidence=sig_info["pattern"],
                details=sig_info["description"]
            )
    
    # 500/501 errors often indicate the vulnerable code path was reached
    # even if the specific signature isn't in the response body
    if status_code in [500, 501]:
        # Check for generic error indicators
        if "error" in text_lower or "typeerror" in text_lower or "digest" in text_lower:
            return CheckResult(
                status=VulnStatus.VULNERABLE,
                confidence="MEDIUM",
                evidence=f"HTTP {status_code} with error response",
                details="Server error during Flight deserialization (likely vulnerable)"
            )
        return CheckResult(
            status=VulnStatus.UNKNOWN,
            confidence="MEDIUM",
            evidence=f"HTTP {status_code}",
            details="Server error - may indicate vulnerability, manual check recommended"
        )
    
    # Status code analysis
    if status_code == 200:
        return CheckResult(
            status=VulnStatus.UNKNOWN,
            confidence="LOW",
            evidence=f"HTTP {status_code}",
            details="Server returned 200 - payload may not have reached vulnerable code"
        )
    else:
        return CheckResult(
            status=VulnStatus.UNKNOWN,
            confidence="LOW",
            evidence=f"HTTP {status_code}",
            details=f"Unexpected status code"
        )


def check_vulnerability(target_url: str, action_id: str, verbose: bool = False) -> CheckResult:
    """
    Perform vulnerability check against target.
    """
    # Ensure URL ends without trailing slash for consistency
    target_url = target_url.rstrip('/')
    
    # Standard headers for Server Action request
    router_state = '%5B%22%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2C%22%2F%22%2C%22refresh%22%5D%7D%2Cnull%2Cnull%2Ctrue%5D'
    
    results = []
    
    # Test 1: $F type payload
    print("[*] Test 1: Sending $F (Server Reference) payload...")
    body, content_type = create_check_payload_f_type(action_id)
    headers = {
        "Content-Type": content_type,
        "Accept": "text/x-component",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Next-Router-State-Tree": router_state,
        "Next-Action": action_id,
        "Origin": target_url,
        "Referer": f"{target_url}/",
        "Connection": "keep-alive",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
    }
    
    try:
        response = requests.post(
            f"{target_url}/",
            data=body,
            headers=headers,
            timeout=15,
            verify=False
        )
        
        if verbose:
            print(f"    Response Body: {response.text[:300]}...")
        
        result = analyze_response(response.text, response.status_code)
        results.append(("$F type", result))
        print(f"    Status: {response.status_code}, Evidence: {result.evidence}")
        
        # If we find HIGH confidence VULNERABLE, return immediately
        if result.status == VulnStatus.VULNERABLE and result.confidence == "HIGH":
            return result
        # Continue to other tests even if this one says NOT_VULNERABLE
            
    except requests.exceptions.Timeout:
        print("    Timeout")
        results.append(("$F type", CheckResult(
            status=VulnStatus.VULNERABLE,
            confidence="MEDIUM",
            evidence="Timeout",
            details="Request timed out"
        )))
    except Exception as e:
        print(f"    Error: {e}")
        results.append(("$F type", CheckResult(
            status=VulnStatus.UNKNOWN,
            confidence="LOW",
            evidence=str(e),
            details="Connection error"
        )))
    
    # Test 2: $L type payload
    print("[*] Test 2: Sending $L (Lazy) payload...")
    body, content_type = create_check_payload_l_type(action_id)
    headers["Content-Type"] = content_type
    
    try:
        response = requests.post(
            f"{target_url}/",
            data=body,
            headers=headers,
            timeout=15,
            verify=False
        )
        
        if verbose:
            print(f"    Response Body: {response.text[:300]}...")
        
        result = analyze_response(response.text, response.status_code)
        results.append(("$L type", result))
        print(f"    Status: {response.status_code}, Evidence: {result.evidence}")
        
        # If we find HIGH confidence VULNERABLE, return immediately
        if result.status == VulnStatus.VULNERABLE and result.confidence == "HIGH":
            return result
        # Continue to aggregation even if this one says NOT_VULNERABLE
            
    except requests.exceptions.Timeout:
        print("    Timeout")
        results.append(("$L type", CheckResult(
            status=VulnStatus.UNKNOWN,
            confidence="LOW",
            evidence="Timeout",
            details="Request timed out"
        )))
    except Exception as e:
        print(f"    Error: {e}")
    
    # Aggregate results - prioritize VULNERABLE, then NOT_VULNERABLE
    for test_name, result in results:
        if result.status == VulnStatus.VULNERABLE:
            return result
    
    for test_name, result in results:
        if result.status == VulnStatus.NOT_VULNERABLE:
            return result
    
    # If we got 500/501 errors, lean towards vulnerable
    for test_name, result in results:
        if "500" in result.evidence or "501" in result.evidence:
            return CheckResult(
                status=VulnStatus.VULNERABLE,
                confidence="MEDIUM",
                evidence=result.evidence,
                details="Server errors during Flight deserialization indicate vulnerability"
            )
    
    return CheckResult(
        status=VulnStatus.UNKNOWN,
        confidence="LOW",
        evidence="No definitive signatures",
        details="Could not determine vulnerability status"
    )


def print_banner():
    print("[+] CVE-2025-55182 and CVE-2025-66478 Vulnerability Checker")
    print()
    print("[+] This tool attempts to check if a server is vulnerable to CVE-2025-55182 and CVE-2025-66478 without executing")
    print("    any malicious code. It sends benign payloads and analyzes error responses for vulnerability")
    print("    signatures unique to the affected code path.")
    print()


def print_result(result: CheckResult):
    print()
    print("[+] Result:")
    
    if result.status == VulnStatus.VULNERABLE:
        print(f"[!] Status:     LIKELY VULNERABLE")
        print(f"[!] Confidence: {result.confidence}")
        print(f"[!] Evidence:   {result.evidence}")
        print(f"[!] Details:    {result.details}")
        print()
        print("[!] RECOMMENDATION: Upgrade to patched version")
    elif result.status == VulnStatus.NOT_VULNERABLE:
        print(f"[+] Status:     LIKELY NOT VULNERABLE")
        print(f"[+] Confidence: {result.confidence}")
        print(f"[+] Evidence:   {result.evidence}")
        print(f"[+] Details:    {result.details}")
    else:
        print(f"[?] Status:     {result.status.value}")
        print(f"[?] Confidence: {result.confidence}")
        print(f"[?] Evidence:   {result.evidence}")
        print(f"[?] Details:    {result.details}")
        print()
        print("[?] Manual verification recommended")
    
    print("=" * 70)


def main():
    parser = argparse.ArgumentParser(
        description="CVE-2025-55182 and CVE-2025-66478 Vulnerability Checker"
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Target URL to check (must start with http:// or https://)"
    )
    parser.add_argument(
        "--action-id",
        default="c67c4e1a40fcc26b5e3c0d5d17f16786f4244989",
        help="Action ID to use (default: c67c4e1a40fcc26b5e3c0d5d17f16786f4244989)"
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose output"
    )
    
    args = parser.parse_args()
    
    print_banner()
    
    target_url = args.target
    action_id = args.action_id
    verbose = args.verbose
    
    if not target_url.startswith(("http://", "https://")):
        print("[!] Error: URL must start with http:// or https://")
        sys.exit(1)
    
    print(f"[*] Target:    {target_url}")
    print(f"[*] Action ID: {action_id}")
    print()
    
    result = check_vulnerability(target_url, action_id, verbose)
    print_result(result)
    
    # Exit code based on status
    if result.status == VulnStatus.VULNERABLE:
        sys.exit(0)
    elif result.status == VulnStatus.NOT_VULNERABLE:
        sys.exit(1)
    else:
        sys.exit(2)


if __name__ == "__main__":
    main()