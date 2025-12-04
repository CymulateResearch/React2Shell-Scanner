# CVE-2025-55182 and CVE-2025-66478 Vulnerability Checker

A non-intrusive detection tool for identifying vulnerable React Server Components (RSC) implementations affected by CVE-2025-55182 (React) and CVE-2025-66478 (Next.js). This tool performs **active detection** using **benign, non-malicious payloads** to determine if a server is vulnerable without executing any harmful code.

## Overview

**CVE-2025-55182** and **CVE-2025-66478** are critical unauthenticated remote code execution (RCE) vulnerabilities in the React Server Components "Flight" protocol. These vulnerabilities affect:

- **React**: `react-server-dom` versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0
- **Next.js**: Versions 14.3.0-canary, 15.x, and 16.x (App Router)

The vulnerabilities stem from insecure deserialization in the RSC payload handling logic, allowing attacker-controlled data to influence server-side execution. **Default configurations are vulnerable** - a standard Next.js app created with `create-next-app` can be exploited without any code changes.

## How It Works

This tool performs **active vulnerability detection** by:

1. **Sending benign test payloads** that trigger the vulnerable code paths without executing malicious code
2. **Analyzing error responses** for unique signatures that indicate whether the vulnerable or patched code path was reached
3. **Providing confidence levels** (HIGH, MEDIUM, LOW) based on the evidence found

The tool uses two detection methods:
- **$F type (Server Reference)**: Tests the `loadServerReference` code path
- **$L type (Lazy)**: Tests the `arrayBuffer` code path

**Important**: This tool does NOT execute any malicious code. It only sends carefully crafted benign payloads designed to trigger error responses that reveal the server's vulnerability status.

### Basic Usage

```bash
python react2shell_scanner.py --target https://example.com
```

### With Custom Action ID

```bash
python react2shell_scanner.py --target https://example.com --action-id YOUR_ACTION_ID
```

### Verbose Output

```bash
python react2shell_scanner.py --target https://example.com --verbose
```

### Command-Line Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `--target` | Yes | - | Target URL to check (must start with `http://` or `https://`) |
| `--action-id` | No | `c67c4e1a40fcc26b5e3c0d5d17f16786f4244989` | Action ID to use in the payload |
| `--verbose`, `-v` | No | False | Enable verbose output showing response bodies |

## Example Output

### Vulnerable Server

```
[+] CVE-2025-55182 and CVE-2025-66478 Vulnerability Checker

[*] Target:    https://example.com
[*] Action ID: c67c4e1a40fcc26b5e3c0d5d17f16786f4244989

[*] Test 1: Sending $F (Server Reference) payload...
    Status: 500, Evidence: workers
[*] Test 2: Sending $L (Lazy) payload...
    Status: 500, Evidence: arraybuffer

[+] Result:
[!] Status:     LIKELY VULNERABLE
[!] Confidence: HIGH
[!] Evidence:   workers
[!] Details:    Server reached loadServerReference (Flight $F deserialization bypass)

[!] RECOMMENDATION: Upgrade to patched version
======================================================================
```

### Patched Server

```
[+] CVE-2025-55182 and CVE-2025-66478 Vulnerability Checker

[*] Target:    https://example.com
[*] Action ID: c67c4e1a40fcc26b5e3c0d5d17f16786f4244989

[*] Test 1: Sending $F (Server Reference) payload...
    Status: 500, Evidence: could not find the module
[*] Test 2: Sending $L (Lazy) payload...
    Status: 500, Evidence: in the react server manifest

[+] Result:
[+] Status:     LIKELY NOT VULNERABLE
[+] Confidence: HIGH
[+] Evidence:   could not find the module
[+] Details:    Server rejected payload with security error (patched)
======================================================================
```

## Detection Methodology

### Vulnerability Signatures

The tool looks for these error patterns that indicate vulnerability:

- `workers` - Server reached `loadServerReference` (HIGH confidence)
- `arraybuffer` - Server reached `$L` type handler (HIGH confidence)
- `cannot read properties of null (reading 'id')` - Server reached `loadServerReference` with null metadata (HIGH confidence)
- `entries` - Server Action received deserialized object instead of FormData (MEDIUM confidence)
- `temporary client reference` - Server processed `$T` type reference (MEDIUM confidence)

### Patched Signatures

These error patterns indicate the server is patched:

- `could not find the module`
- `in the react server manifest`
- `Invalid server reference`
- `Server reference not found`
- `Unexpected token`
- `is probably a bug in the react server components bundler`

## Affected Products

| Product | Vulnerable Versions | Patched Versions |
|---------|---------------------|------------------|
| `react-server-dom` | 19.0.0, 19.1.0, 19.1.1, 19.2.0 | 19.0.1, 19.1.2, 19.2.1 |
| Next.js | 14.3.0-canary, 15.x, 16.x (App Router) | 14.3.0-canary.88, 15.0.5, 15.1.9, 15.2.6, 15.3.6, 15.4.8, 15.5.7, 16.0.7 |

Other frameworks using RSC may also be affected:
- Vite RSC plugin
- Parcel RSC plugin
- React Router RSC preview
- RedwoodSDK
- Waku

## Remediation

**Immediate action required**: Upgrade to patched versions:

- **React**: Upgrade to `react-server-dom` 19.0.1, 19.1.2, or 19.2.1
- **Next.js**: Upgrade to the latest patched version (see table above)
- **Other RSC frameworks**: Check official channels for updates regarding bundled `react-server` versions

## Security Notice

This tool is designed for **defensive security testing** and **vulnerability assessment**. It uses only benign payloads that do not execute malicious code. However:

- Only use this tool on systems you own or have explicit permission to test
- The tool may generate error logs on the target server
- Use responsibly and in accordance with applicable laws and regulations


## Disclaimer

This tool is provided "as-is" without warranty. The authors are not responsible for any misuse or damage caused by this tool. Always ensure you have proper authorization before testing any systems.