# 🔍 ReconNio

<div align="center">

**A Comprehensive Go-Based Reconnaissance Toolkit for Security Professionals**

[![Go Version](https://img.shields.io/badge/Go-1.24.5-00ADD8?style=flat&logo=go)](https://golang.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/shii9/ReconNio?style=social)](https://github.com/shii9/ReconNio)

*Powerful, Fast, and Modular Reconnaissance for Penetration Testers and Bug Bounty Hunters*

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Usage Guide](#-usage-guide)
- [Modules Reference](#-modules-reference)
- [Configuration](#-configuration)
- [Output Formats](#-output-formats)
- [Examples](#-examples)
- [Contributing](#-contributing)
- [Security & Legal](#-security--legal)
- [License](#-license)

---

## 🎯 Overview

**ReconNio** is a comprehensive reconnaissance toolkit written in Go, designed for security professionals, penetration testers, and bug bounty hunters. It provides 19+ specialized modules for information gathering, vulnerability assessment, and security analysis.

### Why ReconNio?

✅ **All-in-One Solution** - 19+ reconnaissance modules in a single binary  
✅ **High Performance** - Concurrent processing with intelligent rate limiting  
✅ **Passive & Active** - Support for both passive and active reconnaissance  
✅ **Flexible Output** - JSON and console output formats  
✅ **Modular Design** - Use individual modules or combine them for comprehensive scans  
✅ **Production Ready** - Built with Go for speed, reliability, and cross-platform support

---

## ✨ Features

### 🔐 Core Capabilities

| Category | Modules | Description |
|----------|---------|-------------|
| **Domain Intelligence** | WHOIS, DNS, Subdomain Discovery | Complete domain reconnaissance and enumeration |
| **Network Analysis** | Port Scanning, Reverse IP, Geolocation | Network mapping and infrastructure analysis |
| **Web Application** | HTTP Headers, Metadata, Directory Discovery | Web technology fingerprinting and content discovery |
| **Security Testing** | Fuzzing, Parameter Discovery, Endpoint Analysis | Vulnerability identification and attack surface mapping |
| **OSINT** | Social Media, Email Analysis, JavaScript Analysis | Open-source intelligence gathering |
| **Infrastructure** | Proxy Scraping, Live Host Detection | Network infrastructure reconnaissance |

### 🚀 Key Features

- **Concurrent Processing**: Multi-threaded execution with configurable workers
- **Rate Limiting**: Built-in rate limiting and jitter to avoid detection
- **Smart Detection**: Automatic technology fingerprinting and WAF/CDN detection
- **Comprehensive Reporting**: Detailed findings with severity ratings and remediation advice
- **TLS Analysis**: Certificate inspection and security header analysis
- **API Integration**: Support for multiple OSINT APIs (GitHub, Reddit, AlienVault, etc.)
- **Secret Detection**: Automatic detection of exposed credentials and API keys
- **GraphQL Support**: GraphQL endpoint discovery and introspection

---

## 📦 Installation

### Prerequisites

- **Go 1.24.5** or higher
- Internet connection for external API queries

### Build from Source

```bash
# Clone the repository
git clone https://github.com/shii9/ReconNio.git
cd ReconNio

# Install dependencies
go mod download

# Build the binary
go build -o reconnio ./internal/reconnio.go

# Verify installation
./reconnio -h
```

### Quick Install (One-liner)

```bash
git clone https://github.com/shii9/ReconNio.git && cd ReconNio && go build -o reconnio ./internal/reconnio.go
```

---

## 🚀 Quick Start

```bash
# Basic WHOIS lookup
./reconnio -whois -d example.com

# Subdomain discovery
./reconnio -subdomain -d example.com

# Port scan with banner grabbing
./reconnio -ports -t example.com

# Comprehensive web analysis
./reconnio -http -metadata -js -target https://example.com

# Full reconnaissance (multiple modules)
./reconnio -whois -dns -subdomain -ports -d example.com -o json -output results.json
```

---

## 📖 Usage Guide

### Basic Syntax

```bash
./reconnio [flags] [options]
```

### Global Flags

| Flag | Description | Example |
|------|-------------|---------|
| `-d <domain>` | Target domain | `-d example.com` |
| `-t <target>` | Target host/IP | `-t 192.168.1.1` |
| `-target <url>` | Target URL | `-target https://example.com` |
| `-o <format>` | Output format (json/console) | `-o json` |
| `-output <file>` | Output file path | `-output results.json` |
| `-h` | Display help | `-h` |

---

## 🔧 Modules Reference

### 1️⃣ Domain & DNS Intelligence

<table>
<tr>
<th>Module</th>
<th>Flag</th>
<th>Description</th>
<th>Example</th>
</tr>

<tr>
<td><strong>WHOIS Lookup</strong></td>
<td><code>-whois</code></td>
<td>
• Domain registration details<br>
• Registrar and registrant info<br>
• Nameserver resolution<br>
• Domain age calculation<br>
• DNSSEC status<br>
• Contact information extraction
</td>
<td><code>./reconnio -whois -d example.com</code></td>
</tr>

<tr>
<td><strong>DNS Records</strong></td>
<td><code>-dns</code></td>
<td>
• A, AAAA, CNAME, MX, NS, TXT records<br>
• SOA, SRV, PTR records<br>
• SPF, DMARC, DKIM parsing<br>
• Zone transfer (AXFR) attempts<br>
• Email security record analysis
</td>
<td><code>./reconnio -dns -d example.com</code></td>
</tr>

<tr>
<td><strong>Subdomain Discovery</strong></td>
<td><code>-subdomain</code></td>
<td>
• Certificate Transparency (crt.sh)<br>
• HackerTarget API<br>
• ThreatCrowd aggregation<br>
• AlienVault OTX<br>
• CertSpotter<br>
• Anubis database
</td>
<td><code>./reconnio -subdomain -d example.com</code></td>
</tr>

</table>

### 2️⃣ Network & Infrastructure

<table>
<tr>
<th>Module</th>
<th>Flag</th>
<th>Description</th>
<th>Example</th>
</tr>

<tr>
<td><strong>Port Scanning</strong></td>
<td><code>-ports</code></td>
<td>
• Scans 80+ common ports<br>
• Service detection & banner grabbing<br>
• TLS/SSL handshake analysis<br>
• HTTP header extraction<br>
• Concurrent scanning (200 workers)<br>
• Protocol and cipher detection
</td>
<td><code>./reconnio -ports -t example.com</code></td>
</tr>

<tr>
<td><strong>Reverse IP Lookup</strong></td>
<td><code>-reverseip</code></td>
<td>
• Discover co-hosted domains<br>
• PTR (reverse DNS) lookups<br>
• TLS certificate SAN extraction<br>
• Geolocation data<br>
• RDAP/ASN information<br>
• Domain resolution verification
</td>
<td><code>./reconnio -reverseip -i 8.8.8.8</code></td>
</tr>

<tr>
<td><strong>Geolocation</strong></td>
<td><code>-geo</code></td>
<td>
• ISP/Organization identification<br>
• ASN information<br>
• City, region, country<br>
• Latitude/longitude coordinates<br>
• Timezone detection<br>
• Network CIDR & abuse contacts
</td>
<td><code>./reconnio -geo -i 8.8.8.8</code></td>
</tr>

<tr>
<td><strong>Proxy Scraper</strong></td>
<td><code>-proxy</code></td>
<td>
• Multiple proxy source aggregation<br>
• Fast TCP validation<br>
• Concurrent validation<br>
• Automatic deduplication
</td>
<td><code>./reconnio -proxy</code></td>
</tr>

</table>

### 3️⃣ Web Application Analysis

<table>
<tr>
<th>Module</th>
<th>Flag</th>
<th>Description</th>
<th>Example</th>
</tr>

<tr>
<td><strong>HTTP Headers</strong></td>
<td><code>-http</code></td>
<td>
• Request/response header capture<br>
• Security headers analysis (HSTS, CSP, X-Frame-Options)<br>
• Cookie analysis (Secure, HttpOnly, SameSite)<br>
• TLS/SSL certificate details<br>
• HTTP/2 and HTTP/3 detection<br>
• Technology fingerprinting<br>
• WAF/CDN detection<br>
• CORS analysis<br>
• Favicon SHA1 hashing
</td>
<td><code>./reconnio -http -target https://example.com</code></td>
</tr>

<tr>
<td><strong>Metadata Extraction</strong></td>
<td><code>-metadata</code></td>
<td>
• HTML meta tags (OG, Twitter cards)<br>
• robots.txt and sitemap parsing<br>
• Cookie information<br>
• Security headers<br>
• DNS records integration<br>
• TLS certificate details<br>
• Framework detection<br>
• Tracker detection<br>
• JSON-LD extraction
</td>
<td><code>./reconnio -metadata -target https://example.com</code></td>
</tr>

<tr>
<td><strong>Directory Discovery</strong></td>
<td><code>-dir</code></td>
<td>
• Wordlist-based brute-forcing<br>
• Baseline 404 fingerprinting<br>
• robots.txt and sitemap parsing<br>
• JavaScript file extraction<br>
• Source map discovery<br>
• Secret detection (AWS keys, credentials)<br>
• Severity classification<br>
• Remediation suggestions<br>
• JSON report generation
</td>
<td><code>./reconnio -dir -target https://example.com -wordlist common.txt</code></td>
</tr>

<tr>
<td><strong>JavaScript Analysis</strong></td>
<td><code>-js</code></td>
<td>
• External and inline script detection<br>
• Framework detection (React, Vue, Angular, Next.js)<br>
• Library detection (jQuery, Webpack, Vite)<br>
• Tracker detection (GA, GTM, Hotjar)<br>
• API endpoint extraction<br>
• GraphQL & WebSocket discovery<br>
• Secret/token detection (AWS keys, JWT)<br>
• Source map analysis<br>
• Obfuscation detection<br>
• Dangerous pattern detection (eval, innerHTML)<br>
• Storage usage analysis
</td>
<td><code>./reconnio -js -target https://example.com</code></td>
</tr>

</table>

### 4️⃣ Security Testing & Fuzzing

<table>
<tr>
<th>Module</th>
<th>Flag</th>
<th>Description</th>
<th>Example</th>
</tr>

<tr>
<td><strong>Parameter Discovery</strong></td>
<td><code>-param</code></td>
<td>
• HTML form parameter extraction<br>
• JavaScript parameter discovery<br>
• Query string analysis<br>
• Header parameter detection<br>
• OpenAPI/Swagger extraction<br>
• GraphQL introspection<br>
• Active parameter fuzzing<br>
• Reflection detection<br>
• Open redirect testing<br>
• Parameter pollution testing
</td>
<td><code>./reconnio -param -target https://example.com</code></td>
</tr>

<tr>
<td><strong>Endpoint Discovery</strong></td>
<td><code>-endpoint</code></td>
<td>
• HTML link and form parsing<br>
• JavaScript API call analysis<br>
• Source map parsing<br>
• GraphQL endpoint detection<br>
• WebSocket discovery<br>
• OpenAPI/Swagger detection<br>
• Active probing (HEAD/GET/OPTIONS)<br>
• CORS analysis<br>
• Token/secret detection<br>
• Open redirect parameter detection
</td>
<td><code>./reconnio -endpoint -target https://example.com</code></td>
</tr>

<tr>
<td><strong>Fuzzing</strong></td>
<td><code>-fuzz</code></td>
<td>
• Path fuzzing<br>
• Parameter fuzzing<br>
• Payload injection<br>
• XSS detection<br>
• SQL injection detection (time-based & error-based)<br>
• Directory traversal detection<br>
• Backup file discovery<br>
• Error disclosure detection<br>
• GraphQL introspection testing<br>
• CORS misconfiguration detection<br>
• SSRF detection<br>
• Rate limiting support
</td>
<td><code>./reconnio -fuzz -target https://example.com</code></td>
</tr>

<tr>
<td><strong>URL Collection</strong></td>
<td><code>-urls</code></td>
<td>
• HTML link extraction<br>
• JavaScript URL extraction<br>
• CSS URL extraction<br>
• Form action extraction<br>
• API endpoint discovery<br>
• robots.txt parsing<br>
• Sitemap parsing<br>
• Recursive crawling (configurable depth)<br>
• Concurrent collection<br>
• Automatic deduplication
</td>
<td><code>./reconnio -urls -target https://example.com</code></td>
</tr>

</table>

### 5️⃣ OSINT & Intelligence

<table>
<tr>
<th>Module</th>
<th>Flag</th>
<th>Description</th>
<th>Example</th>
</tr>

<tr>
<td><strong>Social Media Recon</strong></td>
<td><code>-social</code></td>
<td>
• Username availability checking<br>
• Supported platforms: Twitter, Facebook, GitHub, Instagram, Reddit, LinkedIn<br>
• Profile existence verification<br>
• Advanced profile data extraction<br>
• Username permutation generation<br>
• Concurrent checking with rate limiting
</td>
<td><code>./reconnio -social -u username</code></td>
</tr>

<tr>
<td><strong>Email Analysis</strong></td>
<td><code>-mail</code></td>
<td>
• MX record enumeration<br>
• SPF record parsing<br>
• DMARC policy analysis<br>
• DKIM record discovery<br>
• MTA-STS policy fetching<br>
• TLS-RPT record detection<br>
• CAA record lookup<br>
• Active SMTP probing<br>
• TLS certificate analysis<br>
• RBL (blacklist) checking<br>
• Provider inference (Google Workspace, Microsoft 365)<br>
• Security posture scoring
</td>
<td><code>./reconnio -mail -d example.com</code></td>
</tr>

</table>

---

## ⚙️ Configuration

### Environment Variables

```bash
# Set custom timeout (default: 10s)
export RECONNIO_TIMEOUT=15

# Set custom concurrency (default: 4)
export RECONNIO_CONCURRENCY=8

# Set custom user agent
export RECONNIO_USER_AGENT="ReconNio/1.0"
```

### Rate Limiting

ReconNio includes built-in rate limiting to avoid overwhelming targets and detection:

- Default: 4 requests per second
- Configurable via flags or environment variables
- Automatic jitter for randomization

---

## 📊 Output Formats

### Console Output (Default)

Human-readable formatted output with color-coded results:

```bash
./reconnio -whois -d example.com
```

### JSON Output

Structured JSON for automation and integration:

```bash
./reconnio -whois -d example.com -o json -output results.json
```

**JSON Structure:**
```json
{
  "target": "example.com",
  "whois": "...",
  "dns_records": [...],
  "subdomains": [...],
  "timestamp": "2025-11-27T02:26:03Z"
}
```

---

## 💡 Examples

### Example 1: Basic Domain Reconnaissance

```bash
# Perform WHOIS, DNS, and subdomain discovery
./reconnio -whois -dns -subdomain -d example.com
```

### Example 2: Web Application Security Assessment

```bash
# Comprehensive web analysis with output to JSON
./reconnio -http -metadata -js -param -endpoint \
  -target https://example.com \
  -o json -output webapp_scan.json
```

### Example 3: Network Infrastructure Mapping

```bash
# Port scan with reverse IP and geolocation
./reconnio -ports -reverseip -geo -t example.com
```

### Example 4: Content Discovery

```bash
# Directory brute-forcing with custom wordlist
./reconnio -dir -target https://example.com -wordlist /path/to/wordlist.txt
```

### Example 5: Email Infrastructure Analysis

```bash
# Complete email security assessment
./reconnio -mail -d example.com
```

### Example 6: Full Reconnaissance Suite

```bash
# Run multiple modules for comprehensive reconnaissance
./reconnio \
  -whois -dns -subdomain \
  -ports -reverseip -geo \
  -http -metadata -js \
  -d example.com \
  -o json -output full_recon.json
```

### Example 7: OSINT Investigation

```bash
# Social media and email reconnaissance
./reconnio -social -u targetuser -mail -d targetdomain.com
```

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

### Reporting Issues

1. Check existing issues first
2. Provide detailed reproduction steps
3. Include system information (OS, Go version)
4. Attach relevant logs or screenshots

### Submitting Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines

- Follow Go best practices and conventions
- Add tests for new features
- Update documentation as needed
- Ensure code passes `go fmt` and `go vet`

---

## 🔒 Security & Legal

### ⚠️ Legal Disclaimer

**IMPORTANT**: This tool is designed for **authorized security testing only**.

- ✅ **DO**: Use on systems you own or have explicit written permission to test
- ✅ **DO**: Respect rate limits and avoid overwhelming targets
- ✅ **DO**: Comply with applicable laws and regulations
- ❌ **DON'T**: Use for unauthorized access or malicious purposes
- ❌ **DON'T**: Test systems without proper authorization
- ❌ **DON'T**: Violate terms of service or privacy policies

**Users are solely responsible for ensuring compliance with all applicable laws and regulations. The authors assume no liability for misuse of this tool.**

### Ethical Use Guidelines

1. **Authorization**: Always obtain written permission before testing
2. **Scope**: Stay within the defined scope of your engagement
3. **Rate Limiting**: Use built-in rate limiting to avoid service disruption
4. **Passive First**: Start with passive reconnaissance when possible
5. **Responsible Disclosure**: Report vulnerabilities responsibly
6. **Privacy**: Respect privacy and handle data appropriately

### Security Features

- Built-in rate limiting to prevent abuse
- Support for `-disable-active` flags for passive-only reconnaissance
- Configurable timeouts and concurrency limits
- No credential storage or sensitive data logging

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2025 ReconNio

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

---

## 🙏 Acknowledgments

ReconNio leverages several excellent open-source libraries:

- [miekg/dns](https://github.com/miekg/dns) - DNS operations
- [likexian/whois](https://github.com/likexian/whois) - WHOIS lookups
- [golang.org/x/net/html](https://golang.org/x/net/html) - HTML parsing

Special thanks to the security research community for inspiration and feedback.

---

## 📞 Support & Contact

- **Issues**: [GitHub Issues](https://github.com/shii9/ReconNio/issues)
- **Discussions**: [GitHub Discussions](https://github.com/shii9/ReconNio/discussions)
- **Repository**: [https://github.com/shii9/ReconNio](https://github.com/shii9/ReconNio)

---

<div align="center">

**Made with ❤️ for the Security Community**

⭐ Star this repository if you find it useful!

[Documentation](https://github.com/shii9/ReconNio/wiki)

</div>
