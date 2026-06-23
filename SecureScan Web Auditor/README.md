# SecureScan

OWASP-Aligned Web Security Auditing Framework

## Overview

SecureScan is a web application security auditing platform designed to identify common web security misconfigurations and reconnaissance indicators.

The framework performs automated security header analysis, directory discovery, robots.txt inspection, and authenticated endpoint assessment while generating structured audit reports.

---

## Key Features

### Security Header Analysis

- Content Security Policy (CSP)
- HTTP Strict Transport Security (HSTS)
- X-Frame-Options
- X-Content-Type-Options

Automatically identifies missing headers and provides remediation guidance.

---

### Directory Discovery

Scans for:

- /admin
- /login
- /config
- /wp-admin
- /backup

using customizable wordlists.

---

### Robots.txt Analysis

Identifies:

- Sensitive directories
- Reconnaissance opportunities
- Hidden application paths

---

### Authenticated Security Audits

Supports:

- Bearer Tokens
- Authenticated APIs
- Internal Applications

allowing security reviews beyond public endpoints.

---

### Asynchronous Scanning Engine

Built using:

- asyncio
- aiohttp

Provides high-performance concurrent scanning while maintaining stability through controlled rate limiting.

---

### Soft-404 Detection

Implements baseline fingerprinting to reduce false positives during directory enumeration.

---

### Reporting Engine

Generates:

- JSON Security Reports
- Risk Summaries
- Remediation Recommendations

---

## Architecture

Target Website
      ↓
HTTP Collection Layer
      ↓
Security Analysis Engine
      ↓
Directory Discovery Engine
      ↓
Risk Assessment Layer
      ↓
JSON Reporting System

---

## Technologies Used

- Python
- aiohttp
- asyncio
- JSON
- OWASP Security Standards

---

## Example Findings

### Missing HSTS

Risk:
Potential SSL stripping attacks.

Recommendation:
Enable Strict-Transport-Security headers.

---

### Missing CSP

Risk:
Increased XSS attack surface.

Recommendation:
Implement Content Security Policy.

---

## Screenshots
In Screenshots Folder
- WAF Detection
- CVE Correlation
- Vulnerability Scoring Engine
