# LogGuard

Threat Detection and Automated Response Platform

## Overview

LogGuard is a defensive cybersecurity platform designed to analyze web server logs and identify indicators of malicious activity.

The system performs real-time detection of attack patterns and can automatically respond through blocking and alerting mechanisms.

---

## Key Features

### Brute Force Detection

Identifies:

- Repeated login failures
- Credential stuffing patterns
- Authentication abuse

---

### SQL Injection Detection

Detects signatures including:

- UNION SELECT
- OR 1=1
- SQL keywords
- Injection payload patterns

---

### Cross-Site Scripting Detection

Monitors for:

- Script Injection Attempts
- HTML Payloads
- JavaScript Exploitation Signatures

---

### Alert Throttling

Prevents alert flooding by intelligently grouping repetitive events.

Benefits:

- Reduced analyst fatigue
- Cleaner reporting
- Better prioritization

---

### Automated Blocking

Can automatically:

- Block malicious IP addresses
- Quarantine suspicious sources
- Generate incident logs

---

### Log Parsing Engine

Supports:

- Apache Logs
- Nginx Logs

with extensible architecture for future integrations.

---

## Architecture

Apache/Nginx Logs
         ↓
Log Parsing Layer
         ↓
Threat Detection Engine
         ↓
Correlation Layer
         ↓
Alert Manager
         ↓
Automated Response

---

## Detection Categories

### Authentication Attacks

- Brute Force
- Credential Stuffing

### Web Attacks

- SQL Injection
- XSS Attempts

### Reconnaissance

- Repeated Enumeration Activity
- Suspicious Request Patterns

---

## Technologies Used

- Python
- Regex
- SQLite
- Logging Frameworks

---

## Incident Workflow

Log Event
    ↓
Threat Analysis
    ↓
Detection Match
    ↓
Alert Generation
    ↓
Response Action

---

## Screenshots
In Screenshots folder