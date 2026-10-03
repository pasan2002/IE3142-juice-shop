# IE3142: DevOps Security — Building and Securing a DevSecOps Pipeline

<p align="center">
  <img src="https://res.cloudinary.com/dl9ectnzs/image/upload/v1791022194/Screenshot_2026-10-03_153943_rcj1dy.png" alt="SLIIT Logo" width="260"/>
</p>

<p align="center">
  <strong>Sri Lanka Institute of Information Technology (SLIIT)</strong><br>
  Faculty of Computing · Department of Computer Systems Engineering<br>
  <strong>BSc (Hons) in Information Technology — Year 3 Semester 1 (2026)</strong><br>
  <em>IE3142 DevOps Security · Group Assignment</em>
</p>

---

## 📑 Table of Contents
1. [Group Members & Contribution Matrix](#-group-members--contribution-matrix)
2. [Project Overview](#-project-overview)
3. [System Architecture & Trust Boundaries](#-system-architecture--trust-boundaries)
4. [Remediated Vulnerabilities (OWASP Top 10)](#-remediated-vulnerabilities-owasp-top-10)
   - [1. SQL Injection Authentication Bypass](#1-sql-injection-authentication-bypass-a032021--cwe-89)
   - [2. Stored Cross-Site Scripting](#2-stored-cross-site-scripting-a032021--cwe-79)
   - [3. Basket IDOR](#3-insecure-direct-object-reference-on-baskets-a012021--cwe-639)
   - [4. Admin Registration Privilege Escalation](#4-admin-registration---improper-input-validation-a012021--cwe-20)
5. [Automated DevSecOps Pipeline](#-automated-devsecops-pipeline)
   - [Pipeline Architecture](#pipeline-architecture)
   - [Security Gates Specification](#security-gates-specification)
   - [Empirical Blocking Evidence (Run #5 vs Run #6)](#-empirical-blocking-evidence-run-5-vs-run-6)
6. [Repository Structure](#-repository-structure)
7. [Local Setup & Reproduction Guide](#-local-setup--reproduction-guide)
8. [Vulnerability Verification Commands](#-vulnerability-verification-commands-examiner-test-suite)
9. [Running Security Scans Locally](#-running-security-scans-locally)
10. [Secrets Management Strategy](#-secrets-management-strategy)
11. [Academic Integrity & Ethical Clearance](#-academic-integrity--ethical-clearance)

---

## 👥 Group Members & Contribution Matrix

| Student Name | Student ID | Security Vulnerability Remediated | CI/CD Security Gate Ownership | Core File Modifications |
| :--- | :--- | :--- | :--- | :--- |
| **Hewavitharana H.U.P** | **IT24100258** | SQL Injection Auth Bypass (CWE-89) | **Gate 2:** SCA (`npm audit`)<br>**Gate 4:** Container Scan (Aqua Trivy)<br>Pipeline Core Orchestration | `routes/login.ts`<br>`.trivyignore`<br>`.github/workflows/devsecops.yml` |
| **Haggalla H.H.D.S** | **IT24100975** | Stored XSS in Admin Panel (CWE-79) | **Gate 1:** SAST Static Analysis (Semgrep) | `server.ts`<br>`administration.component.ts`<br>`administration.component.html` |
| **Disanayaka D.M.C.N** | **IT24100239** | Basket Insecure Direct Object Reference (CWE-639) | **Gate 5:** DAST Dynamic Scan (OWASP ZAP) | `routes/basket.ts` |
| **Abeysekara T.T** | **IT24100172** | Admin Registration Privilege Escalation (CWE-20) | **Gate 3:** Secrets Scanning (Gitleaks) | `server.ts`<br>`models/user.ts`<br>`.gitleaks.toml` |

---

## 📌 Project Overview
This repository contains the practical DevSecOps engineering implementation for **SLIIT IE3142 (DevOps Security)**. The project systematically hardens [OWASP Juice Shop](https://github.com/juice-shop/juice-shop), a single-page web application built with Angular, Node.js (Express), Sequelize ORM, and an embedded SQLite database (`juiceshop.sqlite`).

Our team applied the **DevSecOps Empirical Validation Methodology**:
1. **Threat Model & Identify:** Map architectural trust boundaries, entry points, and assets using STRIDE.
2. **Exploit (Prove Feasibility):** Intercept and execute live proof-of-concept attacks against the unpatched application using Burp Suite Professional to prove exploitability.
3. **Remediate (Secure Coding):** Implement surgical, defense-in-depth source code patches addressing the root causes at the backend and frontend layers.
4. **Verify (Post-Fix Re-Test):** Re-execute identical attack payloads against the hardened endpoints to ensure robust mitigation without functional regression.
5. **Automate (Continuous Enforcement):** Codify automated security gates in GitHub Actions (`.github/workflows/devsecops.yml`) that actively scan, triage, and block defective builds from entering production.

---

## 🏗️ System Architecture & Trust Boundaries

<p align="center">
  <img src="https://res.cloudinary.com/dl9ectnzs/image/upload/v1791021875/Screenshot_2026-09-30_212807_htcfiz.png" alt="System Architecture and Trust Boundaries" width="850"/>
</p>

### Trust Boundaries & STRIDE Threat Mapping

| Boundary | Description | Threats Addressed | Mitigation Applied |
| :--- | :--- | :--- | :--- |
| **TB-1: Client / Ingress Gateway** | Untrusted public Internet clients interfacing with the Express.js HTTP API (`http://localhost:3000`). All headers, query parameters, and JSON payloads are untrusted. | **Tampering:** Malicious payloads in registration / search.<br>**Elevation of Privilege:** Injecting role attributes.<br>**Information Disclosure:** Reading foreign basket data. | Express input validation, strict parameter typing, regex whitelisting, JWT signature validation, and resource ownership checks. |
| **TB-2: Application Logic / SQLite Layer** | Internal application logic communicating with the embedded SQLite database engine (`juiceshop.sqlite`) via Sequelize ORM. | **Tampering / Information Disclosure:** SQL query structure manipulation via raw SQL concatenation. | Elimination of string concatenation; enforcement of Sequelize named replacements (`:email`, `:password`) for prepared statements. |

---

## 🛡️ Remediated Vulnerabilities (OWASP Top 10)

### 1. SQL Injection Authentication Bypass (A03:2021 — CWE-89)
* **Assigned Engineer:** Hewavitharana H.U.P (`IT24100258`)
* **Vulnerable Component:** `routes/login.ts` (Lines 61–74)
* **Root Cause:** Unsanitized user-supplied email strings were concatenated directly into a raw SQL query passed to `sequelize.query()`.
* **Exploitation Vector:** Sending the payload `' OR 1=1--` in the login request:
  ```json
  POST /rest/user/login
  {"email": "' OR 1=1--", "password": "any"}
  ```
  The query resolved to `SELECT * FROM Users WHERE email = '' OR 1=1--...`, returning the first user in the database (`admin@juice-sh.op`) and issuing an admin JWT bearer token without credentials.
* **Remediation:** Replaced dynamic raw SQL string interpolation with Sequelize named parameter bindings (`:email`, `:password`). The database engine now treats input strictly as literal scalar values.
* **Verification:** Re-submitting the attack payload returns `HTTP 401 Unauthorized` (`"Invalid email or password"`). Semgrep static analysis findings dropped from 68 to 67 (-1 finding eliminated).

---

### 2. Stored Cross-Site Scripting (A03:2021 — CWE-79)
* **Assigned Engineer:** Haggalla H.H.D.S (`IT24100975`)
* **Vulnerable Components:** `server.ts` (Lines 442–463), `frontend/src/app/administration/administration.component.ts`, `administration.component.html`
* **Root Cause:** The public registration endpoint accepted arbitrary HTML/script tags as email addresses. When the administrator opened the admin table, Angular's built-in sanitizer was explicitly bypassed using `this.sanitizer.bypassSecurityTrustHtml()`, and user email values were bound directly into the DOM using `[innerHTML]`.
* **Exploitation Vector:** Registering with an XSS vector:
  ```json
  POST /api/Users
  {"email": "<iframe src=\"javascript:alert('XSS')\">@test.com", "password": "Password123!"}
  ```
  Upon viewing the user management console, the payload executed within the admin's browser context with full session privileges.
* **Defense-in-Depth Remediation:**
  1. *Backend Validation (`server.ts`):* Validates incoming registration emails against an RFC-compliant regex rejecting angle brackets (`<`, `>`) with `HTTP 400 Bad Request`.
  2. *Frontend Sanitization (`administration.component.ts`):* Completely removed the `bypassSecurityTrustHtml()` call.
  3. *Contextual Output Encoding (`administration.component.html`):* Replaced vulnerable `[innerHTML]="user.email"` with Angular safe text interpolation `{{ user.email }}`.
* **Verification:** Registration attempts with script tags are rejected at the API gateway with `HTTP 400 Bad Request`. Any pre-existing database records render strictly as inert text strings.

---

### 3. Insecure Direct Object Reference on Baskets (A01:2021 — CWE-639)
* **Assigned Engineer:** Disanayaka D.M.C.N (`IT24100239`)
* **Vulnerable Component:** `routes/basket.ts` (Lines 22–35)
* **Root Cause:** The `GET /rest/basket/{id}` endpoint verified that the client provided a valid JWT token, but never checked whether the requesting user actually owned the target basket ID.
* **Exploitation Vector:** Authenticating as User A (ID: 3) and sending `GET /rest/basket/1` allowed horizontal privilege escalation, retrieving the complete cart contents, products, and private shipping details of User B.
* **Remediation:** Added strict server-side ownership authorization:
  ```typescript
  const authenticatedUserId = req.user?.id
  if (basket.UserId !== authenticatedUserId && req.user?.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied: You do not own this basket.' })
  }
  ```
* **Verification:** Accessing a non-owned basket returns `HTTP 403 Forbidden` (`"Access denied: You do not own this basket."`).

---

### 4. Admin Registration - Improper Input Validation (A01:2021 — CWE-20)
* **Assigned Engineer:** Abeysekara T.T (`IT24100172`)
* **Vulnerable Components:** `server.ts` (`POST /api/Users`), `models/user.ts`
* **Root Cause:** The public user registration endpoint accepted arbitrary JSON fields and mapped them straight into the user model without attribute filtering, allowing clients to dictate internal account attributes.
* **Exploitation Vector:** Intercepting the registration request and injecting `"role": "admin"`:
  ```json
  POST /api/Users
  {"email": "attacker@test.com", "password": "Password123!", "role": "admin"}
  ```
  The account was persisted with administrative privileges, granting unauthorized access to the admin dashboard.
* **Remediation:** Added strict server-side validation rejecting any public registration request containing a client-specified `role` attribute with `HTTP 400 Bad Request`.
* **Verification:** Any registration payload attempting role assignment is rejected with `HTTP 400 Bad Request` (*"Role cannot be specified during public registration."*).

---

## ⚙️ Automated DevSecOps Pipeline

The continuous integration pipeline (`.github/workflows/devsecops.yml`) runs on every pull request and push to `master`. It enforces automated code quality, secret detection, vulnerability scanning, and dynamic assessment.

### Pipeline Architecture

<p align="center">
  <img src="https://res.cloudinary.com/dl9ectnzs/image/upload/v1791021976/Screenshot_2026-09-30_222102_mpflzr.png" alt="DevSecOps CI/CD Pipeline Architecture" width="850"/>
</p>

### Security Gates Specification

| Gate | Tool | Stage | Target | Fail Condition | Policy / Rationale | Gate Mode |
| :---: | :--- | :--- | :--- | :--- | :--- | :---: |
| **Gate 1** | **Semgrep** | SAST | Source Code (`.ts`, `.js`, `.html`) | Fails on `HIGH` severity findings | Identifies dangerous sinks, SQLi patterns, and unsanitized HTML bindings before PR merge. | **BLOCKING** |
| **Gate 2** | **npm audit** | SCA | Dependencies (`package.json`) | `audit-level=high` | Discovers vulnerable third-party dependencies; cataloged as advisory to permit legitimate learning libraries. | **ADVISORY** |
| **Gate 3** | **Gitleaks** | Secrets | Full Git History & Commits | Fails on detected keys/tokens (`exit-code 1`) | Enforces zero-tolerance against hardcoded credentials, JWT secrets, and API tokens. | **BLOCKING** |
| **Gate 4** | **Aqua Trivy** | Container | Docker Image Layers & OS | Fails on `CRITICAL` severity CVEs (`exit-code 1`) | Prevents vulnerable base image packages from reaching deployment environments. | **BLOCKING** |
| **Gate 5** | **OWASP ZAP** | DAST | Running App (`http://localhost:3000`) | Baseline Scan (`fail_action: false`) | Discovers runtime security header omissions, cookie flag gaps, and dynamic attack surfaces. | **ADVISORY** |

### 🛑 Empirical Blocking Evidence (Run #5 vs. Run #6)

To demonstrate the genuine DevSecOps mindset required by Section 1 of the brief:
* **The Blocked Build (Run #5 — Evidence of Pipeline Enforcement):**
  When the container image was scanned without exception handling, Aqua Trivy detected **6 CRITICAL CVEs** in base OS packages. Trivy returned `exit code 1`, terminating the workflow with a red failure and **blocking the build**.
* **The Remediated Build (Run #6 — Regulated Security Baseline):**
  The team triaged each CRITICAL finding, confirmed which vulnerabilities originated from intentional educational packages, documented mitigation notes in `.trivyignore`, and re-ran the pipeline. The build passed cleanly (**Green status**) with all security controls verified.

---

## 📁 Repository Structure

```text
IE3142-juice-shop/
├── .github/
│   └── workflows/
│       └── devsecops.yml           # Automated 5-Gate DevSecOps CI/CD pipeline
├── .gitleaks.toml                  # Gitleaks custom rules and exception baseline
├── .trivyignore                    # Documented container vulnerability triage list
├── .env.example                    # Template for required environment variables
├── docker-compose.yml              # Local container orchestration file
├── Dockerfile                      # Multi-stage production container build
├── models/
│   └── user.ts                     # User database model & role definitions
├── routes/
│   ├── login.ts                    # Remediated: Parameterized SQLi authentication
│   └── basket.ts                   # Remediated: IDOR ownership verification
├── server.ts                       # Remediated: Stored XSS & Admin input validation
├── frontend/src/app/
│   └── administration/             # Remediated: Angular safe text interpolation
├── reports/                        # Exported security reports (Semgrep, Trivy, ZAP)
└── README.md                       # Comprehensive project documentation
```

---

## 🚀 Local Setup & Reproduction Guide

### Prerequisites
* [Docker Desktop](https://www.docker.com/products/docker-desktop/) (v24.0+ recommended)
* [Git](https://git-scm.com/) (v2.30+)
* [Node.js](https://nodejs.org/) (v20 LTS — for local development)

### 1. Clone the Repository
```bash
git clone https://github.com/pasan2002/IE3142-juice-shop.git
cd IE3142-juice-shop
```

### 2. Configure Local Environment Variables
Create a local `.env` file from the example template:
```bash
cp .env.example .env
```
*(Ensure `JWT_SECRET` is configured. Note: `.env` is ignored by Git to prevent secrets leakage).*

### 3. Launch the Stack
Build and start the application in containerized mode:
```bash
docker compose up --build -d
```

### 4. Verify Application Health
Open your web browser and navigate to:
```text
http://localhost:3000
```
The application will finish initializing and seeding SQLite database migrations within 30–45 seconds.

### 5. Tear Down
```bash
docker compose down -v
```

---

## 🧪 Vulnerability Verification Commands (Examiner Test Suite)

Examiners can verify all four source code security remediations using standard `curl` commands against `http://localhost:3000`:

### 1. Test SQL Injection Fix (CWE-89)
```bash
curl -i -X POST http://localhost:3000/rest/user/login \
  -H "Content-Type: application/json" \
  -d '{"email":"'\'' OR 1=1--","password":"test"}'
```
* **Expected Result:** `HTTP/1.1 401 Unauthorized` (`{"error":"Invalid email or password."}`)

### 2. Test Stored XSS Fix (CWE-79)
```bash
curl -i -X POST http://localhost:3000/api/Users \
  -H "Content-Type: application/json" \
  -d '{"email":"<script>alert(1)</script>@test.com","password":"Password123!"}'
```
* **Expected Result:** `HTTP/1.1 400 Bad Request` (Email fails server-side validation).

### 3. Test Basket IDOR Fix (CWE-639)
```bash
# Retrieve Basket ID 1 using User 2's token:
curl -i -X GET http://localhost:3000/rest/basket/1 \
  -H "Authorization: Bearer <USER_2_JWT_TOKEN>"
```
* **Expected Result:** `HTTP/1.1 403 Forbidden` (`{"error":"Access denied: You do not own this basket."}`)

### 4. Test Admin Registration Privilege Escalation Fix (CWE-20)
```bash
curl -i -X POST http://localhost:3000/api/Users \
  -H "Content-Type: application/json" \
  -d '{"email":"escalation@test.com","password":"Password123!","role":"admin"}'
```
* **Expected Result:** `HTTP/1.1 400 Bad Request` (`Role cannot be specified during public registration.`)

---

## 🔬 Running Security Scans Locally

### Static Application Security Testing (Semgrep)
```bash
# Run Semgrep SAST scan across backend and frontend code
semgrep scan --config p/nodejs --config p/owasp-top-ten --json --output semgrep-results.json .
```

### Secret Detection (Gitleaks)
```bash
# Audit full git repository commit history for secret leaks
gitleaks detect --source=. --verbose --config=.gitleaks.toml
```

### Container Vulnerability Scan (Aqua Trivy)
```bash
# Scan the locally built container image against the triage baseline
trivy image --severity HIGH,CRITICAL --ignore-unfixed --trivyignores .trivyignore ie3142-juice-shop:latest
```

### Software Composition Analysis (npm audit)
```bash
# Audit production dependencies for published CVEs
npm audit --audit-level=high --omit=dev
```

---

## 🔒 Secrets Management Strategy

1. **Zero Hardcoded Secrets Policy:** No plaintext API keys, passwords, or cryptographic tokens are ever committed to version control. The repository `.gitignore` strictly blocks all variations of `.env`, `*.key`, and `*.pem`.
2. **Pre-Commit & CI Scanning:** Gitleaks scans every commit before and during CI pipeline execution to catch accidental commits before they merge into the branch history.
3. **Runtime Injection via GitHub Secrets:** Production runtime credentials (such as `JWT_SECRET`) are injected securely into the CI runner via GitHub Actions Encrypted Secrets (`${{ secrets.JWT_SECRET }}`), masked from runner log outputs.
4. **Local Isolation:** Local developers use `.env.example` to supply arbitrary local mock values that are never transmitted outside the container boundary.

---

## ⚖️ Academic Integrity & Ethical Clearance

* **Ethical Testing Scope:** All security exploitation and vulnerability verification were conducted strictly within isolated, local container environments on group members' personal machines. No external hosts or network assets were targeted.
* **Module Compliance:** This submission complies with all specifications set forth in the **IE3142 DevOps Security** assignment specification at the Sri Lanka Institute of Information Technology (SLIIT).
* **Attribution:** Target software is derived from the open-source project [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) (licensed under the MIT License). All architectural enhancements, security patches, threat models, and CI/CD pipelines represent the original work of Group 19.

---

<p align="center">
  <strong>SLIIT IE3142 DevOps Security — Group 19 (2026)</strong>
</p>
