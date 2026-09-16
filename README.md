# IE3142 DevOps Security — OWASP Juice Shop Assessment

## Project Overview

This repository contains the group assessment submission for **IE3142 DevOps Security** at the Sri Lanka Institute of Information Technology (SLIIT). The assessment targets [OWASP Juice Shop](https://github.com/juice-shop/juice-shop), a deliberately vulnerable Node.js web application designed for security training.

The goal of this assessment is to demonstrate a practical DevSecOps workflow across three phases:

1. **Exploit** — Identify and manually exploit real vulnerabilities in Juice Shop, mapped to the OWASP Top 10 (2021)
2. **Fix** — Remediate each vulnerability through secure coding practices and verify the fix
3. **Gate** — Enforce automated security checks in a GitHub Actions CI/CD pipeline so that insecure code cannot reach `main`

The pipeline integrates four security gates: static analysis (Semgrep), dependency auditing (npm audit), secret detection (Gitleaks), and container scanning (Trivy).

---
