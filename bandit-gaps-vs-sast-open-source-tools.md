# Bandit vs Full SAST Coverage
## Gaps in Bandit and Open‑Source Tools That Address Them

This document outlines the security coverage gaps present when using **Bandit** as a Python SAST tool, and lists **open‑source tools** that can be used to achieve broader Static Application Security Testing (SAST) coverage.

---

## Capability Coverage Comparison

| Security Capability | Bandit Coverage | Why Bandit Falls Short | Open‑source Tools That Cover It |
|-------------------|-----------------|-----------------------|---------------------------------|
| Cross‑file data flow (taint analysis) | ❌ Not supported | Pattern‑based scanning; no source‑to‑sink tracing across files | CodeQL, Semgrep, Joern |
| Cross‑function propagation | ❌ Not supported | Cannot track data through call stacks | CodeQL, Semgrep |
| Advanced SQL injection paths | ⚠️ Partial | Detects only direct, local patterns | CodeQL, Semgrep |
| Second‑order injections | ❌ Not supported | Requires multi‑step flow awareness | CodeQL, Joern |
| Business logic flaws | ❌ Not supported | No semantic understanding of workflows or rules | Semgrep (custom rules), CodeQL |
| Authorization logic (RBAC / ABAC) | ❌ Not supported | No identity or permission modeling | CodeQL, Semgrep |
| Authentication correctness (JWT, OAuth) | ❌ Not supported | Cannot analyze token lifecycle or claims | CodeQL, Semgrep |
| Framework‑aware security (Django / Flask) | ⚠️ Limited | Generic rules; minimal framework semantics | Semgrep, CodeQL |
| Sensitive data propagation (PII leakage) | ❌ Not supported | Cannot track sensitive data flow | CodeQL, Semgrep |
| Insecure logging of secrets | ⚠️ Partial | Flags literals only; misses derived secrets | Semgrep, CodeQL |
| Error handling & stack‑trace exposure | ❌ Not supported | Runtime behavior not inferred | Semgrep (custom rules) |
| Configuration‑driven vulnerabilities | ❌ Not supported | Source‑only analysis | Semgrep, Checkov |
| Infrastructure‑as‑Code (IaC) issues | ❌ Not applicable | Outside Bandit scope | Checkov, tfsec, KICS |
| Dependency / supply‑chain vulnerabilities (SCA) | ❌ Not supported | SAST ≠ SCA | pip‑audit, OSV‑Scanner, OWASP Dependency‑Check |
| Hardcoded secrets (non‑literal) | ⚠️ Partial | Misses dynamically loaded secrets | Gitleaks, TruffleHog |
| Deserialization gadget chains | ❌ Not supported | Requires deep control‑flow analysis | CodeQL, Joern |

---

## Recommended Open‑Source SAST Stack (Python‑centric)

| Layer | Tool | Purpose |
|-----|------|---------|
| Fast developer SAST | Bandit | Python‑specific pattern checks |
| Deep SAST & taint analysis | CodeQL | Cross‑file, semantic analysis |
| Extensible rule‑based SAST | Semgrep | Framework & business logic rules |
| Dependency security (SCA) | pip‑audit, OSV‑Scanner | Known CVE detection |
| Infrastructure security | Checkov, tfsec | Terraform, YAML, Helm analysis |
| Secrets detection | Gitleaks, TruffleHog | Git & CI secret scanning |

---

## Enterprise‑Grade Positioning Statement

> **Bandit provides Python‑specific, pattern‑based SAST coverage. Advanced SAST requirements such as cross‑file data‑flow analysis, authorization logic validation, and framework‑aware security analysis are achieved through complementary open‑source tools such as CodeQL and Semgrep.**

---

## Key Takeaway

Bandit is a **necessary but not sufficient** SAST control.  
A layered open‑source security toolchain is required to achieve **comprehensive SAST coverage** aligned with OWASP and enterprise DevSecOps standards.
