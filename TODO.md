# TODO: Implement OWASP Top 10 2021 Vulnerabilities

This document tracks the implementation of vulnerabilities for educational purposes in our vulnerable web application. Each item corresponds to a category in the OWASP Top 10 2021.

## A01:2021-Broken Access Control

- [x] Implement access control flaws (plain text cookie for admin privileges)
- [ ] Test for unauthorized access to restricted pages
- [ ] Simulate privilege escalation

## A02:2021-Cryptographic Failures

- [x] Use weak cryptographic algorithms (MD5)
- [x] Store sensitive data without encryption (plaintext passwords)
- [ ] Implement insecure key management

## A03:2021-Injection

- [x] SQL Injection in login and search
- [x] Cross-site Scripting (XSS) in search and username
- [ ] Command Injection (if file upload is added)

## A04:2021-Insecure Design

- [ ] Design application with intentional security flaws
- [ ] Lack of threat modeling and secure design patterns

## A05:2021-Security Misconfiguration

- [x] Default admin credentials
- [x] Debug mode enabled
- [x] Hardcoded secret key
- [x] Insecure HTTP headers

## A06:2021-Vulnerable and Outdated Components

- [ ] Use outdated libraries and dependencies
- [ ] Document known vulnerabilities in used components

## A07:2021-Identification and Authentication Failures

- [x] Plaintext password storage
- [x] Weak password policies
- [x] Session fixation

## A08:2021-Software and Data Integrity Failures

- [x] Simulate insecure software updates
- [x] Lack of integrity checks in CI/CD pipeline
- [x] Implement vulnerable backup functionality

## A09:2021-Security Logging and Monitoring Failures

- [ ] Lack of logging for security events
- [ ] No monitoring or alerting for suspicious activities

## A10:2021-Server-Side Request Forgery

- [x] Implement SSRF vulnerability
- [x] Test for SSRF in server-side requests
- [x] Allow internal network scanning

---

⚠️ **WARNING: These vulnerabilities are for educational purposes only.** ⚠️

This application is intentionally vulnerable and should only be used in a controlled, isolated environment. Never deploy this application in a production environment or expose it to the public internet.
