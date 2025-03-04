# Vulnerabilities in SimpleChat Application

This document outlines the vulnerabilities implemented in the SimpleChat application, based on the [OWASP Top 10 Web Application Security Risks](https://owasp.org/www-project-top-ten/).

## Implemented Vulnerabilities

### A01:2021 - Broken Access Control

- [x] Plain text user cookie allowing session hijacking
- [x] Predictable conversation IDs allowing unauthorized access to private conversations
- [x] No proper authorization checks for admin functions
- [x] Direct object references allowing access to resources of other users

### A02:2021 - Cryptographic Failures

- [x] Passwords stored in plaintext in the database
- [x] Sensitive data exposed in user profiles (SSN, credit card numbers)
- [x] Weak hash function (MD5) used for conversation IDs
- [x] No encryption for sensitive data in transit (no HTTPS)

### A03:2021 - Injection

- [x] SQL Injection in login form
- [x] SQL Injection in search functionality
- [x] SQL Injection in message content (via vulnerable endpoint)
- [x] Cross-Site Scripting (XSS) in message content
- [x] Remote Code Execution via message parsing

### A04:2021 - Insecure Design

- [x] No rate limiting for login attempts
- [x] Debug endpoints exposed in production
- [x] Lack of proper error handling exposing stack traces

### A05:2021 - Security Misconfiguration

- [x] Default admin credentials (admin/admin123)
- [x] Debug mode enabled in production
- [x] Hardcoded secret key
- [x] Insecure HTTP headers

### A06:2021 - Vulnerable and Outdated Components

- [x] Using outdated libraries with known vulnerabilities
- [ ] No dependency checking or updating process

### A07:2021 - Identification and Authentication Failures

- [x] Plaintext password storage
- [x] Weak password policies (minimum 4 characters)
- [x] Session fixation vulnerability (no session ID regeneration)
- [x] No CSRF protection for password change

### A08:2021 - Software and Data Integrity Failures

- [x] Unrestricted file upload vulnerability
- [x] No integrity checks for uploaded content
- [x] Vulnerable update mechanism

### A09:2021 - Security Logging and Monitoring Failures

- [x] No logging of sensitive actions
- [x] No error logging
- [x] Detailed error messages in production
- [x] No rate limiting

### A10:2021 - Server-Side Request Forgery (SSRF)

- [x] Unvalidated URL fetching in profile picture URLs
- [x] Internal network scanning possible
- [x] No URL scheme restrictions

## Testing the Vulnerabilities

Each vulnerability can be tested using specific techniques:

1. **Plain text user cookie**: Modify the `current_user` cookie in the browser to access another user's account
2. **SQL Injection in login**: Use payloads like `' OR 1=1 --` in the login form
3. **SQL Injection in search**: Use payloads like `' UNION SELECT username,password FROM user--` in the search box
4. **SQL Injection in messages**: Send a message to the vulnerable endpoint with payloads like `test message', (SELECT password FROM user WHERE username='admin')), (1, 1, 'Leaked password: ` to extract data
5. **XSS in messages**: Send a message containing JavaScript code like `<script>alert('XSS')</script>`
6. **Remote Code Execution**: Send a message starting with `!exec!` followed by Python code, e.g., `!exec!import os; os.listdir('/')`
7. **CSRF**: Create an HTML form that submits to `/change-password` without the user's knowledge
8. **SSRF**: Use profile picture URLs pointing to internal services like `http://localhost:22` or `file:///etc/passwd`
9. **Unrestricted file upload**: Upload a PHP shell or other malicious file

## Automated Testing

We've implemented automated tests for many of these vulnerabilities in `test_simplechat_vulnerabilities.py`. The test suite includes:

- SQL Injection in login, search, and messages
- Cross-Site Scripting (XSS) in messages
- Cross-Site Request Forgery (CSRF) in password change
- Unrestricted file upload
- Server-Side Request Forgery (SSRF) in profile picture URL
- Sensitive data exposure in user profiles
- Cookie manipulation for authentication
- Predictable conversation hashes
- Debug mode and information disclosure
- Default credentials

To run the tests:

```bash
python test_simplechat_vulnerabilities.py
```

## Security Notice

This application is intentionally vulnerable and should NEVER be deployed in a production environment or exposed to the public internet. It is designed for educational purposes ONLY.
