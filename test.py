#!/usr/bin/env python3
"""
API Security Testing Suite
==========================

This script tests various security vulnerabilities in API endpoints.
It compares insecure (V1) vs secure (V2) implementations to demonstrate
the effectiveness of different security measures.

Author: API Security Research Team
Version: 1.0.0
"""

import requests
import json
import time
import threading
import random
import string
from datetime import datetime
from typing import Dict, List, Tuple, Optional
import argparse
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
import os
import platform

# Add color support for better output
try:
    from colorama import init, Fore, Back, Style
    # Initialize colorama with Windows-specific settings
    # strip=False preserves ANSI color codes in Windows terminal
    # This ensures colors work correctly in both Windows Command Prompt and PowerShell
    init(autoreset=True, strip=False)
    COLORS_AVAILABLE = True
except ImportError:
    COLORS_AVAILABLE = False
    # Fallback color definitions
    class Fore:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ""
    class Style:
        BRIGHT = DIM = RESET_ALL = ""

@dataclass
class TestResult:
    """Data class to store test results"""
    test_name: str
    version: str
    success: bool
    response_code: int
    response_time: float
    vulnerability_found: bool
    details: str
    raw_response: Optional[str] = None

class APISecurityTester:
    """
    Comprehensive API Security Testing Suite

    This class provides methods to test various security vulnerabilities
    including SQL injection, authentication bypass, authorization flaws,
    and rate limiting effectiveness.
    """

    def __init__(self, base_url: str = "http://localhost:3000"):
        self.base_url = base_url.rstrip('/')
        self.v1_base = f"{self.base_url}/v1"
        self.v2_base = f"{self.base_url}/v2"
        self.session = requests.Session()
        self.results: List[TestResult] = []
        self.tokens = {"v1": None, "v2": None}

        # Test configuration
        self.test_users = [
            {"username": "admin", "password": "admin"},
            {"username": "user1", "password": "password123"},
            {"username": "testuser", "password": "testpass123"}
        ]

        print(f"{Fore.CYAN}🔧 API Security Tester Initialized")
        print(f"{Fore.CYAN}📍 Target: {self.base_url}")
        print(f"{Fore.CYAN}{'='*60}")

    def print_header(self, title: str):
        """Print a formatted header for test sections"""
        print(f"\n{Fore.YELLOW}{Style.BRIGHT}{'='*60}")
        print(f"{Fore.YELLOW}{Style.BRIGHT}🧪 {title}")
        print(f"{Fore.YELLOW}{Style.BRIGHT}{'='*60}")

    def print_test_info(self, test_name: str, description: str):
        """Print test information"""
        print(f"\n{Fore.BLUE}🔍 Test: {test_name}")
        print(f"{Fore.BLUE}📝 Description: {description}")
        print(f"{Fore.BLUE}{'-'*50}")

    def print_result(self, result: TestResult):
        """Print formatted test result"""
        status_color = Fore.GREEN if not result.vulnerability_found else Fore.RED
        status_text = "SECURE ✅" if not result.vulnerability_found else "VULNERABLE ❌"

        print(f"{status_color}📊 {result.version.upper()}: {status_text}")
        print(f"   Response Code: {result.response_code}")
        print(f"   Response Time: {result.response_time:.3f}s")
        print(f"   Details: {result.details}")

        if result.vulnerability_found and result.raw_response:
            print(f"   {Fore.RED}⚠️  Vulnerability Evidence: {result.raw_response[:100]}...")

    def check_api_health(self) -> bool:
        """
        Check if the API is running and accessible

        Returns:
            bool: True if API is healthy, False otherwise
        """
        print(f"{Fore.CYAN}🏥 Checking API Health...")

        try:
            response = self.session.get(f"{self.base_url}/health", timeout=5)
            if response.status_code == 200:
                print(f"{Fore.GREEN}✅ API is healthy and running")
                return True
            else:
                print(f"{Fore.RED}❌ API health check failed: {response.status_code}")
                return False
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}❌ Cannot connect to API: {e}")
            print(f"{Fore.YELLOW}💡 Make sure your API server is running on {self.base_url}")
            return False

    def prompt_for_url(self) -> str:
        """
        Prompt user for a new API server URL

        Returns:
            str: New API server URL
        """
        while True:
            new_url = input(f"{Fore.YELLOW}Enter new API server URL [http://localhost:3000]: ").strip()
            if not new_url:
                new_url = "http://localhost:3000"
            # Validate URL format
            if not new_url.startswith(('http://', 'https://')):
                new_url = 'http://' + new_url
            try:
                # Test if URL is valid
                requests.get(new_url, timeout=2)
                return new_url
            except requests.exceptions.RequestException:
                print(f"{Fore.RED}❌ Invalid URL or server not responding. Please try again.")

    def test_sql_injection(self) -> List[TestResult]:
        """
        Test SQL Injection Vulnerabilities

        This test attempts to bypass authentication using SQL injection
        techniques. V1 should be vulnerable, V2 should be protected.
        """
        self.print_test_info(
            "SQL Injection Attack",
            "Attempting to bypass login authentication using SQL injection payloads"
        )

        results = []

        # Common SQL injection payloads
        sql_payloads = [
            {"username": "admin' OR '1'='1", "password": "anything"},
            {"username": "admin'; DROP TABLE users; --", "password": "test"},
            {"username": "admin' UNION SELECT * FROM users --", "password": "test"},
            {"username": "' OR 1=1 --", "password": "anything"},
            {"username": "admin'/**/OR/**/1=1#", "password": "test"}
        ]

        for version in ["v1", "v2"]:
            base_url = self.v1_base if version == "v1" else self.v2_base
            vulnerable = False
            details = "No SQL injection vulnerability found"
            response_data = ""

            print(f"\n{Fore.MAGENTA}Testing {version.upper()} for SQL injection...")

            for i, payload in enumerate(sql_payloads, 1):
                try:
                    start_time = time.time()
                    response = self.session.post(
                        f"{base_url}/auth/login",
                        json=payload,
                        timeout=10
                    )
                    response_time = time.time() - start_time

                    print(f"  Payload {i}: {payload['username'][:30]}... -> {response.status_code}")

                    # Check if injection was successful
                    if response.status_code == 200:
                        try:
                            data = response.json()
                            if data.get('success') or 'token' in data or 'user' in data:
                                vulnerable = True
                                details = f"SQL injection successful with payload: {payload['username']}"
                                response_data = json.dumps(data)[:200]
                                print(f"    {Fore.RED}🚨 INJECTION SUCCESSFUL!")
                                break
                        except json.JSONDecodeError:
                            pass

                except requests.exceptions.RequestException as e:
                    response_time = 0
                    print(f"    {Fore.YELLOW}⚠️  Request failed: {e}")

            result = TestResult(
                test_name="SQL Injection",
                version=version,
                success=True,
                response_code=response.status_code if 'response' in locals() else 0,
                response_time=response_time if 'response_time' in locals() else 0,
                vulnerability_found=vulnerable,
                details=details,
                raw_response=response_data
            )

            results.append(result)
            self.results.append(result)
            self.print_result(result)

        return results

    def test_authentication_bypass(self) -> List[TestResult]:
        """
        Test Authentication Bypass

        This test attempts to access protected resources without proper authentication.
        """
        self.print_test_info(
            "Authentication Bypass",
            "Attempting to access protected resources without authentication"
        )

        results = []
        protected_endpoints = [
            "/users/1",
            "/users",
            "/data/user/1",
            "/data/all"
        ]

        for version in ["v1", "v2"]:
            base_url = self.v1_base if version == "v1" else self.v2_base
            bypass_count = 0
            total_tests = len(protected_endpoints)

            print(f"\n{Fore.MAGENTA}Testing {version.upper()} authentication bypass...")

            for endpoint in protected_endpoints:
                try:
                    start_time = time.time()
                    response = self.session.get(f"{base_url}{endpoint}", timeout=10)
                    response_time = time.time() - start_time

                    print(f"  {endpoint} -> {response.status_code}")

                    # If we get 200 OK without authentication, it's a bypass
                    if response.status_code == 200:
                        bypass_count += 1
                        try:
                            data = response.json()
                            if isinstance(data, (list, dict)) and data:
                                print(f"    {Fore.RED}🚨 DATA EXPOSED!")
                        except:
                            pass

                except requests.exceptions.RequestException as e:
                    response_time = 0
                    print(f"    {Fore.YELLOW}⚠️  Request failed: {e}")

            vulnerable = bypass_count > 0
            details = f"Bypassed authentication on {bypass_count}/{total_tests} endpoints"

            result = TestResult(
                test_name="Authentication Bypass",
                version=version,
                success=True,
                response_code=200 if bypass_count > 0 else 401,
                response_time=response_time if 'response_time' in locals() else 0,
                vulnerability_found=vulnerable,
                details=details
            )

            results.append(result)
            self.results.append(result)
            self.print_result(result)

        return results

    def test_bola_vulnerability(self) -> List[TestResult]:
        """
        Test Broken Object Level Authorization (BOLA)

        This test attempts to access other users' data by manipulating object IDs.
        """
        self.print_test_info(
            "BOLA (Broken Object Level Authorization)",
            "Attempting to access other users' data by manipulating user IDs"
        )

        results = []

        # First, try to get valid authentication for testing
        self._attempt_login()

        for version in ["v1", "v2"]:
            base_url = self.v1_base if version == "v1" else self.v2_base
            bola_successful = False
            details = "BOLA attack failed - proper authorization in place"

            print(f"\n{Fore.MAGENTA}Testing {version.upper()} for BOLA...")

            # Test accessing different user IDs
            for user_id in range(1, 5):
                try:
                    headers = {}
                    if version == "v2" and self.tokens["v2"]:
                        headers["Authorization"] = f"Bearer {self.tokens['v2']}"

                    start_time = time.time()
                    response = self.session.get(
                        f"{base_url}/users/{user_id}",
                        headers=headers,
                        timeout=10
                    )
                    response_time = time.time() - start_time

                    print(f"  User ID {user_id} -> {response.status_code}")

                    if response.status_code == 200:
                        try:
                            data = response.json()
                            if 'password' in str(data) or 'api_key' in str(data):
                                bola_successful = True
                                details = f"BOLA successful - accessed user {user_id} data with sensitive info"
                                print(f"    {Fore.RED}🚨 SENSITIVE DATA EXPOSED!")
                                break
                        except:
                            pass

                except requests.exceptions.RequestException as e:
                    response_time = 0
                    print(f"    {Fore.YELLOW}⚠️  Request failed: {e}")

            result = TestResult(
                test_name="BOLA",
                version=version,
                success=True,
                response_code=response.status_code if 'response' in locals() else 0,
                response_time=response_time if 'response_time' in locals() else 0,
                vulnerability_found=bola_successful,
                details=details
            )

            results.append(result)
            self.results.append(result)
            self.print_result(result)

        return results

    def test_rate_limiting(self) -> List[TestResult]:
        """
        Test Rate Limiting Effectiveness

        This test sends multiple rapid requests to check if rate limiting is properly implemented.
        It tests both authenticated and unauthenticated endpoints to ensure rate limiting works
        in all scenarios.
        """
        self.print_test_info(
            "Rate Limiting",
            "Sending rapid requests to test rate limiting implementation"
        )

        results = []

        for version in ["v1", "v2"]:
            base_url = self.v1_base if version == "v1" else self.v2_base
            rate_limited = False
            successful_requests = 0
            total_requests = 30  # Reduced from 50 to be less aggressive
            rate_limit_headers = []
            rate_limit_responses = []

            print(f"\n{Fore.MAGENTA}Testing {version.upper()} rate limiting with {total_requests} requests...")

            # Test both authenticated and unauthenticated endpoints
            test_endpoints = [
                "/users",  # Unauthenticated endpoint
                "/data/all" if version == "v1" else "/data/public"  # Authenticated endpoint
            ]

            for endpoint in test_endpoints:
                headers = {}
                if version == "v2" and self.tokens["v2"]:
                    headers["Authorization"] = f"Bearer {self.tokens['v2']}"

                # Send rapid requests
                start_time = time.time()
                for i in range(total_requests):
                    try:
                        response = self.session.get(
                            f"{base_url}{endpoint}",
                            headers=headers,
                            timeout=5
                        )

                        # Check for rate limit headers
                        rate_limit_headers.extend([
                            h for h in response.headers.keys()
                            if 'rate' in h.lower() or 'limit' in h.lower()
                        ])

                        if response.status_code == 429:  # Too Many Requests
                            rate_limited = True
                            rate_limit_responses.append(response.text)
                            print(f"  Request {i+1}: {Fore.YELLOW}RATE LIMITED (429)")
                            break
                        elif response.status_code in [200, 401, 403]:
                            successful_requests += 1
                            if i % 10 == 0:  # Print every 10th request
                                print(f"  Request {i+1}: {response.status_code}")

                        # Small delay to avoid overwhelming the server
                        time.sleep(0.1)

                    except requests.exceptions.RequestException as e:
                        print(f"  Request {i+1}: {Fore.YELLOW}FAILED - {e}")
                        break

                if rate_limited:
                    break

            total_time = time.time() - start_time

            # Check for rate limit headers in responses
            has_rate_limit_headers = len(rate_limit_headers) > 0

            # Determine if rate limiting is properly implemented
            # Rate limiting is considered proper if:
            # 1. We get a 429 status code, or
            # 2. We see rate limit headers in the response
            proper_rate_limiting = rate_limited or has_rate_limit_headers

            details = f"Sent {successful_requests}/{total_requests} requests in {total_time:.2f}s"
            if proper_rate_limiting:
                details += " - Rate limiting active"
                if rate_limit_headers:
                    details += f" (Headers: {', '.join(rate_limit_headers)})"
            else:
                details += " - No rate limiting detected"

            result = TestResult(
                test_name="Rate Limiting",
                version=version,
                success=True,
                response_code=429 if rate_limited else 200,
                response_time=total_time,
                vulnerability_found=not proper_rate_limiting,  # Vulnerability if NO proper rate limiting
                details=details
            )

            results.append(result)
            self.results.append(result)
            self.print_result(result)

        return results

    def test_sensitive_data_exposure(self) -> List[TestResult]:
        """
        Test Sensitive Data Exposure

        This test checks if sensitive information like passwords, API keys,
        or internal data is exposed in API responses.
        """
        self.print_test_info(
            "Sensitive Data Exposure",
            "Checking if sensitive information is exposed in API responses"
        )

        results = []

        for version in ["v1", "v2"]:
            base_url = self.v1_base if version == "v1" else self.v2_base
            sensitive_exposed = False
            exposed_fields = []

            print(f"\n{Fore.MAGENTA}Testing {version.upper()} for sensitive data exposure...")

            # Test endpoints that might expose sensitive data
            test_endpoints = [
                "/users",
                "/users/1",
                "/data/all" if version == "v1" else "/data/public"
            ]

            for endpoint in test_endpoints:
                try:
                    headers = {}
                    if version == "v2" and self.tokens["v2"]:
                        headers["Authorization"] = f"Bearer {self.tokens['v2']}"

                    start_time = time.time()
                    response = self.session.get(
                        f"{base_url}{endpoint}",
                        headers=headers,
                        timeout=10
                    )
                    response_time = time.time() - start_time

                    print(f"  {endpoint} -> {response.status_code}")

                    if response.status_code == 200:
                        try:
                            data = response.json()
                            response_text = json.dumps(data).lower()

                            # Check for sensitive fields
                            sensitive_fields = ['password', 'api_key', 'secret', 'token', 'private']
                            for field in sensitive_fields:
                                if field in response_text:
                                    sensitive_exposed = True
                                    exposed_fields.append(field)
                                    print(f"    {Fore.RED}🚨 SENSITIVE FIELD FOUND: {field}")

                        except json.JSONDecodeError:
                            pass

                except requests.exceptions.RequestException as e:
                    response_time = 0
                    print(f"    {Fore.YELLOW}⚠️  Request failed: {e}")

            details = "No sensitive data exposure detected"
            if sensitive_exposed:
                details = f"Sensitive fields exposed: {', '.join(set(exposed_fields))}"

            result = TestResult(
                test_name="Sensitive Data Exposure",
                version=version,
                success=True,
                response_code=response.status_code if 'response' in locals() else 0,
                response_time=response_time if 'response_time' in locals() else 0,
                vulnerability_found=sensitive_exposed,
                details=details
            )

            results.append(result)
            self.results.append(result)
            self.print_result(result)

        return results

    def test_input_validation(self) -> List[TestResult]:
        """
        Test Input Validation

        This test sends malformed and malicious input to check if proper
        input validation is implemented.
        """
        self.print_test_info(
            "Input Validation",
            "Testing input validation with malformed and malicious payloads"
        )

        results = []

        # Malicious payloads
        malicious_payloads = [
            {"username": "<script>alert('xss')</script>", "password": "test"},
            {"username": "../../etc/passwd", "password": "test"},
            {"username": "A" * 1000, "password": "test"},  # Buffer overflow attempt
            {"username": {"$ne": None}, "password": "test"},  # NoSQL injection
            {"username": "admin", "password": None},  # Null injection
        ]

        for version in ["v1", "v2"]:
            base_url = self.v1_base if version == "v1" else self.v2_base
            validation_bypassed = False
            bypass_details = []

            print(f"\n{Fore.MAGENTA}Testing {version.upper()} input validation...")

            for i, payload in enumerate(malicious_payloads, 1):
                try:
                    start_time = time.time()
                    response = self.session.post(
                        f"{base_url}/auth/login",
                        json=payload,
                        timeout=10
                    )
                    response_time = time.time() - start_time

                    print(f"  Payload {i}: {str(payload)[:50]}... -> {response.status_code}")

                    # Check if malicious input was processed without proper validation
                    if response.status_code == 200:
                        validation_bypassed = True
                        bypass_details.append(f"Payload {i} processed successfully")
                        print(f"    {Fore.RED}🚨 VALIDATION BYPASSED!")
                    elif response.status_code == 500:
                        # Server error might indicate injection success
                        validation_bypassed = True
                        bypass_details.append(f"Payload {i} caused server error")
                        print(f"    {Fore.RED}🚨 SERVER ERROR - POSSIBLE INJECTION!")

                except requests.exceptions.RequestException as e:
                    response_time = 0
                    print(f"    {Fore.YELLOW}⚠️  Request failed: {e}")

            details = "Input validation working properly"
            if validation_bypassed:
                details = f"Validation bypassed: {'; '.join(bypass_details)}"

            result = TestResult(
                test_name="Input Validation",
                version=version,
                success=True,
                response_code=response.status_code if 'response' in locals() else 0,
                response_time=response_time if 'response_time' in locals() else 0,
                vulnerability_found=validation_bypassed,
                details=details
            )

            results.append(result)
            self.results.append(result)
            self.print_result(result)

        return results

    def test_brute_force_protection(self) -> List[TestResult]:
        """
        Test Brute Force Protection

        This test attempts multiple login attempts with different passwords
        to check if brute force protection is implemented.
        """
        self.print_test_info(
            "Brute Force Protection",
            "Testing protection against brute force login attempts"
        )

        results = []

        for version in ["v1", "v2"]:
            base_url = self.v1_base if version == "v1" else self.v2_base
            blocked = False
            successful_attempts = 0
            total_attempts = 20

            print(f"\n{Fore.MAGENTA}Testing {version.upper()} brute force protection...")

            # Generate random passwords for brute force
            passwords = [f"password{i}" for i in range(total_attempts)]

            start_time = time.time()
            for i, password in enumerate(passwords, 1):
                try:
                    response = self.session.post(
                        f"{base_url}/auth/login",
                        json={"username": "admin", "password": password},
                        timeout=10
                    )

                    if response.status_code == 429:  # Rate limited
                        blocked = True
                        print(f"  Attempt {i}: {Fore.YELLOW}BLOCKED (429)")
                        break
                    elif response.status_code == 200:
                        successful_attempts += 1
                        print(f"  Attempt {i}: {Fore.GREEN}SUCCESS")
                    else:
                        print(f"  Attempt {i}: {response.status_code}")

                    # Small delay between attempts
                    time.sleep(0.2)

                except requests.exceptions.RequestException as e:
                    print(f"  Attempt {i}: {Fore.YELLOW}FAILED - {e}")
                    break

            total_time = time.time() - start_time

            details = f"Completed {i}/{total_attempts} attempts in {total_time:.2f}s"
            if blocked:
                details += " - Brute force protection active"
            else:
                details += " - No brute force protection detected"

            result = TestResult(
                test_name="Brute Force Protection",
                version=version,
                success=True,
                response_code=429 if blocked else 401,
                response_time=total_time,
                vulnerability_found=not blocked,  # Vulnerability if NOT blocked
                details=details
            )

            results.append(result)
            self.results.append(result)
            self.print_result(result)

        return results

    def _attempt_login(self):
        """Helper method to attempt login for both versions"""
        for version in ["v1", "v2"]:
            base_url = self.v1_base if version == "v1" else self.v2_base

            for user in self.test_users:
                try:
                    response = self.session.post(
                        f"{base_url}/auth/login",
                        json=user,
                        timeout=10
                    )

                    if response.status_code == 200:
                        data = response.json()
                        if 'token' in data:
                            self.tokens[version] = data['token']
                            print(f"  {Fore.GREEN}✅ Logged in to {version.upper()} as {user['username']}")
                            break
                except:
                    continue

    def generate_report(self) -> str:
        """
        Generate a comprehensive security report

        Returns:
            str: Formatted security report
        """
        self.print_header("SECURITY ASSESSMENT REPORT")

        # Summary statistics
        total_tests = len(self.results)
        v1_vulnerabilities = len([r for r in self.results if r.version == "v1" and r.vulnerability_found])
        v2_vulnerabilities = len([r for r in self.results if r.version == "v2" and r.vulnerability_found])
        total_test_types = total_tests // 2  # Since we test both v1 and v2 for each test type

        print(f"\n{Fore.CYAN}📊 SUMMARY STATISTICS")
        print(f"{Fore.CYAN}{'='*40}")
        print(f"Total Tests Conducted: {total_tests}")
        print(f"V1 (Insecure) Vulnerabilities: {Fore.RED}{v1_vulnerabilities}/{total_test_types} ({v1_vulnerabilities/total_test_types*100:.0f}%)")
        print(f"V2 (Secure) Vulnerabilities: {Fore.GREEN}{v2_vulnerabilities}/{total_test_types} ({v2_vulnerabilities/total_test_types*100:.0f}%)")

        # Detailed results by test type
        test_types = list(set([r.test_name for r in self.results]))

        print(f"\n{Fore.CYAN}📋 DETAILED RESULTS BY TEST TYPE")
        print(f"{Fore.CYAN}{'='*50}")

        for test_type in test_types:
            print(f"\n{Fore.YELLOW}🧪 {test_type}")
            print(f"{Fore.YELLOW}{'-'*30}")

            v1_result = next((r for r in self.results if r.test_name == test_type and r.version == "v1"), None)
            v2_result = next((r for r in self.results if r.test_name == test_type and r.version == "v2"), None)

            if v1_result:
                status = "VULNERABLE ❌" if v1_result.vulnerability_found else "SECURE ✅"
                color = Fore.RED if v1_result.vulnerability_found else Fore.GREEN
                print(f"  V1: {color}{status}")
                print(f"      {v1_result.details}")

            if v2_result:
                status = "VULNERABLE ❌" if v2_result.vulnerability_found else "SECURE ✅"
                color = Fore.RED if v2_result.vulnerability_found else Fore.GREEN
                print(f"  V2: {color}{status}")
                print(f"      {v2_result.details}")

        # Recommendations
        print(f"\n{Fore.CYAN}💡 SECURITY RECOMMENDATIONS")
        print(f"{Fore.CYAN}{'='*40}")

        if v1_vulnerabilities > 0:
            print(f"{Fore.YELLOW}🔧 For V1 (Insecure Version):")
            print(f"   • Implement proper input validation and sanitization")
            print(f"   • Add authentication and authorization mechanisms")
            print(f"   • Implement rate limiting to prevent brute force attacks")
            print(f"   • Use parameterized queries to prevent SQL injection")
            print(f"   • Avoid exposing sensitive data in API responses")

        if v2_vulnerabilities == 0:
            print(f"{Fore.GREEN}✅ V2 (Secure Version) shows good security practices!")
        else:
            print(f"{Fore.YELLOW}🔧 For V2 (Secure Version):")
            print(f"   • Review and strengthen remaining vulnerabilities")
            print(f"   • Consider additional security layers")

        # Performance impact
        print(f"\n{Fore.CYAN}⚡ PERFORMANCE IMPACT")
        print(f"{Fore.CYAN}{'='*30}")

        v1_avg_time = sum([r.response_time for r in self.results if r.version == "v1"]) / len([r for r in self.results if r.version == "v1"])
        v2_avg_time = sum([r.response_time for r in self.results if r.version == "v2"]) / len([r for r in self.results if r.version == "v2"])

        print(f"V1 Average Response Time: {v1_avg_time:.3f}s")
        print(f"V2 Average Response Time: {v2_avg_time:.3f}s")
        print(f"Security Overhead: {((v2_avg_time - v1_avg_time) / v1_avg_time * 100):.1f}%")

        return "Report generated successfully"

    def run_all_tests(self):
        """Run all security tests"""
        if not self.check_api_health():
            print(f"{Fore.RED}❌ Cannot proceed with tests - API is not accessible")
            return

        print(f"\n{Fore.GREEN}🚀 Starting comprehensive security testing...")
        print(f"{Fore.GREEN}⏱️  This may take several minutes to complete")

        # Run all tests
        test_methods = [
            self.test_sql_injection,
            self.test_authentication_bypass,
            self.test_bola_vulnerability,
            self.test_sensitive_data_exposure,
            self.test_input_validation,
            self.test_rate_limiting,
            self.test_brute_force_protection
        ]

        for test_method in test_methods:
            try:
                test_method()
                time.sleep(1)  # Brief pause between tests
            except Exception as e:
                print(f"{Fore.RED}❌ Test failed: {e}")

        # Generate final report
        self.generate_report()

        print(f"\n{Fore.GREEN}🎉 Security testing completed!")
        print(f"{Fore.GREEN}📄 Check the detailed report above for findings and recommendations")

def main():
    """Main function to run the security tester"""
    parser = argparse.ArgumentParser(
        description="API Security Testing Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python api_security_tester.py                    # Test localhost:3000
  python api_security_tester.py --url http://api.example.com:8080
  python api_security_tester.py --test sql         # Run only SQL injection tests
  python api_security_tester.py --verbose          # Detailed output
        """
    )

    parser.add_argument(
        '--url',
        default='http://localhost:3000',
        help='Base URL of the API to test (default: http://localhost:3000)'
    )

    parser.add_argument(
        '--test',
        choices=['sql', 'auth', 'bola', 'rate', 'data', 'input', 'brute', 'all'],
        default='all',
        help='Specific test to run (default: all)'
    )

    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose output'
    )

    args = parser.parse_args()

    # Print system information
    print(f"{Fore.CYAN}System Information:")
    print(f"{Fore.CYAN}OS: {platform.system()} {platform.release()}")
    print(f"{Fore.CYAN}Python: {platform.python_version()}")
    print(f"{Fore.CYAN}Colors Available: {'Yes' if COLORS_AVAILABLE else 'No'}")
    print(f"{Fore.CYAN}{'='*60}\n")

    # Create tester instance
    tester = APISecurityTester(args.url)

    # Check if server is running, prompt for new URL if not
    while not tester.check_api_health():
        print(f"{Fore.YELLOW}Would you like to try a different API server URL? [Y/n]", end=" ")
        response = input().lower().strip()
        if response in ['', 'y', 'yes']:
            new_url = tester.prompt_for_url()
            tester = APISecurityTester(new_url)
        else:
            print(f"{Fore.RED}❌ Exiting - API server is required for testing")
            return

    # Run specific test or all tests
    if args.test == 'all':
        tester.run_all_tests()
    else:
        test_map = {
            'sql': tester.test_sql_injection,
            'auth': tester.test_authentication_bypass,
            'bola': tester.test_bola_vulnerability,
            'rate': tester.test_rate_limiting,
            'data': tester.test_sensitive_data_exposure,
            'input': tester.test_input_validation,
            'brute': tester.test_brute_force_protection
        }

        test_map[args.test]()
        tester.generate_report()

if __name__ == "__main__":
    main()
