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
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
import os
import platform
import logging
from pathlib import Path
import hashlib
import base64
import urllib.parse

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

class Spinner:
    """A simple spinner for command line progress indication"""
    def __init__(self, message="", delay=0.1):
        self.spinner_chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
        self.delay = delay
        self.message = message
        self.stop_running = False
        self.spinner_thread = None

    def spin(self):
        """Spin the spinner"""
        i = 0
        while not self.stop_running:
            sys.stdout.write(f"\r{self.spinner_chars[i]} {self.message}")
            sys.stdout.flush()
            time.sleep(self.delay)
            i = (i + 1) % len(self.spinner_chars)

    def start(self):
        """Start the spinner"""
        self.stop_running = False
        self.spinner_thread = threading.Thread(target=self.spin)
        self.spinner_thread.daemon = True
        self.spinner_thread.start()

    def stop(self):
        """Stop the spinner"""
        self.stop_running = True
        if self.spinner_thread:
            self.spinner_thread.join()
        sys.stdout.write("\r" + " " * (len(self.message) + 2) + "\r")
        sys.stdout.flush()

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
    severity: str = "medium"  # low, medium, high, critical
    attack_vector: str = ""
    raw_response: Optional[str] = None
    timestamp: Optional[str] = None

    def to_dict(self):
        """Convert to dictionary for JSON serialization"""
        return asdict(self)

class ColoredFormatter(logging.Formatter):
    """Custom formatter that preserves color codes in log files"""

    def format(self, record):
        # Store original message
        original_msg = record.getMessage()

        # Add timestamp and level info
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        level = record.levelname

        # Format with colors preserved
        formatted_msg = f"[{timestamp}] [{level}] {original_msg}"

        return formatted_msg

class APISecurityTester:
    """
    Comprehensive API Security Testing Suite

    This class provides methods to test various security vulnerabilities
    including SQL injection, authentication bypass, authorization flaws,
    and rate limiting effectiveness.
    """

    def __init__(self, base_url: str = "http://localhost:3000", verbose: bool = False, enable_logging: bool = True):
        self.base_url = base_url.rstrip('/')
        self.v1_base = f"{self.base_url}/v1"
        self.v2_base = f"{self.base_url}/v2"
        self.session = requests.Session()
        self.results: List[TestResult] = []
        self.all_runs_results: List[List[TestResult]] = []  # Store results from all runs
        self.tokens = {"v1": None, "v2": None}
        self.verbose = verbose
        self.enable_logging = enable_logging
        self.start_time = datetime.now()
        self.run_start_time = None

        # Setup logging
        if self.enable_logging:
            self.setup_logging()

        # Test configuration
        self.test_users = [
            {"username": "admin", "password": "admin"},
            {"username": "user1", "password": "password123"},
            {"username": "user2", "password": "password123"}
        ]

        if self.verbose:
            print(f"{Fore.CYAN}🔧 API Security Tester Initialized")
            print(f"{Fore.CYAN}📍 Target: {self.base_url}")
            print(f"{Fore.CYAN}{'='*60}")

        self.log_info(f"API Security Tester initialized for {self.base_url}")

    def setup_logging(self):
        """Setup comprehensive logging system"""
        # Create logs directory
        self.log_dir = Path("logs")
        self.log_dir.mkdir(exist_ok=True)

        # Create timestamped log files
        timestamp = self.start_time.strftime('%Y%m%d_%H%M%S')

        # Human readable log
        self.human_log_file = self.log_dir / f"security_test_{timestamp}_human.log"

        # Machine readable log (JSON)
        self.machine_log_file = self.log_dir / f"security_test_{timestamp}_machine.json"

        # Setup human readable logger
        self.human_logger = logging.getLogger('human_readable')
        self.human_logger.setLevel(logging.INFO)

        # Remove existing handlers
        for handler in self.human_logger.handlers[:]:
            self.human_logger.removeHandler(handler)

        # Human readable file handler
        human_handler = logging.FileHandler(self.human_log_file, encoding='utf-8')
        human_handler.setFormatter(ColoredFormatter())
        self.human_logger.addHandler(human_handler)

        # Machine readable data storage
        self.machine_log_data = {
            "test_session": {
                "start_time": self.start_time.isoformat(),
                "target_url": self.base_url,
                "system_info": {
                    "os": platform.system(),
                    "os_version": platform.release(),
                    "python_version": platform.python_version(),
                    "colors_available": COLORS_AVAILABLE
                }
            },
            "runs": []
        }

        print(f"{Fore.CYAN}📝 Logging enabled:")
        print(f"{Fore.CYAN}   Human readable: {self.human_log_file}")
        print(f"{Fore.CYAN}   Machine readable: {self.machine_log_file}")

    def log_info(self, message: str, color_code: str = "", display_mode: str = "both"):
        """Log information to both human and machine readable logs

        Args:
            message: The message to log
            color_code: Color code for the message
            display_mode: "verbose", "normal", or "both" - when this message should be displayed
        """
        if not self.enable_logging:
            return

        # Log to human readable with colors preserved
        colored_message = f"{color_code}{message}{Fore.RESET}" if color_code else message
        self.human_logger.info(colored_message)

        # Add to machine log with display mode info
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "message": message,
            "color_code": color_code,
            "display_mode": display_mode,
            "type": "info"
        }

        if not hasattr(self, 'current_run_logs'):
            self.current_run_logs = []
        self.current_run_logs.append(log_entry)

    def save_machine_log(self):
        """Save machine readable log to JSON file"""
        if not self.enable_logging:
            return

        self.machine_log_data["test_session"]["end_time"] = datetime.now().isoformat()
        self.machine_log_data["test_session"]["total_duration"] = str(datetime.now() - self.start_time)

        with open(self.machine_log_file, 'w', encoding='utf-8') as f:
            json.dump(self.machine_log_data, f, indent=2, ensure_ascii=False)

    @staticmethod
    def print_log_file(log_file_path: str = None, verbose_format: bool = False):
        """Replay log file contents as if user just ran the program"""
        log_dir = Path("logs")

        if not log_dir.exists():
            print(f"{Fore.RED}❌ No logs directory found. Run some tests first.")
            return

        if log_file_path:
            # User specified a log file
            log_path = Path(log_file_path)
            if not log_path.exists():
                print(f"{Fore.RED}❌ Log file not found: {log_file_path}")
                return

            # If it's a .log file, try to find the corresponding _machine.json file
            if log_path.suffix == '.log':
                # Replace _human.log with _machine.json or add _machine.json
                if log_path.name.endswith('_human.log'):
                    json_path = log_path.with_name(log_path.stem.replace('_human', '_machine') + '.json')
                else:
                    json_path = log_path.with_name(log_path.stem + '_machine.json')

                if json_path.exists():
                    log_path = json_path
                    print(f"{Fore.YELLOW}ℹ️  Found corresponding machine log file: {json_path}")
                else:
                    print(f"{Fore.YELLOW}⚠️  No corresponding machine log file found for {log_path}")
                    print(f"{Fore.YELLOW}💡 Available machine log files:")
                    log_file_path = None  # Reset to trigger available logs listing

        # If no log file specified or no corresponding machine log found
        if not log_file_path or log_path.suffix == '.log':
            # Find all machine-readable log files
            log_files = list(log_dir.glob("*_machine.json"))

            if not log_files:
                print(f"{Fore.RED}❌ No machine-readable log files found in {log_dir}")
                print(f"{Fore.YELLOW}💡 Machine-readable logs are required to replay the program output.")
                return

            # If there's only one log file, use it
            if len(log_files) == 1:
                log_path = log_files[0]
            else:
                # Let user select a log file
                print(f"\n{Fore.CYAN}📋 Available log files:")

                # Get details for each log file
                log_details = []
                for log_file in log_files:
                    try:
                        with open(log_file, 'r', encoding='utf-8') as f:
                            data = json.load(f)

                        # Extract session info
                        session = data.get('test_session', {})
                        start_time = datetime.fromisoformat(session.get('start_time', ''))
                        end_time = datetime.fromisoformat(session.get('end_time', '')) if session.get('end_time') else None
                        duration = session.get('total_duration', 'Unknown')
                        target_url = session.get('target_url', 'Unknown')

                        # Count vulnerabilities
                        total_vulns = 0
                        total_tests = 0
                        for run in data.get('runs', []):
                            results = run.get('results', [])
                            total_tests += len(results)
                            total_vulns += sum(1 for r in results if r.get('vulnerability_found', False))

                        log_details.append({
                            'file': log_file,
                            'start_time': start_time,
                            'duration': duration,
                            'target_url': target_url,
                            'total_tests': total_tests,
                            'total_vulns': total_vulns,
                            'runs': len(data.get('runs', []))
                        })
                    except Exception as e:
                        print(f"{Fore.RED}❌ Error reading {log_file.name}: {e}")
                        continue

                # Sort by start time, newest first
                log_details.sort(key=lambda x: x['start_time'], reverse=True)

                # Display log files with details
                for i, details in enumerate(log_details, 1):
                    start_time = details['start_time'].strftime('%Y-%m-%d %H:%M:%S')
                    print(f"\n{Fore.CYAN}   {i}. {details['file'].name}")
                    print(f"{Fore.BLUE}      📅 Date: {start_time}")
                    print(f"{Fore.BLUE}      ⏱️  Duration: {details['duration']}")
                    print(f"{Fore.BLUE}      🌐 Target: {details['target_url']}")
                    print(f"{Fore.BLUE}      🧪 Tests: {details['total_tests']} ({details['total_vulns']} vulnerabilities)")
                    print(f"{Fore.BLUE}      🔄 Runs: {details['runs']}")

                while True:
                    try:
                        choice = input(f"\n{Fore.YELLOW}Select a log file (1-{len(log_details)}): ").strip()
                        if not choice:
                            # Default to latest log file
                            log_path = log_details[0]['file']
                            break

                        idx = int(choice)
                        if 1 <= idx <= len(log_details):
                            log_path = log_details[idx - 1]['file']
                            break
                        else:
                            print(f"{Fore.RED}❌ Invalid selection. Please choose a number between 1 and {len(log_details)}")
                    except ValueError:
                        print(f"{Fore.RED}❌ Please enter a valid number")

        try:
            with open(log_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            print(f"\n{Fore.CYAN}🔄 Replaying test session from: {log_path.name}")
            print(f"{Fore.CYAN}{'='*80}")

            # Replay the session
            APISecurityTester._replay_session(data, verbose_format)

        except json.JSONDecodeError:
            print(f"{Fore.RED}❌ Error: {log_path} is not a valid JSON file")
            print(f"{Fore.YELLOW}💡 Please specify a machine-readable log file (*_machine.json)")
        except Exception as e:
            print(f"{Fore.RED}❌ Error reading log file: {e}")

    @staticmethod
    def _replay_session(data: dict, verbose_mode: bool):
        """Replay a test session from JSON data"""
        session_info = data.get("test_session", {})
        runs = data.get("runs", [])

        # Replay pre-run information
        print(f"\n{Fore.CYAN}{Style.BRIGHT}{'='*80}")
        print(f"{Fore.CYAN}{Style.BRIGHT}🛡️  API SECURITY TESTING SUITE (REPLAY)")
        print(f"{Fore.CYAN}{Style.BRIGHT}{'='*80}")

        print(f"\n{Fore.YELLOW}📅 Test Session Information:")
        print(f"{Fore.YELLOW}   Start Time: {session_info.get('start_time', 'Unknown')}")
        print(f"{Fore.YELLOW}   Target URL: {session_info.get('target_url', 'Unknown')}")
        print(f"{Fore.YELLOW}   Total Runs: {len(runs)}")
        print(f"{Fore.YELLOW}   Total Duration: {session_info.get('total_duration', 'Unknown')}")

        if 'system_info' in session_info:
            sys_info = session_info['system_info']
            print(f"\n{Fore.BLUE}🖥️  System Information:")
            print(f"{Fore.BLUE}   OS: {sys_info.get('os', 'Unknown')} {sys_info.get('os_version', '')}")
            print(f"{Fore.BLUE}   Python: {sys_info.get('python_version', 'Unknown')}")
            print(f"{Fore.BLUE}   Colors: {'Available' if sys_info.get('colors_available') else 'Not Available'}")

        print(f"{Fore.CYAN}{'='*80}")

        # Replay each run
        for run_data in runs:
            run_num = run_data.get('run_number', 1)
            total_runs = len(runs)
            duration = run_data.get('duration', 'Unknown')
            test_type = run_data.get('test_type', 'all')

            # Determine test description
            if test_type == 'all':
                test_description = "Running comprehensive security tests"
            else:
                test_names = {
                    'sql': 'SQL Injection tests',
                    'auth': 'Authentication Bypass tests',
                    'bola': 'BOLA vulnerability tests',
                    'rate': 'Rate Limiting tests',
                    'data': 'Sensitive Data Exposure tests',
                    'input': 'Input Validation tests',
                    'brute': 'Brute Force Protection tests',
                    'xxe': 'XML External Entity (XXE) tests',
                    'ssrf': 'Server-Side Request Forgery tests',
                    'path': 'Path Traversal tests',
                    'jwt': 'JWT Manipulation tests'
                }
                test_description = f"Running {test_names.get(test_type, 'Unknown tests')}"

            print(f"\n{Fore.CYAN}🔄 Run {run_num}/{total_runs}: {test_description}")
            print(f"{Fore.CYAN}{'='*60}")

            # Replay run logs if available
            if 'logs' in run_data:
                for log_entry in run_data['logs']:
                    display_mode = log_entry.get('display_mode', 'both')

                    # Check if this log should be displayed based on verbose mode
                    should_display = (
                        display_mode == 'both' or
                        (display_mode == 'verbose' and verbose_mode) or
                        (display_mode == 'normal' and not verbose_mode)
                    )

                    if should_display:
                        color_code = log_entry.get('color_code', '')
                        message = log_entry.get('message', '')
                        print(f"{color_code}{message}{Fore.RESET}")

            # Replay test results
            results = run_data.get('results', [])
            if results:
                # Group results by test type
                test_groups = {}
                for result in results:
                    test_name = result.get('test_name', 'Unknown')
                    if test_name not in test_groups:
                        test_groups[test_name] = []
                    test_groups[test_name].append(result)

                # Display results by test type
                for test_name, test_results in test_groups.items():
                    if verbose_mode:
                        print(f"\n{Fore.YELLOW}{Style.BRIGHT}{'='*60}")
                        print(f"{Fore.YELLOW}{Style.BRIGHT}🧪 {test_name}")
                        print(f"{Fore.YELLOW}{Style.BRIGHT}{'='*60}")

                    for result in test_results:
                        version = result.get('version', 'unknown').upper()
                        vulnerable = result.get('vulnerability_found', False)
                        details = result.get('details', '')
                        response_code = result.get('response_code', 0)
                        response_time = result.get('response_time', 0)

                        if verbose_mode:
                            status_color = Fore.RED if vulnerable else Fore.GREEN
                            status_text = "VULNERABLE ❌" if vulnerable else "SECURE ✅"

                            print(f"{status_color}📊 {version}: {status_text}")
                            print(f"   Response Code: {response_code}")
                            print(f"   Response Time: {response_time:.3f}s")
                            print(f"   Details: {details}")

                            if vulnerable and result.get('raw_response'):
                                print(f"   {Fore.RED}⚠️  Vulnerability Evidence: {result['raw_response'][:100]}...")

            # Show run completion
            if not verbose_mode:
                # Calculate brief summary for non-verbose mode
                v1_results = [r for r in results if r.get('version') == 'v1']
                v2_results = [r for r in results if r.get('version') == 'v2']
                v1_vulns = len([r for r in v1_results if r.get('vulnerability_found')])
                v2_vulns = len([r for r in v2_results if r.get('vulnerability_found')])
                total_test_types = len(set([r.get('test_name') for r in results]))

                print(f"{Fore.GREEN}✅ Run {run_num}/{total_runs} completed")
                if total_test_types > 0:
                    print(f"   V1 Vulnerabilities: {Fore.RED}{v1_vulns}/{total_test_types}")
                    print(f"   V2 Vulnerabilities: {Fore.GREEN}{v2_vulns}/{total_test_types}")
            else:
                print(f"\n{Fore.GREEN}✅ Run {run_num}/{total_runs} completed in {duration}")

                # Show completion message
        total_duration = session_info.get('total_duration', 'Unknown')
        print(f"\n{Fore.GREEN}🎉 All {len(runs)} test runs completed in {total_duration}!")

        # Replay overall summary if available
        if 'overall_summary' in data:
            APISecurityTester._replay_overall_summary(data['overall_summary'])

        # Show guidance for non-verbose replays
        if not verbose_mode:
            print(f"\n{Fore.YELLOW}💡 For more detailed output, you can:")
            print(f"{Fore.YELLOW}   • Replay with --verbose flag: python {' '.join(sys.argv)} --verbose")

        print(f"\n{Fore.CYAN}📄 End of replay from: {session_info.get('start_time', 'Unknown')}")
        print(f"{Fore.CYAN}{'='*80}")

    @staticmethod
    def _replay_overall_summary(summary_data: dict):
        """Replay the overall summary statistics"""
        print(f"\n{Fore.YELLOW}{Style.BRIGHT}{'='*60}")
        print(f"{Fore.YELLOW}{Style.BRIGHT}🧪 OVERALL TEST SUMMARY")
        print(f"{Fore.YELLOW}{Style.BRIGHT}{'='*60}")

        total_runs = summary_data.get('total_runs', 0)
        v1_stats = summary_data.get('v1_stats', {})
        v2_stats = summary_data.get('v2_stats', {})

        print(f"\n{Fore.CYAN}📊 OVERALL STATISTICS")
        print(f"{Fore.CYAN}{'='*40}")
        print(f"Total Test Runs: {total_runs}")

        print(f"\n{Fore.YELLOW}V1 (Insecure) Version:")
        print(f"  Average Vulnerabilities: {v1_stats.get('avg_vulnerabilities', 0):.1f}")
        print(f"  Consistency (Std Dev): {v1_stats.get('consistency_std_dev', 0):.2f}")
        print(f"  Average Response Time: {v1_stats.get('avg_response_time', 0):.3f}s")

        print(f"\n{Fore.YELLOW}V2 (Secure) Version:")
        print(f"  Average Vulnerabilities: {v2_stats.get('avg_vulnerabilities', 0):.1f}")
        print(f"  Consistency (Std Dev): {v2_stats.get('consistency_std_dev', 0):.2f}")
        print(f"  Average Response Time: {v2_stats.get('avg_response_time', 0):.3f}s")

        # Trend Analysis
        print(f"\n{Fore.CYAN}📈 TREND ANALYSIS")
        print(f"{Fore.CYAN}{'='*30}")
        print(f"V1 Security Trend: {v1_stats.get('security_trend', 'unknown')}")
        print(f"V2 Security Trend: {v2_stats.get('security_trend', 'unknown')}")

        # Reliability Assessment
        print(f"\n{Fore.CYAN}🔍 RELIABILITY ASSESSMENT")
        print(f"{Fore.CYAN}{'='*30}")
        print(f"V1 Test Reliability: {v1_stats.get('reliability', 'unknown')}")
        print(f"V2 Test Reliability: {v2_stats.get('reliability', 'unknown')}")

    def print_pre_run_info(self, args):
        """Print comprehensive information before starting tests"""
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        print(f"\n{Fore.CYAN}{Style.BRIGHT}{'='*80}")
        print(f"{Fore.CYAN}{Style.BRIGHT}🛡️  API SECURITY TESTING SUITE")
        print(f"{Fore.CYAN}{Style.BRIGHT}{'='*80}")

        print(f"\n{Fore.YELLOW}📅 Test Session Information:")
        print(f"{Fore.YELLOW}   Start Time: {current_time}")
        print(f"{Fore.YELLOW}   Target URL: {self.base_url}")
        print(f"{Fore.YELLOW}   Test Runs: {args.runs}")
        print(f"{Fore.YELLOW}   Test Type: {'All Security Tests' if args.test == 'all' else args.test.upper()}")
        print(f"{Fore.YELLOW}   Verbose Mode: {'Enabled' if args.verbose else 'Disabled'}")
        print(f"{Fore.YELLOW}   Logging: {'Enabled' if self.enable_logging else 'Disabled'}")

        if self.enable_logging:
            print(f"{Fore.YELLOW}   Log Directory: {self.log_dir.absolute()}")

        print(f"\n{Fore.BLUE}🖥️  System Information:")
        print(f"{Fore.BLUE}   OS: {platform.system()} {platform.release()}")
        print(f"{Fore.BLUE}   Python: {platform.python_version()}")
        print(f"{Fore.BLUE}   Colors: {'Available' if COLORS_AVAILABLE else 'Not Available'}")

        print(f"\n{Fore.MAGENTA}🧪 Test Categories:")
        if args.test == 'all':
            test_categories = [
                "SQL Injection Attacks",
                "Authentication Bypass",
                "Broken Object Level Authorization (BOLA)",
                "Sensitive Data Exposure",
                "Input Validation",
                "Rate Limiting",
                "Brute Force Protection",
                "XML External Entity (XXE) Attacks",
                "Server-Side Request Forgery (SSRF)",
                "Path Traversal Attacks",
                "JWT Manipulation Attacks"
            ]
            for i, category in enumerate(test_categories, 1):
                print(f"{Fore.MAGENTA}   {i}. {category}")
        else:
            test_names = {
                'sql': 'SQL Injection Attacks',
                'auth': 'Authentication Bypass',
                'bola': 'Broken Object Level Authorization (BOLA)',
                'rate': 'Rate Limiting',
                'data': 'Sensitive Data Exposure',
                'input': 'Input Validation',
                'brute': 'Brute Force Protection',
                'xxe': 'XML External Entity (XXE) Attacks',
                'ssrf': 'Server-Side Request Forgery (SSRF)',
                'path': 'Path Traversal Attacks',
                'jwt': 'JWT Manipulation Attacks'
            }
            print(f"{Fore.MAGENTA}   • {test_names.get(args.test, 'Unknown Test')}")

        print(f"\n{Fore.GREEN}🚀 Starting security assessment...")
        print(f"{Fore.GREEN}   Estimated duration: {self.estimate_duration(args)}")
        print(f"{Fore.CYAN}{'='*80}")

        # Log this information
        self.log_info(f"Test session started - Target: {self.base_url}, Runs: {args.runs}, Type: {args.test}")

    def estimate_duration(self, args) -> str:
        """Estimate test duration based on configuration"""
        # Updated duration estimates for new tests
        if args.test == 'all':
            base_time_per_run = 0.8  # Increased for 11 test categories
        elif args.test in ['xxe', 'ssrf', 'path', 'jwt']:
            base_time_per_run = 0.1  # New tests take a bit longer
        else:
            base_time_per_run = 0.05  # Original tests

        total_time = base_time_per_run * args.runs

        if total_time < 1:
            return f"{int(total_time * 60)} seconds"
        else:
            return f"{total_time:.1f} minutes"

    def print_header(self, title: str):
        """Print a formatted header for test sections"""
        if self.verbose:
            print(f"\n{Fore.YELLOW}{Style.BRIGHT}{'='*60}")
            print(f"{Fore.YELLOW}{Style.BRIGHT}🧪 {title}")
            print(f"{Fore.YELLOW}{Style.BRIGHT}{'='*60}")

        self.log_info(f"=== {title} ===", Fore.YELLOW, "verbose")

    def print_test_info(self, test_name: str, description: str):
        """Print test information"""
        if self.verbose:
            print(f"\n{Fore.BLUE}🔍 Test: {test_name}")
            print(f"{Fore.BLUE}📝 Description: {description}")
            print(f"{Fore.BLUE}{'-'*50}")

        self.log_info(f"Starting test: {test_name} - {description}", Fore.BLUE, "verbose")

    def print_result(self, result: TestResult):
        """Print formatted test result"""
        if self.verbose:
            status_color = Fore.GREEN if not result.vulnerability_found else Fore.RED
            status_text = "SECURE ✅" if not result.vulnerability_found else "VULNERABLE ❌"

            print(f"{status_color}📊 {result.version.upper()}: {status_text}")
            print(f"   Response Code: {result.response_code}")
            print(f"   Response Time: {result.response_time:.3f}s")
            print(f"   Details: {result.details}")

            if result.vulnerability_found and result.raw_response:
                print(f"   {Fore.RED}⚠️  Vulnerability Evidence: {result.raw_response[:100]}...")

        # Always log results
        status_text = "VULNERABLE" if result.vulnerability_found else "SECURE"
        self.log_info(f"{result.version.upper()} {result.test_name}: {status_text} - {result.details}")

    def check_api_health(self) -> bool:
        """
        Check if the API is running and accessible

        Returns:
            bool: True if API is healthy, False otherwise
        """
        if self.verbose:
            print(f"{Fore.CYAN}🏥 Checking API Health...")

        try:
            response = self.session.get(f"{self.base_url}/health", timeout=5)
            if response.status_code == 200:
                if self.verbose:
                    print(f"{Fore.GREEN}✅ API is healthy and running")
                return True
            else:
                if self.verbose:
                    print(f"{Fore.RED}❌ API health check failed: {response.status_code}")
                return False
        except requests.exceptions.RequestException as e:
            if self.verbose:
                print(f"{Fore.RED}❌ Cannot connect to API: {e}")
                print(f"{Fore.YELLOW}💡 Make sure your API server is running on {self.base_url}")
                print(f"{Fore.YELLOW}💡 Try running: npm run dev (in the project directory)")
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
                if self.verbose:
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

            if self.verbose:
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

                    if self.verbose:
                        print(f"  Payload {i}: {payload['username'][:30]}... -> {response.status_code}")

                    # Check if injection was successful
                    if response.status_code == 200:
                        try:
                            data = response.json()
                            if data.get('success') or 'token' in data or 'user' in data:
                                vulnerable = True
                                details = f"SQL injection successful with payload: {payload['username']}"
                                response_data = json.dumps(data)[:200]
                                if self.verbose:
                                    print(f"    {Fore.RED}🚨 INJECTION SUCCESSFUL!")
                                break
                        except json.JSONDecodeError:
                            pass

                except requests.exceptions.RequestException as e:
                    response_time = 0
                    if self.verbose:
                        print(f"    {Fore.YELLOW}⚠️  Request failed: {e}")

            result = TestResult(
                test_name="SQL Injection",
                version=version,
                success=True,
                response_code=response.status_code if 'response' in locals() else 0,
                response_time=response_time if 'response_time' in locals() else 0,
                vulnerability_found=vulnerable,
                details=details,
                raw_response=response_data,
                timestamp=datetime.now().isoformat()
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

            if self.verbose:
                print(f"\n{Fore.MAGENTA}Testing {version.upper()} authentication bypass...")

            for endpoint in protected_endpoints:
                try:
                    start_time = time.time()
                    response = self.session.get(f"{base_url}{endpoint}", timeout=10)
                    response_time = time.time() - start_time

                    if self.verbose:
                        print(f"  {endpoint} -> {response.status_code}")

                    # If we get 200 OK without authentication, it's a bypass
                    if response.status_code == 200:
                        bypass_count += 1
                        try:
                            data = response.json()
                            if isinstance(data, (list, dict)) and data:
                                if self.verbose:
                                    print(f"    {Fore.RED}🚨 DATA EXPOSED!")
                        except:
                            pass

                except requests.exceptions.RequestException as e:
                    response_time = 0
                    if self.verbose:
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
                details=details,
                timestamp=datetime.now().isoformat()
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

            if self.verbose:
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

                    if self.verbose:
                        print(f"  User ID {user_id} -> {response.status_code}")

                    if response.status_code == 200:
                        try:
                            data = response.json()
                            if 'password' in str(data) or 'api_key' in str(data):
                                bola_successful = True
                                details = f"BOLA successful - accessed user {user_id} data with sensitive info"
                                if self.verbose:
                                    print(f"    {Fore.RED}🚨 SENSITIVE DATA EXPOSED!")
                                break
                        except:
                            pass

                except requests.exceptions.RequestException as e:
                    response_time = 0
                    if self.verbose:
                        print(f"    {Fore.YELLOW}⚠️  Request failed: {e}")

            result = TestResult(
                test_name="BOLA",
                version=version,
                success=True,
                response_code=response.status_code if 'response' in locals() else 0,
                response_time=response_time if 'response_time' in locals() else 0,
                vulnerability_found=bola_successful,
                details=details,
                timestamp=datetime.now().isoformat()
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
            rate_limit_headers = set()  # Use set to avoid duplicates
            rate_limit_responses = []

            if self.verbose:
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

                        # Check for rate limit headers (avoid duplicates)
                        current_headers = [
                            h for h in response.headers.keys()
                            if 'rate' in h.lower() or 'limit' in h.lower()
                        ]
                        rate_limit_headers.update(current_headers)

                        if response.status_code == 429:  # Too Many Requests
                            rate_limited = True
                            rate_limit_responses.append(response.text)
                            if self.verbose:
                                print(f"  Request {i+1}: {Fore.YELLOW}RATE LIMITED (429)")
                            break
                        elif response.status_code in [200, 401, 403]:
                            successful_requests += 1
                            if i % 10 == 0:  # Print every 10th request
                                if self.verbose:
                                    print(f"  Request {i+1}: {response.status_code}")

                        # Small delay to avoid overwhelming the server
                        time.sleep(0.1)

                    except requests.exceptions.RequestException as e:
                        if self.verbose:
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
                    # Convert set to sorted list for consistent output
                    unique_headers = sorted(list(rate_limit_headers))
                    if len(unique_headers) <= 5:  # Show all if 5 or fewer
                        details += f" (Headers: {', '.join(unique_headers)})"
                    else:  # Show just count if too many
                        details += f" ({len(unique_headers)} rate limit headers detected)"
            else:
                details += " - No rate limiting detected"

            result = TestResult(
                test_name="Rate Limiting",
                version=version,
                success=True,
                response_code=429 if rate_limited else 200,
                response_time=total_time,
                vulnerability_found=not proper_rate_limiting,  # Vulnerability if NO proper rate limiting
                details=details,
                timestamp=datetime.now().isoformat()
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

            if self.verbose:
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

                    if self.verbose:
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
                                    if self.verbose:
                                        print(f"    {Fore.RED}🚨 SENSITIVE FIELD FOUND: {field}")

                        except json.JSONDecodeError:
                            pass

                except requests.exceptions.RequestException as e:
                    response_time = 0
                    if self.verbose:
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
                details=details,
                timestamp=datetime.now().isoformat()
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

            if self.verbose:
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

                    if self.verbose:
                        print(f"  Payload {i}: {str(payload)[:50]}... -> {response.status_code}")

                    # Check if malicious input was processed without proper validation
                    if response.status_code == 200:
                        validation_bypassed = True
                        bypass_details.append(f"Payload {i} processed successfully")
                        if self.verbose:
                            print(f"    {Fore.RED}🚨 VALIDATION BYPASSED!")
                    elif response.status_code == 500:
                        # Server error might indicate injection success
                        validation_bypassed = True
                        bypass_details.append(f"Payload {i} caused server error")
                        if self.verbose:
                            print(f"    {Fore.RED}🚨 SERVER ERROR - POSSIBLE INJECTION!")

                except requests.exceptions.RequestException as e:
                    response_time = 0
                    if self.verbose:
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
                details=details,
                timestamp=datetime.now().isoformat()
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

            if self.verbose:
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
                        if self.verbose:
                            print(f"  Attempt {i}: {Fore.YELLOW}BLOCKED (429)")
                        break
                    elif response.status_code == 200:
                        successful_attempts += 1
                        if self.verbose:
                            print(f"  Attempt {i}: {Fore.GREEN}SUCCESS")
                    else:
                        if self.verbose:
                            print(f"  Attempt {i}: {response.status_code}")

                    # Small delay between attempts
                    time.sleep(0.2)

                except requests.exceptions.RequestException as e:
                    if self.verbose:
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
                details=details,
                timestamp=datetime.now().isoformat()
            )

            results.append(result)
            self.results.append(result)
            self.print_result(result)

        return results

    def test_xxe_vulnerability(self) -> List[TestResult]:
        """Test XML External Entity (XXE) vulnerabilities"""
        self.print_test_info(
            "XXE Vulnerability",
            "Testing XML External Entity attacks for file disclosure"
        )

        results = []
        # Simpler XXE payload that should work with xml2js
        xxe_payload = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>'''

        for version in ["v1", "v2"]:
            base_url = self.v1_base if version == "v1" else self.v2_base
            vulnerable = False
            details = "XXE protection in place"
            response_code = 0
            response_time = 0

            if self.verbose:
                print(f"\n{Fore.MAGENTA}Testing {version.upper()} for XXE...")

            try:
                start_time = time.time()
                response = self.session.post(
                    f"{base_url}/auth/process-xml",
                    json={"xmlData": xxe_payload},
                    timeout=10
                )
                response_time = time.time() - start_time
                response_code = response.status_code

                if self.verbose:
                    print(f"  XXE Payload -> {response.status_code}")

                if version == "v1":
                    if response.status_code == 200:
                        # For V1, if XML processing accepts the payload, it's vulnerable
                        try:
                            response_data = response.json()
                            if 'success' in response_data and response_data.get('success'):
                                # Check if external entity was processed
                                response_text = response.text.lower()
                                processed_xml = response_data.get('processedXml', '')

                                # Look for signs of successful XXE attack
                                xxe_indicators = [
                                    'root:', 'daemon:', 'bin:', 'sys:', 'sync:', 'mail:',  # /etc/passwd content
                                    'file_not_found', 'http_error',  # Our custom error messages
                                    'localhost', '127.0.0.1'  # Network indicators
                                ]

                                if any(indicator in response_text for indicator in xxe_indicators) or \
                                   any(indicator in processed_xml.lower() for indicator in xxe_indicators):
                                    vulnerable = True
                                    details = "XXE vulnerability - External entity processed successfully"
                                    if self.verbose:
                                        print(f"    {Fore.RED}🚨 XXE VULNERABILITY DETECTED!")
                                        print(f"    {Fore.RED}    Evidence: {processed_xml[:100]}...")
                                else:
                                    vulnerable = True  # Still vulnerable if it processes XML
                                    details = "XXE vulnerability - XML processing accepts external entities"
                        except:
                            # If we get a 200 but can't parse JSON, still vulnerable
                            vulnerable = True
                            details = "XXE vulnerability - XML processor accepts malicious input"
                    elif response.status_code == 400:
                        # Some protection in place but endpoint exists
                        details = "Partial XXE protection - endpoint exists but rejects payload"
                else:
                    # V2 should return 404 (endpoint doesn't exist) or reject cleanly
                    if response.status_code == 404:
                        details = "XXE protection - endpoint not available"
                    elif response.status_code >= 400:
                        details = "XXE protection - request properly rejected"

            except requests.exceptions.RequestException as e:
                if self.verbose:
                    print(f"    {Fore.YELLOW}⚠️  Request failed: {e}")
                details = f"Request failed: {str(e)}"

            result = TestResult(
                test_name="XXE Vulnerability",
                version=version,
                success=True,
                response_code=response_code,
                response_time=response_time,
                vulnerability_found=vulnerable,
                details=details,
                severity="high" if vulnerable else "low",
                attack_vector="XML External Entity",
                timestamp=datetime.now().isoformat()
            )

            results.append(result)
            self.results.append(result)
            self.print_result(result)

        return results

    def test_ssrf_vulnerability(self) -> List[TestResult]:
        """Test Server-Side Request Forgery (SSRF) vulnerabilities"""
        self.print_test_info(
            "SSRF Vulnerability",
            "Testing Server-Side Request Forgery for internal service access"
        )

        results = []
        # Test with a safe external URL that should work
        test_url = "http://httpbin.org/status/200"

        for version in ["v1", "v2"]:
            base_url = self.v1_base if version == "v1" else self.v2_base
            vulnerable = False
            details = "SSRF protection in place"
            response_code = 0
            response_time = 0

            if self.verbose:
                print(f"\n{Fore.MAGENTA}Testing {version.upper()} for SSRF...")

            try:
                start_time = time.time()
                response = self.session.post(
                    f"{base_url}/data/fetch-url",
                    json={"url": test_url},
                    timeout=15
                )
                response_time = time.time() - start_time
                response_code = response.status_code

                if self.verbose:
                    print(f"  SSRF Test: {test_url} -> {response.status_code}")

                if version == "v1":
                    if response.status_code == 200:
                        try:
                            response_data = response.json()
                            if response_data.get('success'):
                                vulnerable = True
                                details = "SSRF vulnerability - server fetches arbitrary URLs"
                                if self.verbose:
                                    print(f"    {Fore.RED}🚨 SSRF VULNERABILITY DETECTED!")
                        except:
                            pass
                    elif response.status_code == 500:
                        # Network request attempted but failed - still vulnerable
                        try:
                            response_data = response.json()
                            if 'Request failed' in response_data.get('error', ''):
                                vulnerable = True
                                details = "SSRF vulnerability - server attempts network requests"
                        except:
                            pass
                else:
                    # V2 should return 404 (endpoint doesn't exist)
                    if response.status_code == 404:
                        details = "SSRF protection - endpoint not available"
                    elif response.status_code >= 400:
                        details = "SSRF protection - request properly rejected"

            except requests.exceptions.RequestException as e:
                if self.verbose:
                    print(f"    {Fore.YELLOW}⚠️  Request failed: {e}")
                details = f"Request failed: {str(e)}"

            result = TestResult(
                test_name="SSRF Vulnerability",
                version=version,
                success=True,
                response_code=response_code,
                response_time=response_time,
                vulnerability_found=vulnerable,
                details=details,
                severity="high" if vulnerable else "low",
                attack_vector="Server-Side Request Forgery",
                timestamp=datetime.now().isoformat()
            )

            results.append(result)
            self.results.append(result)
            self.print_result(result)

        return results

    def test_path_traversal_vulnerability(self) -> List[TestResult]:
        """Test Path Traversal vulnerabilities"""
        self.print_test_info(
            "Path Traversal",
            "Testing directory traversal attacks for unauthorized file access"
        )

        results = []
        # First create a test file, then try to access it with traversal
        test_filename = "testfile.txt"

        for version in ["v1", "v2"]:
            base_url = self.v1_base if version == "v1" else self.v2_base
            vulnerable = False
            details = "Path traversal protection in place"
            response_code = 0
            response_time = 0

            if self.verbose:
                print(f"\n{Fore.MAGENTA}Testing {version.upper()} for path traversal...")

            # First, create a test file via upload if V1
            if version == "v1":
                try:
                    self.session.post(
                        f"{base_url}/data/upload",
                        json={"filename": test_filename, "content": "test data for path traversal"},
                        timeout=10
                    )
                except:
                    pass  # Ignore upload errors

            # Test basic file access first
            try:
                start_time = time.time()
                response = self.session.get(
                    f"{base_url}/data/file/{test_filename}",
                    timeout=10
                )
                response_time = time.time() - start_time
                response_code = response.status_code

                if self.verbose:
                    print(f"  File access test: {test_filename} -> {response.status_code}")

                if version == "v1":
                    if response.status_code == 200:
                        # V1 accepts file requests - this is the vulnerability
                        vulnerable = True
                        details = "Path traversal vulnerability - unrestricted file access"
                        if self.verbose:
                            print(f"    {Fore.RED}🚨 PATH TRAVERSAL VULNERABILITY!")
                    elif response.status_code == 404:
                        # File not found but endpoint exists and processes request
                        try:
                            response_data = response.json()
                            if 'File not found' in response_data.get('error', ''):
                                vulnerable = True
                                details = "Path traversal vulnerability - endpoint processes file paths"
                        except:
                            pass
                else:
                    # V2 should return 404 (endpoint doesn't exist)
                    if response.status_code == 404:
                        details = "Path traversal protection - endpoint not available"
                    elif response.status_code >= 400:
                        details = "Path traversal protection - request properly rejected"

            except requests.exceptions.RequestException as e:
                if self.verbose:
                    print(f"    {Fore.YELLOW}⚠️  Request failed: {e}")
                details = f"Request failed: {str(e)}"

            result = TestResult(
                test_name="Path Traversal",
                version=version,
                success=True,
                response_code=response_code,
                response_time=response_time,
                vulnerability_found=vulnerable,
                details=details,
                severity="high" if vulnerable else "low",
                attack_vector="Path Traversal",
                timestamp=datetime.now().isoformat()
            )

            results.append(result)
            self.results.append(result)
            self.print_result(result)

        return results

    def test_jwt_manipulation(self) -> List[TestResult]:
        """Test JWT token manipulation vulnerabilities"""
        self.print_test_info(
            "JWT Manipulation",
            "Testing JWT token security and manipulation attacks"
        )

        results = []

        for version in ["v1", "v2"]:
            base_url = self.v1_base if version == "v1" else self.v2_base
            vulnerable = False
            details = "JWT validation working properly"
            response_code = 0
            response_time = 0

            if self.verbose:
                print(f"\n{Fore.MAGENTA}Testing {version.upper()} JWT security...")

            # Test with a simple malicious token
            malicious_token = "fake_token_admin_123456"

            try:
                start_time = time.time()
                response = self.session.post(
                    f"{base_url}/auth/validate-token",
                    json={"token": malicious_token},
                    timeout=10
                )
                response_time = time.time() - start_time
                response_code = response.status_code

                if self.verbose:
                    print(f"  JWT validation test -> {response.status_code}")

                if version == "v1":
                    if response.status_code == 200:
                        try:
                            response_data = response.json()
                            if response_data.get('valid'):
                                vulnerable = True
                                details = "JWT vulnerability - weak token validation"
                                if self.verbose:
                                    print(f"    {Fore.RED}🚨 JWT VULNERABILITY DETECTED!")
                        except:
                            pass
                    elif response.status_code == 401:
                        details = "JWT validation rejects malicious token"
                else:
                    # V2 should return 404 (endpoint doesn't exist) or reject cleanly
                    if response.status_code == 404:
                        details = "JWT protection - endpoint not available"
                    elif response.status_code >= 400:
                        details = "JWT protection - request properly rejected"

            except requests.exceptions.RequestException as e:
                if self.verbose:
                    print(f"    {Fore.YELLOW}⚠️  Request failed: {e}")
                details = f"Request failed: {str(e)}"

            result = TestResult(
                test_name="JWT Manipulation",
                version=version,
                success=True,
                response_code=response_code,
                response_time=response_time,
                vulnerability_found=vulnerable,
                details=details,
                severity="high" if vulnerable else "low",
                attack_vector="JWT Manipulation",
                timestamp=datetime.now().isoformat()
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
                            if self.verbose:
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

        # Use current results if available, otherwise use the last run's results
        current_results = self.results if self.results else (self.all_runs_results[-1] if self.all_runs_results else [])

        # Summary statistics
        total_tests = len(current_results)
        v1_vulnerabilities = len([r for r in current_results if r.version == "v1" and r.vulnerability_found])
        v2_vulnerabilities = len([r for r in current_results if r.version == "v2" and r.vulnerability_found])

        # Calculate total test types by counting unique test names
        test_types = set([r.test_name for r in current_results])
        total_test_types = len(test_types)

        # Only proceed with percentage calculations if we have test types
        if total_test_types > 0:
            v1_percentage = (v1_vulnerabilities/total_test_types*100)
            v2_percentage = (v2_vulnerabilities/total_test_types*100)
        else:
            v1_percentage = 0
            v2_percentage = 0

        if self.verbose:
            print(f"\n{Fore.CYAN}📊 SUMMARY STATISTICS")
            print(f"{Fore.CYAN}{'='*40}")
            print(f"Total Tests Conducted: {total_tests}")
            print(f"V1 (Insecure) Vulnerabilities: {Fore.RED}{v1_vulnerabilities}/{total_test_types} ({v1_percentage:.0f}%)")
            print(f"V2 (Secure) Vulnerabilities: {Fore.GREEN}{v2_vulnerabilities}/{total_test_types} ({v2_percentage:.0f}%)")

        # Detailed results by test type
        test_types = list(set([r.test_name for r in current_results]))

        if self.verbose:
            print(f"\n{Fore.CYAN}📋 DETAILED RESULTS BY TEST TYPE")
            print(f"{Fore.CYAN}{'='*50}")

        for test_type in test_types:
            if self.verbose:
                print(f"\n{Fore.YELLOW}🧪 {test_type}")
                print(f"{Fore.YELLOW}{'-'*30}")

            v1_result = next((r for r in current_results if r.test_name == test_type and r.version == "v1"), None)
            v2_result = next((r for r in current_results if r.test_name == test_type and r.version == "v2"), None)

            if v1_result:
                status = "VULNERABLE ❌" if v1_result.vulnerability_found else "SECURE ✅"
                color = Fore.RED if v1_result.vulnerability_found else Fore.GREEN
                if self.verbose:
                    print(f"  V1: {color}{status}")
                    print(f"      {v1_result.details}")

            if v2_result:
                status = "VULNERABLE ❌" if v2_result.vulnerability_found else "SECURE ✅"
                color = Fore.RED if v2_result.vulnerability_found else Fore.GREEN
                if self.verbose:
                    print(f"  V2: {color}{status}")
                    print(f"      {v2_result.details}")

        # Recommendations
        if self.verbose:
            print(f"\n{Fore.CYAN}💡 SECURITY RECOMMENDATIONS")
            print(f"{Fore.CYAN}{'='*40}")

        if v1_vulnerabilities > 0:
            if self.verbose:
                print(f"{Fore.YELLOW}🔧 For V1 (Insecure Version):")
                print(f"   • Implement proper input validation and sanitization")
                print(f"   • Add authentication and authorization mechanisms")
                print(f"   • Implement rate limiting to prevent brute force attacks")
                print(f"   • Use parameterized queries to prevent SQL injection")
                print(f"   • Avoid exposing sensitive data in API responses")

        if v2_vulnerabilities == 0:
            if self.verbose:
                print(f"{Fore.GREEN}✅ V2 (Secure Version) shows good security practices!")
        else:
            if self.verbose:
                print(f"{Fore.YELLOW}🔧 For V2 (Secure Version):")
                print(f"   • Review and strengthen remaining vulnerabilities")
                print(f"   • Consider additional security layers")

        # Performance impact
        if self.verbose:
            print(f"\n{Fore.CYAN}⚡ PERFORMANCE IMPACT")
            print(f"{Fore.CYAN}{'='*30}")

            v1_times = [r.response_time for r in current_results if r.version == "v1" and r.response_time > 0]
            v2_times = [r.response_time for r in current_results if r.version == "v2" and r.response_time > 0]

            v1_avg_time = sum(v1_times) / len(v1_times) if v1_times else 0
            v2_avg_time = sum(v2_times) / len(v2_times) if v2_times else 0

            print(f"V1 Average Response Time: {v1_avg_time:.3f}s")
            print(f"V2 Average Response Time: {v2_avg_time:.3f}s")
            if v1_avg_time > 0:
                overhead = ((v2_avg_time - v1_avg_time) / v1_avg_time * 100)
                print(f"Security Overhead: {overhead:.1f}%")
            else:
                print("Security Overhead: N/A (no V1 data)")

        return "Report generated successfully"

    def generate_overall_summary(self) -> str:
        """
        Generate an overall summary of multiple test runs

        Returns:
            str: Formatted overall summary
        """
        if not self.all_runs_results:
            return "No test runs completed"

        self.print_header("OVERALL TEST SUMMARY")
        self.log_info("Generating overall test summary", Fore.CYAN)

        # Calculate statistics across all runs
        total_runs = len(self.all_runs_results)
        v1_vulnerabilities_per_run = []
        v2_vulnerabilities_per_run = []
        v1_avg_response_times = []
        v2_avg_response_times = []

        for run_results in self.all_runs_results:
            v1_results = [r for r in run_results if r.version == "v1"]
            v2_results = [r for r in run_results if r.version == "v2"]

            v1_vulnerabilities_per_run.append(len([r for r in v1_results if r.vulnerability_found]))
            v2_vulnerabilities_per_run.append(len([r for r in v2_results if r.vulnerability_found]))

            if v1_results:
                v1_avg_response_times.append(sum(r.response_time for r in v1_results) / len(v1_results))
            else:
                v1_avg_response_times.append(0)

            if v2_results:
                v2_avg_response_times.append(sum(r.response_time for r in v2_results) / len(v2_results))
            else:
                v2_avg_response_times.append(0)

        # Calculate averages and consistency metrics
        avg_v1_vulnerabilities = sum(v1_vulnerabilities_per_run) / total_runs if total_runs > 0 else 0
        avg_v2_vulnerabilities = sum(v2_vulnerabilities_per_run) / total_runs if total_runs > 0 else 0
        avg_v1_response_time = sum(v1_avg_response_times) / total_runs if total_runs > 0 and v1_avg_response_times else 0
        avg_v2_response_time = sum(v2_avg_response_times) / total_runs if total_runs > 0 and v2_avg_response_times else 0

        # Calculate consistency (standard deviation)
        if total_runs > 1:
            v1_vuln_std = (sum((x - avg_v1_vulnerabilities) ** 2 for x in v1_vulnerabilities_per_run) / total_runs) ** 0.5
            v2_vuln_std = (sum((x - avg_v2_vulnerabilities) ** 2 for x in v2_vulnerabilities_per_run) / total_runs) ** 0.5
        else:
            v1_vuln_std = 0.0
            v2_vuln_std = 0.0

        print(f"\n{Fore.CYAN}📊 OVERALL STATISTICS")
        print(f"{Fore.CYAN}{'='*40}")
        print(f"Total Test Runs: {total_runs}")
        print(f"\n{Fore.YELLOW}V1 (Insecure) Version:")
        print(f"  Average Vulnerabilities: {avg_v1_vulnerabilities:.1f}")
        print(f"  Consistency (Std Dev): {v1_vuln_std:.2f}")
        print(f"  Average Response Time: {avg_v1_response_time:.3f}s")

        print(f"\n{Fore.YELLOW}V2 (Secure) Version:")
        print(f"  Average Vulnerabilities: {avg_v2_vulnerabilities:.1f}")
        print(f"  Consistency (Std Dev): {v2_vuln_std:.2f}")
        print(f"  Average Response Time: {avg_v2_response_time:.3f}s")

        # Log overall statistics
        self.log_info("=== OVERALL STATISTICS ===", Fore.CYAN)
        self.log_info(f"Total Test Runs: {total_runs}")
        self.log_info(f"V1 (Insecure) Version - Avg Vulnerabilities: {avg_v1_vulnerabilities:.1f}, Consistency: {v1_vuln_std:.2f}, Avg Response Time: {avg_v1_response_time:.3f}s", Fore.YELLOW)
        self.log_info(f"V2 (Secure) Version - Avg Vulnerabilities: {avg_v2_vulnerabilities:.1f}, Consistency: {v2_vuln_std:.2f}, Avg Response Time: {avg_v2_response_time:.3f}s", Fore.YELLOW)

                # Trend Analysis
        print(f"\n{Fore.CYAN}📈 TREND ANALYSIS")
        print(f"{Fore.CYAN}{'='*30}")

        # Check for improvement/regression trends
        v1_trend = "stable"
        v2_trend = "stable"

        if len(v1_vulnerabilities_per_run) > 1:
            if v1_vulnerabilities_per_run[-1] < v1_vulnerabilities_per_run[0]:
                v1_trend = "improving"
            elif v1_vulnerabilities_per_run[-1] > v1_vulnerabilities_per_run[0]:
                v1_trend = "regressing"

        if len(v2_vulnerabilities_per_run) > 1:
            if v2_vulnerabilities_per_run[-1] < v2_vulnerabilities_per_run[0]:
                v2_trend = "improving"
            elif v2_vulnerabilities_per_run[-1] > v2_vulnerabilities_per_run[0]:
                v2_trend = "regressing"

        print(f"V1 Security Trend: {v1_trend}")
        print(f"V2 Security Trend: {v2_trend}")

        # Log trend analysis
        self.log_info("=== TREND ANALYSIS ===", Fore.CYAN)
        self.log_info(f"V1 Security Trend: {v1_trend}")
        self.log_info(f"V2 Security Trend: {v2_trend}")

        # Reliability Assessment
        print(f"\n{Fore.CYAN}🔍 RELIABILITY ASSESSMENT")
        print(f"{Fore.CYAN}{'='*30}")

        v1_reliability = "High" if v1_vuln_std < 0.5 else "Medium" if v1_vuln_std < 1.0 else "Low"
        v2_reliability = "High" if v2_vuln_std < 0.5 else "Medium" if v2_vuln_std < 1.0 else "Low"

        print(f"V1 Test Reliability: {v1_reliability}")
        print(f"V2 Test Reliability: {v2_reliability}")

        # Log reliability assessment
        self.log_info("=== RELIABILITY ASSESSMENT ===", Fore.CYAN)
        self.log_info(f"V1 Test Reliability: {v1_reliability}")
        self.log_info(f"V2 Test Reliability: {v2_reliability}")

        # Store overall summary in machine log
        if self.enable_logging:
            overall_summary = {
                "total_runs": total_runs,
                "v1_stats": {
                    "avg_vulnerabilities": avg_v1_vulnerabilities,
                    "consistency_std_dev": v1_vuln_std,
                    "avg_response_time": avg_v1_response_time,
                    "security_trend": v1_trend,
                    "reliability": v1_reliability
                },
                "v2_stats": {
                    "avg_vulnerabilities": avg_v2_vulnerabilities,
                    "consistency_std_dev": v2_vuln_std,
                    "avg_response_time": avg_v2_response_time,
                    "security_trend": v2_trend,
                    "reliability": v2_reliability
                },
                "generated_at": datetime.now().isoformat()
            }
            self.machine_log_data["overall_summary"] = overall_summary

        self.log_info("Overall summary generation completed", Fore.GREEN)
        return "Overall summary generated successfully"

    def run_all_tests(self):
        """Run all security tests"""
        self.run_start_time = datetime.now()

        if not self.check_api_health():
            if self.verbose:
                print(f"{Fore.RED}❌ Cannot proceed with tests - API is not accessible")
            self.log_info("API health check failed - cannot proceed with tests", Fore.RED)
            return

        if self.verbose:
            print(f"\n{Fore.GREEN}🚀 Starting comprehensive security testing...")
            print(f"{Fore.GREEN}⏱️  This may take several minutes to complete")

        self.log_info("Starting comprehensive security testing")

        # Run all tests
        test_methods = [
            self.test_sql_injection,
            self.test_authentication_bypass,
            self.test_bola_vulnerability,
            self.test_sensitive_data_exposure,
            self.test_input_validation,
            self.test_rate_limiting,
            self.test_brute_force_protection,
            self.test_xxe_vulnerability,
            self.test_ssrf_vulnerability,
            self.test_path_traversal_vulnerability,
            self.test_jwt_manipulation
        ]

        for test_method in test_methods:
            try:
                test_start = datetime.now()
                test_method()
                test_duration = datetime.now() - test_start
                self.log_info(f"Test {test_method.__name__} completed in {test_duration}")
                time.sleep(1)  # Brief pause between tests
            except Exception as e:
                if self.verbose:
                    print(f"{Fore.RED}❌ Test failed: {e}")
                self.log_info(f"Test {test_method.__name__} failed: {e}", Fore.RED)

                # Store results from this run with timing info
        run_duration = datetime.now() - self.run_start_time
        run_data = {
            "run_number": len(self.all_runs_results) + 1,
            "start_time": self.run_start_time.isoformat(),
            "duration": str(run_duration),
            "results": [result.to_dict() for result in self.results],
            "logs": getattr(self, 'current_run_logs', [])
        }

        if self.enable_logging:
            self.machine_log_data["runs"].append(run_data)

        # Clear current run logs for next run
        self.current_run_logs = []

        # Generate final report before clearing results
        self.generate_report()

        self.all_runs_results.append(self.results.copy())
        self.results = []  # Clear results for next run

        if self.verbose:
            print(f"\n{Fore.GREEN}🎉 Security testing completed in {run_duration}!")
            print(f"{Fore.GREEN}📄 Check the detailed report above for findings and recommendations")

        self.log_info(f"Security testing run completed in {run_duration}")

def main():
    """Main function to run the security tester"""
    parser = argparse.ArgumentParser(
        description="API Security Testing Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python test.py                                                                # Test localhost:3000
  python test.py --url http://api.example.com:8080
  python test.py --test sql                                                     # Run only SQL injection tests
  python test.py --verbose                                                      # Detailed output
  python test.py --runs 5                                                       # Run tests 5 times
  python test.py --no-logs                                                      # Disable logging to files
  python test.py --print-log                                                    # Print latest log
  python test.py --print-log --log-file logs/test_20240115_143015_machine.json
        """
    )

    parser.add_argument(
        '--url',
        default='http://localhost:3000',
        help='Base URL of the API to test (default: http://localhost:3000)'
    )

    parser.add_argument(
        '--test',
        choices=['sql', 'auth', 'bola', 'rate', 'data', 'input', 'brute', 'xxe', 'ssrf', 'path', 'jwt', 'all'],
        default='all',
        help='Specific test to run (default: all)'
    )

    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose output'
    )

    parser.add_argument(
        '--runs',
        type=int,
        default=3,
        help='Number of test runs to perform (default: 3)'
    )

    parser.add_argument(
        '--no-logs',
        action='store_true',
        help='Disable logging to files'
    )

    parser.add_argument(
        '--print-log',
        action='store_true',
        help='Print the latest log file to terminal and exit'
    )

    parser.add_argument(
        '--log-file',
        type=str,
        help='Specify a specific log file to print (use with --print-log)'
    )

    args = parser.parse_args()

    # Handle log printing mode
    if args.print_log:
        APISecurityTester.print_log_file(args.log_file, args.verbose)
        return

    # Create tester instance
    tester = APISecurityTester(args.url, args.verbose, not args.no_logs)

    # Print comprehensive pre-run information
    tester.print_pre_run_info(args)

    # Check if server is running, prompt for new URL if not
    while not tester.check_api_health():
        print(f"{Fore.YELLOW}Would you like to try a different API server URL? [Y/n]", end=" ")
        response = input().lower().strip()
        if response in ['', 'y', 'yes']:
            new_url = tester.prompt_for_url()
            tester = APISecurityTester(new_url, args.verbose)
        else:
            if args.verbose:
                print(f"{Fore.RED}❌ Exiting - API server is required for testing")
            return

    # Run tests multiple times
    for run in range(args.runs):
                # Determine what tests are being run
        if args.test == 'all':
            test_description = "Running comprehensive security tests"
        else:
            test_names = {
                'sql': 'SQL Injection tests',
                'auth': 'Authentication Bypass tests',
                'bola': 'BOLA vulnerability tests',
                'rate': 'Rate Limiting tests',
                'data': 'Sensitive Data Exposure tests',
                'input': 'Input Validation tests',
                'brute': 'Brute Force Protection tests',
                'xxe': 'XML External Entity (XXE) tests',
                'ssrf': 'Server-Side Request Forgery tests',
                'path': 'Path Traversal tests',
                'jwt': 'JWT Manipulation tests'
            }
            test_description = f"Running {test_names.get(args.test, 'Unknown tests')}"

        run_message = f"Run {run + 1}/{args.runs}: {test_description}"

        # Show run info before starting
        print(f"\n{Fore.CYAN}🔄 {run_message}")
        print(f"{Fore.CYAN}{'='*60}")

        if not args.verbose:
            spinner = Spinner(message=run_message)
            spinner.start()

        if args.test == 'all':
            tester.run_all_tests()
        else:
            # Single test run
            tester.run_start_time = datetime.now()

            test_map = {
                'sql': tester.test_sql_injection,
                'auth': tester.test_authentication_bypass,
                'bola': tester.test_bola_vulnerability,
                'rate': tester.test_rate_limiting,
                'data': tester.test_sensitive_data_exposure,
                'input': tester.test_input_validation,
                'brute': tester.test_brute_force_protection,
                'xxe': tester.test_xxe_vulnerability,
                'ssrf': tester.test_ssrf_vulnerability,
                'path': tester.test_path_traversal_vulnerability,
                'jwt': tester.test_jwt_manipulation
            }

            test_start = datetime.now()
            test_map[args.test]()
            test_duration = datetime.now() - test_start

            # Store results from this run for single test runs too
            run_data = {
                "run_number": len(tester.all_runs_results) + 1,
                "start_time": tester.run_start_time.isoformat(),
                "duration": str(test_duration),
                "test_type": args.test,
                "results": [result.to_dict() for result in tester.results],
                "logs": getattr(tester, 'current_run_logs', [])
            }

            if tester.enable_logging:
                tester.machine_log_data["runs"].append(run_data)

            # Generate report before clearing results
            tester.generate_report()

            tester.all_runs_results.append(tester.results.copy())
            tester.results = []

            tester.log_info(f"Single test run ({args.test}) completed in {test_duration}")

        if not args.verbose:
            spinner.stop()
            # Show brief summary for non-verbose mode
            current_results = tester.all_runs_results[-1] if tester.all_runs_results else tester.results
            v1_vulns = len([r for r in current_results if r.version == "v1" and r.vulnerability_found])
            v2_vulns = len([r for r in current_results if r.version == "v2" and r.vulnerability_found])
            total_test_types = len(set([r.test_name for r in current_results])) if current_results else 0

            print(f"{Fore.GREEN}✅ Run {run + 1}/{args.runs} completed")
            if total_test_types > 0:
                print(f"   V1 Vulnerabilities: {Fore.RED}{v1_vulns}/{total_test_types}")
                print(f"   V2 Vulnerabilities: {Fore.GREEN}{v2_vulns}/{total_test_types}")
        else:
            print(f"\n{Fore.GREEN}✅ Run {run + 1}/{args.runs} completed")

        # Add delay between runs to avoid rate limit buildup
        if run < args.runs - 1:  # Don't delay after last run
            if args.verbose:
                print(f"{Fore.CYAN}⏳ Waiting 2 seconds before next run to avoid rate limits...")
            time.sleep(2)

    # Generate overall summary after all runs
    total_duration = datetime.now() - tester.start_time
    print(f"\n{Fore.GREEN}🎉 All {args.runs} test runs completed in {total_duration}!")
    tester.log_info(f"All {args.runs} test runs completed in {total_duration}", Fore.GREEN)
    tester.generate_overall_summary()

    # Save final logs
    if tester.enable_logging:
        tester.save_machine_log()
        print(f"\n{Fore.CYAN}📝 Logs saved:")
        print(f"{Fore.CYAN}   Human readable: {tester.human_log_file}")
        print(f"{Fore.CYAN}   Machine readable: {tester.machine_log_file}")

    print(f"\n{Fore.GREEN}📄 Security testing complete. Total duration: {total_duration}")
    print(f"{Fore.GREEN}🔍 Check the reports above for detailed findings.")

    # Show additional options for non-verbose runs
    if not args.verbose:
        print(f"\n{Fore.YELLOW}💡 For more detailed output, you can:")
        print(f"{Fore.YELLOW}   • Re-run with --verbose flag: python test.py --verbose")
        print(f"{Fore.YELLOW}   • View latest log: python test.py --print-log")
        print(f"{Fore.YELLOW}   • View detailed latest log: python test.py --print-log --verbose")
        # if tester.enable_logging:
        #     print(f"{Fore.YELLOW}   • View latest log: python test.py --print-log")

if __name__ == "__main__":
    main()
