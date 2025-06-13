# API Security Research Experiment

> ⚠️ **Important Notice**
>
> This repository contains intentionally vulnerable code and should **NEVER** be deployed in production environments. It's designed for research and exploration in controlled settings. The vulnerable implementation (V1) demonstrates common security flaws and should only be used for learning and testing security controls.

**Exploring API Security Vulnerabilities and Defense Mechanisms**

## What This Is

This project implements a controlled environment for exploring API security vulnerabilities and their corresponding defenses. I've built two versions of the same API: an intentionally vulnerable version (V1) and a security-hardened version (V2). This allows for direct comparison of how different security approaches perform under attack.

The goal is to provide a hands-on way to understand how common API vulnerabilities work and how effective various security measures are at stopping them.

## Why This Exists

API security is often talked about in abstract terms. This project makes it concrete by letting you see vulnerabilities and defenses in action. Instead of just reading about SQL injection or broken authentication, you can actually observe these attacks working (or failing) against real endpoints.

## Project Structure

The setup is straightforward - everything you'd expect in a real API application:

```
api-security-experiment/
├── server.js              # Main application server
├── package.json           # Node.js dependencies
├── requirements.txt       # Python testing dependencies
├── test.py                # Comprehensive testing suite
├── config/                # Configuration management
│   ├── database.js        # Database connection & schema
│   └── security.js        # Security configuration
├── middleware/            # Security middleware layer
│   ├── auth.js            # Authentication mechanisms
│   ├── rateLimiter.js     # Rate limiting implementation
│   └── zeroTrust.js       # Zero-trust architecture
├── routes/
│   ├── v1/                # Vulnerable implementation
│   │   ├── auth.js        # Insecure authentication
│   │   ├── users.js       # BOLA vulnerabilities
│   │   └── data.js        # Data exposure risks
│   └── v2/                # Secure implementation
│       ├── auth.js        # Hardened authentication
│       ├── users.js       # Proper authorization
│       └── data.js        # Secure data handling
├── utils/
│   └── logger.js          # Comprehensive logging
└── logs/                  # Test result storage
```

## Getting Started

### Prerequisites

- **Node.js** >= 16.0.0
- **Python** >= 3.8
- **npm** package manager
- **pip** package manager
- **Port 3000 available** for the API server

### Installation

```bash
# Clone the repository
git clone https://github.com/mwww/RM_sec_experiment
cd RM_sec_experiment

# Install Node.js dependencies (includes new packages for XXE, SSRF, file handling)
npm install

# Install Python testing dependencies (enhanced with cryptography, JWT, plotting libraries)
pip install -r requirements.txt

# Start the API server
npm run dev
```

### Dependencies

**Node.js Packages:**

- `xml2js` - XML parsing for XXE vulnerability testing
- `request` - HTTP client for SSRF attack simulation
- `multer` - File upload handling for upload vulnerabilities
- `express-validator` - Input validation and sanitization
- `bcryptjs` - Password hashing
- `jsonwebtoken` - JWT token handling
- `helmet` - Security headers
- `express-rate-limit` - Rate limiting

**Python Packages:**

- `requests` - HTTP client for API testing
- `colorama` - Terminal color support
- `argparse` - Command line argument parsing

### Verification

Check that everything's working:

```bash
# Health check endpoint
curl http://localhost:3000/health

# Expected response: {"status": "OK", "timestamp": "..."}
```

## Testing Framework

The automated testing suite (`test.py`) runs attacks against both API versions to demonstrate the differences. It covers **11 main vulnerability categories** with comprehensive attack vectors:

| Test Category                                | V1 Expected Result | V2 Expected Result | Attack Method              | Severity |
| -------------------------------------------- | ------------------ | ------------------ | -------------------------- | -------- |
| **SQL Injection**                            | Vulnerable         | Protected          | Payload injection analysis | High     |
| **Authentication Bypass**                    | Exploitable        | Secured            | Direct endpoint access     | High     |
| **BOLA (Broken Object Level Authorization)** | Exposed            | Controlled         | User data enumeration      | High     |
| **Rate Limiting**                            | Absent             | Enforced           | Rapid request flooding     | Medium   |
| **Sensitive Data Exposure**                  | Leaking            | Sanitized          | Response content analysis  | Medium   |
| **Input Validation**                         | Missing            | Comprehensive      | Malformed input testing    | Medium   |
| **Brute Force Protection**                   | Vulnerable         | Protected          | Automated login attempts   | Medium   |
| **XML External Entity (XXE)**                | Vulnerable         | Protected          | External entity processing | High     |
| **Server-Side Request Forgery (SSRF)**       | Vulnerable         | Protected          | External URL fetching      | High     |
| **Path Traversal**                           | Vulnerable         | Protected          | File system access         | High     |
| **JWT Manipulation**                         | Vulnerable         | Protected          | Token validation bypass    | High     |

### Running Tests

```bash
# Run complete test suite (default: 3 runs)
python test.py

# Multiple test runs for statistical analysis
python test.py --runs 5       # Run tests 5 times

# Specific vulnerability testing
python test.py --test sql     # SQL injection only
python test.py --test auth    # Authentication bypass only
python test.py --test bola    # Authorization flaws only
python test.py --test rate    # Rate limiting only
python test.py --test data    # Data exposure only
python test.py --test input   # Input validation only
python test.py --test brute   # Brute force protection only

# Advanced vulnerability tests
python test.py --test xxe     # XML External Entity attacks
python test.py --test ssrf    # Server-Side Request Forgery
python test.py --test path    # Path traversal attacks
python test.py --test jwt     # JWT manipulation attacks

# Target different servers
python test.py --url http://target-api.example.com:8080

# Detailed output
python test.py --verbose

# Disable logging
python test.py --no-logs

# Review previous test results
python test.py --print-log                    # Latest machine-readable log
python test.py --print-log --verbose          # Latest human-readable log
python test.py --print-log --log-file logs/security_test_20240115_143015_human.log
```

### Command Line Options

| Option            | Description                                  | Example                                                                             |
| ----------------- | -------------------------------------------- | ----------------------------------------------------------------------------------- |
| `--help`          | Display help information and usage guide     | `--help`                                                                            |
| `--url URL`       | Target API server URL                        | `--url http://api.example.com:8080`                                                 |
| `--test TYPE`     | Run specific test category                   | `--test sql` (sql, auth, bola, rate, data, input, brute, xxe, ssrf, path, jwt, all) |
| `--runs N`        | Number of test runs for statistical analysis | `--runs 10`                                                                         |
| `--verbose`       | Enable detailed output during testing        | `--verbose`                                                                         |
| `--no-logs`       | Disable automatic logging to files           | `--no-logs`                                                                         |
| `--print-log`     | Print latest log file to terminal            | `--print-log`                                                                       |
| `--log-file PATH` | Specify specific log file to print           | `--log-file logs/test_20240115.log`                                                 |

#### Help Command Example

```bash
# Display help information
python test.py --help

# Example output:
usage: test.py [-h] [--url URL] [--test {sql,auth,bola,rate,data,input,brute,xxe,ssrf,path,jwt,all}] [--verbose] [--runs RUNS] [--no-logs] [--print-log] [--log-file LOG_FILE]

API Security Testing Suite

options:
  -h, --help            show this help message and exit
  --url URL             Base URL of the API to test (default: http://localhost:3000)
  --test {sql,auth,bola,rate,data,input,brute,xxe,ssrf,path,jwt,all}
                        Specific test to run (default: all)
  --verbose             Enable verbose output
  --runs RUNS           Number of test runs to perform (default: 3)
  --no-logs             Disable logging to files
  --print-log           Print the latest log file to terminal and exit
  --log-file LOG_FILE   Specify a specific log file to print (use with --print-log)
```

#### Log Viewing Examples

```bash
# View latest machine-readable log (JSON format)
python test.py --print-log

# View latest human-readable log (with colors and formatting)
python test.py --print-log --verbose

# View specific log file
python test.py --print-log --log-file logs/security_test_20240115_143015_human.log

# View specific machine log
python test.py --print-log --log-file logs/security_test_20240115_143015_machine.json
```

### Test Accounts

The system includes pre-configured test accounts:

- `admin` / `admin` (Administrative privileges - intentionally weak in V1)
- `user1` / `password123` (Standard user privileges)
- `user2` / `password123` (Standard user privileges)

### Attack Vectors Tested

The testing suite employs realistic attack techniques:

**Core Security Tests:**

- **SQL Injection**: Multiple payload types including union-based and comment-based attacks
- **Authentication Bypass**: Direct endpoint access without proper credentials
- **Authorization Flaws**: Direct object reference and user data enumeration
- **Rate Limiting**: Rapid request flooding to test protection mechanisms
- **Data Exposure**: Checking for sensitive information in API responses
- **Input Validation**: Malformed data including XSS payloads and oversized inputs
- **Brute Force**: Automated login attempts to test account protection

**Advanced Security Tests:**

- **XML External Entity (XXE)**: External entity processing and file access attempts
- **Server-Side Request Forgery (SSRF)**: External URL fetching through the server
- **Path Traversal**: File upload/download and directory access testing
- **JWT Security**: Token validation bypass using weak pattern matching

## Enhanced User Experience

### Pre-Run Information Display

The testing suite provides comprehensive information before starting tests:

```
================================================================================
🛡️  API SECURITY TESTING SUITE
================================================================================

📅 Test Session Information:
   Start Time: 2024-01-15 14:30:15
   Target URL: http://localhost:3000
   Test Runs: 3
   Test Type: All Security Tests
   Verbose Mode: Disabled
   Logging: Enabled
   Log Directory: /path/to/logs

🖥️  System Information:
   OS: Darwin 24.4.0
   Python: 3.11.5
   Colors: Available

🧪 Test Categories:
   1. SQL Injection Attacks
   2. Authentication Bypass
   3. Broken Object Level Authorization (BOLA)
   4. Sensitive Data Exposure
   5. Input Validation
   6. Rate Limiting
   7. Brute Force Protection
   8. XML External Entity (XXE) Attacks
   9. Server-Side Request Forgery (SSRF)
   10. Path Traversal Attacks
   11. JWT Manipulation Attacks

🚀 Starting security assessment...
   Estimated duration: 8.5 minutes
================================================================================
```

### Interactive Features

- **API Health Check**: Automatic server connectivity verification
- **URL Prompting**: Interactive URL entry if server is unavailable
- **Progress Indicators**: Spinner animation for non-verbose mode
- **Duration Estimation**: Intelligent time estimates based on test configuration
- **Real-time Feedback**: Color-coded status updates and progress tracking

### Post-Run Guidance

For non-verbose runs, the suite provides helpful guidance:

```
💡 For more detailed output, you can:
   • Re-run with --verbose flag: python test.py --verbose
   • View detailed logs: python test.py --print-log --verbose
   • View latest human log: python test.py --print-log --verbose
   • View latest machine log: python test.py --print-log
```

## Comprehensive Security Testing

### Complete Vulnerability Coverage

- **11 Vulnerability Categories**: Including XXE, SSRF, Path Traversal, and JWT Manipulation
- **Realistic Attack Scenarios**: File system access, external requests, token bypass
- **Risk Classification**: High, Medium, Low severity scoring
- **Full API Coverage**: Both authentication and data handling vulnerabilities

### API Endpoints

**V1 (Vulnerable) Endpoints:**

- `POST /v1/auth/login` - SQL injection vulnerable login
- `POST /v1/auth/register` - Insecure user registration
- `POST /v1/auth/validate-token` - Weak JWT validation
- `POST /v1/auth/reset-password` - Predictable reset tokens
- `POST /v1/auth/process-xml` - XXE vulnerability
- `GET /v1/users/:id` - BOLA vulnerability
- `GET /v1/users` - No authentication required
- `GET /v1/data/user/:userId` - Direct object access
- `GET /v1/data/all` - Exposes all sensitive data
- `POST /v1/data` - No authentication required
- `POST /v1/data/fetch-url` - SSRF vulnerability
- `GET /v1/data/file/:filename` - Path traversal
- `POST /v1/data/upload` - Unrestricted file upload
- `GET /v1/data/search` - SQL injection in search

**V2 (Secure) Endpoints:**

- `POST /v2/auth/login` - Secure authentication with bcrypt
- `POST /v2/auth/register` - Input validation and rate limiting
- `POST /v2/auth/validate-token` - Proper JWT validation
- `POST /v2/auth/reset-password` - Cryptographically secure tokens
- `POST /v2/auth/process-data` - Safe data processing (no XML)
- `GET /v2/users/:id` - Proper authorization checks
- `GET /v2/users` - Admin-only access
- `GET /v2/data/user/:userId` - Owner authorization required
- `GET /v2/data/public` - Only public data exposed
- `POST /v2/data` - Authentication and validation required

### Testing Capabilities

- **Comprehensive Test Suite**: Single integrated `test.py` with all vulnerability tests
- **Realistic Attack Patterns**: Actual payloads and attack vectors
- **Detailed Reporting**: Statistical analysis across multiple test runs
- **Flexible CLI Options**: Individual test selection and verbose output modes

### Example Attack Testing

```bash
# Test XXE vulnerabilities
python test.py --test xxe --verbose

# Test SSRF for external request access
python test.py --test ssrf

# Test JWT security with token manipulation
python test.py --test jwt

# Run complete security test suite
python test.py --verbose
```

## V1 Implementation (Vulnerable)

The V1 implementation demonstrates common security failures found in real-world applications:

### Vulnerability Categories

1. **SQL Injection (CWE-89)**

   - Direct string concatenation in database queries
   - No input sanitization or parameterization
   - Exploitable through authentication endpoints

2. **Broken Authentication (CWE-287)**

   - Weak credential validation
   - No session management
   - Plaintext password storage

3. **Broken Object Level Authorization (CWE-639)**

   - Missing ownership validation
   - Direct object reference exploitation
   - Unrestricted data access

4. **Sensitive Data Exposure (CWE-200)**

   - Password hashes in API responses
   - Internal system information leakage
   - Excessive data exposure

5. **Security Misconfiguration (CWE-16)**
   - Permissive CORS policy
   - Missing security headers
   - Debug information exposure

### Example Attack Scenarios

```bash
# SQL Injection Authentication Bypass
curl -X POST http://localhost:3000/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin'\'' OR '\''1'\''='\''1", "password": "anything"}'

# Broken Object Level Authorization
curl http://localhost:3000/v1/users/1  # Access any user's data
curl http://localhost:3000/v1/users/   # Enumerate all users with passwords

# Sensitive Data Exposure
curl http://localhost:3000/v1/data/all  # Expose all sensitive information
```

## V2 Implementation (Secure)

The V2 implementation demonstrates proper security controls and how they mitigate the vulnerabilities present in V1:

### Security Controls

1. **Input Validation & Sanitization**

   - express-validator middleware
   - Parameterized database queries
   - Input length and format restrictions

2. **Authentication & Authorization**

   - JWT-based stateless authentication
   - Role-based access control (RBAC)
   - Token expiration and refresh mechanisms

3. **Rate Limiting & Abuse Prevention**

   - Configurable rate limits per endpoint
   - IP-based request throttling
   - Progressive delay implementation

4. **Data Protection**

   - bcrypt password hashing (12 rounds)
   - Sensitive data filtering in responses
   - Minimal data exposure principle

5. **Security Headers & CORS**

   - Helmet.js security headers
   - Strict CORS policy implementation
   - Content Security Policy (CSP)

6. **Zero Trust Architecture**
   - Continuous request validation
   - Behavioral risk scoring
   - Adaptive security responses

### Security Validation Examples

```bash
# Secure Authentication
curl -X POST http://localhost:3000/v2/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username": "researcher", "email": "test@research.lab", "password": "SecurePass123!"}'

# Token-Based Authorization
TOKEN=$(curl -s -X POST http://localhost:3000/v2/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "user1", "password": "password123"}' | jq -r '.token')

curl http://localhost:3000/v2/users/profile \
  -H "Authorization: Bearer $TOKEN"
```

## Data Collection & Analysis

The testing framework includes comprehensive data collection capabilities:

### Advanced Testing Features

#### **Multiple Test Runs & Statistical Analysis**

- **Configurable test runs** (default: 3, customizable with `--runs N`)
- **Consistency metrics** with standard deviation calculations
- **Trend analysis** showing security improvements/regressions across runs
- **Reliability assessment** based on result consistency

#### **Comprehensive Logging System**

- **Dual-format logging**: Human-readable and machine-readable formats
- **Timestamped entries**: All events include precise timing information
- **Color-preserved logs**: Terminal colors maintained in log files
- **Automatic log management**: Organized in `logs/` directory with timestamps
- **Log replay functionality**: Replay previous test sessions as if just run

#### **Advanced Timing & Performance Metrics**

- **Session timing**: Total test duration tracking
- **Individual test timing**: Per-test execution time measurement
- **Run-level timing**: Duration tracking for each test run
- **Performance impact analysis**: Security overhead calculations

### Automated Reporting

The testing suite generates detailed reports including:

- **Vulnerability Assessment Matrix**: Success/failure rates for each attack vector
- **Response Time Analysis**: Performance impact of security implementations
- **Security Effectiveness Metrics**: Quantitative security posture scoring
- **Risk Assessment**: Categorized vulnerability severity ratings
- **Multi-run Statistical Analysis**: Consistency and trend analysis across multiple runs
- **Overall Summary Reports**: Aggregated findings with reliability metrics

### Log File Structure

#### Human-Readable Logs (`*_human.log`)

```
[2024-01-15 14:30:15.123] [INFO] API Security Tester initialized for http://localhost:3000
[2024-01-15 14:30:15.456] [INFO] Test session started - Target: http://localhost:3000, Runs: 3, Type: all
[2024-01-15 14:30:16.789] [INFO] Starting test: SQL Injection - Attempting to bypass login authentication
[2024-01-15 14:30:17.012] [INFO] V1 SQL Injection: VULNERABLE - SQL injection successful
```

#### Machine-Readable Logs (`*_machine.json`)

```json
{
  "test_session": {
    "start_time": "2024-01-15T14:30:15.123456",
    "end_time": "2024-01-15T14:35:20.789012",
    "target_url": "http://localhost:3000",
    "total_duration": "0:05:05.665556",
    "system_info": {
      "os": "Darwin",
      "os_version": "24.4.0",
      "python_version": "3.11.5",
      "colors_available": true
    }
  },
  "runs": [
    {
      "run_number": 1,
      "start_time": "2024-01-15T14:30:15.456789",
      "duration": "0:01:30.123456",
      "results": [...]
    }
  ]
}
```

### Statistical Analysis

```
OVERALL STATISTICS
==================
Total Test Runs: 3
V1 (Insecure) Version:
  Average Vulnerabilities: 7.0
  Consistency (Std Dev): 0.00
  Average Response Time: 0.045s

V2 (Secure) Version:
  Average Vulnerabilities: 0.0
  Consistency (Std Dev): 0.00
  Average Response Time: 0.067s

TREND ANALYSIS
==============
V1 Security Trend: stable
V2 Security Trend: stable

RELIABILITY ASSESSMENT
======================
V1 Test Reliability: High
V2 Test Reliability: High
```

## Use Cases

### Security Research

- **Comparative Security Analysis**: Quantitative vulnerability assessment
- **Security Mechanism Effectiveness**: Empirical validation of security controls
- **Performance vs. Security Trade-offs**: Cost-benefit analysis of security implementations
- **Statistical Security Analysis**: Multi-run consistency and trend analysis
- **Reproducible Research**: Comprehensive logging for result verification

### Practical Applications

- **Security Training**: Hands-on vulnerability demonstration
- **Penetration Testing**: Controlled environment for testing tools and techniques
- **Security Architecture Validation**: Real-world security pattern evaluation
- **Continuous Security Monitoring**: Automated testing with historical analysis
- **Security Metrics Collection**: Quantitative security posture measurement

### Compliance & Standards

- **OWASP Top 10 Mapping**: Direct correlation with industry standards
- **CWE Classification**: Common Weakness Enumeration alignment
- **Security Framework Testing**: Implementation validation for various security frameworks
- **Audit Trail Generation**: Comprehensive logging for compliance reporting

## Important Considerations

**This is a research environment** containing intentionally vulnerable components and should only be used in controlled settings.

### Security Warnings

- **V1 endpoints contain deliberate security flaws**
- **Never deploy V1 patterns in production environments**
- **Ensure proper network isolation during testing**
- **Follow responsible disclosure practices for any discovered issues**

### Data Handling

- All test data is synthetic and non-sensitive
- No personally identifiable information (PII) is used
- Test logs may contain attack patterns for research analysis

## Contributing

### Contributions Welcome

- Additional vulnerability classes and attack vectors
- Enhanced security mechanism implementations
- Performance optimization studies
- Cross-platform compatibility testing
- Statistical analysis improvements

### Guidelines

- Follow scientific methodology for all contributions
- Document experimental procedures thoroughly
- Provide reproducible test cases
- Include performance impact analysis
- Maintain separation between vulnerable and secure implementations

## References

- **OWASP API Security Top 10**: https://owasp.org/www-project-api-security/
- **CWE Common Weakness Enumeration**: https://cwe.mitre.org/
- **NIST Cybersecurity Framework**: https://www.nist.gov/cyberframework
- **Zero Trust Architecture**: NIST SP 800-207

## Citation

If you use this research environment, please cite:

```
Analyzing the Root Causes of API Leaks and Strategies for Security Enhancement (2025)
[https://github.com/mwww/RM_sec_experiment]
```

## License

This research project is provided under [GNU General Public License v3.0](LICENSE) for educational and research purposes. Commercial use requires explicit permission.
