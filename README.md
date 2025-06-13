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

# Install Node.js dependencies
npm install

# Install Python testing dependencies
pip install -r requirements.txt

# Start the API server
npm run dev
```

### Verification

Check that everything's working:

```bash
# Health check endpoint
curl http://localhost:3000/health

# Expected response: {"status": "OK", "timestamp": "..."}
```

## Testing Framework

The automated testing suite (`test.py`) runs attacks against both API versions to demonstrate the differences. It covers seven main vulnerability categories:

| Test Category                                | V1 Expected Result | V2 Expected Result | Attack Method               |
| -------------------------------------------- | ------------------ | ------------------ | --------------------------- |
| **SQL Injection**                            | Vulnerable         | Protected          | Payload injection analysis  |
| **Authentication Bypass**                    | Exploitable        | Secured            | Token validation testing    |
| **BOLA (Broken Object Level Authorization)** | Exposed            | Controlled         | Access control verification |
| **Rate Limiting**                            | Absent             | Enforced           | Request frequency analysis  |
| **Sensitive Data Exposure**                  | Leaking            | Sanitized          | Response content analysis   |
| **Input Validation**                         | Missing            | Comprehensive      | Malformed input testing     |
| **Brute Force Protection**                   | Vulnerable         | Protected          | Automated attack simulation |

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

| Option            | Description                                  | Example                                                  |
| ----------------- | -------------------------------------------- | -------------------------------------------------------- |
| `--url URL`       | Target API server URL                        | `--url http://api.example.com:8080`                      |
| `--test TYPE`     | Run specific test category                   | `--test sql` (sql, auth, bola, rate, data, input, brute) |
| `--runs N`        | Number of test runs for statistical analysis | `--runs 10`                                              |
| `--verbose`       | Enable detailed output during testing        | `--verbose`                                              |
| `--no-logs`       | Disable automatic logging to files           | `--no-logs`                                              |
| `--print-log`     | Print latest log file to terminal            | `--print-log`                                            |
| `--log-file PATH` | Specify specific log file to print           | `--log-file logs/test_20240115.log`                      |

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

The testing suite employs various attack techniques:

- **SQL Injection Payloads**: union-based, boolean-based, time-based, comment-based
- **Authentication Bypass**: Multiple login attempts, token manipulation
- **Authorization Escalation**: Direct object references, user enumeration
- **Rate Limiting Evasion**: Rapid request sequences, endpoint flooding
- **Data Enumeration**: Sensitive field exposure, information leakage
- **Input Validation Bypass**: XSS, path traversal, buffer overflow, NoSQL injection
- **Brute Force Attacks**: Automated password guessing, account lockout testing

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

🚀 Starting security assessment...
   Estimated duration: 6.0 minutes
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
