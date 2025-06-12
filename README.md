# API Security Research Experiment

> ⚠️ **WARNING: RESEARCH USE ONLY**
>
> This repository contains intentionally vulnerable code and should **NEVER** be deployed in production environments. It is designed exclusively for educational and research purposes in controlled settings. The vulnerable implementation (V1) demonstrates common security flaws and should only be used for learning and testing security controls.

**Analyzing the Root Causes of API Leaks and Strategies for Security Enhancement**

## 📋 Abstract

This research project implements a controlled experimental environment to systematically evaluate API security vulnerabilities and their corresponding mitigation strategies. The experiment provides two distinct API implementations: an intentionally vulnerable version (V1) and a security-hardened version (V2), enabling quantitative analysis of common web application security flaws and defensive mechanisms.

## 🔬 Research Objectives

1. **Vulnerability Demonstration**: Systematically expose common API security vulnerabilities in a controlled environment
2. **Mitigation Validation**: Evaluate the effectiveness of modern security implementations
3. **Performance Impact Analysis**: Measure the computational overhead of security mechanisms
4. **Behavioral Analysis**: Study attack patterns and defensive responses through automated testing
5. **Evidence Collection**: Generate reproducible test results for security research

## 🏗️ Experimental Architecture

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
│   ├── v1/                # Control group (vulnerable)
│   │   ├── auth.js        # Insecure authentication
│   │   ├── users.js       # BOLA vulnerabilities
│   │   └── data.js        # Data exposure risks
│   └── v2/                # Treatment group (secure)
│       ├── auth.js        # Hardened authentication
│       ├── users.js       # Proper authorization
│       └── data.js        # Secure data handling
├── utils/
│   └── logger.js          # Comprehensive logging
└── logs/                  # Experimental data storage
```

## 🚀 Environment Setup

### Prerequisites

- **Node.js** >= 16.0.0
- **Python** >= 3.8
- **npm** package manager
- **pip** package manager
- **Port 3000 on host to be open** to run the node server

### Installation

```bash
# 1. Clone the experimental environment
git clone https://github.com/mwww/RM_sec_experiment
cd api-security-experiment

# 2. Install Node.js dependencies
npm install

# 3. Install Python testing dependencies
pip install -r requirements.txt

# 4. Initialize the experimental environment
npm run dev
```

### Verification

```bash
# Health check endpoint
curl http://localhost:3000/health

# Expected response: {"status": "OK", "timestamp": "..."}
```

## 🧪 Experimental Methodology

### Test Suite Overview

The comprehensive testing suite (`test.py`) implements automated vulnerability assessment across seven critical security domains:

| Test Category                                | V1 Expected Result | V2 Expected Result | Methodology                 |
| -------------------------------------------- | ------------------ | ------------------ | --------------------------- |
| **SQL Injection**                            | Vulnerable         | Protected          | Payload injection analysis  |
| **Authentication Bypass**                    | Exploitable        | Secured            | Token validation testing    |
| **BOLA (Broken Object Level Authorization)** | Exposed            | Controlled         | Access control verification |
| **Rate Limiting**                            | Absent             | Enforced           | Request frequency analysis  |
| **Sensitive Data Exposure**                  | Leaking            | Sanitized          | Response content analysis   |
| **Input Validation**                         | Missing            | Comprehensive      | Malformed input testing     |
| **Brute Force Protection**                   | Vulnerable         | Protected          | Automated attack simulation |

### Automated Testing Execution

```bash
# Full experimental battery
python test.py

# Specific vulnerability class testing
python test.py --test sql     # SQL injection only
python test.py --test auth    # Authentication bypass only
python test.py --test bola    # Authorization flaws only
python test.py --test rate    # Rate limiting only
python test.py --test data    # Data exposure only
python test.py --test input   # Input validation only
python test.py --test brute   # Brute force protection only

# Custom target specification
python test.py --url http://target-api.example.com:8080

# Verbose output for detailed analysis
python test.py --verbose
```

### Test Data & Controls

**Pre-configured Test Subjects:**

- `admin` / `admin` (Administrative privileges - V1 weak credential)
- `user1` / `password123` (Standard user privileges)
- `user2` / `password123` (Standard user privileges)

**Attack Vectors:**

- SQL injection payloads (union-based, boolean-based, time-based)
- Authentication bypass techniques
- Authorization escalation attempts
- Rate limiting evasion strategies
- Data enumeration attacks
- Input validation bypass methods

## 🔓 V1 (Control Group) - Vulnerability Catalog

### Implemented Vulnerabilities

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

### Example Exploitation Vectors

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

## 🔒 V2 (Treatment Group) - Security Implementation

### Security Controls Implemented

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

## 📊 Experimental Data Collection

### Automated Reporting

The testing suite generates comprehensive reports including:

- **Vulnerability Assessment Matrix**: Success/failure rates for each attack vector
- **Response Time Analysis**: Performance impact of security implementations
- **Security Effectiveness Metrics**: Quantitative security posture scoring
- **Risk Assessment**: Categorized vulnerability severity ratings

### Statistical Analysis

```
SUMMARY STATISTICS
==================
Total Tests Conducted: 14
V1 (Control) Vulnerabilities: 7/7 (100%)
V2 (Treatment) Vulnerabilities: 0/7 (0%)

PERFORMANCE IMPACT
==================
V1 Average Response Time: 0.045s
V2 Average Response Time: 0.067s
Security Overhead: 48.9%
```

## 🔍 Research Applications

### Academic Research

- **Comparative Security Analysis**: Quantitative vulnerability assessment
- **Security Mechanism Effectiveness**: Empirical validation of security controls
- **Performance vs. Security Trade-offs**: Cost-benefit analysis of security implementations

### Industry Applications

- **Security Training**: Hands-on vulnerability demonstration
- **Penetration Testing**: Controlled environment for testing tools and techniques
- **Security Architecture Validation**: Real-world security pattern evaluation

### Compliance & Standards

- **OWASP Top 10 Mapping**: Direct correlation with industry standards
- **CWE Classification**: Common Weakness Enumeration alignment
- **Security Framework Testing**: Implementation validation for various security frameworks

## ⚠️ Ethical Considerations & Disclaimers

**RESEARCH USE ONLY**: This experimental environment contains intentionally vulnerable components and should only be used in controlled research settings.

### Security Warnings

- **V1 endpoints contain deliberate security flaws**
- **Never deploy V1 patterns in production environments**
- **Ensure proper network isolation during testing**
- **Follow responsible disclosure practices for any discovered issues**

### Data Handling

- All test data is synthetic and non-sensitive
- No personally identifiable information (PII) is used
- Experimental logs may contain attack patterns for research analysis

## 🤝 Contributing to Research

### Research Contributions Welcome

- Additional vulnerability classes and attack vectors
- Enhanced security mechanism implementations
- Performance optimization studies
- Cross-platform compatibility testing
- Statistical analysis improvements

### Collaboration Guidelines

- Follow scientific methodology for all contributions
- Document experimental procedures thoroughly
- Provide reproducible test cases
- Include performance impact analysis
- Maintain separation between vulnerable and secure implementations

## 📚 References & Further Reading

- **OWASP API Security Top 10**: https://owasp.org/www-project-api-security/
- **CWE Common Weakness Enumeration**: https://cwe.mitre.org/
- **NIST Cybersecurity Framework**: https://www.nist.gov/cyberframework
- **Zero Trust Architecture**: NIST SP 800-207

## 📄 Citation

If you use this experimental environment in your research, please cite:

```
Analyzing the Root Causes of API Leaks and Strategies for Security Enhancement (2025)
[https://github.com/mwww/RM_sec_experiment]
```

## 📝 License

This research project is provided under [GNU General Public License v3.0](LICENSE) for educational and research purposes. Commercial use requires explicit permission.
