# AI Security Training Platform

An interactive educational platform for learning AI security vulnerabilities and defenses through hands-on practice with a simulated banking system.

## ⚠️ IMPORTANT SECURITY NOTICE

**This is an intentionally vulnerable application designed for educational purposes only.**

- Contains multiple security vulnerabilities by design
- Should NEVER be deployed in production
- Only run in isolated, controlled environments
- Used for cybersecurity education and AI safety research

## Overview

This platform demonstrates common AI security attacks and defense mechanisms through:

- **Vulnerable Banking API**: FastAPI backend with intentional security flaws
- **Interactive Frontend**: Streamlit-based attack and defense laboratories
- **LLM Integration**: Groq API integration for realistic AI assistant vulnerabilities
- **Educational Content**: Comprehensive learning resources and case studies

## Architecture

```
┌─────────────────────┐    ┌──────────────────────┐    ┌─────────────────┐
│   Streamlit UI      │    │    FastAPI Backend   │    │   SQLite DB     │
│  (Port 8501)        │───▶│    (Port 8000)       │───▶│  secure_bank.db │
│                     │    │                      │    │                 │
│ - Attack Lab        │    │ - Authentication     │    │ - User accounts │
│ - Defense Lab       │    │ - Banking API        │    │ - Transactions  │
│ - Learning Content  │    │ - AI Chat Endpoint   │    │ - System config │
└─────────────────────┘    └──────────────────────┘    └─────────────────┘
                                        │
                                        ▼
                           ┌──────────────────────┐
                           │     Groq API         │
                           │  (LLM Processing)    │
                           └──────────────────────┘
```

## Features

### Attack Laboratory
- **Prompt Injection**: Override system instructions
- **Function Abuse**: Exploit AI function calling
- **Information Disclosure**: Extract sensitive data
- **Context Manipulation**: Abuse conversation memory
- **Social Engineering**: Manipulate through false authority

### Defense Laboratory
- **Pattern Analysis**: Test defense mechanisms
- **Rule Configuration**: Customize security rules
- **Security Monitoring**: Real-time attack detection

### Educational Resources
- Attack type explanations and examples
- Defense strategy documentation
- Security best practices
- Real-world case studies

## Prerequisites

- Python 3.8+
- Groq API key ([Get one here](https://console.groq.com/))
- 2GB+ RAM recommended
- Network access for API calls

## Installation

### 1. Clone Repository
```bash
git clone <repository-url>
cd ai-security-training-platform
```

### 2. Create Virtual Environment
```bash
python -m venv venv

# Windows
venv\Scripts\activate

# macOS/Linux
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install fastapi uvicorn streamlit sqlite3 requests pandas plotly groq numpy
```


## Usage

### 1. Start the Backend Server
```bash
python -m backend
```
The API will be available at `http://localhost:8000`

### 2. Start the Frontend (New Terminal)
```bash
python -m streamlit run app
```
The web interface will open at `http://localhost:8501`

### 3. Login with Demo Accounts

| Username | Password | Security Level | Description |
|----------|----------|----------------|-------------|
| `alice_johnson` | `SecurePass123!` | Level 1 | Standard user |
| `bob_smith` | `MyBankingPwd!` | Level 2 | Premium user |
| `charlie_admin` | `AdminSecure2024!` | Level 3 | Admin user |

### 4. Get Groq API Key
1. Visit [Groq Console](https://console.groq.com/)
2. Create an account and generate an API key
3. Enter the key in the Attack Lab interface

## Intentional Vulnerabilities

This system contains the following educational vulnerabilities:

### Authentication & Authorization
- Weak password policies
- Admin bypass codes in system config
- Insufficient access controls
- Debug endpoints with minimal protection

### AI/LLM Specific
- Prompt injection susceptibility
- Function calling abuse
- Context manipulation vulnerabilities
- Insufficient input sanitization

### API Security
- Information disclosure through error messages
- User enumeration capabilities
- Direct SQL execution endpoints
- Insufficient rate limiting

### Data Protection
- Sensitive data exposure
- Weak encryption practices
- Inadequate data classification
- Audit log vulnerabilities

## Educational Objectives

Students will learn to:

1. **Identify Vulnerabilities**: Recognize AI security weaknesses
2. **Execute Attacks**: Practice exploitation techniques safely
3. **Implement Defenses**: Build security countermeasures
4. **Analyze Threats**: Understand attack patterns
5. **Monitor Systems**: Detect and respond to incidents

## File Structure

```
├── fastapi_banking_system.py    # Vulnerable backend API
├── streamlit_frontend.py        # Interactive frontend
├── secure_bank.db              # SQLite database (auto-generated)
├── security_audit.log          # Security event logs
└── README.md                   # This file
```

## API Endpoints

### Public Endpoints
- `POST /api/login` - User authentication
- `GET /api/health` - System health check

### Protected Endpoints
- `GET /api/account/{id}` - Account information
- `GET /api/transactions/{id}` - Transaction history
- `POST /api/transfer` - Money transfer
- `POST /api/chat` - AI assistant chat

### Admin/Debug Endpoints
- `GET /api/admin/users` - List all users (admin key required)
- `GET /api/system/config` - System configuration
- `POST /api/debug/sql` - Direct SQL execution (debug token required)
- `GET /api/search/users` - User search/enumeration

## Security Monitoring

The system logs all activities to `security_audit.log` including:
- Login attempts (successful and failed)
- API access patterns
- Anomaly scores for requests
- Function call executions
- Admin operations

## Troubleshooting

### Common Issues

**Cannot login with demo accounts:**
- Ensure you've applied the authentication bug fix
- Delete `secure_bank.db` and restart the backend
- Check that both servers are running

**Groq API errors:**
- Verify your API key is valid and has credits
- Check network connectivity
- Review rate limits on your Groq account

**Frontend connection errors:**
- Confirm backend is running on port 8000
- Check firewall settings
- Verify no port conflicts

**Database errors:**
- Delete `secure_bank.db` to reset
- Check file permissions
- Ensure SQLite is properly installed

### Reset Everything
```bash
# Stop both servers
# Delete the database
rm secure_bank.db
rm security_audit.log

# Restart the backend
python fastapi_banking_system.py
```

## Educational Use Guidelines

### For Instructors
- Review all vulnerabilities before class
- Emphasize the educational nature
- Monitor student activities
- Provide guided exercises
- Discuss real-world implications

### For Students
- Only use in authorized environments
- Document your findings
- Practice both attack and defense
- Understand the underlying concepts
- Follow responsible disclosure principles

## Advanced Exercises

1. **Vulnerability Assessment**: Identify all security flaws
2. **Exploit Development**: Create custom attack payloads
3. **Defense Implementation**: Build additional security controls
4. **Monitoring Enhancement**: Improve detection capabilities
5. **Secure Redesign**: Architect a secure version

## Legal and Ethical Considerations

- Educational use only
- No real financial systems
- Respect others' systems and data
- Follow local laws and regulations
- Practice responsible disclosure

## Contributing

When contributing to this educational platform:
- Maintain the educational focus
- Document new vulnerabilities clearly
- Ensure changes don't break core functionality
- Add appropriate learning materials
- Follow security best practices for the educational content

## Support

For technical issues or educational questions:
1. Check the troubleshooting section
2. Review the learning resources
3. Consult security documentation
4. Contact the course instructor

## License

This educational platform is provided for cybersecurity training purposes. Use responsibly and in accordance with applicable laws and regulations.

---

**Remember: This is an intentionally vulnerable system for educational purposes only. Never deploy in production or use against systems you don't own.**