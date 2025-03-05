# Secure Web Application Project

This project demonstrates the transformation of a vulnerable web application into a secure one. It serves as an educational resource for understanding common web application vulnerabilities and how to remediate them.

## Project Structure

- `app/app.py` - The original vulnerable application
- `safe_app.py` - The secure version of the application with vulnerabilities fixed
- `VULNERABILITIES.md` - Comprehensive documentation of vulnerabilities and their fixes
- `EXPLOITATION_GUIDE.md` - Guide for testing security vulnerabilities (for educational purposes only)

## Vulnerabilities Addressed

The secure version of the application addresses 15 common web application vulnerabilities:

1. Plaintext Password Storage
2. SQL Injection
3. Cross-Site Scripting (XSS)
4. Cross-Site Request Forgery (CSRF)
5. Insecure Session Management
6. Sensitive Data Exposure
7. Insecure File Upload
8. Privilege Escalation
9. Weak Password Requirements
10. Lack of Rate Limiting
11. Hardcoded Secrets
12. Insecure Direct Object References (IDOR)
13. Verbose Error Messages
14. Missing Security Headers
15. Unrestricted File Access

For detailed information about each vulnerability and how it was fixed, please refer to the `VULNERABILITIES.md` file.

## Running the Application

### Prerequisites

- Python 3.8 or higher
- Docker (optional)

### Installation

1. Clone the repository:

   ```
   git clone <repository-url>
   cd vulnerable_webapp
   ```

2. Create a virtual environment and install dependencies:

   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. Run the secure application:
   ```
   python safe_app.py
   ```

### Docker Deployment

To run the application using Docker:

```
docker build -t secure-webapp .
docker run -d -p 5001:5001 --name secure-webapp secure-webapp
```

## Security Features

The secure version of the application implements several security best practices:

- **Password Security**: Passwords are hashed using Werkzeug's secure password hashing functions
- **Input Validation**: All user inputs are validated and sanitized
- **CSRF Protection**: All forms include CSRF tokens to prevent cross-site request forgery
- **Secure Session Management**: Sessions are managed securely with appropriate cookie settings
- **Access Controls**: Proper authorization checks are implemented for all resources
- **Secure File Handling**: File uploads are validated and stored securely
- **Error Handling**: Generic error messages are displayed to users while detailed errors are logged
- **Rate Limiting**: Sensitive operations are protected against brute force attacks
- **Environment Configuration**: Sensitive configuration is loaded from environment variables

## Educational Purpose

This project is designed for educational purposes to help developers understand:

1. How common web application vulnerabilities work
2. How to identify vulnerabilities in code
3. How to implement secure coding practices
4. The importance of security in web application development

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

The vulnerable version of this application (`app/app.py`) contains intentional security flaws and should never be deployed in a production environment. It is provided solely for educational purposes to demonstrate security vulnerabilities and their remediation.
