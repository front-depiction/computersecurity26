# Vulnerable Web Application

⚠️ **WARNING: THIS IS AN INTENTIONALLY VULNERABLE APPLICATION** ⚠️

This web application is designed for educational purposes ONLY. It contains numerous security vulnerabilities and should NEVER be deployed in a production environment or exposed to the public internet.

## Intentional Vulnerabilities

1. SQL Injection
   - Login form
   - Search functionality
2. Cross-Site Scripting (XSS)
   - User profile display
   - Search results
3. Security Misconfigurations
   - Default admin credentials (admin/admin123)
   - Debug mode enabled
   - Hardcoded secret key
4. Other Issues
   - No CSRF protection
   - Plaintext password storage
   - Direct object references
   - Unescaped user input

## Setup Instructions

1. Build the Docker image:

   ```bash
   docker build -t vulnerable-webapp .
   ```

2. Run the container:

   ```bash
   docker run -p 5001:5001 vulnerable-webapp
   ```

3. Access the application at http://localhost:5001

## Security Notice

- Run this application ONLY in a controlled, isolated environment
- Never expose this to the public internet
- Use only for educational purposes
- Reset the container regularly to clean the database

## Default Credentials

- Username: admin
- Password: admin123
