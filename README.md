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
   - Insecure HTTP headers (e.g., X-Powered-By, Content-Security-Policy)
4. Cryptographic Failures
   - Weak cryptographic algorithm (MD5)
   - Plaintext password storage
5. Identification and Authentication Failures
   - Plaintext password storage
   - Weak password policies (minimum 4 characters)
   - Session fixation vulnerability (no session ID regeneration)
6. Software and Data Integrity Failures
   - Insecure update mechanism
   - No signature verification
   - Unvalidated backup/restore
7. Security Logging and Monitoring Failures
   - No logging of sensitive actions
   - No error logging
   - Detailed error messages in production
   - No rate limiting
8. Server-Side Request Forgery (SSRF)
   - Unvalidated URL fetching
   - Internal network scanning possible
   - No URL scheme restrictions
9. Other Issues
   - No CSRF protection
   - Direct object references
   - Unescaped user input

## Setup Instructions

1. Run all commands at once:

   ```bash
   docker ps --filter "publish=5001" --format "{{.ID}}" | xargs -r docker stop && \
   docker rm vulnerable-webapp || true && \
   docker rmi vulnerable-webapp || true && \
   docker build --no-cache -t vulnerable-webapp . && \
   docker run -p 5001:5001 --name vulnerable-webapp vulnerable-webapp
   ```

   Or run each step individually:

2. Remove any existing image:

   ```bash
   docker rmi vulnerable-webapp || true
   ```

3. Build the Docker image:

   ```bash
   docker build --no-cache -t vulnerable-webapp .
   ```

4. Run the container:

   ```bash
   docker run -p 5001:5001 vulnerable-webapp
   ```

5. Access the application at http://localhost:5001

## Security Notice

- Run this application ONLY in a controlled, isolated environment
- Never expose this to the public internet
- Use only for educational purposes
- Reset the container regularly to clean the database

## Default Credentials

- Username: admin
- Password: admin123
