# SimpleChat Application Architecture

This document provides a comprehensive overview of the SimpleChat application architecture, including its components, data flow, and intentional security vulnerabilities.

## System Overview

SimpleChat is a lightweight chat application built with Flask and SQLite, designed to demonstrate various web application security vulnerabilities. The application allows users to register, log in, send messages to other users, and manage their profiles.

```
                                 +-------------------+
                                 |                   |
                                 |    Web Browser    |
                                 |                   |
                                 +--------+----------+
                                          |
                                          | HTTP Requests/Responses
                                          |
                                 +--------v----------+
                                 |                   |
                                 |   Flask Server    |
                                 |                   |
                                 +--------+----------+
                                          |
                                          | Database Queries
                                          |
                                 +--------v----------+
                                 |                   |
                                 |  SQLite Database  |
                                 |                   |
                                 +-------------------+
```

## Component Architecture

The application follows a simplified MVC (Model-View-Controller) pattern:

```
+---------------------+    +---------------------+    +---------------------+
|       Models        |    |     Controllers     |    |        Views        |
|---------------------|    |---------------------|    |---------------------|
| User                |<---| Routes (app.py)     |--->| HTML Templates      |
| Message             |    | - Authentication    |    | - base.html         |
| Notification        |    | - Messaging         |    | - messages.html     |
| Post                |    | - User Management   |    | - profile.html      |
| Comment             |    | - Search            |    | - login.html        |
| Like                |    | - Admin Functions   |    | - etc.              |
+---------------------+    +---------------------+    +---------------------+
```

## Database Schema

The application uses SQLite with the following schema:

```
+---------------+       +---------------+       +---------------+
| User          |       | Message       |       | Notification  |
|---------------|       |---------------|       |---------------|
| id            |<----->| sender_id     |       | id            |
| username      |       | recipient_id  |<----->| user_id       |
| password      |       | content       |       | content       |
| email         |       | timestamp     |       | is_read       |
| full_name     |       | is_read       |       | notification_type |
| address       |       +---------------+       | related_id    |
| phone         |                               | id            |
| credit_card   |       +---------------+       | content       |
| ssn           |       | Post          |       | timestamp     |
| date_of_birth |       |---------------|       | is_read       |
| bio           |<----->| id            |       | is_private    |
| profile_picture|      | user_id       |       | location      |
| cover_photo   |       | image_url     |<----->| notification_type |
| join_date     |       | caption       |       | related_id    |
| is_private    |       | timestamp     |       | id            |
+---------------+       | is_private    |       | content       |
                        | location      |       | timestamp     |
                        +---------------+       +---------------+
                                |
                                v
                        +---------------+
                        | Like          |
                        |---------------|
                        | id            |
                        | user_id       |
                        | post_id       |
                        | timestamp     |
                        +---------------+
```

## Authentication Flow

The application uses cookie-based authentication with intentionally vulnerable implementation:

```
+--------+                                +--------+                  +--------+
| Client |                                | Server |                  |   DB   |
+--------+                                +--------+                  +--------+
    |                                         |                           |
    | 1. Login Request                        |                           |
    |---------------------------------------->|                           |
    |                                         |                           |
    |                                         | 2. Query User             |
    |                                         |-------------------------->|
    |                                         |                           |
    |                                         | 3. Return User Data       |
    |                                         |<--------------------------|
    |                                         |                           |
    |                                         | 4. Verify Password        |
    |                                         | (plaintext comparison)    |
    |                                         |                           |
    | 5. Set Cookies (plaintext)              |                           |
    |<----------------------------------------|                           |
    | - current_user=username                 |                           |
    | - is_admin=false                        |                           |
    |                                         |                           |
    | 6. Subsequent Requests with Cookies     |                           |
    |---------------------------------------->|                           |
    |                                         |                           |
    |                                         | 7. Read Cookies Directly  |
    |                                         | (no validation)           |
    |                                         |                           |
    | 8. Response                             |                           |
    |<----------------------------------------|                           |
    |                                         |                           |
```

## Messaging System

The messaging system allows users to send and receive messages:

```
+--------+                                +--------+                  +--------+
| User A |                                | Server |                  | User B |
+--------+                                +--------+                  +--------+
    |                                         |                           |
    | 1. Send Message to User B               |                           |
    |---------------------------------------->|                           |
    |                                         |                           |
    |                                         | 2. Store Message in DB    |
    |                                         |                           |
    |                                         | 3. Create Notification    |
    |                                         |                           |
    | 4. Confirmation                         |                           |
    |<----------------------------------------|                           |
    |                                         |                           |
    |                                         |                           |
    |                                         |  5. User B Requests       |
    |                                         |<--------------------------|
    |                                         |                           |
    |                                         |  6. Fetch Messages        |
    |                                         |                           |
    |                                         |  7. Mark as Read          |
    |                                         |                           |
    |                                         |  8. Return Messages       |
    |                                         |-------------------------->|
    |                                         |                           |
```

## Conversation Identification

The application uses two methods to identify conversations:

1. Direct username-based access: `/messages/<username>`
2. Hash-based access (vulnerable): `/conversation/<conversation_hash>`

```
+-------------------+                  +-------------------+
| User A            |                  | User B            |
| ID: 1             |                  | ID: 2             |
+-------------------+                  +-------------------+
          |                                      |
          |                                      |
          v                                      v
+---------------------------------------------------+
|                                                   |
|  Conversation Hash Generation (Vulnerable)        |
|  MD5("conversation_1_2")                          |
|                                                   |
+---------------------------------------------------+
                      |
                      v
+---------------------------------------------------+
|                                                   |
|  Conversation URL:                                |
|  /conversation/5f4dcc3b5aa765d61d8327deb882cf99   |
|                                                   |
+---------------------------------------------------+
```

## File Upload System

The application includes a vulnerable file upload system:

```
+--------+                                +--------+                  +--------+
| Client |                                | Server |                  |   FS   |
+--------+                                +--------+                  +--------+
    |                                         |                           |
    | 1. Upload File Request                  |                           |
    |---------------------------------------->|                           |
    |                                         |                           |
    |                                         | 2. Save File Without      |
    |                                         |    Validation             |
    |                                         |-------------------------->|
    |                                         |                           |
    |                                         | 3. File Saved             |
    |                                         |<--------------------------|
    |                                         |                           |
    | 4. File URL Response                    |                           |
    |<----------------------------------------|                           |
    |                                         |                           |
    | 5. Access File                          |                           |
    |---------------------------------------->|                           |
    |                                         |                           |
    |                                         | 6. Retrieve File          |
    |                                         |-------------------------->|
    |                                         |                           |
    |                                         | 7. Return File            |
    |                                         |<--------------------------|
    |                                         |                           |
    | 8. File Content                         |                           |
    |<----------------------------------------|                           |
    |                                         |                           |
```

## Security Vulnerabilities Map

The application intentionally includes various security vulnerabilities:

```
+---------------------------------------------------------------------+
|                                                                     |
|                    SimpleChat Vulnerability Map                     |
|                                                                     |
+---------------------+-------------------+-------------------------+
|                     |                   |                         |
| Authentication      | Data Storage      | Input Handling          |
| ------------------- | ----------------- | ----------------------- |
| - Plaintext cookies | - Plaintext       | - SQL Injection         |
| - No CSRF protection|   passwords       | - XSS in messages       |
| - Session fixation  | - Sensitive data  | - CSRF in forms         |
| - Default creds     |   exposure        | - Command injection     |
|                     |                   |                         |
+---------------------+-------------------+-------------------------+
|                     |                   |                         |
| Access Control      | File Operations   | Network                 |
| ------------------- | ----------------- | ----------------------- |
| - Predictable IDs   | - Unrestricted    | - SSRF in profile       |
| - Missing auth      |   file uploads    |   picture URL           |
| - Direct object     | - Path traversal  | - No TLS/HTTPS          |
|   references        |   vulnerability   | - Information           |
|                     |                   |   disclosure            |
+---------------------+-------------------+-------------------------+
```

## Data Flow and Vulnerability Points

The following diagram shows the data flow through the application and highlights key vulnerability points:

```
                   +----------------+
                   |  User Browser  |
                   +-------+--------+
                           |
                           | HTTP (no HTTPS)
                           v
+------------------------------------------------------+
|                      Flask App                       |
|------------------------------------------------------|
| +----------------+  +----------------+               |
| | Authentication |  | User Profile   |               |
| |----------------|  |----------------|               |
| | - SQL Injection|  | - XSS          |               |
| | - Plaintext    |  | - CSRF         |               |
| |   cookies      |  | - SSRF         |               |
| +----------------+  +----------------+               |
|                                                      |
| +----------------+  +----------------+               |
| | Messaging      |  | File Upload    |               |
| |----------------|  |----------------|               |
| | - XSS          |  | - Unrestricted |               |
| | - SQL Injection|  |   file types   |               |
| | - Predictable  |  | - No validation|               |
| |   hashes       |  |                |               |
| +----------------+  +----------------+               |
+------------------------------------------------------+
                           |
                           | SQL Queries
                           v
+------------------------------------------------------+
|                   SQLite Database                    |
|------------------------------------------------------|
| - Plaintext passwords                                |
| - Sensitive personal data                            |
| - No input sanitization                              |
+------------------------------------------------------+
```

## Deployment Architecture

The application is deployed using Docker:

```
+-------------------------------------------------------+
| Docker Container                                      |
|-------------------------------------------------------|
| +-------------------+  +------------------------+     |
| | Python 3.9        |  | Flask Web Application  |     |
| +-------------------+  +------------------------+     |
|                                                       |
| +-------------------+  +------------------------+     |
| | SQLite Database   |  | Static Files           |     |
| +-------------------+  +------------------------+     |
|                                                       |
+-------------------------------------------------------+
                        |
                        | Port 5001
                        v
+-------------------------------------------------------+
| Host Machine                                          |
+-------------------------------------------------------+
```

## Testing Architecture

The application includes automated vulnerability testing:

```
+-------------------------------------------------------------+
| Vulnerability Test Suite                                    |
|-------------------------------------------------------------|
| +-------------------+  +----------------------------+       |
| | HTTP Client       |  | Test Cases                 |       |
| | (Requests)        |  | - SQL Injection            |       |
| +-------------------+  | - XSS                      |       |
|                        | - CSRF                     |       |
| +-------------------+  | - File Upload              |       |
| | Test Runner       |  | - SSRF                     |       |
| +-------------------+  | - Cookie Manipulation      |       |
|                        | - Predictable Hashes       |       |
| +-------------------+  | - Debug Mode               |       |
| | Result Reporter   |  | - Default Credentials      |       |
| +-------------------+  +----------------------------+       |
+-------------------------------------------------------------+
                        |
                        | HTTP Requests
                        v
+-------------------------------------------------------------+
| SimpleChat Application                                      |
+-------------------------------------------------------------+
```

## Security Considerations

This application is intentionally vulnerable and designed for educational purposes only. It should never be deployed in a production environment or exposed to the public internet.

The vulnerabilities are implemented to demonstrate common security issues in web applications and to provide a platform for learning about web application security testing.

## Educational Purpose

The architecture of SimpleChat is designed to showcase various security vulnerabilities in a controlled environment. Each component has been carefully crafted to demonstrate specific security issues, making it an ideal platform for learning about web application security.

```
+-------------------------------------------------------------+
| Educational Goals                                           |
|-------------------------------------------------------------|
| - Demonstrate OWASP Top 10 vulnerabilities                  |
| - Provide hands-on experience with security testing         |
| - Illustrate secure coding practices (by negative example)  |
| - Show the importance of input validation and sanitization  |
| - Highlight the risks of improper authentication            |
+-------------------------------------------------------------+
```
