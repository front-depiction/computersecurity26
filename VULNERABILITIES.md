# Vulnerabilities and Security Fixes

This document outlines the security vulnerabilities present in the original application (`app/app.py`) and how they were addressed in the secure version (`safe_app.py`).

## 1. Plaintext Password Storage

### Vulnerability

In the original application, user passwords were stored in plaintext in the database, making them immediately accessible to anyone with database access.

```python
# Vulnerable code
class User(db.Model):
    # ...
    password = db.Column(db.String(80), nullable=False)  # Plaintext password
    # ...
```

### Fix

In the secure version, passwords are hashed using Werkzeug's secure password hashing functions before storage. The application never stores the actual password.

```python
# Secure code
class User(db.Model):
    # ...
    password_hash = db.Column(db.String(256), nullable=False)  # Hashed password
    # ...

    def set_password(self, password):
        """Hash the password and store it in the database."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Check if the provided password matches the stored hash."""
        return check_password_hash(self.password_hash, password)
```

## 2. SQL Injection

### Vulnerability

The original application used string formatting to construct SQL queries, allowing attackers to inject malicious SQL code.

```python
# Vulnerable code
sql_query = f"SELECT * FROM user WHERE username LIKE '%{query}%' OR full_name LIKE '%{query}%' OR email LIKE '%{query}%'"
cursor.execute(sql_query)
```

### Fix

The secure version uses SQLAlchemy's ORM with parameterized queries to prevent SQL injection.

```python
# Secure code
search_pattern = f"%{query}%"
results = User.query.filter(
    db.or_(
        User.username.like(search_pattern),
        User.full_name.like(search_pattern),
        User.email.like(search_pattern)
    )
).all()
```

## 3. Cross-Site Scripting (XSS)

### Vulnerability

The original application did not sanitize user input before displaying it, allowing attackers to inject malicious JavaScript.

```python
# Vulnerable code
# In templates: {{ message.content | safe }}
# In Python:
new_comment = Comment(
    user_id=current_user.id,
    post_id=post_id,
    content=content  # Unsanitized content
)
```

### Fix

The secure version sanitizes all user input using the Bleach library to strip dangerous HTML and JavaScript.

```python
# Secure code
sanitized_content = Comment.sanitize_content(content)
new_comment = Comment(
    user_id=current_user.id,
    post_id=post_id,
    content=sanitized_content
)

# Sanitization method
@staticmethod
def sanitize_content(content):
    """Sanitize content to prevent XSS attacks."""
    if content:
        allowed_tags = ['p', 'br', 'strong', 'em', 'u']
        allowed_attributes = {}
        return bleach.clean(content, tags=allowed_tags, attributes=allowed_attributes)
    return content
```

## 4. Cross-Site Request Forgery (CSRF)

### Vulnerability

The original application did not implement CSRF protection, making it vulnerable to cross-site request forgery attacks.

```python
# Vulnerable code
# No CSRF token validation in form submissions
@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    if request.method == 'POST':
        # Process form without CSRF validation
```

### Fix

The secure version implements CSRF protection by generating and validating tokens for all form submissions.

```python
# Secure code
def generate_csrf_token():
    """Generate a CSRF token and store it in the session."""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

@app.context_processor
def inject_csrf_token():
    return {'csrf_token': generate_csrf_token()}

# In routes:
token = request.form.get('csrf_token')
if not token or token != session.get('csrf_token'):
    error = "Invalid request. Please try again."
    return render_template('change_password.html', error=error, success=success, current_user=current_user)
```

## 5. Insecure Session Management

### Vulnerability

The original application used cookies for authentication without proper security measures.

```python
# Vulnerable code
response = make_response(redirect('/feed'))
response.set_cookie('current_user', username)
response.set_cookie('is_admin', 'true' if is_admin else 'false')
```

### Fix

The secure version uses Flask's session management with secure settings.

```python
# Secure code
session.clear()
session['user_id'] = user.id
session['username'] = user.username
session['is_admin'] = user.is_admin
session.permanent = True

# Secure cookie settings
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to cookies
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Restrict cookie sending to same-site requests
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)  # Session expires after 1 hour
```

## 6. Sensitive Data Exposure

### Vulnerability

The original application stored and exposed sensitive user information like credit card numbers and social security numbers.

```python
# Vulnerable code
class User(db.Model):
    # ...
    credit_card = db.Column(db.String(19), nullable=False)
    ssn = db.Column(db.String(11), nullable=False)
    # ...
```

### Fix

The secure version removes the storage of highly sensitive information and makes other personal fields optional.

```python
# Secure code
class User(db.Model):
    # ...
    # Fix: Store only necessary personal information, encrypt sensitive data
    address = db.Column(db.String(200), nullable=True)  # Made nullable
    phone = db.Column(db.String(20), nullable=True)  # Made nullable

    # Fix: Remove plaintext storage of highly sensitive information
    # credit_card = db.Column(db.String(19), nullable=False)  # Removed
    # ssn = db.Column(db.String(11), nullable=False)  # Removed
    # ...
```

## 7. Insecure File Upload

### Vulnerability

The original application allowed unrestricted file uploads without proper validation, enabling attackers to upload malicious files.

```python
# Vulnerable code
# No validation of file type or content
filename = file.filename  # Using original filename without sanitization
filepath = os.path.join(upload_dir, filename)
file.save(filepath)
```

### Fix

The secure version implements comprehensive file upload security:

```python
# Secure code
# Validate file type and size
allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'txt', 'doc', 'docx'}
file_ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
if file_ext not in allowed_extensions:
    error = f"File type not allowed. Allowed types: {', '.join(allowed_extensions)}"
    return render_template('upload_file.html', error=error, success=success, uploaded_file=uploaded_file, current_user=current_user)

# Check file size (limit to 5MB)
file.seek(0, os.SEEK_END)
file_size = file.tell()
file.seek(0)  # Reset file pointer
if file_size > 5 * 1024 * 1024:  # 5MB
    error = "File size exceeds the limit (5MB)."
    return render_template('upload_file.html', error=error, success=success, uploaded_file=uploaded_file, current_user=current_user)

# Generate a secure filename to prevent path traversal
secure_filename = f"{current_user.id}_{int(datetime.utcnow().timestamp())}_{secrets.token_hex(8)}.{file_ext}"
```

## 8. Privilege Escalation

### Vulnerability

The original application had weak access controls, allowing users to potentially gain admin privileges.

```python
# Vulnerable code
# Admin check based on cookie that could be manipulated
if not current_user or not current_user.is_admin:
    return redirect('/login')
```

### Fix

The secure version implements proper access control with decorators and database verification.

```python
# Secure code
def admin_required(f):
    """Decorator to require admin privileges for a route."""
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if not user or not user.is_admin:
            abort(403)  # Forbidden
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    # Only accessible to admins
```

## 9. Weak Password Requirements

### Vulnerability

The original application had minimal password requirements, allowing weak passwords.

```python
# Vulnerable code
elif len(new_password) < 4:
    error = "Password must be at least 4 characters long."
```

### Fix

The secure version implements strong password requirements.

```python
# Secure code
def validate_password(password):
    """
    Validate password strength.

    Requirements:
    - At least 8 characters long
    - Contains at least one uppercase letter
    - Contains at least one lowercase letter
    - Contains at least one digit
    - Contains at least one special character
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."

    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter."

    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter."

    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one digit."

    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character."

    return True, "Password is strong."
```

## 10. Lack of Rate Limiting

### Vulnerability

The original application did not implement rate limiting, making it vulnerable to brute force attacks.

### Fix

The secure version implements rate limiting for sensitive operations like login and password changes.

```python
# Secure code
# For login attempts
if 'login_attempts' not in session:
    session['login_attempts'] = 1
    session['first_attempt_time'] = datetime.utcnow().timestamp()
else:
    session['login_attempts'] += 1

    # If too many attempts in a short time, add delay
    if session['login_attempts'] >= 5:
        time_diff = datetime.utcnow().timestamp() - session['first_attempt_time']
        if time_diff < 300:  # 5 minutes
            error = "Too many login attempts. Please try again later."
            return render_template('login.html', error=error, current_user=None)
```

## 11. Hardcoded Secrets

### Vulnerability

The original application used hardcoded secrets for sensitive operations.

```python
# Vulnerable code
app.secret_key = 'very_secret_key_123'  # Hardcoded secret key
```

### Fix

The secure version uses environment variables or generates secure random keys.

```python
# Secure code
# Fix: Generate a secure random secret key or load from environment variable
if os.environ.get('FLASK_SECRET_KEY'):
    app.secret_key = os.environ.get('FLASK_SECRET_KEY')
else:
    # Generate a secure random key if not provided in environment
    app.secret_key = secrets.token_hex(32)
    print("WARNING: Using a generated secret key. For production, set FLASK_SECRET_KEY environment variable.")
```

## 12. Insecure Direct Object References (IDOR)

### Vulnerability

The original application did not properly validate access to resources, allowing users to access other users' data.

```python
# Vulnerable code
@app.route('/post/<int:post_id>')
def view_post(post_id):
    # No check if user has permission to view this post
    post = Post.query.get(post_id)
    # ...
```

### Fix

The secure version implements proper access controls for all resources.

```python
# Secure code
@app.route('/post/<int:post_id>')
@login_required
def view_post(post_id):
    current_user = get_current_user()

    # Get the post with proper error handling
    post = Post.query.get_or_404(post_id)

    # Check if user has permission to view the post
    if post.is_private and post.user_id != current_user.id and not current_user.is_following(User.query.get(post.user_id)):
        abort(403)  # Forbidden

    # ...
```

## 13. Verbose Error Messages

### Vulnerability

The original application exposed detailed error messages that could reveal sensitive information.

```python
# Vulnerable code
except Exception as e:
    # Make SQL errors visible for easier exploitation
    return str(e), 500
```

### Fix

The secure version implements proper error handling with generic error messages for users.

```python
# Secure code
except Exception as e:
    # Fix: Don't expose detailed error messages to users
    app.logger.error(f"Search error: {str(e)}")
    return render_template('search.html',
                          results=[],
                          query=query,
                          error="An error occurred during search. Please try again.",
                          current_user=current_user)
```

## 14. Missing Security Headers

### Vulnerability

The original application did not set important security headers.

### Fix

The secure version sets secure cookie options and could be extended to include additional security headers.

```python
# Secure code
# Fix: Set secure cookie options
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to cookies
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Restrict cookie sending to same-site requests
```

## 15. Unrestricted File Access

### Vulnerability

The original application did not restrict access to uploaded files, allowing anyone to access any file.

### Fix

The secure version implements access controls for file access.

```python
# Secure code
@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    # Check if the file exists
    upload_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'static', 'uploads')
    filepath = os.path.join(upload_dir, filename)

    if not os.path.exists(filepath):
        abort(404)

    # Extract user ID from filename (assuming format: user_id_timestamp_random.ext)
    try:
        user_id = int(filename.split('_')[0])
    except (ValueError, IndexError):
        abort(403)  # Forbidden if filename doesn't match expected format

    current_user = get_current_user()

    # Check if user has permission to access the file
    if current_user.id != user_id and not current_user.is_admin:
        abort(403)  # Forbidden

    # Serve the file
    return send_from_directory(upload_dir, filename)
```
