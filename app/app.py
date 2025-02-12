from flask import Flask, request, render_template, redirect, session, jsonify, abort, make_response, Response
from flask_sqlalchemy import SQLAlchemy
import os
import hashlib  # Import for weak cryptographic example
import json
import requests
from urllib.parse import urlparse
import sqlite3  # Add SQLite3 import

app = Flask(__name__, template_folder='../templates', static_folder='../static')
app.secret_key = 'very_secret_key_123'  # Vulnerable: Hardcoded secret key

# Updated database path to work in Docker
db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'instance', 'vulnerable.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Ensure debug mode is enabled
app.config['DEBUG'] = True
app.config['PROPAGATE_EXCEPTIONS'] = True

db = SQLAlchemy(app)

# Vulnerable: Passwords stored in plaintext
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    full_name = db.Column(db.String(120), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    credit_card = db.Column(db.String(19), nullable=False)  # Format: XXXX-XXXX-XXXX-XXXX
    ssn = db.Column(db.String(11), nullable=False)  # Format: XXX-XX-XXXX
    date_of_birth = db.Column(db.String(10), nullable=False)  # Format: YYYY-MM-DD

# Create tables and initialize with fake users
def init_db():
    # Ensure the instance directory exists
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    
    with app.app_context():
        db.create_all()
        
        # Only add users if the database is empty
        if not User.query.first():
            try:
                # Load users from generated JSON file
                with open('fake_users.json', 'r') as f:
                    users_data = json.load(f)
                
                # Add all users to database
                for user_data in users_data:
                    user = User(**user_data)
                    db.session.add(user)
                
                db.session.commit()
                print(f"Successfully initialized database with {len(users_data)} users")
                
            except Exception as e:
                print(f"Error initializing database: {str(e)}")
                # If JSON file doesn't exist, add default admin user
                if not User.query.filter_by(username='admin').first():
                    admin = User(
                        username='admin',
                        password='admin123',
                        email='admin@company.com',
                        full_name='Admin User',
                        address='123 Admin St, Tech City, TC 12345',
                        phone='555-0123',
                        credit_card='4532-1234-5678-9012',
                        ssn='123-45-6789',
                        date_of_birth='1980-01-01'
                    )
                    db.session.add(admin)
                    db.session.commit()
                    print("Added default admin user")

@app.after_request
def add_insecure_headers(response):
    # Add insecure HTTP headers
    response.headers['X-Powered-By'] = 'Flask'  # Expose server technology
    response.headers['X-Content-Type-Options'] = 'nosniff'  # Disable MIME type sniffing
    response.headers['X-Frame-Options'] = 'ALLOW-FROM http://example.com'  # Allow framing from any site
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'unsafe-inline' 'unsafe-eval' *"  # Allow unsafe inline scripts
    return response

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        try:
            # Use direct SQLite3 connection instead of SQLAlchemy
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Vulnerable: Direct string formatting in SQL query
            query = f"SELECT * FROM user WHERE username='{username}' AND password='{password}'"
            cursor.execute(query)
            result = cursor.fetchone()
            
            if result:
                session['username'] = username
                # Vulnerable: Set plain text cookies for user identification
                resp = make_response(redirect('/dashboard'))
                resp.set_cookie('is_admin', 'true' if username == 'admin' else 'false')
                resp.set_cookie('current_user', username)  # Vulnerable: Plain text cookie
                return resp
            return 'Invalid credentials'
        except Exception as e:
            # Make SQL errors visible for easier exploitation
            return str(e), 500
        finally:
            cursor.close()
            conn.close()
            
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect('/login')
    
    # Vulnerable: XSS possible here
    username = session['username']
    is_admin = request.cookies.get('is_admin', 'false')
    return render_template('dashboard.html', username=username, is_admin=is_admin)

@app.route('/search')
def search():
    # Vulnerable: XSS and SQL Injection
    query = request.args.get('q', '')
    
    try:
        # Use direct SQLite3 connection
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Vulnerable: Direct string formatting in SQL query
        sql = f"SELECT * FROM user WHERE username LIKE '%{query}%'"
        cursor.execute(sql)
        
        # Get column names
        columns = [description[0] for description in cursor.description]
        
        # Convert results to list of dicts
        results = []
        for row in cursor.fetchall():
            results.append(dict(zip(columns, row)))
        
        return jsonify(results)
    except Exception as e:
        # Return error in a way that helps with SQL injection testing
        return jsonify({"error": str(e), "query": query})
    finally:
        cursor.close()
        conn.close()

@app.route('/hash', methods=['POST'])
def hash_example():
    # Example of weak cryptographic algorithm
    data = request.form.get('data', '')
    hashed_data = hashlib.md5(data.encode()).hexdigest()  # Vulnerable: MD5 is weak
    return jsonify({"hashed_data": hashed_data})

@app.route('/debug-test')
def debug_test():
    """Route to test debug mode by raising an exception"""
    abort(500, "Debug mode test")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form.get('email', f"{username}@example.com")
        full_name = request.form.get('full_name', username)
        
        # Vulnerable: No password requirements at all
        new_user = User(
            username=username,
            password=password,  # Store password in plaintext
            email=email,
            full_name=full_name,
            address='123 Default St',
            phone='555-0000',
            credit_card='4532-0000-0000-0000',
            ssn='000-00-0000',
            date_of_birth='2000-01-01'
        )
        
        try:
            db.session.add(new_user)
            db.session.commit()
            return redirect('/login')
        except Exception as e:
            return str(e), 400
            
    return render_template('register.html')

@app.route('/fixation-login', methods=['GET', 'POST'])
def fixation_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        try:
            # Vulnerable: SQL Injection still possible here with SQLAlchemy execute
            result = db.session.execute(
                f"SELECT * FROM user WHERE username='{username}' AND password='{password}'"
            ).fetchone()
            
            if result:
                # Session fixation vulnerability: Do not regenerate session ID
                session['username'] = username
                return redirect('/dashboard')
            return 'Invalid credentials'
        except Exception as e:
            # Make SQL errors visible for easier exploitation
            return str(e), 500
            
    return render_template('login.html')

# Vulnerable: No validation of update source
UPDATE_SERVER = "http://example.com/updates"

@app.route('/check-update')
def check_update():
    """
    Vulnerable update checker that doesn't verify the source or content
    """
    try:
        # Vulnerable: No SSL/TLS verification
        response = requests.get(f"{UPDATE_SERVER}/version.json", verify=False)
        return jsonify(response.json())
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/apply-update', methods=['POST'])
def apply_update():
    """
    Vulnerable update mechanism that doesn't verify integrity
    """
    update_url = request.form.get('update_url', '')
    
    try:
        # Vulnerable: No validation of URL
        parsed = urlparse(update_url)
        
        # Vulnerable: No signature verification
        response = requests.get(update_url, verify=False)
        update_data = response.json()
        
        # Vulnerable: Blindly execute update commands
        if 'commands' in update_data:
            for cmd in update_data['commands']:
                # Vulnerable: Remote code execution
                os.system(cmd)
        
        return jsonify({"status": "Update applied successfully"})
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/backup')
def backup():
    """Vulnerable backup endpoint that exposes all user data"""
    users = User.query.all()
    backup_data = {
        'users': [{
            'username': user.username,
            'password': user.password,
            'email': user.email,
            'full_name': user.full_name,
            'address': user.address,
            'phone': user.phone,
            'credit_card': user.credit_card,
            'ssn': user.ssn,
            'date_of_birth': user.date_of_birth
        } for user in users]
    }
    return jsonify(backup_data)

@app.route('/admin/delete-user/<username>')
def delete_user(username):
    """
    Vulnerable admin endpoint with no logging
    """
    # Vulnerable: No logging of sensitive actions
    # Vulnerable: No proper authentication check
    if request.cookies.get('is_admin') == 'true':
        user = User.query.filter_by(username=username).first()
        if user:
            db.session.delete(user)
            db.session.commit()
            return jsonify({"status": "success"})
    return jsonify({"error": "unauthorized"}), 403

@app.route('/admin/reset-password', methods=['POST'])
def reset_password():
    """Vulnerable password reset with no CSRF protection"""
    username = request.form.get('username')
    new_password = request.form.get('password')
    
    # Vulnerable: No authentication check
    user = User.query.filter_by(username=username).first()
    if user:
        user.password = new_password
        db.session.commit()
        return jsonify({"status": "success"})
    return jsonify({"error": "user not found"}), 404

@app.errorhandler(Exception)
def handle_error(error):
    """
    Vulnerable error handler with no proper logging
    """
    # Vulnerable: No logging of errors
    # Vulnerable: Detailed error messages in production
    return jsonify({
        "error": str(error),
        "traceback": str(error.__traceback__)
    }), 500

@app.route('/fetch-avatar')
def fetch_avatar():
    """
    Vulnerable SSRF endpoint that fetches avatars from URLs
    """
    avatar_url = request.args.get('url', '')
    
    try:
        # Vulnerable: No URL validation
        # Attacker can access internal network or localhost
        response = requests.get(avatar_url, verify=False)
        return response.content, 200, {'Content-Type': response.headers['Content-Type']}
    except Exception as e:
        return str(e), 500

@app.route('/check-website')
def check_website():
    """Vulnerable SSRF endpoint"""
    url = request.args.get('url', '')
    try:
        # Vulnerable: No URL validation at all
        response = requests.get(url, timeout=5, verify=False)
        return jsonify({
            "status": response.status_code,
            "content": response.text
        })
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/profile/<username>')
def view_profile(username):
    """Vulnerable profile view with IDOR"""
    # Vulnerable: No authentication check at all
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "User not found"}), 404
        
    return jsonify({
        "username": user.username,
        "password": user.password,  # Vulnerable: Exposing password
        "email": user.email,
        "full_name": user.full_name,
        "address": user.address,
        "phone": user.phone,
        "credit_card": user.credit_card,
        "ssn": user.ssn,
        "date_of_birth": user.date_of_birth
    })

@app.route('/robots.txt')
def robots():
    """Poorly configured robots.txt that exposes sensitive endpoints"""
    content = """
User-agent: *
Disallow: /admin/
Disallow: /backup
Disallow: /debug-test
Disallow: /hash
Disallow: /profile/
Disallow: /check-update
Disallow: /apply-update
Disallow: /fetch-avatar
Disallow: /check-website

# Internal endpoints (should not be exposed):
Disallow: /admin/delete-user/
Disallow: /admin/reset-password
Disallow: /fixation-login
"""
    return Response(content, mimetype='text/plain')

@app.route('/sitemap.xml')
def sitemap():
    """Poorly configured sitemap that exposes all endpoints"""
    xml = ['<?xml version="1.0" encoding="UTF-8"?>',
           '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']
    
    # Add all routes to sitemap
    for rule in app.url_map.iter_rules():
        if "GET" in rule.methods and not rule.arguments:  # Only add routes without parameters
            url = f"http://localhost:5001{rule.rule}"
            xml.append(f"  <url><loc>{url}</loc></url>")
    
    xml.append('</urlset>')
    return Response('\n'.join(xml), mimetype='application/xml')

@app.route('/endpoints')
def list_endpoints():
    """Debug endpoint that lists all available routes"""
    routes = []
    for rule in app.url_map.iter_rules():
        routes.append({
            "endpoint": rule.endpoint,
            "methods": list(rule.methods),
            "path": rule.rule,
            "params": list(rule.arguments)
        })
    return jsonify(routes)

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5001, debug=True)  # Vulnerable: Debug mode enabled 