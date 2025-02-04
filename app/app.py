from flask import Flask, request, render_template, redirect, session, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
import os

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

# Create tables and admin user
def init_db():
    # Ensure the instance directory exists
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    
    with app.app_context():
        db.create_all()
        # Vulnerable: Default admin credentials
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', password='admin123')
            db.session.add(admin)
            db.session.commit()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        try:
            # Vulnerable: SQL Injection still possible here with SQLAlchemy execute
            result = db.session.execute(
                f"SELECT * FROM user WHERE username='{username}' AND password='{password}'"
            ).fetchone()
            
            if result:
                session['username'] = username
                return redirect('/dashboard')
            return 'Invalid credentials'
        except Exception as e:
            # Make SQL errors visible for easier exploitation
            return str(e), 500
            
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect('/login')
    
    # Vulnerable: XSS possible here
    username = session['username']
    return render_template('dashboard.html', username=username)

@app.route('/search')
def search():
    # Vulnerable: XSS and SQL Injection
    query = request.args.get('q', '')
    
    try:
        # Using SQLAlchemy but still vulnerable to SQL injection
        # Modified to return results in a more consistent format
        results = db.session.execute(
            f"SELECT * FROM user WHERE username LIKE '%{query}%'"
        ).fetchall()
        
        # Convert results to list of dicts with column names
        formatted_results = []
        for row in results:
            # Get column names from the result
            columns = row.keys() if hasattr(row, 'keys') else ['id', 'username', 'password']
            formatted_results.append(dict(zip(columns, row)))
        
        return jsonify(formatted_results)
    except Exception as e:
        # Return error in a way that helps with SQL injection testing
        return jsonify({"error": str(e), "query": query})

@app.route('/debug-test')
def debug_test():
    """Route to test debug mode by raising an exception"""
    abort(500, "Debug mode test")

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5001, debug=True)  # Vulnerable: Debug mode enabled 