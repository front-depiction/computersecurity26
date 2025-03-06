from flask import Flask, request, render_template, redirect, session, jsonify, abort, make_response, Response, url_for, flash
from flask_sqlalchemy import SQLAlchemy
import os
import hashlib  # Import for weak cryptographic example
import json
import requests
from urllib.parse import urlparse
import sqlite3  # Add SQLite3 import
from datetime import datetime, timedelta

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

# Define followers association table
followers = db.Table('followers',
    db.Column('follower_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('followed_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)

# Vulnerable: Passwords stored in plaintext, sensitive information exposed
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)  # Vulnerable: Plaintext password
    email = db.Column(db.String(120), nullable=False)
    full_name = db.Column(db.String(120), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    credit_card = db.Column(db.String(19), nullable=False)  # Format: XXXX-XXXX-XXXX-XXXX
    ssn = db.Column(db.String(11), nullable=False)  # Format: XXX-XX-XXXX
    date_of_birth = db.Column(db.String(10), nullable=False)  # Format: YYYY-MM-DD
    
    # New social media profile fields
    bio = db.Column(db.String(500), nullable=True)
    profile_picture = db.Column(db.String(200), nullable=True, default='default_avatar.jpg')
    cover_photo = db.Column(db.String(200), nullable=True, default='default_cover.jpg')
    join_date = db.Column(db.DateTime, default=datetime.utcnow)
    is_private = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)  # New field to track admin status
    
    # Relationships
    posts = db.relationship('Post', backref='author', lazy='dynamic', cascade='all, delete-orphan')
    comments = db.relationship('Comment', backref='author', lazy='dynamic', cascade='all, delete-orphan')
    likes = db.relationship('Like', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    sent_messages = db.relationship('Message', 
                                   foreign_keys='Message.sender_id',
                                   backref='sender', 
                                   lazy='dynamic',
                                   cascade='all, delete-orphan')
    received_messages = db.relationship('Message', 
                                       foreign_keys='Message.recipient_id',
                                       backref='recipient', 
                                       lazy='dynamic',
                                       cascade='all, delete-orphan')
    notifications = db.relationship('Notification', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    
    # Many-to-many relationship for followers
    followed = db.relationship(
        'User', secondary=followers,
        primaryjoin=(followers.c.follower_id == id),
        secondaryjoin=(followers.c.followed_id == id),
        backref=db.backref('followers', lazy='dynamic'), 
        lazy='dynamic'
    )
    
    def follow(self, user):
        if not self.is_following(user):
            self.followed.append(user)
            return self
    
    def unfollow(self, user):
        if self.is_following(user):
            self.followed.remove(user)
            return self
    
    def is_following(self, user):
        return self.followed.filter(followers.c.followed_id == user.id).count() > 0
    
    def followed_posts(self):
        # Return posts from followed users
        return Post.query.join(
            followers, (followers.c.followed_id == Post.user_id)
        ).filter(followers.c.follower_id == self.id).order_by(Post.timestamp.desc())

# Post model for user photo/content sharing
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    image_url = db.Column(db.String(200), nullable=True)  # URL to the image
    caption = db.Column(db.String(500), nullable=True)  # Vulnerable: XSS possible
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_private = db.Column(db.Boolean, default=False)
    location = db.Column(db.String(100), nullable=True)  # Vulnerable: Privacy leak
    
    # Relationships
    comments = db.relationship('Comment', backref='post', lazy='dynamic', cascade='all, delete-orphan')
    likes = db.relationship('Like', backref='post', lazy='dynamic', cascade='all, delete-orphan')

# Comment model for post comments
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    content = db.Column(db.String(500), nullable=False)  # Vulnerable: XSS possible
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Like model for post likes
class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Ensure a user can only like a post once
    __table_args__ = (db.UniqueConstraint('user_id', 'post_id', name='_user_post_like_uc'),)

# Message model for private messaging
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.String(1000), nullable=False)  # Vulnerable: Stored in plaintext
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)

# Notification model for user notifications
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    notification_type = db.Column(db.String(20), nullable=False)  # like, comment, follow, message
    related_id = db.Column(db.Integer, nullable=True)  # ID of the related object (post, comment, etc.)

# Create tables and initialize with fake users
def init_db():
    # Ensure the instance directory exists
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    
    # Check if database file exists before initializing
    if os.path.exists(db_path) and os.path.getsize(db_path) > 0:
        print("Database already exists, skipping initialization")
        return
        
    with app.app_context():
        db.create_all()
        
        # Only add users if the database is empty
        if not User.query.first():
            try:
                # Add a minimal set of users for testing
                admin = User(
                    username='admin',
                    password='admin123',
                    email='admin@example.com',
                    full_name='Admin User',
                    address='123 Admin St',
                    phone='555-1234',
                    credit_card='1234-5678-9012-3456',
                    ssn='123-45-6789',
                    date_of_birth='1990-01-01',
                    bio='Admin user',
                    profile_picture='default_avatar.jpg',
                    cover_photo='default_cover.jpg',
                    join_date=datetime.utcnow(),
                    is_private=False,
                    is_admin=True
                )
                
                user = User(
                    username='user',
                    password='user123',
                    email='user@example.com',
                    full_name='Regular User',
                    address='456 User St',
                    phone='555-5678',
                    credit_card='9876-5432-1098-7654',
                    ssn='987-65-4321',
                    date_of_birth='1995-05-05',
                    bio='Regular user',
                    profile_picture='default_avatar.jpg',
                    cover_photo='default_cover.jpg',
                    join_date=datetime.utcnow(),
                    is_private=False,
                    is_admin=False
                )
                
                # Add more test users
                alice = User(
                    username='alice',
                    password='alice123',
                    email='alice@example.com',
                    full_name='Alice Johnson',
                    address='789 Alice Ave',
                    phone='555-9012',
                    credit_card='4567-8901-2345-6789',
                    ssn='234-56-7890',
                    date_of_birth='1992-03-15',
                    bio='Hello, I am Alice!',
                    profile_picture='default_avatar.jpg',
                    cover_photo='default_cover.jpg',
                    join_date=datetime.utcnow(),
                    is_private=False,
                    is_admin=False
                )
                
                bob = User(
                    username='bob',
                    password='bob123',
                    email='bob@example.com',
                    full_name='Bob Smith',
                    address='101 Bob Blvd',
                    phone='555-3456',
                    credit_card='5678-9012-3456-7890',
                    ssn='345-67-8901',
                    date_of_birth='1988-07-22',
                    bio='Hello, I am Bob!',
                    profile_picture='default_avatar.jpg',
                    cover_photo='default_cover.jpg',
                    join_date=datetime.utcnow(),
                    is_private=False,
                    is_admin=False
                )
                
                charlie = User(
                    username='charlie',
                    password='charlie123',
                    email='charlie@example.com',
                    full_name='Charlie Brown',
                    address='202 Charlie Ct',
                    phone='555-7890',
                    credit_card='6789-0123-4567-8901',
                    ssn='456-78-9012',
                    date_of_birth='1985-11-30',
                    bio='Hello, I am Charlie!',
                    profile_picture='default_avatar.jpg',
                    cover_photo='default_cover.jpg',
                    join_date=datetime.utcnow(),
                    is_private=False,
                    is_admin=False
                )
                
                db.session.add_all([admin, user, alice, bob, charlie])
                db.session.commit()
                
                # Create follow relationships
                admin.follow(user)
                admin.follow(alice)
                user.follow(admin)
                user.follow(bob)
                alice.follow(admin)
                alice.follow(bob)
                bob.follow(charlie)
                charlie.follow(admin)
                
                db.session.commit()
                
                # Generate fake messages
                messages = [
                    # Admin and User conversation
                    Message(
                        sender_id=admin.id,
                        recipient_id=user.id,
                        content="Hey there! Welcome to SimpleChat!",
                        timestamp=datetime.utcnow() - timedelta(days=2, hours=3),
                        is_read=True
                    ),
                    Message(
                        sender_id=user.id,
                        recipient_id=admin.id,
                        content="Thanks! This app looks great!",
                        timestamp=datetime.utcnow() - timedelta(days=2, hours=2),
                        is_read=True
                    ),
                    Message(
                        sender_id=admin.id,
                        recipient_id=user.id,
                        content="Let me know if you have any questions.",
                        timestamp=datetime.utcnow() - timedelta(days=2, hours=1),
                        is_read=True
                    ),
                    Message(
                        sender_id=user.id,
                        recipient_id=admin.id,
                        content="Will do! How secure is this app?",
                        timestamp=datetime.utcnow() - timedelta(days=1, hours=12),
                        is_read=True
                    ),
                    Message(
                        sender_id=admin.id,
                        recipient_id=user.id,
                        content="It's... um... very secure! Trust me!",
                        timestamp=datetime.utcnow() - timedelta(days=1, hours=11),
                        is_read=False
                    ),
                    
                    # Admin and Alice conversation
                    Message(
                        sender_id=alice.id,
                        recipient_id=admin.id,
                        content="Hi Admin, can you help me with something?",
                        timestamp=datetime.utcnow() - timedelta(days=3, hours=5),
                        is_read=True
                    ),
                    Message(
                        sender_id=admin.id,
                        recipient_id=alice.id,
                        content="Sure Alice, what do you need?",
                        timestamp=datetime.utcnow() - timedelta(days=3, hours=4),
                        is_read=True
                    ),
                    Message(
                        sender_id=alice.id,
                        recipient_id=admin.id,
                        content="I think there might be a security issue with the app.",
                        timestamp=datetime.utcnow() - timedelta(days=3, hours=3),
                        is_read=True
                    ),
                    Message(
                        sender_id=admin.id,
                        recipient_id=alice.id,
                        content="Shh! Don't tell anyone! We're working on it...",
                        timestamp=datetime.utcnow() - timedelta(days=3, hours=2),
                        is_read=True
                    ),
                    
                    # User and Bob conversation
                    Message(
                        sender_id=bob.id,
                        recipient_id=user.id,
                        content="Hey, have you tried the new features?",
                        timestamp=datetime.utcnow() - timedelta(days=1, hours=8),
                        is_read=True
                    ),
                    Message(
                        sender_id=user.id,
                        recipient_id=bob.id,
                        content="Not yet, are they good?",
                        timestamp=datetime.utcnow() - timedelta(days=1, hours=7),
                        is_read=True
                    ),
                    Message(
                        sender_id=bob.id,
                        recipient_id=user.id,
                        content="They're amazing! But I found a weird bug...",
                        timestamp=datetime.utcnow() - timedelta(days=1, hours=6),
                        is_read=False
                    ),
                    
                    # Charlie and Admin conversation
                    Message(
                        sender_id=charlie.id,
                        recipient_id=admin.id,
                        content="Admin, I think someone hacked my account!",
                        timestamp=datetime.utcnow() - timedelta(hours=12),
                        is_read=True
                    ),
                    Message(
                        sender_id=admin.id,
                        recipient_id=charlie.id,
                        content="That's impossible! Our security is... well... Let me look into it.",
                        timestamp=datetime.utcnow() - timedelta(hours=11),
                        is_read=False
                    )
                ]
                
                db.session.add_all(messages)
                db.session.commit()
                
                print("Successfully initialized database with test users and messages")
                
            except Exception as e:
                print(f"Error initializing database: {str(e)}")

                # Load users from generated JSON file
                try:
                    with open('fake_users.json', 'r') as f:
                        users_data = json.load(f)
                    
                    # Add all users to database with new social media fields
                    for user_data in users_data:
                        try:
                            # Extract only the fields that match the User model
                            user = User(
                                username=user_data['username'],
                                password=user_data['password'],
                                email=user_data['email'],
                                full_name=user_data['full_name'],
                                address=user_data['address'],
                                phone=user_data['phone'],
                                credit_card=user_data['credit_card'],
                                ssn=user_data['ssn'],
                                date_of_birth=user_data['date_of_birth'],
                                bio=f"Hi, I'm {user_data['full_name']}. Welcome to my profile!",
                                profile_picture='default_avatar.jpg',
                                cover_photo='default_cover.jpg',
                                join_date=datetime.utcnow(),
                                is_private=False,
                                is_admin=False
                            )
                            db.session.add(user)
                        except Exception as e:
                            print(f"Error adding user {user_data.get('username', 'unknown')}: {str(e)}")
                            continue
                    
                    db.session.commit()
                    print(f"Successfully initialized database with {len(users_data)} users")
                    
                    # Create some initial follows between users
                    users = User.query.all()
                    for i, user in enumerate(users):
                        # Each user follows 5-10 random users
                        import random
                        follow_count = random.randint(5, min(10, len(users)-1))
                        potential_follows = [u for u in users if u != user]
                        follows = random.sample(potential_follows, follow_count)
                        
                        for follow in follows:
                            user.follow(follow)
                        
                    db.session.commit()
                    print("Added initial follow relationships")
                except Exception as e:
                    print(f"Error loading users from JSON: {str(e)}")
                    db.session.rollback()
                    
                    # If JSON file doesn't exist or there's an error, add default admin user
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
                            date_of_birth='1980-01-01',
                            bio='Administrator of PixelShare',
                            profile_picture='default_avatar.jpg',
                            cover_photo='default_cover.jpg',
                            join_date=datetime.utcnow(),
                            is_private=False,
                            is_admin=True
                        )
                        db.session.add(admin)
                        
                        # Add a demo user
                        demo = User(
                            username='demo',
                            password='demo123',
                            email='demo@pixelshare.com',
                            full_name='Demo User',
                            address='456 Demo Ave, Sample City, SC 54321',
                            phone='555-4567',
                            credit_card='4532-9876-5432-1098',
                            ssn='987-65-4321',
                            date_of_birth='1990-05-15',
                            bio='This is a demo account for PixelShare',
                            profile_picture='default_avatar.jpg',
                            cover_photo='default_cover.jpg',
                            join_date=datetime.utcnow(),
                            is_private=False,
                            is_admin=False
                        )
                        db.session.add(demo)
                        db.session.commit()
                        
                        # Admin follows demo
                        admin.follow(demo)
                        # Demo follows admin
                        demo.follow(admin)
                        db.session.commit()
                        
                        print("Added default admin and demo users")

@app.after_request
def add_insecure_headers(response):
    # Add insecure HTTP headers
    response.headers['X-Powered-By'] = 'Flask'  # Expose server technology
    response.headers['X-Content-Type-Options'] = 'nosniff'  # Disable MIME type sniffing
    response.headers['X-Frame-Options'] = 'ALLOW-FROM http://example.com'  # Allow framing from any site
    
    # Updated Content Security Policy to allow inline styles and external stylesheets
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'unsafe-inline' 'unsafe-eval' *; style-src 'unsafe-inline' 'self' https://cdnjs.cloudflare.com https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src * data:;"
    
    return response

# Helper function to check if user is logged in
def is_logged_in():
    # Changed from session check to cookie check for consistency
    return request.cookies.get('current_user') is not None

# Helper function to get current user
def get_current_user():
    # Vulnerable: Using plain text cookies for authentication
    user_data_json = request.cookies.get('current_user')
    if user_data_json:
        try:
            # Parse the JSON data from the cookie
            user_data = json.loads(user_data_json)
            username = user_data.get('username')
            
            if username:
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
                user = cursor.fetchone()
                conn.close()
                
                if user:
                    # Convert to dictionary for easier access
                    columns = [column[0] for column in cursor.description]
                    user_dict = {columns[i]: user[i] for i in range(len(columns))}
                    return user_dict
            return None
        except Exception as e:
            print(f"Error in get_current_user: {str(e)}")
            return None
    return None

# Helper function to ensure current_user is a User object
def ensure_user_object(user):
    """
    Ensures that the user is a User object, not a dictionary.
    If it's a dictionary, converts it to a User object.
    """
    if not user:
        return None
    
    # If user is already a User object, return it
    if isinstance(user, User):
        return user
    
    try:
        # If user is a dictionary, get the User object from the database
        if isinstance(user, dict) and 'username' in user:
            user_obj = User.query.filter_by(username=user['username']).first()
            if user_obj:
                # Vulnerable: Set admin status based on cookie
                if request.cookies.get('is_admin') == 'true':
                    print(f"User {user_obj.username} has admin privileges from cookie")
                return user_obj
    except Exception as e:
        print(f"Error in ensure_user_object: {str(e)}")
    
    return None

@app.route('/')
def index():
    current_user = ensure_user_object(get_current_user())
    return render_template('index.html', current_user=current_user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html', current_user=None)
    
    error = None
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            error = 'Username and password are required'
        else:
            # Vulnerable: Using string concatenation in SQL query
            # This is intentionally vulnerable to SQL injection
            try:
                # First, let's try the ORM approach as a fallback
                user = User.query.filter_by(username=username).first()
                
                # Now try the vulnerable SQL approach
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                
                # Get column names to map results correctly
                cursor.execute("PRAGMA table_info(user)")
                columns = [col[1] for col in cursor.fetchall()]
                
                # Vulnerable SQL query - directly concatenating user input
                query = f"SELECT * FROM user WHERE username = '{username}' AND password = '{password}'"
                cursor.execute(query)
                
                user_data = cursor.fetchone()
                
                if user_data:
                    # Create a response with a redirect
                    response = make_response(redirect('/'))
                    
                    # Create a dictionary mapping column names to values
                    user_dict = {columns[i]: user_data[i] for i in range(len(columns))}
                    
                    # Store user info in a cookie
                    user_info = {
                        'id': user_dict['id'],
                        'username': user_dict['username'],
                        'email': user_dict['email']
                    }
                    
                    response.set_cookie('current_user', json.dumps(user_info))
                    
                    # Set admin cookie based on user's admin status in the database
                    if user_dict['is_admin']:
                        response.set_cookie('is_admin', 'true')
                    
                    conn.close()
                    return response
                
                # If SQL injection didn't work, fall back to ORM for normal login
                elif user and user.password == password:
                    # Create a response with a redirect
                    response = make_response(redirect('/'))
                    
                    # Store user info in a cookie
                    user_info = {
                        'id': user.id,
                        'username': user.username,
                        'email': user.email
                    }
                    
                    response.set_cookie('current_user', json.dumps(user_info))
                    
                    # Set admin cookie based on user's admin status in the database
                    if user.is_admin:
                        response.set_cookie('is_admin', 'true')
                    
                    conn.close()
                    return response
                else:
                    conn.close()
                    error = 'Invalid username or password'
            except Exception as e:
                print(f"Login error: {str(e)}")
                error = 'An error occurred during login'
    
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    # Clear cookies instead of session
    response = make_response(redirect('/login'))
    response.delete_cookie('current_user')
    response.delete_cookie('is_admin')
    return response

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html', current_user=None)
    
    if request.method == 'POST':
        # Get form data
        username = request.form['username']
        password = request.form['password']  # Vulnerable: No password requirements
        email = request.form['email']
        full_name = request.form['full_name']
        address = request.form.get('address', '')
        phone = request.form.get('phone', '')
        credit_card = request.form.get('credit_card', '')
        ssn = request.form.get('ssn', '')
        date_of_birth = request.form.get('date_of_birth', '')
        bio = request.form.get('bio', f"Hi, I'm {full_name}. Welcome to my PixelShare profile!")
        
        # Check if username exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return "Username already exists"
        
        # Create new user
        new_user = User(
            username=username,
            password=password,  # Vulnerable: Plaintext password
            email=email,
            full_name=full_name,
            address=address,
            phone=phone,
            credit_card=credit_card,
            ssn=ssn,
            date_of_birth=date_of_birth,
            bio=bio,
            profile_picture='default_avatar.jpg',
            cover_photo='default_cover.jpg',
            join_date=datetime.utcnow(),
            is_private=False
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        # Log in the new user
        session['username'] = username
        resp = make_response(redirect('/messages'))  # Redirect to messages instead of feed
        resp.set_cookie('is_admin', 'false')
        resp.set_cookie('current_user', username)
        return resp
        
    return render_template('register.html')

@app.route('/feed')
def feed():
    current_user = ensure_user_object(get_current_user())
    if not current_user:
        return redirect('/login')
    
    # Get posts from followed users and own posts
    followed_posts = current_user.followed_posts()
    own_posts = Post.query.filter_by(user_id=current_user.id).all()
    
    # Combine and sort by timestamp
    all_posts = list(followed_posts) + own_posts
    all_posts.sort(key=lambda p: p.timestamp, reverse=True)
    
    return render_template('feed.html', 
                          posts=all_posts, 
                          current_user=current_user)

@app.route('/explore')
def explore():
    current_user = ensure_user_object(get_current_user())
    if not current_user:
        return redirect('/login')
    
    # Get all public posts, excluding own posts
    posts = Post.query.filter(
        Post.is_private == False,
        Post.user_id != current_user.id
    ).order_by(Post.timestamp.desc()).all()
    
    return render_template('explore.html', 
                          posts=posts, 
                          current_user=current_user)

@app.route('/profile')
def profile():
    current_user = ensure_user_object(get_current_user())
    if not current_user:
        return redirect('/login')
    
    return render_template('profile.html', current_user=current_user)

@app.route('/profile/<username>')
def view_profile(username):
    current_user = ensure_user_object(get_current_user())
    if not current_user:
        return redirect('/login')
    
    user = User.query.filter_by(username=username).first_or_404()
    
    # Check if the profile is private and the current user is not following
    if user.is_private and not current_user.is_following(user) and current_user.id != user.id:
        flash("This profile is private. You need to follow this user to view their profile.")
        return redirect('/explore')
    
    posts = Post.query.filter_by(user_id=user.id).order_by(Post.timestamp.desc()).all()
    
    return render_template('view_profile.html', 
                          user=user, 
                          posts=posts, 
                          current_user=current_user)

@app.route('/follow/<username>')
def follow(username):
    if not is_logged_in():
        return redirect('/login')
    
    current_user = get_current_user()
    if not current_user:
        return redirect('/logout')
    
    # Get the user to follow
    user_to_follow = User.query.filter_by(username=username).first_or_404()
    
    # Vulnerable: No CSRF protection
    current_user.follow(user_to_follow)
    db.session.commit()
    
    # Create notification
    notification = Notification(
        user_id=user_to_follow.id,
        content=f"{current_user.username} started following you",
        notification_type="follow",
        related_id=current_user.id
    )
    db.session.add(notification)
    db.session.commit()
    
    return redirect(f'/profile/{username}')

@app.route('/unfollow/<username>')
def unfollow(username):
    if not is_logged_in():
        return redirect('/login')
    
    current_user = get_current_user()
    if not current_user:
        return redirect('/logout')
    
    # Get the user to unfollow
    user_to_unfollow = User.query.filter_by(username=username).first_or_404()
    
    # Vulnerable: No CSRF protection
    current_user.unfollow(user_to_unfollow)
    db.session.commit()
    
    return redirect(f'/profile/{username}')

@app.route('/post/new', methods=['GET', 'POST'])
def new_post():
    if not is_logged_in():
        return redirect('/login')
    
    current_user = get_current_user()
    if not current_user:
        return redirect('/logout')
    
    if request.method == 'POST':
        # Get form data
        image_url = request.form['image_url']
        caption = request.form['caption']  # Vulnerable: XSS possible
        location = request.form.get('location', '')
        is_private = 'is_private' in request.form
        
        # Create new post
        new_post = Post(
            user_id=current_user.id,
            image_url=image_url,
            caption=caption,
            location=location,
            is_private=is_private
        )
        
        db.session.add(new_post)
        db.session.commit()
        
        return redirect('/feed')
    
    return render_template('new_post.html', current_user=current_user)

@app.route('/post/<int:post_id>')
def view_post(post_id):
    if not is_logged_in():
        return redirect('/login')
    
    current_user = get_current_user()
    if not current_user:
        return redirect('/logout')
    
    # Get the post
    # Vulnerable: IDOR - no check if user should be able to see this post
    post = Post.query.get_or_404(post_id)
    
    # Get the post author
    author = User.query.get(post.user_id)
    
    # Get comments
    comments = Comment.query.filter_by(post_id=post_id).order_by(Comment.timestamp.desc())
    
    # Check if current user has liked this post
    has_liked = Like.query.filter_by(user_id=current_user.id, post_id=post_id).first() is not None
    
    return render_template('view_post.html', 
                          post=post, 
                          author=author,
                          comments=comments,
                          current_user=current_user,
                          has_liked=has_liked)

@app.route('/post/<int:post_id>/like')
def like_post(post_id):
    if not is_logged_in():
        return redirect('/login')
    
    current_user = get_current_user()
    if not current_user:
        return redirect('/logout')
    
    # Check if post exists
    post = Post.query.get_or_404(post_id)
    
    # Check if user already liked this post
    existing_like = Like.query.filter_by(user_id=current_user.id, post_id=post_id).first()
    
    if not existing_like:
        # Create new like
        new_like = Like(
            user_id=current_user.id,
            post_id=post_id
        )
        
        db.session.add(new_like)
        
        # Create notification for post author
        if post.user_id != current_user.id:
            notification = Notification(
                user_id=post.user_id,
                content=f"{current_user.username} liked your post",
                notification_type="like",
                related_id=post_id
            )
            db.session.add(notification)
        
        db.session.commit()
    
    # Vulnerable: No CSRF protection
    return redirect(f'/post/{post_id}')

@app.route('/post/<int:post_id>/unlike')
def unlike_post(post_id):
    if not is_logged_in():
        return redirect('/login')
    
    current_user = get_current_user()
    if not current_user:
        return redirect('/logout')
    
    # Delete the like
    # Vulnerable: No CSRF protection
    Like.query.filter_by(user_id=current_user.id, post_id=post_id).delete()
    db.session.commit()
    
    return redirect(f'/post/{post_id}')

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

@app.route('/messages')
def messages():
    current_user = ensure_user_object(get_current_user())
    if not current_user:
        return redirect('/login')
    
    # Pass the user ID instead of the user object
    conversations = get_conversations_for_user(current_user.id)
    return render_template('messages.html', conversations=conversations, current_user=current_user)

@app.route('/messages/<username>', methods=['GET', 'POST'])
def conversation(username):
    current_user = ensure_user_object(get_current_user())
    if not current_user:
        return redirect('/login')
    
    # Get the other user
    other_user = User.query.filter_by(username=username).first()
    if not other_user:
        flash("User not found.")
        return redirect('/messages')
    
    # Create database connection
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Handle POST request for sending a message
    if request.method == 'POST':
        # Process message sending
        message_content = request.form.get('message', '').strip()
        if not message_content:
            message_content = request.form.get('content', '').strip()  # Try alternative field name
            
        if message_content:
            try:
                # Get current user ID - handle both User objects and dictionaries
                current_user_id = current_user.id if hasattr(current_user, 'id') else current_user['id']
                
                # Vulnerable: No escaping of message content (XSS)
                # Store the raw message content without any sanitization
                cursor.execute(
                    "INSERT INTO message (sender_id, recipient_id, content, timestamp, is_read) VALUES (?, ?, ?, ?, ?)",
                    (current_user_id, other_user.id, message_content, datetime.utcnow(), False)
                )
                
                # Create notification for the recipient
                current_username = current_user.username if hasattr(current_user, 'username') else current_user['username']
                notification_content = f"New message from {current_username}"
                cursor.execute(
                    "INSERT INTO notification (user_id, content, timestamp, is_read, notification_type, related_id) VALUES (?, ?, ?, ?, ?, ?)",
                    (other_user.id, notification_content, datetime.utcnow(), False, 'message', current_user_id)
                )
                
                conn.commit()
                print(f"Message sent successfully: {message_content}")
            except Exception as e:
                print(f"Error sending message: {str(e)}")
                conn.rollback()
    
    # Get messages between the two users
    current_user_id = current_user.id if hasattr(current_user, 'id') else current_user['id']
    cursor.execute(
        """
        SELECT * FROM message 
        WHERE (sender_id = ? AND recipient_id = ?) OR (sender_id = ? AND recipient_id = ?)
        ORDER BY timestamp ASC
        """,
        (current_user_id, other_user.id, other_user.id, current_user_id)
    )
    messages_data = cursor.fetchall()
    
    # Convert to list of dictionaries
    messages = []
    for message_data in messages_data:
        columns = [column[0] for column in cursor.description]
        message = {columns[i]: message_data[i] for i in range(len(columns))}
        
        # Convert timestamp string to datetime object if it's a string
        if 'timestamp' in message and message['timestamp'] and isinstance(message['timestamp'], str):
            try:
                # Try to parse the timestamp string to a datetime object
                message['timestamp'] = datetime.strptime(message['timestamp'], '%Y-%m-%d %H:%M:%S.%f')
            except (ValueError, TypeError):
                try:
                    # Alternative format without microseconds
                    message['timestamp'] = datetime.strptime(message['timestamp'], '%Y-%m-%d %H:%M:%S')
                except (ValueError, TypeError):
                    # If parsing fails, set to current time to avoid template errors
                    message['timestamp'] = datetime.utcnow()
        
        # Mark messages as read - handle None values for is_read
        if message['recipient_id'] == current_user_id:
            # Check if is_read is False or None/null
            if message.get('is_read') is None or message.get('is_read') == 0:
                cursor.execute("UPDATE message SET is_read = ? WHERE id = ?", (True, message['id']))
        
        messages.append(message)
    
    conn.commit()
    conn.close()
    
    # Get all conversations for sidebar
    conversations = get_conversations_for_user(current_user.id)
    
    return render_template('messages.html', 
                        conversations=conversations, 
                        messages=messages, 
                        active_user=other_user,
                        current_user=current_user)

@app.route('/send-message-vulnerable/<username>', methods=['POST'])
def send_message_vulnerable(username):
    """
    Vulnerable endpoint for sending messages using string concatenation
    This is intentionally vulnerable to SQL injection
    """
    if not is_logged_in():
        return redirect('/login')
    
    current_user = ensure_user_object(get_current_user())
    if not current_user:
        return redirect('/login')
    
    # Get the other user
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        other_user_data = cursor.fetchone()
        
        if not other_user_data:
            return "User not found", 404
        
        # Convert to dictionary
        columns = [column[0] for column in cursor.description]
        other_user = {columns[i]: other_user_data[i] for i in range(len(columns))}
        
        # Handle message sending (POST request)
        message_content = request.form.get('message', '').strip()
        if message_content:
            try:
                # VULNERABLE: Using string concatenation instead of parameterized queries
                # This is intentionally vulnerable to SQL injection
                current_user_id = current_user['id'] if isinstance(current_user, dict) else current_user.id
                other_user_id = other_user['id']
                
                # Print the message content for debugging
                print(f"Vulnerable message content: {message_content}")
                
                # Create the SQL query with string concatenation (VULNERABLE)
                sql_query = f"INSERT INTO message (sender_id, recipient_id, content, timestamp, is_read) VALUES ({current_user_id}, {other_user_id}, '{message_content}', '{datetime.utcnow()}', 0)"
                
                # Print the SQL query for debugging
                print(f"Executing SQL query: {sql_query}")
                
                # Execute the query (this will be vulnerable to SQL injection)
                cursor.execute(sql_query)
                
                # Create notification for the recipient (also vulnerable)
                current_username = current_user['username'] if isinstance(current_user, dict) else current_user.username
                notification_content = f"New message from {current_username}"
                notification_sql = f"INSERT INTO notification (user_id, content, timestamp, is_read, notification_type, related_id) VALUES ({other_user_id}, '{notification_content}', '{datetime.utcnow()}', 0, 'message', {current_user_id})"
                cursor.execute(notification_sql)
                
                conn.commit()
                
                # Return a response that includes the message content to make it easier for tests to detect
                return f"""
                <html>
                <body>
                    <h1>Message sent successfully!</h1>
                    <p>Message content: {message_content}</p>
                    <p>SQL Query executed: {sql_query}</p>
                    <a href="/messages/{username}">Back to conversation</a>
                </body>
                </html>
                """
            except Exception as e:
                print(f"Error sending message: {str(e)}")
                conn.rollback()
                return f"""
                <html>
                <body>
                    <h1>Error sending message</h1>
                    <p>Error: {str(e)}</p>
                    <p>Message content: {message_content}</p>
                    <p>SQL Query attempted: {sql_query if 'sql_query' in locals() else 'Not available'}</p>
                    <a href="/messages/{username}">Back to conversation</a>
                </body>
                </html>
                """, 500
        else:
            return "Message content cannot be empty", 400
    
    except Exception as e:
        print(f"Error in vulnerable message route: {str(e)}")
        if 'conn' in locals():
            conn.close()
        return f"An error occurred: {str(e)}", 500
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/notifications')
def notifications():
    current_user = ensure_user_object(get_current_user())
    if not current_user:
        return redirect('/login')
    
    # Get all notifications for the current user
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.timestamp.desc()).all()
    
    # Mark all as read
    for notification in notifications:
        notification.is_read = True
    db.session.commit()
    
    return render_template('notifications.html', 
                          notifications=notifications, 
                          current_user=current_user)

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

@app.route('/dashboard')
def dashboard():
    current_user = ensure_user_object(get_current_user())
    if not current_user:
        return redirect('/login')
    
    # Check if user is admin
    if current_user.username != 'admin':
        return "Access denied", 403
    
    # Get all users
    users = User.query.all()
    
    return render_template('dashboard.html', 
                          users=users, 
                          current_user=current_user)

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

@app.route('/new_chat', methods=['GET', 'POST'])
def new_chat():
    current_user = ensure_user_object(get_current_user())
    if not current_user:
        return redirect('/login')
    
    if request.method == 'POST':
        username = request.form.get('username')
        if username:
            # Find the user
            user = User.query.filter_by(username=username).first()
            if user:
                # Redirect to the conversation with this user
                return redirect(f'/messages/{username}')
            else:
                flash(f"User {username} not found")
                return redirect('/new_chat')
    
    # Get all users except current user
    users = User.query.filter(User.id != current_user.id).all()
    
    return render_template('new_chat.html', 
                          users=users, 
                          current_user=current_user)

# Add a debug endpoint to list all users
@app.route('/debug/users')
def debug_users():
    try:
        users = User.query.all()
        user_list = []
        
        for i, user in enumerate(users):
            try:
                user_info = {
                    'index': i,
                    'type': str(type(user)),
                    'id': user.id if hasattr(user, 'id') else 'N/A',
                    'username': user.username if hasattr(user, 'username') else 'N/A',
                    'email': user.email if hasattr(user, 'email') else 'N/A',
                    'password': user.password if hasattr(user, 'password') else 'N/A'
                }
                user_list.append(user_info)
            except Exception as e:
                user_list.append({
                    'index': i,
                    'error': str(e),
                    'type': str(type(user)),
                    'raw': str(user)
                })
        
        return jsonify({
            'total_users': len(users),
            'users': user_list
        })
    except Exception as e:
        import traceback
        return jsonify({
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500

# Also add a debug endpoint to check the login process
@app.route('/debug/login/<username>')
def debug_login(username):
    try:
        print(f"Debug login for username: {username}")
        
        # Get the user from the database
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Use parameterized query for safety
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        user_row = cursor.fetchone()
        
        if not user_row:
            print(f"User {username} not found in database")
            return jsonify({'error': f'User {username} not found'}), 404
        
        # Convert row to dict for display
        user_dict = dict(user_row)
        print(f"SQLite user: {user_dict}")
        
        # Get the same user using SQLAlchemy
        sqlalchemy_user = User.query.filter_by(username=username).first()
        print(f"SQLAlchemy user type: {type(sqlalchemy_user)}")
        
        if sqlalchemy_user:
            print(f"SQLAlchemy user: {sqlalchemy_user.username}")
        else:
            print(f"SQLAlchemy user not found for username: {username}")
        
        return jsonify({
            'sqlite_user': {
                'type': str(type(user_row)),
                'data': user_dict
            },
            'sqlalchemy_user': {
                'type': str(type(sqlalchemy_user)),
                'has_username': hasattr(sqlalchemy_user, 'username'),
                'username': sqlalchemy_user.username if sqlalchemy_user else None
            }
        })
    except Exception as e:
        import traceback
        error_traceback = traceback.format_exc()
        print(f"Error in debug_login: {str(e)}")
        print(error_traceback)
        return jsonify({
            'error': str(e),
            'traceback': error_traceback
        }), 500

# Add a debug endpoint to check the database schema
@app.route('/debug/schema')
def debug_schema():
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Get all tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        
        schema_info = {}
        
        for table in tables:
            table_name = table[0]
            cursor.execute(f"PRAGMA table_info({table_name});")
            columns = cursor.fetchall()
            
            schema_info[table_name] = [
                {
                    'cid': col[0],
                    'name': col[1],
                    'type': col[2],
                    'notnull': col[3],
                    'default': col[4],
                    'pk': col[5]
                }
                for col in columns
            ]
        
        return jsonify(schema_info)
    except Exception as e:
        import traceback
        return jsonify({
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500

# Add a debug endpoint to check the first few rows of each table
@app.route('/debug/data')
def debug_data():
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get all tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        
        data = {}
        
        for table in tables:
            table_name = table[0]
            cursor.execute(f"SELECT * FROM {table_name} LIMIT 5;")
            rows = cursor.fetchall()
            
            data[table_name] = [dict(row) for row in rows]
        
        return jsonify(data)
    except Exception as e:
        import traceback
        return jsonify({
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500

# Generate a predictable hash for conversation IDs
def generate_conversation_hash(user1_id, user2_id):
    """
    Generate a predictable hash for conversation IDs.
    Vulnerable: Uses a weak hash function (MD5) with no salt.
    Always uses the smaller user ID first to ensure consistency.
    """
    # Ensure consistent ordering of user IDs (smaller ID first)
    if int(user1_id) > int(user2_id):
        user1_id, user2_id = user2_id, user1_id
    
    # Create a predictable string pattern
    conversation_string = f"conversation_{user1_id}_{user2_id}"
    
    # Use MD5 (weak hash function) with no salt
    return hashlib.md5(conversation_string.encode()).hexdigest()

@app.route('/conversation/<conversation_hash>', methods=['GET', 'POST'])
def conversation_by_hash(conversation_hash):
    """
    Access a conversation using a predictable hash.
    This is intentionally vulnerable to allow guessing of conversation hashes.
    """
    current_user = ensure_user_object(get_current_user())
    if not current_user:
        return redirect('/login')
    
    # Get current user ID - handle both User objects and dictionaries
    current_user_id = current_user.id if hasattr(current_user, 'id') else current_user['id']
    
    # For demonstration purposes, try to find the conversation by brute-forcing
    # In a real attack, someone would try different user ID combinations
    found_user = None
    
    # Try the first 100 user IDs (this is intentionally inefficient for demonstration)
    for user_id in range(1, 100):
        if user_id != current_user_id:
            test_hash = generate_conversation_hash(current_user_id, user_id)
            if test_hash == conversation_hash:
                # Try to get the user from the database
                try:
                    found_user = User.query.get(user_id)
                    if not found_user:
                        # Fallback to direct database query
                        conn = sqlite3.connect(db_path)
                        cursor = conn.cursor()
                        cursor.execute("SELECT * FROM user WHERE id = ?", (user_id,))
                        user_data = cursor.fetchone()
                        if user_data:
                            columns = [column[0] for column in cursor.description]
                            found_user = {columns[i]: user_data[i] for i in range(len(columns))}
                        conn.close()
                except Exception as e:
                    print(f"Error finding user: {str(e)}")
                break
    
    if not found_user:
        return jsonify({
            "error": "Conversation not found",
            "note": "This is a vulnerable endpoint that uses predictable hashes for conversation IDs"
        }), 404
    
    # Now that we found the user, redirect to the regular conversation view
    username = found_user.username if hasattr(found_user, 'username') else found_user['username']
    return redirect(f'/messages/{username}')

# Add functions to template context
@app.context_processor
def utility_processor():
    return {
        'generate_conversation_hash': generate_conversation_hash
    }

@app.route('/debug/conversation_hashes')
def debug_conversation_hashes():
    """
    Debug endpoint to show how an attacker could generate hashes for any user combination.
    This demonstrates the vulnerability of predictable conversation hashes.
    """
    try:
        # Get all users
        users = User.query.all()
        
        # Generate a table of conversation hashes for the first 10 users
        hash_table = []
        for i in range(min(10, len(users))):
            for j in range(i+1, min(10, len(users))):
                user1 = users[i]
                user2 = users[j]
                conversation_hash = generate_conversation_hash(user1.id, user2.id)
                hash_table.append({
                    "user1_id": user1.id,
                    "user1_username": user1.username,
                    "user2_id": user2.id,
                    "user2_username": user2.username,
                    "conversation_hash": conversation_hash,
                    "conversation_url": f"/conversation/{conversation_hash}"
                })
        
        # Create a simple HTML page with the hash table and links to test
        html_response = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Conversation Hash Debug</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
                tr:nth-child(even) { background-color: #f9f9f9; }
                .warning { color: red; font-weight: bold; }
                .note { color: #666; font-style: italic; }
            </style>
        </head>
        <body>
            <h1>Conversation Hash Debug</h1>
            <p class="warning">WARNING: This page demonstrates a security vulnerability!</p>
            <p class="note">This shows how predictable conversation hashes can be exploited to access private conversations.</p>
            
            <h2>Conversation Hash Table</h2>
            <table>
                <tr>
                    <th>User 1 ID</th>
                    <th>User 1 Username</th>
                    <th>User 2 ID</th>
                    <th>User 2 Username</th>
                    <th>Conversation Hash</th>
                    <th>Test Link</th>
                </tr>
        """
        
        for entry in hash_table:
            html_response += f"""
                <tr>
                    <td>{entry['user1_id']}</td>
                    <td>{entry['user1_username']}</td>
                    <td>{entry['user2_id']}</td>
                    <td>{entry['user2_username']}</td>
                    <td>{entry['conversation_hash']}</td>
                    <td><a href="{entry['conversation_url']}" target="_blank">Test Access</a></td>
                </tr>
            """
        
        html_response += """
            </table>
            
            <h2>How to Exploit</h2>
            <p>An attacker can generate these hashes for any user combination and access private conversations:</p>
            <pre>
import hashlib

def generate_conversation_hash(user1_id, user2_id):
    # Ensure consistent ordering (smaller ID first)
    if int(user1_id) > int(user2_id):
        user1_id, user2_id = user2_id, user1_id
    
    # Create a predictable string pattern
    conversation_string = f"conversation_{user1_id}_{user2_id}"
    
    # Use MD5 (weak hash function) with no salt
    return hashlib.md5(conversation_string.encode()).hexdigest()

# Example: Generate hash for conversation between users 1 and 2
hash = generate_conversation_hash(1, 2)
print(f"Access URL: /conversation/{hash}")
            </pre>
        </body>
        </html>
        """
        
        return html_response
        
    except Exception as e:
        # Return the error with traceback for debugging
        import traceback
        return jsonify({
            "error": str(e),
            "traceback": traceback.format_exc()
        }), 500

def get_conversations_for_user(current_user):
    # Get all conversations for the current user
    try:
        # Get current user ID - handle both User objects and dictionaries
        current_user_id = current_user
        if hasattr(current_user, 'id'):
            current_user_id = current_user.id
        elif isinstance(current_user, dict) and 'id' in current_user:
            current_user_id = current_user['id']
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Get all users that the current user has exchanged messages with
        cursor.execute("""
            SELECT DISTINCT 
                CASE 
                    WHEN sender_id = ? THEN recipient_id 
                    ELSE sender_id 
                END as partner_id
            FROM message
            WHERE sender_id = ? OR recipient_id = ?
        """, (current_user_id, current_user_id, current_user_id))
        
        partner_ids = [row[0] for row in cursor.fetchall()]
        
        conversations = []
        for partner_id in partner_ids:
            # Get partner user info
            try:
                # Try to get user from SQLAlchemy ORM
                partner = User.query.get(partner_id)
                if partner:
                    partner_username = partner.username
                else:
                    # Fallback to direct SQL query
                    cursor.execute("SELECT username FROM user WHERE id = ?", (partner_id,))
                    partner_data = cursor.fetchone()
                    if not partner_data:
                        continue  # Skip if user not found
                    partner_username = partner_data[0]
            except Exception as e:
                print(f"Error getting partner info: {str(e)}")
                # Fallback to direct SQL query
                cursor.execute("SELECT username FROM user WHERE id = ?", (partner_id,))
                partner_data = cursor.fetchone()
                if not partner_data:
                    continue  # Skip if user not found
                partner_username = partner_data[0]
            
            # Get the most recent message
            cursor.execute("""
                SELECT content, timestamp, sender_id, is_read
                FROM message
                WHERE (sender_id = ? AND recipient_id = ?) OR (sender_id = ? AND recipient_id = ?)
                ORDER BY timestamp DESC
                LIMIT 1
            """, (current_user_id, partner_id, partner_id, current_user_id))
            
            message_data = cursor.fetchone()
            if not message_data:
                continue  # Skip if no messages
            
            content, timestamp_str, sender_id, is_read = message_data
            
            # Format the message preview
            if len(content) > 30:
                content = content[:27] + "..."
            
            # Convert timestamp string to datetime if needed
            timestamp_obj = None
            if timestamp_str:
                if isinstance(timestamp_str, str):
                    try:
                        timestamp_obj = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S.%f')
                    except (ValueError, TypeError):
                        try:
                            timestamp_obj = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                        except (ValueError, TypeError):
                            timestamp_obj = datetime.utcnow()  # Fallback to current time
                else:
                    # If it's already a datetime object
                    timestamp_obj = timestamp_str
            else:
                timestamp_obj = datetime.utcnow()  # Fallback to current time
            
            # Format the time for display
            try:
                formatted_time = timestamp_obj.strftime('%H:%M')
            except (AttributeError, TypeError):
                formatted_time = "Unknown"
            
            # Count unread messages
            cursor.execute("""
                SELECT COUNT(*)
                FROM message
                WHERE sender_id = ? AND recipient_id = ? AND is_read = 0
            """, (partner_id, current_user_id))
            
            unread_count_result = cursor.fetchone()
            unread_count = unread_count_result[0] if unread_count_result else 0
            
            conversations.append({
                'user_id': partner_id,
                'username': partner_username,
                'last_message': content,
                'timestamp': formatted_time,
                'timestamp_obj': timestamp_obj,  # Store the actual datetime object for sorting
                'unread': unread_count if unread_count > 0 else None
            })
        
        # Sort conversations by the timestamp_obj (actual datetime) instead of formatted string
        conversations.sort(key=lambda x: x['timestamp_obj'] if x['timestamp_obj'] else datetime.min, reverse=True)
        
        # Remove the timestamp_obj from the dictionaries as it's not needed in the template
        for convo in conversations:
            if 'timestamp_obj' in convo:
                del convo['timestamp_obj']
        
        conn.close()
        return conversations
        
    except Exception as e:
        print(f"Error getting conversations: {str(e)}")
        if 'conn' in locals():
            conn.close()
        return []

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

@app.route('/update-profile-picture', methods=['GET', 'POST'])
def update_profile_picture():
    current_user = ensure_user_object(get_current_user())
    if not current_user:
        return redirect('/login')
    
    error = None
    success = None
    
    if request.method == 'POST':
        picture_url = request.form.get('picture_url')
        
        if not picture_url:
            error = "Please provide a URL for the profile picture."
        else:
            try:
                # Vulnerable: No validation of URL scheme or domain
                # This allows SSRF attacks to internal resources
                response = requests.get(picture_url, timeout=5)
                
                if response.status_code == 200:
                    # Successfully fetched the image
                    current_user.profile_picture = picture_url
                    db.session.commit()
                    success = "Profile picture updated successfully."
                    print(f"Profile picture updated for user: {current_user.username}")
                else:
                    error = f"Failed to fetch image from URL. Status code: {response.status_code}"
            except Exception as e:
                db.session.rollback()
                error = f"An error occurred: {str(e)}"
                print(f"Error updating profile picture: {str(e)}")
    
    return render_template('update_profile_picture.html', error=error, success=success, current_user=current_user)

@app.route('/debug/all-users')
def debug_all_users():
    # Vulnerable: Exposing sensitive information about all users
    # No authentication check
    try:
        users = User.query.all()
        user_data = []
        
        for user in users:
            user_info = {
                'id': user.id,
                'username': user.username,
                'password': user.password,  # Exposing plaintext passwords
                'email': user.email,
                'full_name': user.full_name,
                'address': user.address,
                'phone': user.phone,
                'credit_card': user.credit_card,
                'ssn': user.ssn,
                'date_of_birth': user.date_of_birth,
                'is_private': user.is_private
            }
            user_data.append(user_info)
        
        return jsonify({
            'count': len(user_data),
            'users': user_data
        })
    except Exception as e:
        return jsonify({
            'error': str(e),
            'traceback': traceback.format_exc()  # Exposing detailed error information
        }), 500

@app.route('/upload-file', methods=['GET', 'POST'])
def upload_file():
    current_user = ensure_user_object(get_current_user())
    if not current_user:
        return redirect('/login')
    
    error = None
    success = None
    uploaded_file = None
    
    if request.method == 'POST':
        if 'file' not in request.files:
            error = "No file part in the request."
        else:
            file = request.files['file']
            
            if file.filename == '':
                error = "No file selected."
            else:
                try:
                    # Vulnerable: No validation of file type or content
                    # This allows uploading malicious files (e.g., PHP shells)
                    
                    # Create uploads directory if it doesn't exist
                    upload_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'static', 'uploads')
                    os.makedirs(upload_dir, exist_ok=True)
                    
                    # Vulnerable: Using the original filename without sanitization
                    # This can lead to path traversal attacks
                    filename = file.filename
                    filepath = os.path.join(upload_dir, filename)
                    
                    # Save the file
                    file.save(filepath)
                    
                    # Get the relative path for display
                    relative_path = f'/static/uploads/{filename}'
                    uploaded_file = relative_path
                    
                    success = f"File uploaded successfully: {filename}"
                    print(f"File uploaded by {current_user.username}: {filename}")
                except Exception as e:
                    error = f"An error occurred: {str(e)}"
                    print(f"Error uploading file: {str(e)}")
    
    return render_template('upload_file.html', error=error, success=success, uploaded_file=uploaded_file, current_user=current_user)

# Admin routes
@app.route('/admin/dashboard')
def admin_dashboard():
    """Admin dashboard that displays all user data - intentionally vulnerable"""
    # Get current user
    current_user = ensure_user_object(get_current_user())
    
    # Check if user is logged in and has admin privileges
    if not current_user or not current_user.is_admin:
        return redirect('/login')
    
    try:
        # Get all users from database
        users = User.query.all()
        users_list = []
        
        for user in users:
            users_list.append({
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'password': user.password,  # Intentionally exposing passwords
                'full_name': user.full_name,
                'address': user.address,
                'phone': user.phone,
                'credit_card': user.credit_card,
                'ssn': user.ssn,
                'date_of_birth': user.date_of_birth,
                'is_admin': user.is_admin  # Include admin status
            })
        
        return render_template('admin_dashboard.html', users=users_list, current_user=current_user)
    except Exception as e:
        print(f"Error in admin dashboard: {str(e)}")
        return str(e), 500

@app.route('/admin/update_user', methods=['POST'])
def admin_update_user():
    """Update user data - intentionally vulnerable"""
    # Get current user
    current_user = ensure_user_object(get_current_user())
    
    # Check if user is logged in and has admin privileges
    if not current_user or not current_user.is_admin:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
    try:
        data = request.json
        user_id = data.get('id')
        
        # Get user from database
        user = User.query.get(user_id)
        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        # Update user data
        user.username = data.get('username', user.username)
        user.email = data.get('email', user.email)
        user.password = data.get('password', user.password)  # Intentionally not hashing password
        user.full_name = data.get('full_name', user.full_name)
        user.address = data.get('address', user.address)
        user.phone = data.get('phone', user.phone)
        user.credit_card = data.get('credit_card', user.credit_card)
        user.ssn = data.get('ssn', user.ssn)
        user.date_of_birth = data.get('date_of_birth', user.date_of_birth)
        user.is_admin = data.get('is_admin', user.is_admin)  # Update admin status
        
        db.session.commit()
        
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        print(f"Error updating user: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/delete_user/<int:user_id>', methods=['DELETE'])
def admin_delete_user(user_id):
    """Delete user - intentionally vulnerable"""
    # Get current user
    current_user = ensure_user_object(get_current_user())
    
    # Check if user is logged in and has admin privileges
    if not current_user or not current_user.is_admin:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
    try:
        # Get user from database
        user = User.query.get(user_id)
        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        # Delete user
        db.session.delete(user)
        db.session.commit()
        
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting user: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/execute_sql', methods=['POST'])
def admin_execute_sql():
    """Execute SQL query - intentionally vulnerable to SQL injection"""
    # Get current user
    current_user = ensure_user_object(get_current_user())
    
    # Check if user is logged in and has admin privileges
    if not current_user or not current_user.is_admin:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
    try:
        data = request.json
        query = data.get('query', '')
        
        if not query:
            return jsonify({'success': False, 'error': 'No query provided'}), 400
        
        # Execute query directly without any sanitization (intentionally vulnerable)
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute(query)
        
        # Get column names
        column_names = [description[0] for description in cursor.description] if cursor.description else []
        
        # Fetch results
        results = []
        for row in cursor.fetchall():
            result = {}
            for i, column in enumerate(column_names):
                result[column] = row[i]
            results.append(result)
        
        conn.close()
        
        return jsonify({'success': True, 'results': results})
    except Exception as e:
        if 'conn' in locals():
            conn.close()
        print(f"Error executing SQL query: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5001, debug=True)  # Vulnerable: Debug mode enabled 