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
                    is_private=False
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
                    is_private=False
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
                    is_private=False
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
                    is_private=False
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
                    is_private=False
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
                                is_private=False
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
                            is_private=False
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
                            is_private=False
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
    return 'username' in session

# Helper function to get current user
def get_current_user():
    if not is_logged_in():
        return None
    return User.query.filter_by(username=session['username']).first()

@app.route('/')
def index():
    # Render the index template instead of redirecting
    current_user = get_current_user()
    return render_template('index.html', current_user=current_user)

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
                resp = make_response(redirect('/messages'))  # Redirect to messages instead of feed
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

@app.route('/logout')
def logout():
    session.pop('username', None)
    resp = make_response(redirect('/'))
    resp.set_cookie('is_admin', '', expires=0)
    resp.set_cookie('current_user', '', expires=0)
    return resp

@app.route('/register', methods=['GET', 'POST'])
def register():
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
    if not is_logged_in():
        return redirect('/login')
    
    current_user = get_current_user()
    if not current_user:
        return redirect('/logout')
    
    # Get posts from users that the current user follows
    followed_posts = current_user.followed_posts()
    
    # Also get the current user's posts
    own_posts = Post.query.filter_by(user_id=current_user.id).order_by(Post.timestamp.desc())
    
    # Combine and sort by timestamp
    all_posts = followed_posts.union(own_posts).order_by(Post.timestamp.desc())
    
    return render_template('feed.html', 
                          posts=all_posts, 
                          current_user=current_user)

@app.route('/explore')
def explore():
    if not is_logged_in():
        return redirect('/login')
    
    current_user = get_current_user()
    if not current_user:
        return redirect('/logout')
    
    # Get all public posts, ordered by timestamp
    # Vulnerable: Shows private posts too due to lack of filtering
    posts = Post.query.order_by(Post.timestamp.desc()).limit(50)
    
    return render_template('explore.html', 
                          posts=posts, 
                          current_user=current_user)

@app.route('/profile')
def profile():
    current_user = get_current_user()
    if not current_user:
        return redirect('/login')
    return render_template('profile.html', current_user=current_user)

@app.route('/profile/<username>')
def view_profile(username):
    current_user = get_current_user()
    if not current_user:
        return redirect('/login')
    
    # Get the profile user - VULNERABLE: No access control
    profile_user = User.query.filter_by(username=username).first_or_404()
    
    # VULNERABLE: We're passing the entire user object with sensitive information
    # to the template without any filtering
    return render_template('profile.html', current_user=profile_user)

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
    current_user = get_current_user()
    if not current_user:
        # If user is not logged in, still render the messages template
        # The template will handle showing a login prompt
        return render_template('messages.html', current_user=None, conversations=[], active_user=None, messages=[])
    
    # Get all conversations for the current user
    conversations = db.session.query(User, Message) \
        .join(Message, ((Message.sender_id == User.id) & (Message.recipient_id == current_user.id)) | 
                      ((Message.recipient_id == User.id) & (Message.sender_id == current_user.id))) \
        .filter(User.id != current_user.id) \
        .group_by(User.id) \
        .order_by(Message.timestamp.desc()) \
        .all()
    
    # Format conversations for display
    formatted_conversations = []
    for user, last_message in conversations:
        formatted_conversations.append({
            'user': user,
            'last_message': last_message.content[:50] + '...' if len(last_message.content) > 50 else last_message.content,
            'last_message_time': last_message.timestamp.strftime('%H:%M'),
            'last_message_is_mine': last_message.sender_id == current_user.id,
            'unread': not last_message.is_read and last_message.recipient_id == current_user.id
        })
    
    return render_template('messages.html', current_user=current_user, 
                          conversations=formatted_conversations, active_user=None, messages=[])

@app.route('/messages/<username>', methods=['GET', 'POST'])
def conversation(username):
    current_user = get_current_user()
    if not current_user:
        # If user is not logged in, redirect to login page
        return redirect('/login')
    
    # Get the other user
    other_user = User.query.filter_by(username=username).first_or_404()
    
    if request.method == 'POST':
        content = request.form.get('content')
        if content:
            # Create a new message
            new_message = Message(
                sender_id=current_user.id,
                recipient_id=other_user.id,
                content=content
            )
            db.session.add(new_message)
            
            # Create a notification for the recipient
            notification = Notification(
                user_id=other_user.id,
                content=f"{current_user.username} sent you a message",
                notification_type="message",
                related_id=new_message.id
            )
            db.session.add(notification)
            
            db.session.commit()
            
            # In a real app, we might use AJAX or WebSockets here
            # For simplicity, we'll just redirect back to the conversation
            return redirect(f'/messages/{username}')
    
    # Get all messages between the current user and the other user
    messages_query = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.recipient_id == other_user.id)) |
        ((Message.sender_id == other_user.id) & (Message.recipient_id == current_user.id))
    ).order_by(Message.timestamp.asc())
    
    messages = []
    for msg in messages_query:
        messages.append({
            'content': msg.content,
            'time': msg.timestamp.strftime('%H:%M'),
            'is_mine': msg.sender_id == current_user.id,
            'read': msg.is_read
        })
    
    # Mark unread messages as read
    unread_messages = Message.query.filter_by(
        sender_id=other_user.id,
        recipient_id=current_user.id,
        is_read=False
    ).all()
    
    for msg in unread_messages:
        msg.is_read = True
    
    db.session.commit()
    
    # Get all conversations for the sidebar
    conversations = db.session.query(User, Message) \
        .join(Message, ((Message.sender_id == User.id) & (Message.recipient_id == current_user.id)) | 
                      ((Message.recipient_id == User.id) & (Message.sender_id == current_user.id))) \
        .filter(User.id != current_user.id) \
        .group_by(User.id) \
        .order_by(Message.timestamp.desc()) \
        .all()
    
    # Format conversations for display
    formatted_conversations = []
    for user, last_message in conversations:
        formatted_conversations.append({
            'user': user,
            'last_message': last_message.content[:50] + '...' if len(last_message.content) > 50 else last_message.content,
            'last_message_time': last_message.timestamp.strftime('%H:%M'),
            'last_message_is_mine': last_message.sender_id == current_user.id,
            'unread': not last_message.is_read and last_message.recipient_id == current_user.id
        })
    
    return render_template('messages.html', 
                          current_user=current_user,
                          conversations=formatted_conversations,
                          active_user=other_user,
                          messages=messages)

@app.route('/notifications')
def notifications():
    if not is_logged_in():
        return redirect('/login')
    
    current_user = get_current_user()
    if not current_user:
        return redirect('/logout')
    
    # Get all notifications for current user
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.timestamp.desc())
    
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
    query = request.args.get('q', '')
    
    try:
        # Use direct SQLite3 connection
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Vulnerable: Direct string formatting in SQL query
        sql = f"SELECT * FROM user WHERE username LIKE '%{query}%' OR full_name LIKE '%{query}%' OR email LIKE '%{query}%'"
        cursor.execute(sql)
        
        # Get column names
        columns = [description[0] for description in cursor.description]
        
        # Fetch all results
        results = cursor.fetchall()
        
        # Convert to list of dicts
        users = []
        for row in results:
            user_dict = {columns[i]: row[i] for i in range(len(columns))}
            users.append(user_dict)
        
        return jsonify(users)
    except Exception as e:
        return jsonify({"error": str(e)})
    finally:
        cursor.close()
        conn.close()

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect('/login')
    
    # Vulnerable: XSS possible here
    username = session['username']
    is_admin = request.cookies.get('is_admin', 'false')
    return render_template('dashboard.html', username=username, is_admin=is_admin)

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
    current_user = get_current_user()
    if not current_user:
        return redirect('/login')
    
    if request.method == 'POST':
        # Vulnerable: Direct use of user input without validation
        username = request.form.get('username')
        
        # Vulnerable: SQL Injection possible
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Vulnerable: Direct string formatting in SQL query
        query = f"SELECT * FROM user WHERE username='{username}'"
        cursor.execute(query)
        result = cursor.fetchone()
        
        if result:
            # User found, redirect to conversation
            return redirect(f'/messages/{username}')
        else:
            # User not found
            return "User not found", 404
    
    # Get all users except current user for the dropdown
    users = User.query.filter(User.id != current_user.id).all()
    return render_template('new_chat.html', current_user=current_user, users=users)

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
                    'email': user.email if hasattr(user, 'email') else 'N/A'
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
        # Get the user from the database
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Use parameterized query for safety
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        user_row = cursor.fetchone()
        
        if not user_row:
            return jsonify({'error': f'User {username} not found'}), 404
        
        # Convert row to dict for display
        user_dict = dict(user_row)
        
        # Get the same user using SQLAlchemy
        sqlalchemy_user = User.query.filter_by(username=username).first()
        
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
        return jsonify({
            'error': str(e),
            'traceback': traceback.format_exc()
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

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5001, debug=True)  # Vulnerable: Debug mode enabled 