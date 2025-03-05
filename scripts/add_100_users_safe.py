#!/usr/bin/env python3
import os
import sys
import random
import json
from datetime import datetime, timedelta
from faker import Faker
import string
import traceback
from werkzeug.security import generate_password_hash

# Add the parent directory to the path so we can import from app
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import the app and database models from safe_app.py
from app.safe_app import app, db, User, Message, followers

fake = Faker()

def reset_database():
    """Drop all tables and recreate them to start with a clean database"""
    with app.app_context():
        try:
            print("Dropping all tables...")
            db.drop_all()
            print("Creating all tables...")
            db.create_all()
            print("Database reset successfully!")
        except Exception as e:
            print(f"Error resetting database: {str(e)}")
            traceback.print_exc()

def create_users(num_users=100):
    """Create specified number of fake users"""
    print(f"Creating {num_users} fake users...")
    
    # Check if database already has users
    with app.app_context():
        try:
            # Create tables if they don't exist
            db.create_all()
            
            existing_count = User.query.count()
            print(f"Found {existing_count} existing users in the database")
            
            # Generate and add users
            new_users = []
            for i in range(num_users):
                try:
                    # Generate a unique username
                    while True:
                        first_name = fake.first_name()
                        last_name = fake.last_name()
                        username = f"{first_name.lower()}.{last_name.lower()}{random.randint(1, 999)}"
                        if not User.query.filter_by(username=username).first():
                            break
                    
                    # Create user with fake data - ensure it matches the schema of the secure User model
                    user = User(
                        username=username,
                        email=f"{username}@{fake.free_email_domain()}",
                        full_name=f"{first_name} {last_name}",
                        address=fake.address().replace('\n', ', '),
                        phone=fake.phone_number(),
                        date_of_birth=fake.date_of_birth(minimum_age=18, maximum_age=80).strftime('%Y-%m-%d'),
                        bio=fake.paragraph(nb_sentences=3),
                        profile_picture='default_avatar.jpg',
                        cover_photo='default_cover.jpg',
                        join_date=datetime.utcnow() - timedelta(days=random.randint(1, 365)),
                        is_private=random.random() < 0.2,  # 20% chance of being private
                        is_admin=False  # Explicitly set to False
                    )
                    # Set password securely using the set_password method
                    user.set_password(f"password{i+1}")
                    
                    new_users.append(user)
                    
                    # Add in batches to avoid memory issues
                    if len(new_users) >= 10 or i == num_users - 1:
                        db.session.add_all(new_users)
                        db.session.commit()
                        print(f"Added users {i-len(new_users)+1} to {i+1}")
                        new_users = []
                except Exception as e:
                    print(f"Error creating user {i}: {str(e)}")
                    traceback.print_exc()
                    db.session.rollback()
            
            # Create follow relationships
            print("Creating follow relationships...")
            try:
                all_users = User.query.all()
                print(f"Found {len(all_users)} users for creating follow relationships")
                
                for user in all_users:
                    # Each user follows 5-15 random users
                    follow_count = random.randint(5, min(15, len(all_users)-1))
                    potential_follows = [u for u in all_users if u != user and not user.is_following(u)]
                    
                    if potential_follows:
                        follows = random.sample(potential_follows, min(follow_count, len(potential_follows)))
                        for follow in follows:
                            user.follow(follow)
                
                db.session.commit()
                print("Follow relationships created successfully")
            except Exception as e:
                print(f"Error creating follow relationships: {str(e)}")
                traceback.print_exc()
                db.session.rollback()
            
            # Create some messages between users
            print("Creating messages between users...")
            messages_created = 0
            
            try:
                all_users = User.query.all()
                print(f"Found {len(all_users)} users for creating messages")
                
                for _ in range(300):  # Create 300 random messages
                    sender = random.choice(all_users)
                    recipient = random.choice([u for u in all_users if u != sender])
                    
                    # Create a message with random content
                    content = fake.paragraph(nb_sentences=random.randint(1, 3))
                    # Sanitize content using the Message class method
                    sanitized_content = Message.sanitize_content(content)
                    
                    message = Message(
                        sender_id=sender.id,
                        recipient_id=recipient.id,
                        content=sanitized_content,
                        timestamp=datetime.utcnow() - timedelta(days=random.randint(0, 30), 
                                                              hours=random.randint(0, 23),
                                                              minutes=random.randint(0, 59)),
                        is_read=random.random() < 0.7  # 70% chance of being read
                    )
                    db.session.add(message)
                    messages_created += 1
                    
                    # Commit in batches
                    if messages_created % 50 == 0:
                        db.session.commit()
                        print(f"Added {messages_created} messages")
                
                db.session.commit()
                print("Messages created successfully")
            except Exception as e:
                print(f"Error creating messages: {str(e)}")
                traceback.print_exc()
                db.session.rollback()
            
            # Print summary
            final_user_count = User.query.count()
            message_count = Message.query.count()
            print(f"\nDatabase now has {final_user_count} users and {message_count} messages")
            print("Script completed successfully!")
            
        except Exception as e:
            print(f"Error creating users: {str(e)}")
            traceback.print_exc()
            db.session.rollback()

def export_users_to_json():
    """Export all users to a JSON file for reference"""
    with app.app_context():
        try:
            users = User.query.all()
            user_data = []
            
            print(f"Exporting {len(users)} users to JSON")
            
            for i, user in enumerate(users):
                try:
                    # Print the type of user to debug
                    print(f"User {i} type: {type(user)}")
                    
                    user_data.append({
                        'id': user.id,
                        'username': user.username,
                        'email': user.email,
                        'full_name': user.full_name,
                        'join_date': user.join_date.strftime('%Y-%m-%d %H:%M:%S'),
                        'is_private': user.is_private,
                        'followers_count': len(user.followers.all()),
                        'following_count': len(user.followed.all())
                    })
                except Exception as e:
                    print(f"Error exporting user {i}: {str(e)}")
                    print(f"User data: {user}")
                    traceback.print_exc()
            
            # Save to JSON file
            with open('user_directory_safe.json', 'w') as f:
                json.dump(user_data, f, indent=2)
            
            print(f"Exported {len(user_data)} users to user_directory_safe.json")
        except Exception as e:
            print(f"Error exporting users to JSON: {str(e)}")
            traceback.print_exc()

def initialize_database():
    """Initialize the database with default admin user if it doesn't exist"""
    with app.app_context():
        try:
            # Create tables if they don't exist
            db.create_all()
            
            # Create admin user (always create it since we reset the database)
            print("Creating default admin user...")
            admin = User(
                username='admin',
                email='admin@example.com',
                full_name='Admin User',
                address='123 Admin St',
                phone='555-1234',
                date_of_birth='1990-01-01',
                bio='Admin user',
                profile_picture='default_avatar.jpg',
                cover_photo='default_cover.jpg',
                join_date=datetime.utcnow(),
                is_private=False,
                is_admin=True  # Set admin flag to True
            )
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            print("Admin user created successfully")
            
            # Add other default users
            user = User(
                username='user',
                email='user@example.com',
                full_name='Regular User',
                address='456 User St',
                phone='555-5678',
                date_of_birth='1995-05-05',
                bio='Regular user',
                profile_picture='default_avatar.jpg',
                cover_photo='default_cover.jpg',
                join_date=datetime.utcnow(),
                is_private=False,
                is_admin=False  # Explicitly set to False
            )
            user.set_password('user123')
            
            alice = User(
                username='alice',
                email='alice@example.com',
                full_name='Alice Johnson',
                address='789 Alice Ave',
                phone='555-9012',
                date_of_birth='1992-03-15',
                bio='Hello, I am Alice!',
                profile_picture='default_avatar.jpg',
                cover_photo='default_cover.jpg',
                join_date=datetime.utcnow(),
                is_private=False,
                is_admin=False  # Explicitly set to False
            )
            alice.set_password('alice123')
            
            bob = User(
                username='bob',
                email='bob@example.com',
                full_name='Bob Smith',
                address='101 Bob Blvd',
                phone='555-3456',
                date_of_birth='1988-07-22',
                bio='Hello, I am Bob!',
                profile_picture='default_avatar.jpg',
                cover_photo='default_cover.jpg',
                join_date=datetime.utcnow(),
                is_private=False,
                is_admin=False  # Explicitly set to False
            )
            bob.set_password('bob123')
            
            charlie = User(
                username='charlie',
                email='charlie@example.com',
                full_name='Charlie Brown',
                address='202 Charlie Ct',
                phone='555-7890',
                date_of_birth='1985-11-30',
                bio='Hello, I am Charlie!',
                profile_picture='default_avatar.jpg',
                cover_photo='default_cover.jpg',
                join_date=datetime.utcnow(),
                is_private=False,
                is_admin=False  # Explicitly set to False
            )
            charlie.set_password('charlie123')
            
            db.session.add_all([user, alice, bob, charlie])
            db.session.commit()
            print("Default users created successfully")
        except Exception as e:
            print(f"Error initializing database: {str(e)}")
            traceback.print_exc()
            db.session.rollback()

if __name__ == "__main__":
    # Get number of users from command line argument, default to 100
    num_users = 100
    if len(sys.argv) > 1:
        try:
            num_users = int(sys.argv[1])
        except ValueError:
            print(f"Invalid number of users: {sys.argv[1]}. Using default: 100")
    
    # First reset the database completely
    reset_database()
    
    # Then initialize the database with default users
    initialize_database()
    
    # Then create additional fake users
    create_users(num_users)
    
    # Finally export user data to JSON
    export_users_to_json() 