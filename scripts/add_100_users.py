#!/usr/bin/env python3
import os
import sys
import random
import json
from datetime import datetime, timedelta
from faker import Faker
import string
import traceback

# Add the parent directory to the path so we can import from app
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import the app and database models
from app.app import app, db, User, Message, followers

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

def generate_credit_card():
    """Generate a fake credit card number in the format XXXX-XXXX-XXXX-XXXX"""
    return '-'.join(''.join(random.choices(string.digits, k=4)) for _ in range(4))

def generate_ssn():
    """Generate a fake SSN in the format XXX-XX-XXXX"""
    return f"{random.randint(100, 999)}-{random.randint(10, 99)}-{random.randint(1000, 9999)}"

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
                    
                    # Create user with fake data - ensure it matches the schema of admin user
                    user = User(
                        username=username,
                        password=f"password{i+1}",  # Simple password pattern
                        email=f"{username}@{fake.free_email_domain()}",
                        full_name=f"{first_name} {last_name}",
                        address=fake.address().replace('\n', ', '),
                        phone=fake.phone_number(),
                        credit_card=generate_credit_card(),
                        ssn=generate_ssn(),
                        date_of_birth=fake.date_of_birth(minimum_age=18, maximum_age=80).strftime('%Y-%m-%d'),
                        bio=fake.paragraph(nb_sentences=3),
                        profile_picture='default_avatar.jpg',
                        cover_photo='default_cover.jpg',
                        join_date=datetime.utcnow() - timedelta(days=random.randint(1, 365)),
                        is_private=random.random() < 0.2  # 20% chance of being private
                    )
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
                    message = Message(
                        sender_id=sender.id,
                        recipient_id=recipient.id,
                        content=fake.paragraph(nb_sentences=random.randint(1, 3)),
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
                        'followers_count': user.followers.count(),
                        'following_count': user.followed.count()
                    })
                except Exception as e:
                    print(f"Error exporting user {i}: {str(e)}")
                    print(f"User data: {user}")
                    traceback.print_exc()
            
            # Save to JSON file
            with open('user_directory.json', 'w') as f:
                json.dump(user_data, f, indent=2)
            
            print(f"Exported {len(user_data)} users to user_directory.json")
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
            db.session.add(admin)
            db.session.commit()
            print("Admin user created successfully")
            
            # Add other default users
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
            
            db.session.add_all([user, alice, bob, charlie])
            db.session.commit()
            print("Default users created successfully")
        except Exception as e:
            print(f"Error initializing database: {str(e)}")
            traceback.print_exc()
            db.session.rollback()

# Check if fake_users.json exists and load it
def load_fake_users_json():
    """Load fake users from JSON file if it exists"""
    try:
        json_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fake_users.json')
        if os.path.exists(json_path):
            print(f"Found fake_users.json at {json_path}")
            with open(json_path, 'r') as f:
                users_data = json.load(f)
                print(f"Loaded {len(users_data)} users from fake_users.json")
                return users_data
        else:
            print(f"fake_users.json not found at {json_path}")
            return None
    except Exception as e:
        print(f"Error loading fake_users.json: {str(e)}")
        traceback.print_exc()
        return None

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
    
    # Check if fake_users.json exists and print its contents
    fake_users = load_fake_users_json()
    if fake_users:
        print("Sample user from fake_users.json:")
        print(json.dumps(fake_users[0], indent=2))
    
    # Then create additional fake users
    create_users(num_users)
    
    # Finally export user data to JSON
    export_users_to_json() 