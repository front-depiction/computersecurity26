#!/usr/bin/env python3
from faker import Faker
import json
import random
from datetime import datetime

fake = Faker()

def generate_credit_card():
    """Generate a fake credit card number in XXXX-XXXX-XXXX-XXXX format"""
    return f"4532-{random.randint(1000,9999)}-{random.randint(1000,9999)}-{random.randint(1000,9999)}"

def generate_ssn():
    """Generate a fake SSN in XXX-XX-XXXX format"""
    return f"{random.randint(100,999)}-{random.randint(10,99)}-{random.randint(1000,9999)}"

def generate_fake_users(num_users=100):
    """Generate fake user data"""
    users = []
    
    # Add our known test users first
    test_users = [
        {
            'username': 'admin',
            'password': 'admin123',
            'email': 'admin@company.com',
            'full_name': 'Admin User',
            'address': '123 Admin St, Tech City, TC 12345',
            'phone': '555-0123',
            'credit_card': '4532-1234-5678-9012',
            'ssn': '123-45-6789',
            'date_of_birth': '1980-01-01'
        },
        {
            'username': 'john.doe',
            'password': 'password123',
            'email': 'john.doe@email.com',
            'full_name': 'John Doe',
            'address': '456 Oak Lane, Springfield, SP 67890',
            'phone': '555-4567',
            'credit_card': '4532-9876-5432-1098',
            'ssn': '987-65-4321',
            'date_of_birth': '1992-03-15'
        },
        {
            'username': 'jane.smith',
            'password': 'letmein123',
            'email': 'jane.smith@email.com',
            'full_name': 'Jane Smith',
            'address': '789 Maple Ave, Riverside, RS 34567',
            'phone': '555-7890',
            'credit_card': '4532-5678-1234-5678',
            'ssn': '456-78-9012',
            'date_of_birth': '1988-07-22'
        }
    ]
    
    users.extend(test_users)
    
    # Generate random users
    for i in range(num_users - len(test_users)):
        # Generate a realistic full name
        first_name = fake.first_name()
        last_name = fake.last_name()
        
        # Create username from name (e.g., john.doe)
        username = f"{first_name.lower()}.{last_name.lower()}"
        
        # Generate date of birth (between 18 and 80 years old)
        dob = fake.date_of_birth(minimum_age=18, maximum_age=80)
        
        user = {
            'username': username,
            'password': fake.password(length=random.randint(8, 16)),
            'email': f"{username}@{fake.free_email_domain()}",
            'full_name': f"{first_name} {last_name}",
            'address': fake.address().replace('\n', ', '),
            'phone': fake.phone_number(),
            'credit_card': generate_credit_card(),
            'ssn': generate_ssn(),
            'date_of_birth': dob.strftime('%Y-%m-%d')
        }
        users.append(user)
    
    return users

def main():
    users = generate_fake_users()
    
    # Save to JSON file
    with open('fake_users.json', 'w') as f:
        json.dump(users, f, indent=2)
    
    print(f"Generated {len(users)} fake users")
    print("Sample user data:")
    print(json.dumps(users[3], indent=2))  # Print a random generated user

if __name__ == "__main__":
    main() 