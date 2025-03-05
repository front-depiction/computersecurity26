# Computer Security Project

This repository contains a vulnerable web application and its secure version for educational purposes.

## Project Structure

```
.
├── app/                    # Application code
│   └── app.py              # Vulnerable application
├── config/                 # Configuration files
│   ├── requirements.txt    # Dependencies for vulnerable app
│   └── requirements_safe.txt # Dependencies for secure app
├── docs/                   # Documentation
│   ├── ARCHITECTURE.md     # Application architecture
│   ├── EXPLOITATION_GUIDE.md # Guide for exploiting vulnerabilities
│   ├── README.md           # Detailed project documentation
│   ├── SNIPPETS.md         # Code snippets
│   ├── TODO.md             # Project todos
│   └── VULNERABILITIES.md  # List of vulnerabilities and fixes
├── docker/                 # Docker configuration
│   ├── Dockerfile          # Docker for vulnerable app
│   └── Dockerfile_safe     # Docker for secure app
├── instance/               # Database files
├── requirements.txt        # Symlink to config/requirements.txt
├── safe_app.py             # Secure version of the application
├── scripts/                # Utility scripts
│   ├── add_100_users.py    # Script to add test users
│   ├── generate_fake_users.py # Script to generate fake user data
│   └── user_directory.json # Sample user data
├── static/                 # Static files
│   └── uploads/            # User uploads directory
├── templates/              # HTML templates
└── tests/                  # Test files
    └── test_simplechat_vulnerabilities.py # Test for vulnerabilities
```

## Getting Started

1. Clone this repository
2. Install dependencies: `pip install -r config/requirements.txt`
3. Run the vulnerable application: `python app/app.py`
4. Run the secure application: `python safe_app.py`

## Docker

To run the application using Docker:

```bash
# For the vulnerable version
docker build -t vulnerable-app -f docker/Dockerfile .
docker run -p 5001:5001 vulnerable-app

# For the secure version
docker build -t secure-app -f docker/Dockerfile_safe .
docker run -p 5001:5001 secure-app
```

## Documentation

For detailed documentation, please refer to the files in the `docs/` directory.
