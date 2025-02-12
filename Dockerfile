FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install Faker  # Add Faker library

COPY . .

# Create scripts directory if it doesn't exist
RUN mkdir -p scripts

# Create instance directory for SQLite database
RUN mkdir -p instance && chmod 777 instance

# Generate fake users and initialize database
RUN python scripts/generate_fake_users.py

EXPOSE 5001

CMD ["python", "app/app.py"] 