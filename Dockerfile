FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create instance directory for SQLite database
RUN mkdir -p instance && chmod 777 instance

# Make our script executable and run it to add 100 users to the database
RUN chmod +x scripts/add_100_users.py
RUN python scripts/add_100_users.py

EXPOSE 5001

CMD ["python", "app/app.py"] 