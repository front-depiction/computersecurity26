FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create instance directory for SQLite database
RUN mkdir -p instance && chmod 777 instance

EXPOSE 5001

CMD ["python", "app/app.py"] 