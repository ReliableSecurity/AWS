
# Docker Support
# Dockerfile configuration
FROM python:3.8-slim

# Set working directory
WORKDIR /app

# Copy all files
COPY . .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Run the application
CMD ['python', 'akuma_advanced_scanner.py']

