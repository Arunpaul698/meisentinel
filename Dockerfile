# Use an official lightweight Python image
FROM python:3.11-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8080

# Install system dependencies (including osslsigncode, git, nodejs, and npm for background Ruflo agent runs)
RUN apt-get update && apt-get install -y --no-install-recommends \
    osslsigncode \
    ca-certificates \
    git \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all application code and static assets
COPY . .

# Expose port (Cloud Run sets PORT env variable dynamically, default to 8080)
EXPOSE 8080

# Run FastAPI app using uvicorn
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT}"]
