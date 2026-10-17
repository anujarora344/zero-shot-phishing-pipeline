# Use a lightweight Python base image
FROM python:3.11-slim

# Set the working directory inside the container
WORKDIR /app

# Copy dependencies and install them
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Expose the port Uvicorn runs on++
EXPOSE 8000

# Command to run the API server
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]