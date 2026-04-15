FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY app.py fraud_engine.py train_model.py ./
COPY templates/ templates/
COPY static/ static/

# Pre-trained models (optional — mount volume or run train_model.py)
COPY models/ models/

# Persistent data directory
RUN mkdir -p data

EXPOSE 8000

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
