FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Installation des dépendances système
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copie requirements et installation
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copie du projet
COPY . .

# Collectstatic (pour la prod)
RUN python manage.py collectstatic --noinput

EXPOSE 8000

# Lance avec Gunicorn (adapte le nom de ton projet !)
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "Unified_tool.wsgi:application"]
