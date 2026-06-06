# 🚨 Threat Alert API

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green.svg)](https://fastapi.tiangolo.com/)
[![JWT](https://img.shields.io/badge/JWT-Authentication-orange.svg)](https://jwt.io/)
[![SQLite](https://img.shields.io/badge/SQLite-Database-lightgrey.svg)](https://www.sqlite.org/)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://www.docker.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## 📋 Overview

A **production-ready REST API** for managing cybersecurity threat alerts with secure JWT authentication. Built with FastAPI for high performance and automatic API documentation.

### Key Features

| Feature | Description |
|---------|-------------|
| **🔐 JWT Authentication** | Secure user registration and login |
| **📊 Alert Management** | Create, retrieve, and delete threat alerts |
| **📈 Statistics Endpoint** | Analyze alert patterns and trends |
| **🗄️ SQLite Database** | Easy to swap with PostgreSQL for production |
| **📚 Auto-generated Docs** | Interactive Swagger UI at `/docs` |

## 🏗️ Architecture
User Request
↓
FastAPI Backend
↓
┌───────┼───────┐
↓ ↓ ↓
JWT Alert Stats
Auth CRUD Analysis
↓
SQLite Database

text

## 🛠️ Tech Stack

| Component | Technology |
|-----------|------------|
| **Framework** | FastAPI |
| **Authentication** | JWT (python-jose) |
| **Password Hashing** | pbkdf2_sha256 (passlib) |
| **ORM** | SQLAlchemy |
| **Database** | SQLite (PostgreSQL ready) |
| **Container** | Docker |

## 🔌 API Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `POST` | `/register` | Create new user account | ❌ No |
| `POST` | `/token` | Login → receive JWT token | ❌ No |
| `POST` | `/alerts` | Create new threat alert | ✅ Yes |
| `GET` | `/alerts` | Get all alerts for user | ✅ Yes |
| `GET` | `/alerts/{id}` | Get single alert by ID | ✅ Yes |
| `DELETE` | `/alerts/{id}` | Delete specific alert | ✅ Yes |
| `GET` | `/stats` | Get alert statistics | ✅ Yes |

## 📦 Installation

### Local Development

```bash
# Clone repository
git clone https://github.com/Aikaksh-Singh-Routela/threat-alert-api.git
cd threat-alert-api

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
.\venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Run the server
uvicorn main:app --reload
Docker
bash
# Build image
docker build -t threat-alert-api .

# Run container
docker run -d -p 8000:8000 threat-alert-api
🔧 Usage Examples
Register a New User
bash
curl -X POST http://localhost:8000/register \
  -H "Content-Type: application/json" \
  -d '{"username": "analyst", "password": "securepass"}'
Login and Get JWT Token
bash
curl -X POST http://localhost:8000/token \
  -H "Content-Type: application/json" \
  -d '{"username": "analyst", "password": "securepass"}'
Create a New Alert
bash
curl -X POST http://localhost:8000/alerts \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"title": "Suspicious Login", "severity": "high", "description": "Multiple failed attempts from unknown IP"}'
Get All Alerts
bash
curl -X GET http://localhost:8000/alerts \
  -H "Authorization: Bearer YOUR_TOKEN"
📊 Sample Response
json
{
  "alerts": [
    {
      "id": 1,
      "title": "Suspicious Login",
      "severity": "high",
      "description": "Multiple failed attempts from unknown IP",
      "created_at": "2024-01-15T10:30:00"
    }
  ]
}
📁 Project Structure
text
threat-alert-api/
├── main.py              # FastAPI application
├── database.py          # SQLAlchemy setup
├── models.py            # Pydantic models
├── auth.py              # JWT authentication
├── requirements.txt     # Python dependencies
├── Dockerfile           # Container configuration
└── README.md            # Documentation
🚀 Deployment
Deploy to Render (Free)
Push code to GitHub

Connect repository to Render

Set environment variables

Deploy

Environment Variables
Variable	Description
SECRET_KEY	JWT signing key (required)
DATABASE_URL	Database connection string
📚 Interactive API Documentation
Once running, visit:

Swagger UI: http://localhost:8000/docs

ReDoc: http://localhost:8000/redoc

🔗 Links
GitHub: threat-alert-api

📄 License
MIT License

Built with 🚨, ⚡, and 🐍 by Aikaksh Singh Routela
