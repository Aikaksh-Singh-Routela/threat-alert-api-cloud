# Threat Alert API

A REST API for managing cybersecurity threat alerts with JWT authentication.

## Features

- User registration and authentication (JWT tokens)
- Create, retrieve, and delete threat alerts
- Statistics endpoint for alert analysis
- SQLite database (easy to swap with PostgreSQL)

## Technologies

- FastAPI (Python web framework)
- SQLAlchemy (ORM)
- JWT (JSON Web Tokens for authentication)
- pbkdf2_sha256 (password hashing)
- SQLite (database)

## API Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/register` | Create new user | No |
| POST | `/token` | Login → get JWT token | No |
| POST | `/alerts` | Create threat alert | Yes |
| GET | `/alerts` | Get all alerts | Yes |
| GET | `/alerts/{id}` | Get single alert | Yes |
| DELETE | `/alerts/{id}` | Delete alert | Yes |
| GET | `/stats` | Get alert statistics | Yes |
| GET | `/health` | Health check | No |

## Run Locally

```bash
pip install -r requirements.txt
python main.py