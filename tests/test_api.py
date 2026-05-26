import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def test_health_endpoint():
    """Test health check endpoint"""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "database" in data
    assert "ml_model" in data


def test_register_user():
    """Test user registration"""
    response = client.post("/register", json={
        "username": "testuser_pytest",
        "password": "testpass123"
    })
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "testuser_pytest"
    assert "id" in data
    assert data["is_active"] == True


def test_register_duplicate_user():
    """Test duplicate registration fails"""
    # First registration
    client.post("/register", json={
        "username": "duplicate_user",
        "password": "testpass123"
    })
    # Second registration should fail
    response = client.post("/register", json={
        "username": "duplicate_user",
        "password": "testpass123"
    })
    assert response.status_code == 400
    assert "Username already registered" in response.text


def test_login_success():
    """Test successful login"""
    # Register first
    client.post("/register", json={
        "username": "login_user",
        "password": "loginpass"
    })
    # Login
    response = client.post("/token", data={
        "username": "login_user",
        "password": "loginpass"
    })
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


def test_login_failure():
    """Test login with wrong password"""
    response = client.post("/token", data={
        "username": "nonexistent",
        "password": "wrong"
    })
    assert response.status_code == 401
    assert "Incorrect username or password" in response.text


def test_protected_endpoint_without_token():
    """Test accessing protected endpoint without token"""
    response = client.get("/alerts")
    assert response.status_code == 401
    assert "Not authenticated" in response.text


def test_protected_endpoint_with_token():
    """Test accessing protected endpoint with valid token"""
    # Register and login
    client.post("/register", json={
        "username": "alert_user",
        "password": "alertpass"
    })
    login_response = client.post("/token", data={
        "username": "alert_user",
        "password": "alertpass"
    })
    token = login_response.json()["access_token"]

    # Access protected endpoint
    response = client.get("/alerts", headers={
        "Authorization": f"Bearer {token}"
    })
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_create_alert():
    """Test creating an alert"""
    # Register and login
    client.post("/register", json={
        "username": "create_alert_user",
        "password": "alertpass"
    })
    login_response = client.post("/token", data={
        "username": "create_alert_user",
        "password": "alertpass"
    })
    token = login_response.json()["access_token"]

    # Create alert
    alert_data = {
        "source_ip": "192.168.1.100",
        "dest_ip": "185.142.53.35",
        "port": 3389,
        "protocol": "TCP",
        "threat_type": "Ransomware",
        "is_suspicious": True,
        "confidence": 0.98,
        "raw_log": "Test alert from pytest"
    }
    response = client.post("/alerts", json=alert_data, headers={
        "Authorization": f"Bearer {token}"
    })
    assert response.status_code == 200
    data = response.json()
    assert data["source_ip"] == alert_data["source_ip"]
    assert data["threat_type"] == "Ransomware"
    assert "id" in data


def test_stats_endpoint():
    """Test stats endpoint"""
    # Register and login
    client.post("/register", json={
        "username": "stats_user",
        "password": "statspass"
    })
    login_response = client.post("/token", data={
        "username": "stats_user",
        "password": "statspass"
    })
    token = login_response.json()["access_token"]

    response = client.get("/stats", headers={
        "Authorization": f"Bearer {token}"
    })
    assert response.status_code == 200
    data = response.json()
    assert "total_alerts" in data
    assert "suspicious" in data
    assert "normal" in data
    assert "suspicious_percentage" in data