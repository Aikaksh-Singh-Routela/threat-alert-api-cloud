import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from auth import get_password_hash, verify_password, create_access_token
from jose import jwt
from datetime import timedelta

SECRET_KEY = "your-secret-key-change-this"
ALGORITHM = "HS256"


def test_password_hashing():
    """Test that password hashing works correctly"""
    password = "test123"
    hashed = get_password_hash(password)

    # Hash should be different from original
    assert hashed != password
    # Verify should pass
    assert verify_password(password, hashed) == True
    # Wrong password should fail
    assert verify_password("wrong", hashed) == False


def test_password_truncation():
    """Test that passwords longer than 72 chars are truncated"""
    long_password = "a" * 100
    hashed = get_password_hash(long_password)

    # Should still hash without error
    assert hashed is not None
    # Should verify with the truncated version
    assert verify_password(long_password, hashed) == True


def test_create_access_token():
    """Test JWT token creation and decoding"""
    data = {"sub": "testuser"}
    token = create_access_token(data)

    # Token should be a string
    assert isinstance(token, str)
    assert len(token) > 0

    # Decode and verify
    decoded = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    assert decoded["sub"] == "testuser"
    assert "exp" in decoded


def test_token_expiration():
    """Test that token has expiration time"""
    data = {"sub": "testuser"}
    token = create_access_token(data, expires_delta=timedelta(minutes=1))

    decoded = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    assert "exp" in decoded