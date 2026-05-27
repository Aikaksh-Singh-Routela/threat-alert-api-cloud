from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from datetime import timedelta
from fastapi.security import OAuth2PasswordRequestForm
import joblib
from database import engine, get_db
import models
import schemas
import auth

# Create tables
models.Base.metadata.create_all(bind=engine)

# Load ML model
try:
    clf = joblib.load('threat_detector.pkl')
    vectorizer = joblib.load('tfidf_vectorizer.pkl')
    model_loaded = True
except:
    model_loaded = False
    print("ML model not loaded - prediction endpoints will be disabled")

# ==================== CREATE APP FIRST ====================
app = FastAPI(title="Threat Alert API", version="1.0.0")

# ==================== THEN ADD CORS ====================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==================== AUTH ENDPOINTS ====================
@app.post("/api/register", response_model=schemas.UserOut)
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    """Register a new user"""
    db_user = db.query(models.User).filter(models.User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = auth.get_password_hash(user.password)
    db_user = models.User(
        email=user.email,
        username=user.username,
        hashed_password=hashed_password
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.post("/api/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """Login to get access token"""
    user = db.query(models.User).filter(models.User.username == form_data.username).first()
    if not user or not auth.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth.create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/api/users/me", response_model=schemas.UserOut)
def read_users_me(current_user: models.User = Depends(auth.get_current_user)):
    """Get current user info"""
    return current_user

# ==================== THREAT DETECTION ENDPOINTS ====================
@app.post("/api/predict")
def predict_threat(text: str, current_user: models.User = Depends(auth.get_current_user)):
    """Predict if text contains a threat"""
    if not model_loaded:
        raise HTTPException(status_code=503, detail="ML model not available")
    
    text_vectorized = vectorizer.transform([text])
    prediction = clf.predict(text_vectorized)[0]
    probability = clf.predict_proba(text_vectorized)[0].tolist()
    
    return {
        "text": text,
        "is_threat": bool(prediction),
        "probability": probability,
        "prediction": "THREAT DETECTED" if prediction else "SAFE"
    }

@app.post("/api/alerts")
def create_alert(
    alert: schemas.AlertCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user)
):
    """Create a new threat alert"""
    db_alert = models.Alert(
        title=alert.title,
        description=alert.description,
        severity=alert.severity,
        user_id=current_user.id
    )
    db.add(db_alert)
    db.commit()
    db.refresh(db_alert)
    return db_alert

@app.get("/api/alerts")
def get_alerts(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user)
):
    """Get all alerts for current user"""
    alerts = db.query(models.Alert).filter(
        models.Alert.user_id == current_user.id
    ).offset(skip).limit(limit).all()
    return alerts

@app.get("/api/alerts/{alert_id}")
def get_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user)
):
    """Get a specific alert"""
    alert = db.query(models.Alert).filter(
        models.Alert.id == alert_id,
        models.Alert.user_id == current_user.id
    ).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert

@app.delete("/api/alerts/{alert_id}")
def delete_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user)
):
    """Delete an alert"""
    alert = db.query(models.Alert).filter(
        models.Alert.id == alert_id,
        models.Alert.user_id == current_user.id
    ).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    db.delete(alert)
    db.commit()
    return {"message": "Alert deleted successfully"}

@app.get("/api/health")
def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "model_loaded": model_loaded,
        "version": "1.0.0"
    }

# ==================== RUN APP ====================
if __name__ == "__main__":
    import uvicorn
    import os
    port = int(os.environ.get("PORT", 8000))
    print("🚀 Threat Alert API Starting...")
    print(f"Documentation: http://localhost:{port}/docs")
    uvicorn.run(app, host="0.0.0.0", port=port)