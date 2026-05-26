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
    print("⚠️ ML model not loaded - prediction endpoints will be disabled")

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

# ==================== AUTHENTICATION ENDPOINTS ====================

@app.post("/register", response_model=schemas.UserResponse)
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    existing = db.query(models.User).filter(models.User.username == user.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed = auth.get_password_hash(user.password)
    db_user = models.User(username=user.username, hashed_password=hashed)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.post("/token", response_model=schemas.Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = auth.authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token = auth.create_access_token(
        data={"sub": user.username},
        expires_delta=timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": access_token, "token_type": "bearer"}

# ==================== THREAT ALERTS ENDPOINTS ====================

@app.post("/alerts", response_model=schemas.ThreatAlertResponse)
def create_alert(alert: schemas.ThreatAlertCreate, db: Session = Depends(get_db), current_user=Depends(auth.get_current_user)):
    db_alert = models.ThreatAlert(**alert.dict())
    db.add(db_alert)
    db.commit()
    db.refresh(db_alert)
    return db_alert

@app.get("/alerts", response_model=list[schemas.ThreatAlertResponse])
def get_alerts(skip: int = 0, limit: int = 100, threat_type: str = None, db: Session = Depends(get_db), current_user=Depends(auth.get_current_user)):
    query = db.query(models.ThreatAlert)
    if threat_type:
        query = query.filter(models.ThreatAlert.threat_type == threat_type)
    return query.order_by(models.ThreatAlert.timestamp.desc()).offset(skip).limit(limit).all()

@app.get("/alerts/{alert_id}", response_model=schemas.ThreatAlertResponse)
def get_alert(alert_id: int, db: Session = Depends(get_db), current_user=Depends(auth.get_current_user)):
    alert = db.query(models.ThreatAlert).filter(models.ThreatAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert

@app.delete("/alerts/{alert_id}")
def delete_alert(alert_id: int, db: Session = Depends(get_db), current_user=Depends(auth.get_current_user)):
    alert = db.query(models.ThreatAlert).filter(models.ThreatAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    db.delete(alert)
    db.commit()
    return {"message": "Alert deleted"}

@app.get("/stats")
def get_stats(db: Session = Depends(get_db), current_user=Depends(auth.get_current_user)):
    total = db.query(models.ThreatAlert).count()
    suspicious = db.query(models.ThreatAlert).filter(models.ThreatAlert.is_suspicious == True).count()
    normal = total - suspicious
    return {
        "total_alerts": total,
        "suspicious": suspicious,
        "normal": normal,
        "suspicious_percentage": (suspicious / total * 100) if total > 0 else 0
    }

# ==================== ML PREDICTION ENDPOINT ====================

@app.post("/predict")
def predict_alert(log_text: str, current_user=Depends(auth.get_current_user)):
    if not model_loaded:
        raise HTTPException(status_code=503, detail="ML model not available")
    X = vectorizer.transform([log_text])
    prediction = clf.predict(X)[0]
    confidence = clf.predict_proba(X)[0].max()
    return {
        "is_suspicious": bool(prediction),
        "confidence": float(confidence),
        "log_text": log_text
    }

# ==================== HEALTH CHECK ====================

@app.get("/health")
def health_check():
    return {"status": "healthy", "database": "connected", "ml_model": model_loaded}

# ==================== RUN APP ====================

if __name__ == "__main__":
    import uvicorn
    print("🚀 Threat Alert API Starting...")
    print("Documentation: http://localhost:8000/docs")
    uvicorn.run(app, host="0.0.0.0", port=8000)