import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

# EXPANDED training data - much more realistic
threat_texts = [
    "I will hack the system", "destroy all files", "break into database",
    "bypass security", "steal user data", "malware injection",
    "denial of service attack", "privilege escalation", "backdoor access",
    "execute malicious code", "I want to attack", "compromise network",
    "sql injection attempt", "cross site scripting", "buffer overflow",
    "rootkit installation", "phishing email detected", "ransomware detected",
    "unauthorized access", "password cracking", "ddos attack started",
    "malicious payload detected", "exploit attempt failed", "suspicious process running"
]

safe_texts = [
    "Hello, how are you", "nice weather today", "let's meet for coffee",
    "thank you for your help", "good morning everyone", "project deadline tomorrow",
    "team meeting at 2pm", "great job on the presentation", "lunch break time",
    "need to submit report", "customer feedback positive", "update documentation",
    "system backup completed", "user logged in successfully", "password updated",
    "email sent to customer", "report generated", "database query executed",
    "file uploaded to cloud", "meeting scheduled", "task completed",
    "new feature deployed", "bug fix released", "performance improved"
]

print(f"Training data: {len(threat_texts) + len(safe_texts)} samples")
print(f"Threat samples: {len(threat_texts)}, Safe samples: {len(safe_texts)}")

# Create labels (1 = threat, 0 = safe)
texts = threat_texts + safe_texts
labels = [1] * len(threat_texts) + [0] * len(safe_texts)

# Train TF-IDF vectorizer
vectorizer = TfidfVectorizer(max_features=500, stop_words='english', ngram_range=(1, 2))
X = vectorizer.fit_transform(texts)
y = np.array(labels)

# Split data - use more for training now
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)

# Train model with better parameters
model = RandomForestClassifier(
    n_estimators=200,
    max_depth=10,
    random_state=42,
    class_weight='balanced'
)
model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)
print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=['Safe', 'Threat']))
print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# Save model and vectorizer
joblib.dump(model, 'threat_detector.pkl')
joblib.dump(vectorizer, 'tfidf_vectorizer.pkl')
print("\n✅ Model saved successfully!")

# Comprehensive test
test_texts = [
    "Hello, good morning",  # Safe
    "Nice weather today",  # Safe
    "Let's have lunch together",  # Safe
    "I will destroy the server",  # Threat
    "Hack the database",  # Threat
    "Malware detected in system"  # Threat
]

X_test_new = vectorizer.transform(test_texts)
predictions = model.predict(X_test_new)
probabilities = model.predict_proba(X_test_new)

print("\n" + "="*50)
print("Detailed Test Results:")
print("="*50)
for text, pred, prob in zip(test_texts, predictions, probabilities):
    status = "🔴 THREAT" if pred == 1 else "🟢 SAFE"
    confidence = max(prob) * 100
    print(f"{status}: '{text}'")
    print(f"   Confidence: {confidence:.1f}% (Safe: {prob[0]:.2f}, Threat: {prob[1]:.2f})\n")