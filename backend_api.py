"""
Phase 5: Backend Infrastructure & API Proxy
FastAPI backend for handling LLM requests, authentication, and rate limiting.
Designed for cloud deployment and subscription management.
"""

from fastapi import FastAPI, HTTPException, Depends, status, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, Dict
import hashlib
import time
import json
import logging
from datetime import datetime, timedelta
import jwt

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Configuration ---
SECRET_KEY = "YOUR_SECRET_KEY_CHANGE_IN_PRODUCTION"
ALGORITHM = "HS256"
TOKEN_EXPIRATION_HOURS = 24

# In-memory user store (replace with database in production)
USERS_DB = {
    "demo@aereguard.com": {
        "password_hash": hashlib.sha256("demo123".encode()).hexdigest(),
        "tier": "free",
        "requests_today": 0,
        "rate_limit": 10  # Free tier: 10 requests/day
    }
}

# In-memory rate limit tracker
RATE_LIMITS = {}

# --- Pydantic Models ---

class User(BaseModel):
    email: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str
    expires_in: int

class LLMRequest(BaseModel):
    flow_data: Dict
    analysis_type: str = "root_cause"  # root_cause, threat_intelligence, pattern_analysis

class LLMResponse(BaseModel):
    analysis: str
    timestamp: str
    usage: Dict

class AnalyticsData(BaseModel):
    user_email: str
    flows_analyzed: int
    anomalies_detected: int
    timestamp: str

# --- FastAPI Setup ---
app = FastAPI(
    title="AeroGuard IDS Backend",
    description="Phase 5: Cloud backend for LLM proxying, authentication, and analytics",
    version="1.0.0"
)

# --- Authentication Functions ---

def hash_password(password: str) -> str:
    """Hash password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(plain_password: str, password_hash: str) -> bool:
    """Verify password against hash."""
    return hash_password(plain_password) == password_hash

def create_access_token(email: str, tier: str) -> Dict:
    """Create JWT access token."""
    payload = {
        "email": email,
        "tier": tier,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=TOKEN_EXPIRATION_HOURS)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": TOKEN_EXPIRATION_HOURS * 3600
    }

def verify_token(authorization: Optional[str] = Header(None)) -> Dict:
    """Verify JWT token from Authorization header."""
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authorization header"
        )
    
    try:
        scheme, token = authorization.split()
        if scheme.lower() != "bearer":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid scheme")
        
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

def check_rate_limit(email: str, tier: str) -> bool:
    """Check if user has exceeded rate limit."""
    today = datetime.now().date().isoformat()
    key = f"{email}:{today}"
    
    if key not in RATE_LIMITS:
        RATE_LIMITS[key] = 0
    
    limit = USERS_DB.get(email, {}).get("rate_limit", 100)
    
    if RATE_LIMITS[key] >= limit:
        return False
    
    RATE_LIMITS[key] += 1
    return True

# --- Authentication Endpoints ---

@app.post("/auth/register", response_model=Token)
def register(user: User):
    """Register a new user."""
    if user.email in USERS_DB:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User already exists"
        )
    
    USERS_DB[user.email] = {
        "password_hash": hash_password(user.password),
        "tier": "free",
        "requests_today": 0,
        "rate_limit": 10
    }
    
    logger.info(f"New user registered: {user.email}")
    return create_access_token(user.email, "free")

@app.post("/auth/login", response_model=Token)
def login(user: User):
    """Login and receive JWT token."""
    if user.email not in USERS_DB:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    
    stored_user = USERS_DB[user.email]
    if not verify_password(user.password, stored_user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    
    logger.info(f"User logged in: {user.email}")
    return create_access_token(user.email, stored_user["tier"])

# --- LLM Proxy Endpoints ---

@app.post("/api/analyze", response_model=LLMResponse)
def analyze_anomaly(
    request: LLMRequest,
    token_payload: Dict = Depends(verify_token)
):
    """
    Proxy endpoint for LLM analysis.
    Handles authentication, rate limiting, and cost tracking.
    """
    email = token_payload.get("email")
    tier = token_payload.get("tier")
    
    # Check rate limit
    if not check_rate_limit(email, tier):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Your tier ({tier}) allows {USERS_DB[email]['rate_limit']} requests/day"
        )
    
    try:
        # Import LLM integrator
        from llm_integration import LLMIntegrator
        llm = LLMIntegrator()
        
        # Perform analysis
        analysis_text = llm.analyze_anomaly(request.flow_data)
        
        logger.info(f"Analysis completed for user: {email}")
        
        return LLMResponse(
            analysis=analysis_text,
            timestamp=datetime.now().isoformat(),
            usage={
                "user_tier": tier,
                "requests_today": RATE_LIMITS.get(f"{email}:{datetime.now().date().isoformat()}", 0),
                "rate_limit": USERS_DB[email]["rate_limit"]
            }
        )
        
    except Exception as e:
        logger.error(f"Analysis error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="LLM analysis failed"
        )

# --- Analytics & Management Endpoints ---

@app.post("/api/analytics")
def log_analytics(
    data: AnalyticsData,
    token_payload: Dict = Depends(verify_token)
):
    """Log user analytics for dashboard and billing."""
    email = token_payload.get("email")
    
    # In production, save to database
    logger.info(f"Analytics logged for {email}: {data.flows_analyzed} flows, {data.anomalies_detected} anomalies")
    
    return {
        "status": "success",
        "message": "Analytics recorded"
    }

@app.get("/api/user/profile")
def get_user_profile(token_payload: Dict = Depends(verify_token)):
    """Get authenticated user's profile and usage stats."""
    email = token_payload.get("email")
    tier = token_payload.get("tier")
    
    user_data = USERS_DB.get(email, {})
    today_key = f"{email}:{datetime.now().date().isoformat()}"
    requests_used = RATE_LIMITS.get(today_key, 0)
    
    return {
        "email": email,
        "tier": tier,
        "rate_limit": user_data.get("rate_limit", 100),
        "requests_today": requests_used,
        "requests_remaining": user_data.get("rate_limit", 100) - requests_used
    }

@app.get("/api/health")
def health_check():
    """Health check endpoint for monitoring."""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0"
    }

@app.post("/api/upgrade")
def upgrade_subscription(
    new_tier: str,
    token_payload: Dict = Depends(verify_token)
):
    """Upgrade user subscription tier."""
    email = token_payload.get("email")
    
    max_requests = {
        "free": 10,
        "pro": 1000,
        "enterprise": 100000
    }
    
    if new_tier not in max_requests:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid tier"
        )
    
    if email in USERS_DB:
        USERS_DB[email]["tier"] = new_tier
        USERS_DB[email]["rate_limit"] = max_requests[new_tier]
        logger.info(f"User {email} upgraded to tier: {new_tier}")
        return {"status": "success", "new_tier": new_tier}
    
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

# --- Error Handlers ---

@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    """Global exception handler."""
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"}
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
