# 🚀 Phase 5: Deployment & Backend Infrastructure Guide

## Overview
Phase 5 provides three deployment options for AeroGuard IDS:
1. **Standalone Desktop Application** (Windows .exe)
2. **API Backend Service** (FastAPI cloud deployment)
3. **Complete Enterprise Setup** (Full stack with auth & monitoring)

---

## 🖥️ Option 1: Windows Desktop Application

### Build Standalone .exe

#### Prerequisites
```bash
pip install -r requirements.txt
pip install PyInstaller
```

#### Lightweight Build (Cloud LLM Only)
```bash
python build_executable.py
```
**Output:** `dist/AeroGuard.exe` (~300-400 MB)
- Uses cloud-based Gemini API for LLM
- No bundled Ollama model
- Fastest installation

#### Full Build (With Local Ollama)
```bash
python build_executable.py --with-ollama
```
**Output:** `dist/AeroGuard.exe` (~2.8 GB)
- Bundles Ollama + phi4-mini model
- Complete offline capability
- Larger file size, but no internet required for LLM

### Create Installer

#### Using Inno Setup
1. Download Inno Setup from [jrsoftware.org](https://jrsoftware.org)
2. Open `AeroGuard_Installer.iss` in Inno Setup Compiler
3. Click "Compile" → Creates `dist/AeroGuard_IDS_Installer.exe`

#### Installation Options
Users can select during setup:
- **Core** (required): UI + ML Engine
- **Ollama** (optional): Local LLM support (~2.5GB)
- **Backend** (optional): FastAPI service
- **Wireshark** (optional): Packet analysis integration

---

## 🌐 Option 2: FastAPI Backend Service

### Local Development

#### Start Backend API Server
```bash
python backend_api.py
```
Server runs on `http://localhost:8000`

#### API Documentation
Visit `http://localhost:8000/docs` for interactive Swagger UI

### Production Deployment

#### Using Uvicorn with Gunicorn (Recommended)
```bash
pip install gunicorn
gunicorn -w 4 -k uvicorn.workers.UvicornWorker backend_api:app --bind 0.0.0.0:8000
```

#### Docker Deployment
```dockerfile
FROM python:3.10-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

CMD ["gunicorn", "-w", "4", "-k", "uvicorn.workers.UvicornWorker", "backend_api:app", "--bind", "0.0.0.0:8000"]
```

Build & run:
```bash
docker build -t aereguard-backend .
docker run -p 8000:8000 aereguard-backend
```

#### Deploy to Cloud (Example: Heroku)
```bash
heroku login
heroku create aereguard-backend
git push heroku main
# API runs at https://aereguard-backend.herokuapp.com
```

### Backend API Endpoints

#### Authentication
```http
POST /auth/register
{
  "email": "user@example.com",
  "password": "secure_password"
}

POST /auth/login
{
  "email": "user@example.com",
  "password": "secure_password"
}
```

Returns JWT token valid for 24 hours

#### LLM Analysis
```http
POST /api/analyze
Authorization: Bearer <JWT_TOKEN>
{
  "flow_data": {
    "src_ip": "192.168.1.100",
    "dst_ip": "52.1.2.3",
    "src_port": 54321,
    "dst_port": 443,
    "protocol": "tcp",
    "application_name": "chrome.exe",
    "bidirectional_bytes": 50000
  },
  "analysis_type": "root_cause"
}
```

#### User Profile
```http
GET /api/user/profile
Authorization: Bearer <JWT_TOKEN>

Response:
{
  "email": "user@example.com",
  "tier": "pro",
  "rate_limit": 1000,
  "requests_today": 45,
  "requests_remaining": 955
}
```

#### Subscription Upgrade
```http
POST /api/upgrade
Authorization: Bearer <JWT_TOKEN>
{
  "new_tier": "pro"  // free, pro, enterprise
}
```

---

## 📊 Integration with Desktop App

### Configure Backend Connection

**config.json** (Desktop App):
```json
{
  "llm_config": {
    "mode": "local",
    "backend": {
      "api_url": "https://your-backend.com",
      "api_key": "your_jwt_token_here"
    }
  }
}
```

### Desktop App → Backend Flow
1. User detects anomaly in desktop app
2. Clicks "Analyze with LLM"
3. Desktop sends encrypted request to backend
4. Backend validates JWT + rate limits
5. Backend runs Gemini LLM analysis
6. Results returned to desktop UI

---

## 🔐 Security Best Practices

### Before Production Deployment

#### 1. Update Secret Key
**backend_api.py:**
```python
# Change this immediately!
SECRET_KEY = "YOUR_SECURE_RANDOM_KEY_HERE"
```

Generate secure key:
```python
import secrets
print(secrets.token_urlsafe(32))
```

#### 2. Environment Variables
Don't hardcode API keys or passwords!

**.env file:**
```
GEMINI_API_KEY=your_actual_key
JWT_SECRET_KEY=your_secure_key
DATABASE_URL=postgresql://user:pass@localhost/aereguard
```

Load in Python:
```python
from dotenv import load_dotenv
import os

load_dotenv()
SECRET_KEY = os.getenv("JWT_SECRET_KEY")
```

#### 3. HTTPS/TLS
Always use HTTPS in production. Get free certificate from [Let's Encrypt](https://letsencrypt.org)

Nginx proxy example:
```nginx
server {
    listen 443 ssl http2;
    server_name api.aereguard.io;
    ssl_certificate /etc/letsencrypt/live/api.aereguard.io/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.aereguard.io/privkey.pem;
    
    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Authorization $http_authorization;
    }
}
```

#### 4. Database Integration
Replace in-memory store with persistent database:

```python
# backend_api.py
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./aereguard.db")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)

# Then use SQLAlchemy models instead of USERS_DB dict
```

---

## 📈 Scalability & Monitoring

### Rate Limiting
Current implementation: In-memory tracking
**For production:** Use Redis
```python
import redis
redis_client = redis.Redis(host='localhost', port=6379)

def check_rate_limit(email: str, tier: str) -> bool:
    key = f"{email}:{datetime.now().date().isoformat()}"
    limit = tier_limits[tier]
    count = redis_client.incr(key)
    redis_client.expire(key, 86400)  # 24 hours
    return count <= limit
```

### Monitoring & Logging
```python
import logging
from pythonjsonlogger import jsonlogger

logHandler = logging.StreamHandler()
formatter = jsonlogger.JsonFormatter()
logHandler.setFormatter(formatter)
logger = logging.getLogger()
logger.addHandler(logHandler)
logger.setLevel(logging.INFO)
```

View logs in cloud dashboards (Datadog, CloudWatch, etc.)

---

## 🎯 Monetization Models

### Tier Structure
| Feature | Free | Pro | Enterprise |
|---------|------|-----|------------|
| Daily Requests | 10 | 1,000 | 100,000 |
| Anomaly Detection | ✅ | ✅ | ✅ |
| LLM Analysis | ❌ | ✅ | ✅ |
| API Access | ❌ | ✅ | ✅ |
| Offline Mode | ❌ | ✅ | ✅ |
| Support | Community | Email | 24/7 Phone |
| Price | Free | $29/mo | Custom |

### Payment Integration
Add Stripe/PayPal webhooks for automatic upgrades:
```python
@app.post("/api/payment/webhook")
def handle_payment_webhook(event: Dict):
    if event["type"] == "customer.subscription.updated":
        email = event["data"]["email"]
        tier = event["data"]["tier"]
        USERS_DB[email]["tier"] = tier
    return {"status": "received"}
```

---

## 🧪 Testing

### Backend API Testing
```bash
pip install pytest httpx

# Run tests
pytest test_backend.py -v
```

**test_backend.py example:**
```python
from fastapi.testclient import TestClient
from backend_api import app

client = TestClient(app)

def test_register():
    response = client.post("/auth/register", json={
        "email": "test@example.com",
        "password": "testpass123"
    })
    assert response.status_code == 200
    assert "access_token" in response.json()

def test_rate_limiting():
    for i in range(11):
        response = client.post("/api/analyze", headers={"Authorization": "Bearer token"})
    assert response.status_code == 429  # Too Many Requests
```

---

## 📦 Deployment Checklist

- [ ] Update `SECRET_KEY` in `backend_api.py`
- [ ] Set environment variables for sensitive data
- [ ] Test all endpoints locally with `pytest`
- [ ] Configure HTTPS/TLS certificates
- [ ] Set up database (PostgreSQL recommended)
- [ ] Enable logging and monitoring
- [ ] Configure rate limiting with Redis
- [ ] Build .exe: `python build_executable.py`
- [ ] Create installer: Use Inno Setup
- [ ] Deploy backend to cloud (Heroku/AWS/GCP)
- [ ] Update client config with backend URL
- [ ] Smoke test desktop app with backend
- [ ] Set up uptime monitoring
- [ ] Plan backup & disaster recovery
- [ ] Document API for partners

---

## 🆘 Troubleshooting

### Common Issues

**Issue:** PyInstaller build fails with "module not found"
```bash
# Solution: Install missing dependencies
pip install --collect-all streamlit
python build_executable.py
```

**Issue:** Backend 500 errors in production
```bash
# Check logs
journalctl -u aereguard-backend -f

# Increase verbosity
LOGLEVEL=DEBUG gunicorn backend_api:app
```

**Issue:** Rate limiting not working
```bash
# Ensure Redis is running
redis-cli ping  # Should return PONG
```

---

## 📚 Reference

- [FastAPI Documentation](https://fastapi.tiangolo.com)
- [PyInstaller Manual](https://pyinstaller.readthedocs.io)
- [Inno Setup Documentation](https://jrsoftware.org/ishelp/)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8949)
