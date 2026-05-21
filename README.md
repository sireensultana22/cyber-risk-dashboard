# Cyber Risk Dashboard Backend

## Backend Features

### Authentication & Security
- JWT-based user authentication
- Secure password hashing using bcrypt
- Rate limiting on scan APIs to prevent abuse
- Protected API architecture

### Cybersecurity Scan APIs
- URL reputation scanning using VirusTotal
- Network/port scanning using Nmap
- Email header phishing analysis
- File malware scanning integration (ClamAV/mock scanning)

### Scan Management
- Scan history storage using PostgreSQL
- Retrieve scan reports by ID
- Delete scan reports
- Persistent database logging

### AI Integration
- Pass raw cybersecurity tool outputs to AI service
- Receive enriched human-readable threat analysis
- Frontend-ready AI responses

### Admin & Monitoring
- Aggregated threat logging
- Registered user management APIs
- Threat analytics support

### Tech Stack
- FastAPI
- PostgreSQL
- SQLAlchemy
- JWT Authentication
- SlowAPI Rate Limiting
- VirusTotal API
- Nmap
- ClamAV

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /register | Register new user |
| POST | /login | User login |
| POST | /api/scan/url | Scan URLs |
| POST | /api/scan/network | Network scan |
| POST | /api/scan/email | Email phishing analysis |
| POST | /api/scan/file | File malware scan |
| GET | /scan-history | Get all scan history |
| GET | /scan-history/{id} | Get scan by ID |
| DELETE | /scan-history/{id} | Delete scan |

---

## Run Backend

```bash
pip install -r requirements.txt
uvicorn main:app --reload
