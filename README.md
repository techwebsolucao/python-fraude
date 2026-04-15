<div align="center">

<img src="https://img.shields.io/badge/Python-3.9+-blue?style=flat-square&logo=python" />
<img src="https://img.shields.io/badge/FastAPI-0.115-009688?style=flat-square&logo=fastapi" />
<img src="https://img.shields.io/badge/ML-Random%20Forest-orange?style=flat-square&logo=scikit-learn" />
<img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" />

# Agmete — Anti-Fraud Payment API

**Real-time fraud detection engine for payment transactions.**  
Combines Machine Learning + rule-based heuristics + entity blocking + velocity analysis.  
Plug into any gateway — the HTML frontend is a demo, **the API is the product**.

[Demo](#demo) · [Quick Start](#quick-start) · [API Reference](#api-reference) · [Docker](#docker) · [Integration](#integrating-via-api)

</div>

---

## Features

- **Risk scoring (0–100)** with automatic decision: `APPROVED`, `MANUAL REVIEW`, or `BLOCKED`
- **14 layered fraud checks** — ML, BIN lookup, velocity, geolocation, name matching, CPF validation, expiry, and more
- **Payment methods**: Credit card, PIX, Boleto
- **Individual blocking**: email, CPF, IP address
- **Combo blocking**: block when multiple fields match simultaneously (e.g. `email + CPF`, `card_last4 + email + IP`)
- **Country allowlist**: accept transactions only from specific countries
- **Suspicious bank list**: flag known high-risk issuers detected via BIN lookup
- **Persistent history**: transactions and blocks saved to JSON (swap for DB in production)
- **Manual review queue**: hold pending transactions for human approval/rejection
- **Auto-block**: velocity trigger auto-blocks email/CPF on fraud pattern detection
- **Demo frontend**: transparent checkout + full admin dashboard (5 tabs)

---

## Demo

| Page | URL | Audience |
|------|-----|----------|
| Checkout | `http://localhost:8000/` | Customer — sees only generic messages |
| Admin dashboard | `http://localhost:8000/admin` | Operator — full fraud detail, blocking tools, history |
| API docs (Swagger) | `http://localhost:8000/docs` | Developers |

---

## Quick Start

### 1. Clone & install

```bash
git clone https://github.com/techwebsolucao/agmete.git
cd agmete

python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Train the ML model

Download the [Credit Card Fraud Detection dataset](https://www.kaggle.com/datasets/mlg-ulb/creditcardfraud) (`creditcard.csv`), place it in the project root, then:

```bash
python train_model.py
```

This generates `models/fraud_model.pkl` and `models/scaler.pkl`.

> The engine works without the model — it will use rule-based checks only.

### 3. Run

```bash
uvicorn app:app --reload --host 0.0.0.0 --port 8000
```

---

## Docker

```bash
# Copy and configure environment variables
cp .env.example .env

# Build and run
docker compose up --build
```

Or without Compose:

```bash
docker build -t agmete .
docker run -p 8000:8000 -v $(pwd)/data:/app/data -v $(pwd)/models:/app/models agmete
```

---

## API Reference

All endpoints return JSON. Base URL: `http://localhost:8000`

### Quick Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/payment` | Analyze a transaction (main endpoint) |
| `GET` | `/api/transactions/pending` | List transactions awaiting manual review |
| `POST` | `/api/transactions/{id}/release` | Approve a pending transaction |
| `POST` | `/api/transactions/{id}/reject` | Reject a pending transaction |
| `GET` | `/api/transactions/history` | Full transaction history |
| `POST` | `/api/block` | Block an email, CPF, or IP |
| `DELETE` | `/api/block/{type}/{value}` | Unblock an entity |
| `GET` | `/api/blocked` | List all blocked entities |
| `POST` | `/api/combos` | Create a combo block (2+ fields) |
| `DELETE` | `/api/combos/{id}` | Remove a combo block |
| `GET` | `/api/combos` | List all combo blocks |
| `GET` | `/api/countries` | List allowed countries |
| `POST` | `/api/countries/{country}` | Add a country to the allowlist |
| `DELETE` | `/api/countries/{country}` | Remove a country |
| `POST` | `/api/countries` | Replace full country list |
| `POST` | `/api/banks/flag` | Flag a bank issuer as suspicious |
| `DELETE` | `/api/banks/flag/{name}` | Unflag a bank issuer |
| `GET` | `/api/banks/flagged` | List all flagged bank issuers |
| `GET` | `/api/health` | System status |
| `GET` | `/api/ip-info` | Client IP + geolocation |

---

### Analyze a transaction

```http
POST /api/payment
Content-Type: application/json
```

```json
{
  "amount": 750.00,
  "payment_method": "credit_card",
  "customer_name": "João Silva",
  "email": "joao@email.com",
  "cpf": "529.982.247-25",
  "card_holder_name": "JOAO SILVA",
  "card_number": "4532 0123 4567 5678",
  "card_expiry": "12/28",
  "city": "São Paulo",
  "state": "SP"
}
```

`payment_method`: `"credit_card"` | `"pix"` | `"boleto"`  
Card fields (`card_holder_name`, `card_number`, `card_expiry`) are only used for `credit_card`.  
`card_number` is used to identify the issuing bank via BIN lookup (first 6–8 digits).

**Response:**
```json
{
  "transaction_id": "TX-ABC12345",
  "risk_score": 25,
  "decision": "APROVADO",
  "decision_reason": "Transação dentro dos parâmetros normais",
  "alerts": [],
  "details": {
    "bin_lookup": { "issuer": "ITAU UNIBANCO S.A.", "scheme": "VISA", "type": "CREDIT" },
    "bank_analysis": { "issuer": "ITAU UNIBANCO S.A.", "flagged": false },
    "ml_prediction": { "probability": 3.2, "prediction": "legitimate" },
    "ip_analysis": { ... }
  },
  "customer_response": {
    "message": "Pagamento aprovado com sucesso!",
    "status": "success",
    "transaction_id": "TX-ABC12345"
  }
}
```

> **Note:** `customer_response` is the only field that should be shown to the end customer. Everything else is for your backend/admin use only.

---

### Individual Blocking

```http
POST   /api/block                     Block an email, CPF, or IP
DELETE /api/block/{type}/{value}      Unblock
GET    /api/blocked                   List all blocked entities
```

```json
// POST /api/block
{ "entity_type": "email", "value": "fraud@test.com", "reason": "Chargeback confirmed" }
```

### Combo Blocking

Block a transaction only when **all** specified fields match simultaneously:

```http
POST   /api/combos                    Create a combo block (min 2 fields)
DELETE /api/combos/{combo_id}         Remove a combo
GET    /api/combos                    List all combos
```

```json
// POST /api/combos — fires only when BOTH email AND CPF match
{ "conditions": { "email": "x@x.com", "cpf": "52998224725" }, "reason": "Known fraudster" }

// POST /api/combos — fires only when ALL THREE match
{ "conditions": { "card_last4": "0001", "email": "x@x.com", "ip": "1.2.3.4" }, "reason": "" }
```

Available combo fields: `email`, `cpf`, `ip`, `card_last4`

### Country Allowlist

```http
GET    /api/countries                 List allowed countries (empty = all allowed)
POST   /api/countries/{country}       Add a country
DELETE /api/countries/{country}       Remove a country
POST   /api/countries                 Replace full list: { "countries": ["Brazil"] }
```

By default, only `Brazil` is allowed. Transactions with IPs from other countries are blocked.

### Suspicious Banks

Bank issuers are identified automatically from the card number via [HandyAPI BIN lookup](https://www.handyapi.com/bin-list). Configure your key in `.env`:

```
HANDY_API_KEY=your_key_here
```

Then flag issuers to increase the risk score on matching transactions:

```http
POST   /api/banks/flag                Flag a bank issuer as suspicious
DELETE /api/banks/flag/{name}         Unflag
GET    /api/banks/flagged             List all flagged issuers
```

```json
// POST /api/banks/flag
// Use the exact bank name as returned by the BIN lookup (e.g. from details.bin_lookup.issuer)
{ "bank_name": "BANCO XYZ S.A.", "risk_level": "alto", "reason": "High chargeback rate" }
```

`risk_level`: `"baixo"` (+10) | `"medio"` (+20) | `"alto"` (+35)

### Transaction Queue

```http
GET  /api/transactions/pending
GET  /api/transactions/history?limit=100
POST /api/transactions/{id}/release
POST /api/transactions/{id}/reject
```

### System

```http
GET /api/health       Status, model state, pending count, blocked count
GET /api/ip-info      Client IP + geolocation
```

---

## Risk Score Logic

| Score | Decision | Description |
|-------|----------|-------------|
| 0–39 | ✅ APROVADO | Low risk — auto-approved |
| 40–69 | ⚠️ REVISÃO MANUAL | Medium risk — held for manual review |
| 70–100 | 🚫 BLOQUEADO | High risk — auto-blocked |

---

## Fraud Detection Checks

| Check | Condition | Score Impact |
|-------|-----------|-------------|
| Entity blocked (email/CPF/IP) | In individual blocklist | **Score = 100** |
| Combo block | All combo fields matched | **Score = 100** |
| Country block | IP outside allowed countries | **Score = 100** |
| Invalid CPF | Failed check digit algorithm | +25 |
| Expired card | Past expiry date | +30 |
| High value | > R$ 2,000 / > R$ 5,000 | +10 / +20 |
| Name mismatch | Card holder ≠ customer name | +15–30 |
| Email mismatch | Email prefix ≠ customer name | +20 |
| High-risk hour | Between 01:00–05:00 | +15 |
| IP geolocation mismatch | City/region diverges from declared | +20 |
| Proxy/VPN | IP flagged as proxy or hosting | +25 |
| Suspicious bank | Issuer in operator’s flagged list (via BIN) | +10–35 |
| Velocity — multiple names | Same card, 3+ different names in 24h | +30–55 |
| Velocity — excessive attempts | Same card, 10+ attempts in 24h | +30 + auto-block |
| ML model | Random Forest fraud probability | up to +30 |

---

## Integrating via API

Agmete sits between your backend and your payment gateway:

```
Browser  →  Your backend  →  Agmete  →  Stripe / gateway
```

When the customer submits the checkout form, the request hits **your backend**. At this point you already have the real client IP in the incoming request headers — just extract it and forward it to Agmete via the `ip_address` field.

### ⚠️ Always forward the client IP

If you omit `ip_address`, Agmete receives **your server's IP** instead of the customer's, breaking geolocation, VPN detection, and country blocking.

**Python (Flask/FastAPI example):**
```python
import requests
from fastapi import Request

@app.post("/checkout")
def checkout(data: dict, request: Request):
    # Extract the real client IP from the incoming request
    client_ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    if not client_ip:
        client_ip = request.client.host

    result = requests.post("https://your-agmete.com/api/payment", json={
        "amount": data["amount"],
        "payment_method": data["payment_method"],
        "customer_name": data["customer_name"],
        "email": data["email"],
        "cpf": data["cpf"],
        "card_number": data["card_number"],
        "card_expiry": data["card_expiry"],
        "card_holder_name": data["card_holder_name"],
        "ip_address": client_ip,   # ← real client IP from the incoming request
        "city": data["city"],
        "state": data["state"],
    }).json()

    if result["decision"] == "APROVADO":
        pass  # proceed with payment gateway
    elif result["decision"] == "REVISÃO MANUAL":
        pass  # hold order
    else:
        pass  # reject — show result["customer_response"]["message"] to the customer
```

**Node.js (Express example):**
```javascript
app.post('/checkout', async (req, res) => {
    const clientIp = (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
                  || req.socket.remoteAddress;

    const result = await fetch('https://your-agmete.com/api/payment', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            ...req.body,
            ip_address: clientIp,   // ← real client IP from the incoming request
        }),
    }).then(r => r.json());

    res.json(result.customer_response);
});
```

**PHP example:**
```php
$clientIp = $_SERVER['HTTP_X_FORWARDED_FOR']
    ?? $_SERVER['REMOTE_ADDR']
    ?? '';

$result = json_decode(file_get_contents('https://your-agmete.com/api/payment', false,
    stream_context_create(['http' => [
        'method' => 'POST',
        'header' => 'Content-Type: application/json',
        'content' => json_encode([
            'amount'          => $_POST['amount'],
            'payment_method'  => $_POST['payment_method'],
            'customer_name'   => $_POST['customer_name'],
            'email'           => $_POST['email'],
            'cpf'             => $_POST['cpf'],
            'card_number'     => $_POST['card_number'],
            'card_expiry'     => $_POST['card_expiry'],
            'ip_address'      => $clientIp,   // ← real client IP from the incoming request
            'city'            => $_POST['city'],
            'state'           => $_POST['state'],
        ]),
    ]])
), true);
```

---

## Project Structure

```
agmete/
├── app.py                  # FastAPI routes
├── fraud_engine.py         # Core fraud detection engine
├── train_model.py          # ML model training script
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── .env.example
├── creditcard.csv          # Training data (not included — download from Kaggle)
├── models/
│   ├── fraud_model.pkl     # Trained Random Forest (auto-generated)
│   └── scaler.pkl
├── data/
│   ├── transactions.json   # Persistent history (auto-created)
│   └── blocked.json        # Blocked entities, combos, countries (auto-created)
├── templates/
│   ├── checkout.html       # Customer-facing demo checkout
│   └── admin.html          # Admin dashboard demo
└── static/
    └── style.css
```

---

## Production Recommendations

| Concern | Recommendation |
|---------|---------------|
| **Persistence** | Replace JSON files with PostgreSQL + Redis |
| **Auth** | Add `X-API-Key` header validation on all `/api/*` routes |
| **Rate limiting** | Add `slowapi` middleware |
| **Geolocation** | Replace ip-api.com with MaxMind GeoIP2 (no rate limits) |
| **Retrain ML** | Run `train_model.py` with your own labeled transaction data |
| **Score thresholds** | Adjust the `40`/`70` values in `analyze_transaction()` per your risk appetite |
| **HTTPS** | Deploy behind nginx or a reverse proxy with TLS termination |

---

## Tech Stack

- **Python 3.9+** + **FastAPI** + **Uvicorn**
- **scikit-learn** — Random Forest classifier
- **ip-api.com** — IP geolocation (free tier: 45 req/min)
- **api.ipify.org** — Public IP resolution
- **Jinja2** — HTML templates
- **Font Awesome 6.5** — Icons (CDN)

---

## License

MIT — see [LICENSE](LICENSE)
