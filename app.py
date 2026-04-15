"""
app.py - Agmete: API de Pagamento com Sistema Anti-Fraude
FastAPI + Motor de detecção de fraude + Frontend HTML
"""

import re
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

import fraud_engine

# ── App ──────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Agmete - Anti-Fraud Payment API",
    description="API de pagamento com sistema anti-fraude inteligente",
    version="3.0.0",
)

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


@app.on_event("startup")
def startup():
    fraud_engine.load_model()


# ── Models ───────────────────────────────────────────────────────────────────
class PaymentRequest(BaseModel):
    amount: float = Field(..., gt=0)
    payment_method: str = Field(default="credit_card", pattern=r"^(credit_card|pix|boleto)$")
    customer_name: str = Field(..., min_length=2, max_length=100)
    email: str = Field(..., min_length=5, max_length=100)
    cpf: str = Field(default="", max_length=20)
    card_holder_name: str = Field(default="", max_length=100)
    card_last4: str = Field(default="", max_length=4)
    card_expiry: str = Field(default="", max_length=7)
    bank_name: str = Field(default="", max_length=100)
    city: str = Field(default="", max_length=100)
    state: str = Field(default="", max_length=50)
    purchase_hour: Optional[int] = Field(default=None, ge=0, le=23)


class FlaggedBankRequest(BaseModel):
    bank_name: str = Field(..., min_length=2, max_length=100)
    risk_level: str = Field(default="alto", pattern=r"^(alto|medio|baixo)$")
    reason: str = Field(default="", max_length=500)


class BlockEntityRequest(BaseModel):
    entity_type: str = Field(..., pattern=r"^(email|cpf|ip)$")
    value: str = Field(..., min_length=1, max_length=200)
    reason: str = Field(default="", max_length=500)


class ComboBlockRequest(BaseModel):
    conditions: dict  # e.g. {"email": "x@x.com", "cpf": "12345678901"}
    reason: str = Field(default="", max_length=500)


class CountryListRequest(BaseModel):
    countries: list[str]


# ── Pagamento ────────────────────────────────────────────────────────────────
@app.post("/api/payment", tags=["Pagamento"])
def process_payment(payment: PaymentRequest, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()

    client_ip = fraud_engine.resolve_ip(client_ip)

    if payment.purchase_hour is None:
        payment.purchase_hour = datetime.now().hour

    tx_data = {
        "amount": payment.amount,
        "payment_method": payment.payment_method,
        "card_holder_name": payment.card_holder_name,
        "customer_name": payment.customer_name,
        "email": payment.email,
        "cpf": payment.cpf,
        "card_last4": payment.card_last4,
        "card_expiry": payment.card_expiry,
        "ip_address": client_ip,
        "bank_name": payment.bank_name,
        "city": payment.city,
        "state": payment.state,
        "purchase_hour": payment.purchase_hour,
    }

    result = fraud_engine.analyze_transaction(tx_data)
    return result


@app.get("/api/ip-info", tags=["Sistema"])
def get_client_ip(request: Request):
    client_ip = request.client.host if request.client else "unknown"
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()

    client_ip = fraud_engine.resolve_ip(client_ip)
    geo = fraud_engine.get_ip_geolocation(client_ip)
    return {"ip": client_ip, "geolocation": geo}


# ── Transações ───────────────────────────────────────────────────────────────
@app.get("/api/transactions/pending", tags=["Admin"])
def list_pending():
    return {"pending": fraud_engine.get_pending_transactions()}


@app.get("/api/transactions/history", tags=["Admin"])
def list_history(limit: int = 100):
    return {"history": fraud_engine.get_transaction_history(limit)}


@app.post("/api/transactions/{tx_id}/release", tags=["Admin"])
def release_tx(tx_id: str):
    result = fraud_engine.release_transaction(tx_id)
    if result:
        return {"message": f"Transação {tx_id} liberada", "transaction": result}
    return {"message": f"Transação {tx_id} não encontrada", "error": True}


@app.post("/api/transactions/{tx_id}/reject", tags=["Admin"])
def reject_tx(tx_id: str):
    result = fraud_engine.reject_transaction(tx_id)
    if result:
        return {"message": f"Transação {tx_id} rejeitada", "transaction": result}
    return {"message": f"Transação {tx_id} não encontrada", "error": True}


# ── Bloqueios ────────────────────────────────────────────────────────────────
@app.post("/api/block", tags=["Bloqueios"])
def block_entity(req: BlockEntityRequest):
    fraud_engine.block_entity(req.entity_type, req.value, req.reason)
    return {
        "message": f"{req.entity_type.upper()} '{req.value}' bloqueado",
        "type": req.entity_type,
        "value": req.value,
    }


@app.delete("/api/block/{entity_type}/{value}", tags=["Bloqueios"])
def unblock_entity(entity_type: str, value: str):
    if fraud_engine.unblock_entity(entity_type, value):
        return {"message": f"{entity_type.upper()} '{value}' desbloqueado"}
    return {"message": f"{entity_type.upper()} '{value}' não encontrado", "error": True}


@app.get("/api/blocked", tags=["Bloqueios"])
def list_blocked():
    return {"blocked": fraud_engine.get_blocked_entities()}


# ── Bloqueios Combinados ─────────────────────────────────────────────────────────
@app.post("/api/combos", tags=["Bloqueios"])
def block_combo_route(req: ComboBlockRequest):
    non_empty = {k: v for k, v in req.conditions.items() if v and str(v).strip()}
    if len(non_empty) < 2:
        return {"error": True, "message": "Mínimo 2 campos para bloqueio combinado"}
    combo_id = fraud_engine.block_combo(non_empty, req.reason)
    return {"message": "Bloqueio combinado criado", "combo_id": combo_id}


@app.delete("/api/combos/{combo_id}", tags=["Bloqueios"])
def unblock_combo_route(combo_id: str):
    if fraud_engine.unblock_combo(combo_id):
        return {"message": f"Combo {combo_id} desbloqueado"}
    return {"error": True, "message": f"Combo {combo_id} não encontrado"}


@app.get("/api/combos", tags=["Bloqueios"])
def list_combos():
    return {"combos": fraud_engine.get_blocked_combos()}


# ── Países Permitidos ─────────────────────────────────────────────────────────
@app.get("/api/countries", tags=["Países"])
def get_countries():
    return {"allowed_countries": fraud_engine.get_allowed_countries()}


@app.post("/api/countries", tags=["Países"])
def set_countries(req: CountryListRequest):
    fraud_engine.set_allowed_countries(req.countries)
    return {"message": "Lista de países atualizada", "allowed_countries": fraud_engine.get_allowed_countries()}


@app.post("/api/countries/{country}", tags=["Países"])
def add_country(country: str):
    fraud_engine.add_allowed_country(country)
    return {"message": f"País '{country}' adicionado", "allowed_countries": fraud_engine.get_allowed_countries()}


@app.delete("/api/countries/{country}", tags=["Países"])
def remove_country(country: str):
    if fraud_engine.remove_allowed_country(country):
        return {"message": f"País '{country}' removido", "allowed_countries": fraud_engine.get_allowed_countries()}
    return {"error": True, "message": f"País '{country}' não encontrado"}


# ── Bancos suspeitos ─────────────────────────────────────────────────────────
@app.post("/api/banks/flag", tags=["Bancos"])
def flag_bank(bank: FlaggedBankRequest):
    fraud_engine.add_flagged_bank(bank.bank_name, bank.risk_level, bank.reason)
    return {"message": f"Banco '{bank.bank_name}' marcado como suspeito"}


@app.delete("/api/banks/flag/{bank_name}", tags=["Bancos"])
def unflag_bank(bank_name: str):
    if fraud_engine.remove_flagged_bank(bank_name):
        return {"message": f"Banco '{bank_name}' removido"}
    return {"message": f"Banco '{bank_name}' não encontrado", "error": True}


@app.get("/api/banks/flagged", tags=["Bancos"])
def list_flagged_banks():
    return {"flagged_banks": fraud_engine.get_flagged_banks()}


# ── Sistema ──────────────────────────────────────────────────────────────────
@app.get("/api/health", tags=["Sistema"])
def health_check():
    return {
        "status": "online",
        "model_loaded": fraud_engine._model is not None,
        "timestamp": datetime.now().isoformat(),
        "flagged_banks_count": len(fraud_engine.FLAGGED_BANKS),
        "pending_transactions": len(fraud_engine._pending_transactions),
        "total_transactions": len(fraud_engine._transaction_history),
        "blocked_entities": sum(len(v) for v in fraud_engine._blocked_entities.values()),
    }


# ── Frontend ─────────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse, tags=["Frontend"])
def checkout_page(request: Request):
    return templates.TemplateResponse("checkout.html", {"request": request})


@app.get("/admin", response_class=HTMLResponse, tags=["Frontend"])
def admin_page(request: Request):
    return templates.TemplateResponse("admin.html", {"request": request})
