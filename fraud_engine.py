"""
fraud_engine.py - Agmete: Motor de detecção de fraude
Combina ML + regras heurísticas + bloqueios + velocity checks.
Suporta cartão, PIX e boleto.
"""

import hashlib
import json
import os
import re
import uuid
from collections import defaultdict
from datetime import datetime, timedelta
from difflib import SequenceMatcher
from typing import Optional

import joblib
import numpy as np
import requests

# ── Config ───────────────────────────────────────────────────────────────────
HISTORY_FILE = "data/transactions.json"
BLOCKED_FILE = "data/blocked.json"

# ── Bancos marcados como alto risco ─────────────────────────────────────────
FLAGGED_BANKS = {}

# ── Modelo ML ────────────────────────────────────────────────────────────────
_model = None
_scaler = None

# ── Histórico de tentativas por cartão (velocity check) ─────────────────────
_card_attempts = defaultdict(list)

# ── Transações pendentes ────────────────────────────────────────────────────
_pending_transactions = {}

# ── Histórico completo ──────────────────────────────────────────────────────
_transaction_history = []

# ── Entidades bloqueadas (email, cpf, ip) ────────────────────────────────────
_blocked_entities = {"email": {}, "cpf": {}, "ip": {}}

# ── Bloqueios combinados (email+cpf, card_last4+email+ip, etc.) ───────────────
_blocked_combos: list = []

# ── Países permitidos (allowlist; vazio = todos liberados) ────────────────────
_allowed_countries: set = {"brazil", "brasil"}

# ── Cache de geolocalização de IP ────────────────────────────────────────────
_ip_geo_cache = {}

# ── Cache do IP público real ─────────────────────────────────────────────────
_real_public_ip = None


def load_model():
    global _model, _scaler
    try:
        _model = joblib.load("models/fraud_model.pkl")
        _scaler = joblib.load("models/scaler.pkl")
        print("[Agmete] Modelo ML carregado")
    except FileNotFoundError:
        print("[Agmete] AVISO: Modelo não encontrado. Execute train_model.py primeiro.")
        _model = None
        _scaler = None
    _load_persisted_data()


def _load_persisted_data():
    global _transaction_history, _blocked_entities
    os.makedirs("data", exist_ok=True)
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r") as f:
                _transaction_history = json.load(f)
            print(f"[Agmete] {len(_transaction_history)} transações carregadas do histórico")
        except Exception:
            _transaction_history = []
    if os.path.exists(BLOCKED_FILE):
        try:
            with open(BLOCKED_FILE, "r") as f:
                loaded = json.load(f)
                for k in ("email", "cpf", "ip"):
                    if k in loaded:
                        _blocked_entities[k] = loaded[k]
                if "combos" in loaded:
                    _blocked_combos[:] = loaded["combos"]
                if "allowed_countries" in loaded:
                    _allowed_countries.clear()
                    _allowed_countries.update(c.lower() for c in loaded["allowed_countries"])
            total = sum(len(v) for v in _blocked_entities.values())
            print(f"[Agmete] {total} entidade(s), {len(_blocked_combos)} combo(s) carregados")
        except Exception:
            _blocked_entities = {"email": {}, "cpf": {}, "ip": {}}


def _save_history():
    os.makedirs("data", exist_ok=True)
    try:
        with open(HISTORY_FILE, "w") as f:
            json.dump(_transaction_history[-500:], f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"[Agmete] Erro ao salvar histórico: {e}")


def _save_blocked():
    os.makedirs("data", exist_ok=True)
    try:
        with open(BLOCKED_FILE, "w") as f:
            data = dict(_blocked_entities)
            data["combos"] = _blocked_combos
            data["allowed_countries"] = sorted(_allowed_countries)
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"[Agmete] Erro ao salvar bloqueados: {e}")


# ── Bloqueios ────────────────────────────────────────────────────────────────
def block_entity(entity_type: str, value: str, reason: str = ""):
    et = entity_type.lower().strip()
    if et not in _blocked_entities:
        return False
    key = value.lower().strip()
    _blocked_entities[et][key] = {
        "reason": reason,
        "blocked_at": datetime.now().isoformat(),
    }
    _save_blocked()
    return True


def unblock_entity(entity_type: str, value: str):
    et = entity_type.lower().strip()
    if et not in _blocked_entities:
        return False
    key = value.lower().strip()
    if key in _blocked_entities[et]:
        del _blocked_entities[et][key]
        _save_blocked()
        return True
    return False


def get_blocked_entities():
    return dict(_blocked_entities)


def is_entity_blocked(entity_type: str, value: str) -> dict:
    et = entity_type.lower().strip()
    if et not in _blocked_entities:
        return {"blocked": False}
    key = value.lower().strip()
    if key in _blocked_entities[et]:
        info = _blocked_entities[et][key]
        return {"blocked": True, "reason": info.get("reason", ""), "blocked_at": info.get("blocked_at", "")}
    return {"blocked": False}


# ── Bloqueios combinados ─────────────────────────────────────────────────────
def block_combo(conditions: dict, reason: str = "") -> str:
    """Bloqueia transações onde TODOS os campos da combinação coincidem."""
    combo_id = uuid.uuid4().hex[:8]
    _blocked_combos.append({
        "id": combo_id,
        "conditions": {k.lower(): v.lower().strip() for k, v in conditions.items() if v},
        "reason": reason,
        "blocked_at": datetime.now().isoformat(),
    })
    _save_blocked()
    return combo_id


def unblock_combo(combo_id: str) -> bool:
    to_remove = [c for c in _blocked_combos if c["id"] == combo_id]
    for c in to_remove:
        _blocked_combos.remove(c)
    if to_remove:
        _save_blocked()
        return True
    return False


def get_blocked_combos() -> list:
    return list(_blocked_combos)


def _check_combos(tx_data: dict) -> list:
    """Retorna alertas para cada bloqueio combinado que corresponde à transação."""
    field_map = {
        "email": tx_data.get("email", "").lower().strip(),
        "cpf": re.sub(r"\D", "", tx_data.get("cpf", "")),
        "ip": tx_data.get("ip_address", "").strip(),
        "card_last4": tx_data.get("card_last4", "").strip(),
    }
    matched = []
    for combo in _blocked_combos:
        conds = combo.get("conditions", {})
        if not conds:
            continue
        if all(field_map.get(k, "") == v for k, v in conds.items()):
            desc = " + ".join(f"{k}:{v}" for k, v in conds.items())
            reason = combo.get("reason", "")
            matched.append(f"Bloqueio combinado [{desc}]" + (f" — {reason}" if reason else ""))
    return matched


# ── Países permitidos ─────────────────────────────────────────────────────────
def get_allowed_countries() -> list:
    return sorted(_allowed_countries)


def set_allowed_countries(countries: list):
    _allowed_countries.clear()
    _allowed_countries.update(c.lower().strip() for c in countries if c.strip())
    _save_blocked()


def add_allowed_country(country: str):
    _allowed_countries.add(country.lower().strip())
    _save_blocked()


def remove_allowed_country(country: str) -> bool:
    key = country.lower().strip()
    if key in _allowed_countries:
        _allowed_countries.discard(key)
        _save_blocked()
        return True
    return False


# ── Bancos suspeitos ─────────────────────────────────────────────────────────
def add_flagged_bank(bank_name: str, risk_level: str = "alto", reason: str = ""):
    FLAGGED_BANKS[bank_name.lower().strip()] = {
        "risk_level": risk_level,
        "reason": reason,
        "added_at": datetime.now().isoformat(),
    }


def remove_flagged_bank(bank_name: str):
    key = bank_name.lower().strip()
    if key in FLAGGED_BANKS:
        del FLAGGED_BANKS[key]
        return True
    return False


def get_flagged_banks():
    return dict(FLAGGED_BANKS)


# ── Transações pendentes ────────────────────────────────────────────────────
def get_pending_transactions():
    return dict(_pending_transactions)


def release_transaction(tx_id: str):
    if tx_id in _pending_transactions:
        tx = _pending_transactions.pop(tx_id)
        tx["decision"] = "APROVADO (LIBERADO)"
        tx["released_at"] = datetime.now().isoformat()
        for h in _transaction_history:
            if h.get("transaction_id") == tx_id:
                h["decision"] = tx["decision"]
                break
        _save_history()
        return tx
    return None


def reject_transaction(tx_id: str):
    if tx_id in _pending_transactions:
        tx = _pending_transactions.pop(tx_id)
        tx["decision"] = "REJEITADO"
        tx["rejected_at"] = datetime.now().isoformat()
        for h in _transaction_history:
            if h.get("transaction_id") == tx_id:
                h["decision"] = tx["decision"]
                break
        _save_history()
        return tx
    return None


# ── Histórico ────────────────────────────────────────────────────────────────
def get_transaction_history(limit: int = 100):
    return list(reversed(_transaction_history[-limit:]))


# ── IP Público Real ──────────────────────────────────────────────────────────
def get_real_public_ip() -> str:
    global _real_public_ip
    if _real_public_ip:
        return _real_public_ip
    try:
        resp = requests.get("https://api.ipify.org?format=json", timeout=5)
        _real_public_ip = resp.json().get("ip", "")
        return _real_public_ip
    except Exception:
        return ""


def resolve_ip(ip: str) -> str:
    if ip in ("127.0.0.1", "localhost", "::1", "unknown", ""):
        real = get_real_public_ip()
        return real if real else ip
    return ip


# ── Utilidades ───────────────────────────────────────────────────────────────
def _name_similarity(name1: str, name2: str) -> float:
    if not name1 or not name2:
        return 0.0
    n1 = re.sub(r"[^a-zA-ZÀ-ÿ\s]", "", name1.lower().strip())
    n2 = re.sub(r"[^a-zA-ZÀ-ÿ\s]", "", name2.lower().strip())
    return SequenceMatcher(None, n1, n2).ratio()


def _extract_name_from_email(email: str) -> str:
    if not email or "@" not in email:
        return ""
    prefix = email.split("@")[0]
    prefix = re.sub(r"[._\-\d]+", " ", prefix)
    return prefix.strip()


def _is_high_risk_hour(hour: int) -> bool:
    return 1 <= hour <= 5


def validate_card_expiry(expiry: str) -> dict:
    if not expiry:
        return {"valid": True, "message": ""}
    expiry = expiry.strip()
    match = re.match(r"^(\d{2})/(\d{2,4})$", expiry)
    if not match:
        return {"valid": False, "message": "Formato inválido. Use MM/AA"}
    month = int(match.group(1))
    year_str = match.group(2)
    if month < 1 or month > 12:
        return {"valid": False, "message": f"Mês inválido: {month:02d}"}
    year = 2000 + int(year_str) if len(year_str) == 2 else int(year_str)
    now = datetime.now()
    if year < now.year or (year == now.year and month < now.month):
        return {"valid": False, "expired": True, "message": f"Cartão vencido ({month:02d}/{year_str})"}
    return {"valid": True, "month": month, "year": year, "message": ""}


def _validate_cpf(cpf: str) -> bool:
    cpf = re.sub(r"\D", "", cpf)
    if len(cpf) != 11:
        return False
    if cpf == cpf[0] * 11:
        return False
    total = sum(int(cpf[i]) * (10 - i) for i in range(9))
    d1 = 11 - (total % 11)
    if d1 >= 10:
        d1 = 0
    if d1 != int(cpf[9]):
        return False
    total = sum(int(cpf[i]) * (11 - i) for i in range(10))
    d2 = 11 - (total % 11)
    if d2 >= 10:
        d2 = 0
    if d2 != int(cpf[10]):
        return False
    return True


def get_ip_geolocation(ip: str) -> dict:
    if not ip or ip in ("unknown", ""):
        return {
            "ip": ip, "city": "", "region": "", "country": "",
            "isp": "", "proxy": False, "success": False,
            "error": "IP inválido",
        }
    if ip in ("127.0.0.1", "localhost", "::1"):
        return {
            "ip": ip, "city": "", "region": "", "country": "",
            "isp": "", "proxy": False, "success": False,
            "error": "IP local",
        }
    if ip in _ip_geo_cache:
        return _ip_geo_cache[ip]

    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,message,country,regionName,city,isp,proxy,hosting,query"},
            timeout=5,
        )
        data = resp.json()
        if data.get("status") == "success":
            result = {
                "ip": ip,
                "city": data.get("city", ""),
                "region": data.get("regionName", ""),
                "country": data.get("country", ""),
                "isp": data.get("isp", ""),
                "proxy": data.get("proxy", False),
                "hosting": data.get("hosting", False),
                "success": True,
            }
        else:
            result = {
                "ip": ip, "city": "", "region": "", "country": "",
                "isp": "", "proxy": False, "success": False,
                "error": data.get("message", "Erro desconhecido"),
            }
        _ip_geo_cache[ip] = result
        return result
    except Exception as e:
        return {
            "ip": ip, "city": "", "region": "", "country": "",
            "isp": "", "proxy": False, "success": False,
            "error": str(e),
        }


def _check_ip(ip: str, declared_city: str, declared_state: str) -> dict:
    alerts = []
    risk = 0
    geo = get_ip_geolocation(ip)

    if geo.get("proxy") or geo.get("hosting"):
        alerts.append(f"IP detectado como proxy/VPN/hosting ({geo.get('isp', 'N/A')})")
        risk += 25

    if geo.get("success") and declared_city:
        ip_city = geo.get("city", "").lower().strip()
        decl_city = declared_city.lower().strip()
        if ip_city and decl_city and ip_city != decl_city:
            sim = _name_similarity(ip_city, decl_city)
            if sim < 0.5:
                alerts.append(
                    f"Cidade do IP ({geo['city']}, {geo['region']}) diverge da declarada ({declared_city}, {declared_state})"
                )
                risk += 20

    return {"alerts": alerts, "risk_score": risk, "geolocation": geo}


def _check_velocity(card_last4: str, card_holder_name: str) -> dict:
    alerts = []
    risk = 0
    auto_block = False
    now = datetime.now()

    cutoff = now - timedelta(hours=24)
    _card_attempts[card_last4] = [
        a for a in _card_attempts[card_last4] if a["timestamp"] > cutoff
    ]

    _card_attempts[card_last4].append({
        "name": card_holder_name,
        "timestamp": now,
    })

    attempts = _card_attempts[card_last4]
    total_attempts = len(attempts)
    unique_names = set(a["name"].lower().strip() for a in attempts)

    if total_attempts >= 5:
        alerts.append(f"Cartão *{card_last4} usado {total_attempts}x nas últimas 24h")
        risk += 20

    if len(unique_names) >= 3:
        alerts.append(
            f"Cartão *{card_last4} usado com {len(unique_names)} nomes diferentes: "
            f"{', '.join(unique_names)}"
        )
        risk += 30

    if total_attempts >= 5 and len(unique_names) >= 2:
        alerts.append("Padrão de fraudador — múltiplas tentativas com nomes diferentes")
        risk += 25
        auto_block = True

    if total_attempts >= 10:
        alerts.append(f"Tentativas excessivas: {total_attempts}x em 24h — bloqueio automático")
        risk += 30
        auto_block = True

    return {
        "alerts": alerts,
        "risk_score": risk,
        "total_attempts_24h": total_attempts,
        "unique_names": list(unique_names),
        "auto_block": auto_block,
    }


def _ml_prediction(amount: float, time_seconds: float = 0) -> dict:
    if _model is None or _scaler is None:
        return {"available": False, "probability": 0.0, "prediction": "unavailable"}

    features = np.zeros(30)
    features[0] = time_seconds
    features[29] = amount

    time_amount = np.array([[time_seconds, amount]])
    time_amount_scaled = _scaler.transform(time_amount)
    features[0] = time_amount_scaled[0][0]
    features[29] = time_amount_scaled[0][1]

    features = features.reshape(1, -1)
    proba = _model.predict_proba(features)[0]
    fraud_prob = float(proba[1]) if len(proba) > 1 else 0.0

    return {
        "available": True,
        "probability": round(fraud_prob * 100, 2),
        "prediction": "fraud" if fraud_prob > 0.5 else "legitimate",
    }


def analyze_transaction(data: dict) -> dict:
    """
    Analisa uma transação. Suporta cartão, PIX e boleto.
    Retorna customer_response (genérico) e details (admin).
    """
    alerts = []
    risk_score = 0
    details = {}
    blocked_by = []

    amount = data.get("amount", 0)
    payment_method = data.get("payment_method", "credit_card")
    card_holder = data.get("card_holder_name", "")
    customer_name = data.get("customer_name", "")
    email = data.get("email", "")
    cpf = data.get("cpf", "")
    ip_address = data.get("ip_address", "")
    city = data.get("city", "")
    state = data.get("state", "")
    bank_name = data.get("bank_name", "")
    purchase_hour = data.get("purchase_hour", datetime.now().hour)
    card_last4 = data.get("card_last4", "")
    card_expiry = data.get("card_expiry", "")

    # ── 0. Verificar bloqueios ───────────────────────────────────────────
    if email:
        check = is_entity_blocked("email", email)
        if check["blocked"]:
            blocked_by.append(f"Email bloqueado: {email} ({check.get('reason', '')})")
    if cpf:
        cpf_clean = re.sub(r"\D", "", cpf)
        check = is_entity_blocked("cpf", cpf_clean)
        if check["blocked"]:
            blocked_by.append(f"CPF bloqueado: {cpf} ({check.get('reason', '')})")
    if ip_address:
        check = is_entity_blocked("ip", ip_address)
        if check["blocked"]:
            blocked_by.append(f"IP bloqueado: {ip_address} ({check.get('reason', '')})")

    # ── 0b. Verificar bloqueios combinados ───────────────────────────────
    combo_matches = _check_combos(data)
    blocked_by.extend(combo_matches)

    if blocked_by:
        alerts.extend(blocked_by)
        risk_score = 100
        details["blocked_entities"] = blocked_by

    # ── 1. Validação de CPF ──────────────────────────────────────────────
    if cpf:
        cpf_clean = re.sub(r"\D", "", cpf)
        cpf_valid = _validate_cpf(cpf_clean)
        if not cpf_valid:
            alerts.append(f"CPF inválido: {cpf}")
            risk_score += 25
        details["cpf_validation"] = {"cpf": cpf, "valid": cpf_valid}

    # ── 2. Validação de validade do cartão ───────────────────────────────
    if payment_method == "credit_card" and card_expiry:
        expiry_check = validate_card_expiry(card_expiry)
        if not expiry_check["valid"]:
            alerts.append(f"Cartão: {expiry_check['message']}")
            risk_score += 30 if expiry_check.get("expired") else 15
        details["card_expiry"] = expiry_check

    # ── 3. Análise de valor ──────────────────────────────────────────────
    if amount > 5000:
        alerts.append(f"Transação de alto valor: R$ {amount:,.2f}")
        risk_score += 20
    elif amount > 2000:
        alerts.append(f"Transação de valor elevado: R$ {amount:,.2f}")
        risk_score += 10
    details["amount_analysis"] = {"value": amount}

    # ── 4. Divergência de nomes (cartão) ─────────────────────────────────
    if card_holder and customer_name and payment_method == "credit_card":
        similarity = _name_similarity(card_holder, customer_name)
        details["name_match"] = {
            "card_holder": card_holder,
            "customer_name": customer_name,
            "similarity": round(similarity * 100, 1),
        }
        if similarity < 0.5:
            alerts.append(
                f"Nome do cartão '{card_holder}' diferente do cliente '{customer_name}' "
                f"({similarity*100:.0f}%)"
            )
            risk_score += 30
        elif similarity < 0.8:
            alerts.append(
                f"Nome do cartão parcialmente diferente ({similarity*100:.0f}%)"
            )
            risk_score += 15

    # ── 5. Email vs Nome ─────────────────────────────────────────────────
    if email and customer_name:
        email_name = _extract_name_from_email(email)
        email_sim = _name_similarity(email_name, customer_name)
        details["email_analysis"] = {
            "email": email,
            "extracted_name": email_name,
            "similarity_to_customer": round(email_sim * 100, 1),
        }
        if email_sim < 0.3:
            alerts.append(f"Email '{email}' não corresponde ao cliente '{customer_name}'")
            risk_score += 20

    # ── 6. Horário de compra ─────────────────────────────────────────────
    if _is_high_risk_hour(purchase_hour):
        alerts.append(f"Compra em horário de alto risco: {purchase_hour:02d}:00")
        risk_score += 15
    details["time_analysis"] = {
        "hour": purchase_hour,
        "high_risk": _is_high_risk_hour(purchase_hour),
    }

    # ── 7. IP / Geolocalização ───────────────────────────────────────────
    if ip_address:
        ip_result = _check_ip(ip_address, city, state)
        if ip_result["alerts"]:
            alerts.extend(ip_result["alerts"])
            risk_score += ip_result["risk_score"]
        details["ip_analysis"] = {
            "ip": ip_address,
            "declared_city": city,
            "declared_state": state,
            "geolocation": ip_result["geolocation"],
            "alerts": ip_result["alerts"],
        }

    # ── 7b. Bloqueio por país ─────────────────────────────────────────────
    if _allowed_countries and ip_address:
        geo = details.get("ip_analysis", {}).get("geolocation", {})
        country = geo.get("country", "").lower().strip()
        if country and country not in _allowed_countries:
            country_display = geo.get("country", country)
            allowed_display = ", ".join(c.title() for c in sorted(_allowed_countries))
            msg = f"País bloqueado: {country_display} (apenas {allowed_display} permitido)"
            alerts.append(msg)
            blocked_by.append(msg)
            risk_score = max(risk_score, 100)
            details["country_block"] = {"country": country_display, "blocked": True}

    # ── 8. Banco emissor ─────────────────────────────────────────────────
    if bank_name:
        bank_key = bank_name.lower().strip()
        if bank_key in FLAGGED_BANKS:
            bank_info = FLAGGED_BANKS[bank_key]
            alert_msg = (
                f"Banco '{bank_name}' na lista de suspeitos "
                f"(risco: {bank_info['risk_level']})"
            )
            if bank_info.get("reason"):
                alert_msg += f" — {bank_info['reason']}"
            alerts.append(alert_msg)
            risk_add = {"alto": 35, "medio": 20, "baixo": 10}.get(
                bank_info["risk_level"], 20
            )
            risk_score += risk_add
            details["bank_analysis"] = {
                "bank": bank_name,
                "flagged": True,
                "risk_level": bank_info["risk_level"],
            }
        else:
            details["bank_analysis"] = {"bank": bank_name, "flagged": False}

    # ── 9. Velocity check (cartão) ───────────────────────────────────────
    auto_block_entity = False
    if card_last4 and payment_method == "credit_card":
        velocity = _check_velocity(card_last4, card_holder)
        if velocity["alerts"]:
            alerts.extend(velocity["alerts"])
            risk_score += velocity["risk_score"]
        if velocity.get("auto_block"):
            auto_block_entity = True
        details["velocity_check"] = {
            "attempts_24h": velocity["total_attempts_24h"],
            "unique_names": velocity["unique_names"],
        }

    # ── 10. Predição ML ──────────────────────────────────────────────────
    ml_result = _ml_prediction(amount, purchase_hour * 3600)
    details["ml_prediction"] = ml_result
    if ml_result["available"] and ml_result["probability"] > 50:
        alerts.append(f"ML: probabilidade de fraude {ml_result['probability']}%")
        risk_score += int(ml_result["probability"] * 0.3)

    # ── Score final ──────────────────────────────────────────────────────
    risk_score = min(risk_score, 100)

    if risk_score >= 70:
        decision = "BLOQUEADO"
        decision_reason = "Score de risco muito alto"
        customer_message = "Não foi possível processar seu pagamento. Verifique os dados e tente novamente."
        customer_status = "error"
    elif risk_score >= 40:
        decision = "REVISÃO MANUAL"
        decision_reason = "Score de risco moderado — aguardando revisão"
        customer_message = "Seu pagamento está sendo processado. Você receberá uma confirmação em breve."
        customer_status = "processing"
    else:
        decision = "APROVADO"
        decision_reason = "Transação dentro dos parâmetros normais"
        customer_message = "Pagamento aprovado com sucesso!"
        customer_status = "success"

    tx_raw = f"{card_last4}{cpf}{amount}{datetime.now().isoformat()}"
    tx_id = f"TX-{hashlib.sha256(tx_raw.encode()).hexdigest()[:12].upper()}"

    result = {
        "transaction_id": tx_id,
        "timestamp": datetime.now().isoformat(),
        "payment_method": payment_method,
        "risk_score": risk_score,
        "decision": decision,
        "decision_reason": decision_reason,
        "alerts": alerts,
        "alert_count": len(alerts),
        "details": details,
        "customer_response": {
            "message": customer_message,
            "status": customer_status,
            "transaction_id": tx_id,
        },
    }

    # Salvar no histórico
    history_entry = {
        "transaction_id": tx_id,
        "timestamp": result["timestamp"],
        "payment_method": payment_method,
        "amount": amount,
        "customer_name": customer_name,
        "email": email,
        "cpf": re.sub(r"\D", "", cpf) if cpf else "",
        "ip": ip_address,
        "risk_score": risk_score,
        "decision": decision,
        "alert_count": len(alerts),
        "alerts": alerts,
    }
    _transaction_history.append(history_entry)
    _save_history()

    if decision in ("BLOQUEADO", "REVISÃO MANUAL"):
        _pending_transactions[tx_id] = result

    # Auto-block se velocity detectou padrão de fraude
    if auto_block_entity:
        if email:
            block_entity("email", email, "Bloqueio automático: tentativas excessivas")
        if cpf:
            block_entity("cpf", re.sub(r"\D", "", cpf), "Bloqueio automático: tentativas excessivas")

    return result
