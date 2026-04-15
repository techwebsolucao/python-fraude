"""
conftest.py - Fixtures compartilhadas entre test_unit.py e test_features.py
"""

import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient

# ── Constantes reutilizáveis ─────────────────────────────────────────────────

GEO_BRAZIL = {
    "ip": "189.40.12.55",
    "city": "São Paulo",
    "region": "São Paulo",
    "country": "Brazil",
    "isp": "Claro S.A.",
    "proxy": False,
    "hosting": False,
    "success": True,
}

# Payload de transação válida que deve sempre resultar em APROVADO
VALID_PAYLOAD = {
    "amount": 150.00,
    "payment_method": "credit_card",
    "customer_name": "Maria Oliveira",
    "email": "maria@empresa.com",
    "cpf": "529.982.247-25",       # CPF matematicamente válido
    "card_holder_name": "MARIA OLIVEIRA",
    "card_number": "4532 0123 4567 5678",
    "card_expiry": "12/30",         # Válido até 2030
    "ip_address": "189.40.12.55",
    "city": "São Paulo",
    "state": "SP",
    "purchase_hour": 14,
}


# ── Fixture: reset de estado global ─────────────────────────────────────────

@pytest.fixture(autouse=True)
def reset_state(monkeypatch):
    """
    Reseta todos os globals mutáveis do fraud_engine antes de cada teste e
    impede qualquer escrita em disco durante os testes.
    """
    import fraud_engine as fe

    fe._blocked_entities = {"email": {}, "cpf": {}, "ip": {}}
    fe._blocked_combos.clear()
    fe._pending_transactions.clear()
    fe._transaction_history.clear()
    fe._allowed_countries.clear()
    fe._allowed_countries.add("brazil")
    fe._flagged_banks.clear()
    fe._card_attempts.clear()
    fe._bin_cache.clear()
    fe._ip_geo_cache.clear()
    fe._real_public_ip = None

    # Evita escrita em disco em todos os testes
    monkeypatch.setattr(fe, "_save_history", lambda: None)
    monkeypatch.setattr(fe, "_save_blocked", lambda: None)

    yield


# ── Fixture: cliente HTTP ────────────────────────────────────────────────────

@pytest.fixture
def client(reset_state):
    """
    TestClient do FastAPI com:
    - load_model mockado (sem leitura de arquivos)
    - get_ip_geolocation mockado para retornar Brasil (sem chamadas HTTP)
    - lookup_bin mockado para retornar falha silenciosa (sem HandyAPI)
    - get_real_public_ip mockado para evitar chamada ao ipify
    """
    with (
        patch("fraud_engine.load_model"),
        patch("fraud_engine.get_real_public_ip", return_value="189.40.12.55"),
        patch("fraud_engine.get_ip_geolocation", return_value=GEO_BRAZIL),
        patch("fraud_engine.lookup_bin", return_value={"success": False, "error": "no key"}),
    ):
        from app import app
        with TestClient(app, raise_server_exceptions=True) as c:
            yield c
