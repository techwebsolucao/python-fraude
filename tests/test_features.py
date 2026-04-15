"""
test_features.py - Testes de feature (integração via HTTP) para todos os endpoints.

Cada grupo de testes cobre um domínio funcional da API.
O fixture `client` em conftest.py fornece um TestClient com externos mockados.
"""

import pytest
from unittest.mock import patch

from tests.conftest import GEO_BRAZIL, VALID_PAYLOAD


# ── Hepers ───────────────────────────────────────────────────────────────────

def _create_manual_review(client):
    """
    Envia payload que acumula 45 pts de risco → decisão REVISÃO MANUAL.
    Composição:
      - amount 2500  → +10 (valor elevado)
      - purchase_hour 3 → +15 (horário de risco)
      - email 'xfactory2023@email.com' vs customer_name 'Maria Oliveira' → +20 (mismatch)
    Total: 45 → REVISÃO MANUAL (40–69)
    """
    payload = {
        **VALID_PAYLOAD,
        "amount": 2500.00,
        "purchase_hour": 3,
        "email": "xfactory2023@email.com",
    }
    r = client.post("/api/payment", json=payload)
    assert r.status_code == 200
    data = r.json()
    assert data["decision"] == "REVISÃO MANUAL", (
        f"Esperado REVISÃO MANUAL, obtido {data['decision']} (score={data['risk_score']})"
    )
    return data


# ── Transação aprovada ───────────────────────────────────────────────────────

class TestApprovedTransaction:
    def test_transacao_valida_e_aprovada(self, client):
        r = client.post("/api/payment", json=VALID_PAYLOAD)
        assert r.status_code == 200
        data = r.json()
        assert data["decision"] == "APROVADO"
        assert data["risk_score"] < 40
        assert data["customer_response"]["status"] == "success"

    def test_pix_aprovado(self, client):
        r = client.post("/api/payment", json={**VALID_PAYLOAD, "payment_method": "pix"})
        assert r.json()["decision"] == "APROVADO"

    def test_boleto_aprovado(self, client):
        r = client.post("/api/payment", json={**VALID_PAYLOAD, "payment_method": "boleto"})
        assert r.json()["decision"] == "APROVADO"

    def test_response_contem_todos_os_campos_obrigatorios(self, client):
        r = client.post("/api/payment", json=VALID_PAYLOAD)
        data = r.json()
        for field in ("transaction_id", "timestamp", "risk_score", "decision",
                      "alerts", "alert_count", "details", "customer_response"):
            assert field in data, f"Campo '{field}' ausente na resposta"

    def test_transaction_id_tem_formato_esperado(self, client):
        r = client.post("/api/payment", json=VALID_PAYLOAD)
        tx_id = r.json()["transaction_id"]
        assert tx_id.startswith("TX-")
        assert len(tx_id) == 15  # "TX-" + 12 hex chars

    def test_customer_response_nao_expoe_detalhes_de_fraude(self, client):
        # A mensagem do customer_response deve ser genérica
        r = client.post("/api/payment", json=VALID_PAYLOAD)
        msg = r.json()["customer_response"]["message"]
        assert "score" not in msg.lower()
        assert "fraude" not in msg.lower()
        assert "bloqueado" not in msg.lower()


# ── Bloqueio de entidades ────────────────────────────────────────────────────

class TestBlockedEntities:
    def test_email_bloqueado_retorna_score_100(self, client):
        client.post("/api/block", json={"entity_type": "email", "value": "fraud@test.com", "reason": "teste"})
        r = client.post("/api/payment", json={**VALID_PAYLOAD, "email": "fraud@test.com"})
        data = r.json()
        assert data["decision"] == "BLOQUEADO"
        assert data["risk_score"] == 100

    def test_cpf_bloqueado_retorna_score_100(self, client):
        # Blocklist usa CPF sem formatação; pagamento pode enviar formatado
        client.post("/api/block", json={"entity_type": "cpf", "value": "52998224725", "reason": "teste"})
        r = client.post("/api/payment", json={**VALID_PAYLOAD, "cpf": "529.982.247-25"})
        data = r.json()
        assert data["decision"] == "BLOQUEADO"
        assert data["risk_score"] == 100

    def test_ip_bloqueado_retorna_score_100(self, client):
        client.post("/api/block", json={"entity_type": "ip", "value": "1.2.3.4", "reason": "teste"})
        r = client.post("/api/payment", json={**VALID_PAYLOAD, "ip_address": "1.2.3.4"})
        data = r.json()
        assert data["decision"] == "BLOQUEADO"
        assert data["risk_score"] == 100

    def test_desbloquear_remove_restricao(self, client):
        client.post("/api/block", json={"entity_type": "email", "value": "temp@test.com", "reason": ""})
        client.delete("/api/block/email/temp@test.com")
        r = client.post("/api/payment", json={**VALID_PAYLOAD, "email": "temp@test.com"})
        assert r.json()["decision"] == "APROVADO"

    def test_listar_entidades_bloqueadas(self, client):
        client.post("/api/block", json={"entity_type": "email", "value": "x@x.com", "reason": "teste"})
        client.post("/api/block", json={"entity_type": "ip", "value": "9.9.9.9", "reason": "teste"})
        r = client.get("/api/blocked")
        assert r.status_code == 200
        blocked = r.json()["blocked"]
        assert "x@x.com" in blocked["email"]
        assert "9.9.9.9" in blocked["ip"]

    def test_desbloquear_entidade_inexistente_retorna_error(self, client):
        r = client.delete("/api/block/email/nobody@test.com")
        assert r.json().get("error") is True


# ── Bloqueios combinados ─────────────────────────────────────────────────────

class TestComboBlocks:
    def test_combo_bloqueia_quando_todos_campos_coincidem(self, client):
        client.post("/api/combos", json={
            "conditions": {"email": "fraud@test.com", "cpf": "52998224725"},
            "reason": "teste",
        })
        r = client.post("/api/payment", json={
            **VALID_PAYLOAD,
            "email": "fraud@test.com",
            "cpf": "529.982.247-25",     # strips para 52998224725 no check
        })
        assert r.json()["decision"] == "BLOQUEADO"

    def test_combo_nao_bloqueia_por_match_parcial(self, client):
        # Combo: email + ip específico. Apenas o email coincide, IP é diferente.
        client.post("/api/combos", json={
            "conditions": {"email": "fraud@test.com", "ip": "1.2.3.4"},
            "reason": "teste",
        })
        r = client.post("/api/payment", json={
            **VALID_PAYLOAD,
            "email": "fraud@test.com",
            "ip_address": "189.40.12.55",   # diferente de 1.2.3.4
        })
        alerts = r.json()["alerts"]
        assert not any("Bloqueio combinado" in a for a in alerts)

    def test_remover_combo_libera_transacao(self, client):
        resp = client.post("/api/combos", json={
            "conditions": {"email": "a@b.com", "ip": "1.2.3.4"},
            "reason": "",
        })
        combo_id = resp.json()["combo_id"]
        client.delete(f"/api/combos/{combo_id}")

        r = client.post("/api/payment", json={
            **VALID_PAYLOAD,
            "email": "a@b.com",
            "ip_address": "1.2.3.4",
        })
        alerts = r.json()["alerts"]
        assert not any("Bloqueio combinado" in a for a in alerts)

    def test_listar_combos(self, client):
        client.post("/api/combos", json={"conditions": {"email": "a@b.com", "ip": "1.2.3.4"}, "reason": ""})
        r = client.get("/api/combos")
        assert r.status_code == 200
        assert len(r.json()["combos"]) == 1

    def test_combo_com_campo_unico_retorna_error(self, client):
        r = client.post("/api/combos", json={"conditions": {"email": "a@b.com"}, "reason": ""})
        assert r.json().get("error") is True

    def test_remover_combo_inexistente_retorna_error(self, client):
        r = client.delete("/api/combos/inexistente")
        assert r.json().get("error") is True


# ── Regras de detecção de fraude ─────────────────────────────────────────────

class TestFraudDetectionRules:
    def test_cpf_invalido_adiciona_alerta_e_eleva_score(self, client):
        r = client.post("/api/payment", json={**VALID_PAYLOAD, "cpf": "111.111.111-11"})
        data = r.json()
        assert any("CPF" in a for a in data["alerts"])
        assert data["risk_score"] >= 25

    def test_cartao_vencido_adiciona_alerta(self, client):
        r = client.post("/api/payment", json={**VALID_PAYLOAD, "card_expiry": "01/20"})
        data = r.json()
        assert any("cartão" in a.lower() or "venc" in a.lower() for a in data["alerts"])

    def test_horario_madrugada_adiciona_alerta(self, client):
        r = client.post("/api/payment", json={**VALID_PAYLOAD, "purchase_hour": 3})
        data = r.json()
        assert any("03:00" in a or "horário" in a.lower() for a in data["alerts"])
        assert data["risk_score"] >= 15

    def test_valor_alto_acima_de_5000_adiciona_alerta(self, client):
        r = client.post("/api/payment", json={**VALID_PAYLOAD, "amount": 6000.00})
        data = r.json()
        assert any("alto valor" in a.lower() for a in data["alerts"])
        assert data["risk_score"] >= 20

    def test_valor_elevado_entre_2000_e_5000_adiciona_alerta(self, client):
        r = client.post("/api/payment", json={**VALID_PAYLOAD, "amount": 3000.00})
        data = r.json()
        assert any("elevado" in a.lower() for a in data["alerts"])
        assert data["risk_score"] >= 10

    def test_nome_cartao_muito_diferente_adiciona_alerta(self, client):
        r = client.post("/api/payment", json={**VALID_PAYLOAD, "card_holder_name": "JUAN RODRIGUEZ"})
        data = r.json()
        assert any("nome" in a.lower() or "cartão" in a.lower() for a in data["alerts"])
        sim = data["details"]["name_match"]["similarity"]
        assert sim < 50.0

    def test_pais_bloqueado_retorna_decision_bloqueado(self, client):
        geo_argentina = {**GEO_BRAZIL, "country": "Argentina", "city": "Buenos Aires", "region": "Buenos Aires"}
        with patch("fraud_engine.get_ip_geolocation", return_value=geo_argentina):
            r = client.post("/api/payment", json=VALID_PAYLOAD)
        data = r.json()
        assert data["decision"] == "BLOQUEADO"
        assert any("país" in a.lower() or "pa" in a.lower() for a in data["alerts"])

    def test_pais_bloqueado_nao_afeta_ip_permitido(self, client):
        # Brasil está na allowlist, transação deve ser aprovada
        r = client.post("/api/payment", json=VALID_PAYLOAD)
        assert r.json()["decision"] == "APROVADO"

    def test_banco_suspeito_nivel_alto_adiciona_35_pts(self, client):
        import fraud_engine
        fraud_engine.add_flagged_bank("BANCO SUSPEITO S.A.", "alto", "teste")
        bin_result = {
            "success": True, "bin": "45320123", "scheme": "VISA", "type": "CREDIT",
            "issuer": "BANCO SUSPEITO S.A.", "card_tier": "CLASSIC", "country": "Brazil", "luhn": True,
        }
        with patch("fraud_engine.lookup_bin", return_value=bin_result):
            r = client.post("/api/payment", json=VALID_PAYLOAD)
        data = r.json()
        assert data["details"]["bank_analysis"]["flagged"] is True
        assert data["risk_score"] >= 35

    def test_banco_suspeito_nivel_medio_adiciona_20_pts(self, client):
        import fraud_engine
        fraud_engine.add_flagged_bank("BANCO MEDIO S.A.", "medio", "teste")
        bin_result = {
            "success": True, "bin": "45320123", "scheme": "VISA", "type": "CREDIT",
            "issuer": "BANCO MEDIO S.A.", "card_tier": "CLASSIC", "country": "Brazil", "luhn": True,
        }
        with patch("fraud_engine.lookup_bin", return_value=bin_result):
            r = client.post("/api/payment", json=VALID_PAYLOAD)
        data = r.json()
        assert data["risk_score"] >= 20

    def test_ip_proxy_adiciona_alerta(self, client):
        geo_proxy = {**GEO_BRAZIL, "proxy": True, "isp": "VPN Provider Inc."}
        with patch("fraud_engine.get_ip_geolocation", return_value=geo_proxy):
            r = client.post("/api/payment", json=VALID_PAYLOAD)
        data = r.json()
        assert any("proxy" in a.lower() or "vpn" in a.lower() for a in data["alerts"])
        assert data["risk_score"] >= 25

    def test_cidade_ip_diverge_da_declarada_adiciona_alerta(self, client):
        geo_outra_cidade = {**GEO_BRAZIL, "city": "Manaus", "region": "Amazonas"}
        with patch("fraud_engine.get_ip_geolocation", return_value=geo_outra_cidade):
            # Payload declara "São Paulo" mas IP aponta para Manaus
            r = client.post("/api/payment", json=VALID_PAYLOAD)
        data = r.json()
        assert any("cidade" in a.lower() or "diverge" in a.lower() for a in data["alerts"])


# ── Revisão manual e fila pendente ───────────────────────────────────────────

class TestManualReview:
    def test_transacao_media_risco_vai_para_revisao_manual(self, client):
        data = _create_manual_review(client)
        assert data["decision"] == "REVISÃO MANUAL"
        assert 40 <= data["risk_score"] <= 69
        assert data["customer_response"]["status"] == "processing"

    def test_transacao_revisao_manual_aparece_na_fila_pendente(self, client):
        data = _create_manual_review(client)
        tx_id = data["transaction_id"]
        r = client.get("/api/transactions/pending")
        assert tx_id in r.json()["pending"]

    def test_liberar_transacao_pendente(self, client):
        tx_id = _create_manual_review(client)["transaction_id"]
        r = client.post(f"/api/transactions/{tx_id}/release")
        assert r.status_code == 200
        assert "APROVADO" in r.json()["transaction"]["decision"]
        # Não deve mais estar na fila
        assert tx_id not in client.get("/api/transactions/pending").json()["pending"]

    def test_rejeitar_transacao_pendente(self, client):
        tx_id = _create_manual_review(client)["transaction_id"]
        r = client.post(f"/api/transactions/{tx_id}/reject")
        assert r.status_code == 200
        assert r.json()["transaction"]["decision"] == "REJEITADO"
        assert tx_id not in client.get("/api/transactions/pending").json()["pending"]

    def test_liberar_tx_inexistente_retorna_error(self, client):
        r = client.post("/api/transactions/TX-INEXISTENTE123/release")
        assert r.json().get("error") is True

    def test_rejeitar_tx_inexistente_retorna_error(self, client):
        r = client.post("/api/transactions/TX-INEXISTENTE123/reject")
        assert r.json().get("error") is True


# ── Histórico de transações ──────────────────────────────────────────────────

class TestTransactionHistory:
    def test_historico_registra_transacao(self, client):
        client.post("/api/payment", json=VALID_PAYLOAD)
        r = client.get("/api/transactions/history")
        assert r.status_code == 200
        assert len(r.json()["history"]) >= 1

    def test_historico_respeita_parametro_limit(self, client):
        for _ in range(5):
            client.post("/api/payment", json=VALID_PAYLOAD)
        r = client.get("/api/transactions/history?limit=3")
        assert len(r.json()["history"]) == 3

    def test_historico_retorna_mais_recente_primeiro(self, client):
        client.post("/api/payment", json=VALID_PAYLOAD)
        client.post("/api/payment", json={**VALID_PAYLOAD, "amount": 500.00})
        history = client.get("/api/transactions/history").json()["history"]
        # O primeiro item deve ser o mais recente (maior timestamp)
        assert history[0]["timestamp"] >= history[1]["timestamp"]


# ── Gerenciamento de países ──────────────────────────────────────────────────

class TestCountryManagement:
    def test_get_countries_retorna_lista(self, client):
        r = client.get("/api/countries")
        assert r.status_code == 200
        assert "brazil" in r.json()["allowed_countries"]

    def test_adicionar_pais(self, client):
        r = client.post("/api/countries/Argentina")
        assert r.status_code == 200
        assert "argentina" in r.json()["allowed_countries"]

    def test_remover_pais(self, client):
        r = client.delete("/api/countries/brazil")
        assert r.status_code == 200
        assert "brazil" not in r.json()["allowed_countries"]

    def test_remover_pais_inexistente_retorna_error(self, client):
        r = client.delete("/api/countries/Inexistente")
        assert r.json().get("error") is True

    def test_set_countries_substitui_lista_completa(self, client):
        r = client.post("/api/countries", json={"countries": ["United States", "Canada"]})
        assert r.status_code == 200
        countries = r.json()["allowed_countries"]
        assert "brazil" not in countries
        assert "united states" in countries
        assert "canada" in countries

    def test_set_countries_vazia_libera_todos(self, client):
        r = client.post("/api/countries", json={"countries": []})
        assert r.json()["allowed_countries"] == []


# ── Gerenciamento de bancos suspeitos ────────────────────────────────────────

class TestBankManagement:
    def test_marcar_banco_suspeito(self, client):
        r = client.post("/api/banks/flag", json={
            "bank_name": "BANCO XYZ S.A.", "risk_level": "alto", "reason": "chargebacks"
        })
        assert r.status_code == 200
        assert "marcado" in r.json()["message"].lower()

    def test_listar_bancos_suspeitos(self, client):
        client.post("/api/banks/flag", json={"bank_name": "BANCO XYZ S.A.", "risk_level": "medio", "reason": ""})
        r = client.get("/api/banks/flagged")
        assert r.status_code == 200
        assert "BANCO XYZ S.A." in r.json()["flagged_banks"]

    def test_desmarcar_banco_suspeito(self, client):
        client.post("/api/banks/flag", json={"bank_name": "BANCO XYZ S.A.", "risk_level": "baixo", "reason": ""})
        r = client.delete("/api/banks/flag/BANCO XYZ S.A.")
        assert r.status_code == 200
        assert "BANCO XYZ S.A." not in client.get("/api/banks/flagged").json()["flagged_banks"]

    def test_desmarcar_banco_inexistente_retorna_error(self, client):
        r = client.delete("/api/banks/flag/BANCO INEXISTENTE SA")
        assert r.json().get("error") is True

    def test_risk_level_invalido_retorna_422(self, client):
        r = client.post("/api/banks/flag", json={
            "bank_name": "BANCO XYZ S.A.", "risk_level": "extremo", "reason": ""
        })
        assert r.status_code == 422


# ── Health check ─────────────────────────────────────────────────────────────

class TestHealthEndpoint:
    def test_health_retorna_online(self, client):
        r = client.get("/api/health")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "online"
        assert "model_loaded" in data
        assert "timestamp" in data

    def test_health_reflete_contagem_de_transacoes(self, client):
        client.post("/api/payment", json=VALID_PAYLOAD)
        r = client.get("/api/health")
        assert r.json()["total_transactions"] >= 1

    def test_health_reflete_entidades_bloqueadas(self, client):
        client.post("/api/block", json={"entity_type": "email", "value": "x@x.com", "reason": ""})
        r = client.get("/api/health")
        assert r.json()["blocked_entities"] >= 1
