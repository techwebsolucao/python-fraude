"""
test_unit.py - Testes unitários para as funções do fraud_engine.

Testa cada função isoladamente, sem chamadas HTTP.
O fixture `reset_state` em conftest.py é autouse e garante estado limpo em cada teste.
"""

import pytest
from unittest.mock import patch

import fraud_engine as fe


# ── Validação de CPF ─────────────────────────────────────────────────────────

class TestCPFValidation:
    def test_cpf_valido(self):
        assert fe._validate_cpf("52998224725") is True

    def test_cpf_formatado_valido(self):
        # A função limpa os caracteres não numéricos internamente
        assert fe._validate_cpf("529.982.247-25") is True

    def test_cpf_digito_verificador_errado(self):
        assert fe._validate_cpf("52998224726") is False

    def test_cpf_todos_digitos_iguais(self):
        assert fe._validate_cpf("11111111111") is False
        assert fe._validate_cpf("00000000000") is False

    def test_cpf_curto_demais(self):
        assert fe._validate_cpf("12345678") is False

    def test_cpf_vazio(self):
        assert fe._validate_cpf("") is False


# ── Validade do cartão ───────────────────────────────────────────────────────

class TestCardExpiry:
    def test_cartao_valido(self):
        result = fe.validate_card_expiry("12/30")
        assert result["valid"] is True
        assert result["month"] == 12
        assert result["year"] == 2030

    def test_cartao_vencido(self):
        result = fe.validate_card_expiry("01/20")
        assert result["valid"] is False
        assert result.get("expired") is True
        assert "vencido" in result["message"].lower()

    def test_formato_invalido(self):
        result = fe.validate_card_expiry("1220")
        assert result["valid"] is False

    def test_mes_zero_invalido(self):
        result = fe.validate_card_expiry("00/30")
        assert result["valid"] is False

    def test_mes_treze_invalido(self):
        result = fe.validate_card_expiry("13/30")
        assert result["valid"] is False

    def test_campo_vazio_considerado_valido(self):
        result = fe.validate_card_expiry("")
        assert result["valid"] is True

    def test_formato_ano_quatro_digitos(self):
        result = fe.validate_card_expiry("06/2035")
        assert result["valid"] is True
        assert result["year"] == 2035


# ── Similaridade de nomes ────────────────────────────────────────────────────

class TestNameSimilarity:
    def test_nomes_identicos(self):
        assert fe._name_similarity("Maria Oliveira", "Maria Oliveira") == 1.0

    def test_nomes_identicos_case_diferente(self):
        sim = fe._name_similarity("MARIA OLIVEIRA", "maria oliveira")
        assert sim == 1.0

    def test_nomes_parcialmente_iguais(self):
        sim = fe._name_similarity("Maria Oliveira", "Maria Santos")
        assert 0.0 < sim < 1.0

    def test_nomes_completamente_diferentes(self):
        sim = fe._name_similarity("Juan Rodriguez", "Maria Oliveira")
        assert sim < 0.5

    def test_nome_vazio_retorna_zero(self):
        assert fe._name_similarity("", "Maria Oliveira") == 0.0
        assert fe._name_similarity("Maria Oliveira", "") == 0.0

    def test_ambos_vazios_retorna_zero(self):
        assert fe._name_similarity("", "") == 0.0


# ── Extração de nome do email ────────────────────────────────────────────────

class TestExtractNameFromEmail:
    def test_email_simples(self):
        result = fe._extract_name_from_email("maria@empresa.com")
        assert result == "maria"

    def test_email_com_ponto(self):
        result = fe._extract_name_from_email("maria.oliveira@empresa.com")
        assert "maria" in result
        assert "oliveira" in result

    def test_email_com_numeros(self):
        result = fe._extract_name_from_email("user123@email.com")
        assert "123" not in result

    def test_sem_arroba_retorna_vazio(self):
        assert fe._extract_name_from_email("notanemail") == ""

    def test_email_vazio_retorna_vazio(self):
        assert fe._extract_name_from_email("") == ""


# ── Horário de alto risco ────────────────────────────────────────────────────

class TestHighRiskHour:
    @pytest.mark.parametrize("hour", [1, 2, 3, 4, 5])
    def test_horario_de_risco_alto(self, hour):
        assert fe._is_high_risk_hour(hour) is True

    @pytest.mark.parametrize("hour", [0, 6, 12, 18, 23])
    def test_horario_seguro(self, hour):
        assert fe._is_high_risk_hour(hour) is False


# ── Bloqueio de entidades ────────────────────────────────────────────────────

class TestEntityBlocking:
    def test_bloquear_email(self):
        fe.block_entity("email", "bad@test.com", "teste")
        result = fe.is_entity_blocked("email", "bad@test.com")
        assert result["blocked"] is True
        assert result["reason"] == "teste"

    def test_bloquear_cpf(self):
        fe.block_entity("cpf", "52998224725", "fraude")
        assert fe.is_entity_blocked("cpf", "52998224725")["blocked"] is True

    def test_bloquear_ip(self):
        fe.block_entity("ip", "1.2.3.4", "suspeito")
        assert fe.is_entity_blocked("ip", "1.2.3.4")["blocked"] is True

    def test_entidade_nao_bloqueada_por_padrao(self):
        result = fe.is_entity_blocked("email", "clean@test.com")
        assert result["blocked"] is False

    def test_desbloquear_entidade(self):
        fe.block_entity("email", "temp@test.com", "")
        assert fe.unblock_entity("email", "temp@test.com") is True
        assert fe.is_entity_blocked("email", "temp@test.com")["blocked"] is False

    def test_desbloquear_inexistente_retorna_false(self):
        assert fe.unblock_entity("email", "nobody@test.com") is False

    def test_bloqueio_normaliza_case(self):
        fe.block_entity("email", "BAD@TEST.COM", "")
        assert fe.is_entity_blocked("email", "bad@test.com")["blocked"] is True

    def test_tipo_invalido_retorna_false(self):
        assert fe.block_entity("telefone", "11999999999", "") is False

    def test_get_blocked_entities_retorna_dict(self):
        fe.block_entity("email", "x@x.com", "")
        blocked = fe.get_blocked_entities()
        assert "x@x.com" in blocked["email"]


# ── Bloqueios combinados ─────────────────────────────────────────────────────

class TestComboBlocking:
    def test_criar_combo_retorna_id(self):
        combo_id = fe.block_combo({"email": "x@x.com", "cpf": "12345678901"}, "teste")
        assert combo_id
        assert len(combo_id) == 8  # uuid4 hex[:8]

    def test_combo_adicionado_na_lista(self):
        fe.block_combo({"email": "x@x.com", "ip": "1.2.3.4"}, "teste")
        combos = fe.get_blocked_combos()
        assert len(combos) == 1
        assert "email" in combos[0]["conditions"]

    def test_check_combos_todos_campos_matches(self):
        fe.block_combo({"email": "fraud@test.com", "cpf": "52998224725"}, "teste")
        tx = {"email": "fraud@test.com", "cpf": "529.982.247-25", "ip_address": "", "card_last4": ""}
        matches = fe._check_combos(tx)
        assert len(matches) == 1

    def test_check_combos_match_parcial_nao_dispara(self):
        fe.block_combo({"email": "fraud@test.com", "ip": "1.2.3.4"}, "teste")
        # Só o email coincide, IP é diferente
        tx = {"email": "fraud@test.com", "cpf": "", "ip_address": "200.100.50.1", "card_last4": ""}
        matches = fe._check_combos(tx)
        assert len(matches) == 0

    def test_remover_combo(self):
        combo_id = fe.block_combo({"email": "a@b.com", "cpf": "00000000000"}, "")
        assert fe.unblock_combo(combo_id) is True
        assert len(fe.get_blocked_combos()) == 0

    def test_remover_combo_inexistente(self):
        assert fe.unblock_combo("inexistente") is False

    def test_combo_normaliza_valores(self):
        fe.block_combo({"email": "FRAUD@TEST.COM", "cpf": "52998224725"}, "")
        # Verifica que foi normalizado para lowercase
        combo = fe.get_blocked_combos()[0]
        assert combo["conditions"]["email"] == "fraud@test.com"


# ── Gerenciamento de países ──────────────────────────────────────────────────

class TestCountryManagement:
    def test_estado_inicial_tem_brazil(self):
        assert "brazil" in fe.get_allowed_countries()

    def test_set_countries_substitui_lista(self):
        fe.set_allowed_countries(["Argentina", "Chile"])
        countries = fe.get_allowed_countries()
        assert "brazil" not in countries
        assert "argentina" in countries
        assert "chile" in countries

    def test_adicionar_pais(self):
        fe.add_allowed_country("Canada")
        assert "canada" in fe.get_allowed_countries()

    def test_adicionar_pais_normaliza_case(self):
        fe.add_allowed_country("UNITED STATES")
        assert "united states" in fe.get_allowed_countries()

    def test_remover_pais(self):
        assert fe.remove_allowed_country("brazil") is True
        assert "brazil" not in fe.get_allowed_countries()

    def test_remover_pais_inexistente_retorna_false(self):
        assert fe.remove_allowed_country("inexistente") is False

    def test_lista_vazia_permite_todos(self):
        fe.set_allowed_countries([])
        assert fe.get_allowed_countries() == []


# ── Gerenciamento de bancos suspeitos ────────────────────────────────────────

class TestBankManagement:
    def test_marcar_banco_suspeito(self):
        fe.add_flagged_bank("BANCO XYZ S.A.", "alto", "chargebacks")
        banks = fe.get_flagged_banks()
        assert "BANCO XYZ S.A." in banks
        assert banks["BANCO XYZ S.A."]["risk_level"] == "alto"
        assert banks["BANCO XYZ S.A."]["reason"] == "chargebacks"

    def test_marcar_banco_normaliza_uppercase(self):
        fe.add_flagged_bank("banco xyz s.a.", "medio", "")
        assert "BANCO XYZ S.A." in fe.get_flagged_banks()

    def test_desmarcar_banco(self):
        fe.add_flagged_bank("BANCO XYZ S.A.", "alto", "")
        assert fe.remove_flagged_bank("BANCO XYZ S.A.") is True
        assert "BANCO XYZ S.A." not in fe.get_flagged_banks()

    def test_desmarcar_banco_inexistente(self):
        assert fe.remove_flagged_bank("BANCO INEXISTENTE S.A.") is False

    def test_substituir_nivel_de_risco(self):
        fe.add_flagged_bank("BANCO XYZ S.A.", "baixo", "")
        fe.add_flagged_bank("BANCO XYZ S.A.", "alto", "atualizado")
        bank = fe.get_flagged_banks()["BANCO XYZ S.A."]
        assert bank["risk_level"] == "alto"
        assert bank["reason"] == "atualizado"


# ── Velocity check ───────────────────────────────────────────────────────────

class TestVelocityCheck:
    def test_primeira_tentativa_sem_alertas(self):
        result = fe._check_velocity("1234", "Maria Oliveira")
        assert result["total_attempts_24h"] == 1
        assert len(result["alerts"]) == 0
        assert result["auto_block"] is False

    def test_cinco_tentativas_dispara_alerta_de_frequencia(self):
        for _ in range(5):
            result = fe._check_velocity("9999", "Maria Oliveira")
        assert result["total_attempts_24h"] == 5
        assert any("5x" in a for a in result["alerts"])

    def test_tres_nomes_distintos_dispara_alerta(self):
        fe._check_velocity("5555", "Maria Oliveira")
        fe._check_velocity("5555", "João Silva")
        result = fe._check_velocity("5555", "Carlos Mendes")
        assert any("nomes diferentes" in a for a in result["alerts"])
        assert result["risk_score"] >= 30

    def test_auto_block_ativado_com_alta_frequencia_e_multiplos_nomes(self):
        # 5+ tentativas com 2+ nomes distintos ativa auto_block
        for i in range(5):
            name = "Maria Oliveira" if i % 2 == 0 else "João Silva"
            fe._check_velocity("7777", name)
        result = fe._check_velocity("7777", "Maria Oliveira")
        assert result.get("auto_block") is True

    def test_reset_entre_testes_garante_isolamento(self):
        # Se o estado foi resetado corretamente, este cartão começa do zero
        result = fe._check_velocity("1234", "Novo Teste")
        assert result["total_attempts_24h"] == 1


# ── Resolução de IP ──────────────────────────────────────────────────────────

class TestResolveIP:
    def test_localhost_resolve_para_ip_publico(self):
        with patch("fraud_engine.get_real_public_ip", return_value="200.100.50.25"):
            assert fe.resolve_ip("127.0.0.1") == "200.100.50.25"

    def test_loopback_ipv6_resolve_para_ip_publico(self):
        with patch("fraud_engine.get_real_public_ip", return_value="200.100.50.25"):
            assert fe.resolve_ip("::1") == "200.100.50.25"

    def test_ip_real_passado_sem_alteracao(self):
        assert fe.resolve_ip("189.40.12.55") == "189.40.12.55"

    def test_ip_vazio_resolve_para_publico(self):
        with patch("fraud_engine.get_real_public_ip", return_value="200.100.50.25"):
            assert fe.resolve_ip("") == "200.100.50.25"

    def test_ip_publico_indisponivel_retorna_original(self):
        with patch("fraud_engine.get_real_public_ip", return_value=""):
            assert fe.resolve_ip("127.0.0.1") == "127.0.0.1"
