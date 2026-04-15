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
    title="Agmete — Anti-Fraud Payment API",
    description="""
## Primeira camada de proteção contra fraudes em pagamentos

Agmete fica entre o **seu backend** e o **gateway de pagamento** (Stripe, PagSeguro, etc).
Analisa cada transação em tempo real e retorna uma decisão antes de você cobrar qualquer coisa.

```
Browser → Seu backend → Agmete → Gateway de pagamento
```

### Como funciona

1. Seu backend recebe os dados do checkout do cliente
2. Repassa para `POST /api/payment` junto com o IP real do cliente
3. Agmete retorna `decision`: **APROVADO**, **REVISÃO MANUAL** ou **BLOQUEADO**
4. Você só aciona o gateway se a decisão for `APROVADO`

### Decisões

| Score | Decisão | O que fazer |
|-------|---------|-------------|
| 0–39 | APROVADO | Prossiga para o gateway |
| 40–69 | REVISÃO MANUAL | Segure o pedido para revisão humana |
| 70–100 | BLOQUEADO | Rejeite — mostre `customer_response.message` ao cliente |

### Importante: IP do cliente

Em chamadas server-to-server, envie sempre o campo `ip_address` com o IP real do cliente
(extraído de `X-Forwarded-For` ou `REMOTE_ADDR` no seu backend).
Se omitido, Agmete usará o IP da requisição recebida.
""",
    version="3.0.0",
    contact={"name": "Agmete", "url": "https://github.com/eduardoparcianello/agmete"},
    license_info={"name": "MIT"},
    openapi_tags=[
        {
            "name": "Pagamento",
            "description": "Endpoint principal — analisa uma transação e retorna a decisão de risco.",
        },
        {
            "name": "Bloqueios",
            "description": "Bloqueie emails, CPFs, IPs individualmente ou por combinação de campos.",
        },
        {
            "name": "Países",
            "description": "Allowlist de países. Transações de IPs fora da lista são automaticamente bloqueadas.",
        },
        {
            "name": "Bancos",
            "description": "Marque bancos emissores como suspeitos. O banco é identificado automaticamente pelo BIN do cartão via HandyAPI.",
        },
        {
            "name": "Transações",
            "description": "Consulte o histórico e gerencie a fila de revisão manual.",
        },
        {
            "name": "Sistema",
            "description": "Status da API, modelo ML e informações de IP/geolocalização.",
        },
        {
            "name": "Frontend",
            "description": "Páginas HTML de demonstração (checkout e painel admin).",
        },
    ],
)

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


@app.on_event("startup")
def startup():
    fraud_engine.load_model()


# ── Models ───────────────────────────────────────────────────────────────────
class PaymentRequest(BaseModel):
    model_config = {"json_schema_extra": {"example": {
        "amount": 299.90,
        "payment_method": "credit_card",
        "customer_name": "Maria Oliveira",
        "email": "maria@empresa.com",
        "cpf": "529.982.247-25",
        "card_holder_name": "MARIA OLIVEIRA",
        "card_number": "4532 0123 4567 5678",
        "card_expiry": "12/28",
        "ip_address": "189.40.12.55",
        "city": "São Paulo",
        "state": "SP",
    }}}

    amount: float = Field(..., gt=0, example=299.90, description="Valor da transação em reais (R$)")
    payment_method: str = Field(
        default="credit_card",
        pattern=r"^(credit_card|pix|boleto)$",
        example="credit_card",
        description="Método de pagamento. Valores aceitos: `credit_card`, `pix`, `boleto`",
    )
    customer_name: str = Field(..., min_length=2, max_length=100, example="Maria Oliveira", description="Nome completo do cliente")
    email: str = Field(..., min_length=5, max_length=100, example="maria@empresa.com", description="Email do cliente")
    cpf: str = Field(default="", max_length=20, example="529.982.247-25", description="CPF do cliente — com ou sem formatação. Validado pelo algoritmo de dígito verificador.")
    card_holder_name: str = Field(default="", max_length=100, example="MARIA OLIVEIRA", description="Nome impresso no cartão. Usado apenas para `credit_card`. Comparado com `customer_name` para detectar divergência.")
    card_number: str = Field(default="", max_length=19, example="4532 0123 4567 5678", description="Número completo do cartão (16 dígitos, com ou sem espaços). Usado para identificar o banco emissor via BIN lookup. Apenas `credit_card`.")
    card_last4: str = Field(default="", max_length=4, example="5678", description="Últimos 4 dígitos do cartão. Usado como fallback para velocity check quando `card_number` não for enviado.")
    card_expiry: str = Field(default="", max_length=7, example="12/28", description="Validade do cartão no formato `MM/AA`. Apenas `credit_card`.")
    ip_address: str = Field(
        default="",
        max_length=45,
        example="189.40.12.55",
        description=(
            "IP real do cliente. "
            "**Obrigatório em integrações server-to-server** — extraia de `X-Forwarded-For` "
            "ou `REMOTE_ADDR` no seu backend e passe aqui. "
            "Se omitido, Agmete usa o IP da própria requisição (funciona quando o browser chama diretamente)."
        ),
    )
    city: str = Field(default="", max_length=100, example="São Paulo", description="Cidade declarada pelo cliente. Comparada com a localização real do IP para detectar inconsistências.")
    state: str = Field(default="", max_length=50, example="SP", description="Estado declarado pelo cliente (sigla ou nome completo).")
    purchase_hour: Optional[int] = Field(
        default=None, ge=0, le=23, example=14,
        description="Hora da compra (0–23). Se omitido, usa a hora atual do servidor. Compras entre 01:00–05:00 elevam o score de risco.",
    )


class FlaggedBankRequest(BaseModel):
    model_config = {"json_schema_extra": {"example": {
        "bank_name": "BANCO XYZ S.A.",
        "risk_level": "alto",
        "reason": "Alto índice de chargebacks",
    }}}

    bank_name: str = Field(..., min_length=1, max_length=200, description="Nome exato do banco emissor conforme retornado pelo BIN lookup (campo `details.bin_lookup.issuer` na resposta de `/api/payment`)")
    risk_level: str = Field(default="medio", pattern=r"^(alto|medio|baixo)$", description="Nível de risco: `baixo` (+10 pts), `medio` (+20 pts), `alto` (+35 pts)")
    reason: str = Field(default="", max_length=500, description="Motivo do bloqueio (opcional, exibido no painel admin)")


class BlockEntityRequest(BaseModel):
    model_config = {"json_schema_extra": {"example": {
        "entity_type": "email",
        "value": "fraud@tempmail.com",
        "reason": "Chargeback confirmado",
    }}}

    entity_type: str = Field(..., pattern=r"^(email|cpf|ip)$", description="Tipo de entidade a bloquear: `email`, `cpf` ou `ip`")
    value: str = Field(..., min_length=1, max_length=200, description="Valor a bloquear (ex: `fraude@email.com`, `52998224725`, `1.2.3.4`)")
    reason: str = Field(default="", max_length=500, description="Motivo do bloqueio (opcional)")


class ComboBlockRequest(BaseModel):
    model_config = {"json_schema_extra": {"example": {
        "conditions": {"email": "fraud@email.com", "cpf": "52998224725"},
        "reason": "Fraudador conhecido",
    }}}

    conditions: dict = Field(..., description="Campos que devem coincidir **simultaneamente** para o bloqueio disparar. Mínimo 2 campos. Campos disponíveis: `email`, `cpf`, `ip`, `card_last4`.")
    reason: str = Field(default="", max_length=500, description="Motivo do bloqueio combinado (opcional)")


class CountryListRequest(BaseModel):
    model_config = {"json_schema_extra": {"example": {"countries": ["Brazil", "United States"]}}}

    countries: list[str] = Field(..., description="Lista completa de países permitidos (substitui a lista atual). Use nomes em inglês conforme retornado pela geolocalização (ex: `Brazil`, `Argentina`). Envie lista vazia `[]` para liberar todos os países.")


# ── Response Models ───────────────────────────────────────────────────────────
class CustomerResponse(BaseModel):
    message: str = Field(description="Mensagem genérica para exibir ao cliente (não expõe detalhes de fraude)")
    status: str = Field(description="`success` | `processing` | `error`")
    transaction_id: str = Field(description="ID único da transação no formato `TX-<12 hex>`")


class PaymentResponse(BaseModel):
    model_config = {"json_schema_extra": {"example": {
        "transaction_id": "TX-A1B2C3D4E5F6",
        "timestamp": "2026-04-15T14:30:00.000000",
        "payment_method": "credit_card",
        "risk_score": 15,
        "decision": "APROVADO",
        "decision_reason": "Transação dentro dos parâmetros normais",
        "alerts": [],
        "alert_count": 0,
        "details": {
            "cpf_validation": {"cpf": "529.982.247-25", "valid": True},
            "card_expiry": {"valid": True, "message": "Cartão válido"},
            "amount_analysis": {"value": 299.90},
            "name_match": {"card_holder": "MARIA OLIVEIRA", "customer_name": "Maria Oliveira", "similarity": 98.5},
            "email_analysis": {"email": "maria@empresa.com", "extracted_name": "maria", "similarity_to_customer": 72.0},
            "time_analysis": {"hour": 14, "high_risk": False},
            "ip_analysis": {
                "ip": "189.40.12.55",
                "declared_city": "São Paulo",
                "declared_state": "SP",
                "geolocation": {"country": "Brazil", "regionName": "São Paulo", "city": "São Paulo", "lat": -23.5, "lon": -46.6},
                "alerts": [],
            },
            "bin_lookup": {"success": True, "issuer": "BANCO BRADESCO S.A.", "scheme": "VISA", "type": "CREDIT", "country": "Brazil"},
            "bank_analysis": {"issuer": "BANCO BRADESCO S.A.", "flagged": False},
            "velocity_check": {"attempts_24h": 1, "unique_names": 1},
            "ml_prediction": {"available": True, "probability": 12, "label": "legítima"},
        },
        "customer_response": {
            "message": "Pagamento aprovado com sucesso!",
            "status": "success",
            "transaction_id": "TX-A1B2C3D4E5F6",
        },
    }}}

    transaction_id: str = Field(description="ID único da transação no formato `TX-<12 hex>`")
    timestamp: str = Field(description="ISO 8601 timestamp do momento da análise")
    payment_method: str = Field(description="`credit_card` | `pix` | `boleto`")
    risk_score: int = Field(description="Score de risco de 0 (sem risco) a 100 (fraude confirmada)")
    decision: str = Field(description="`APROVADO` (0–39) | `REVISÃO MANUAL` (40–69) | `BLOQUEADO` (70–100)")
    decision_reason: str = Field(description="Motivo resumido da decisão")
    alerts: list[str] = Field(description="Lista de alertas disparados durante a análise")
    alert_count: int = Field(description="Total de alertas")
    details: dict = Field(description=(
        "Dados detalhados para uso interno/admin. Chaves possíveis: "
        "`cpf_validation`, `card_expiry`, `amount_analysis`, `name_match`, "
        "`email_analysis`, `time_analysis`, `ip_analysis`, `country_block`, "
        "`bin_lookup`, `bank_analysis`, `velocity_check`, `ml_prediction`, "
        "`blocked_entities`"
    ))
    customer_response: CustomerResponse


# ── Pagamento ────────────────────────────────────────────────────────────────
@app.post(
    "/api/payment",
    tags=["Pagamento"],
    summary="Analisar transação",
    response_model=PaymentResponse,
    description="""
Endpoint principal do Agmete. Analisa uma transação e retorna:

- **`decision`**: `APROVADO`, `REVISÃO MANUAL` ou `BLOQUEADO`
- **`risk_score`**: 0–100
- **`alerts`**: lista de alertas disparados
- **`customer_response`**: mensagem genérica para exibir ao cliente (não expõe detalhes de fraude)
- **`details`**: dados completos para uso interno/admin (geolocalização, BIN lookup, ML, etc.)

### Fluxo recomendado
```
POST /api/payment
  → decision == "APROVADO"     → chame o gateway
  → decision == "REVISÃO MANUAL" → segure o pedido
  → decision == "BLOQUEADO"    → rejeite, mostre customer_response.message ao cliente
```
""",
)
def process_payment(payment: PaymentRequest, request: Request):
    # Prioridade: 1) ip_address no payload (server-to-server), 2) X-Forwarded-For, 3) request.client
    if payment.ip_address:
        client_ip = payment.ip_address.strip()
    else:
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
        "card_number": payment.card_number,
        "card_last4": payment.card_last4,
        "card_expiry": payment.card_expiry,
        "ip_address": client_ip,
        "city": payment.city,
        "state": payment.state,
        "purchase_hour": payment.purchase_hour,
    }

    result = fraud_engine.analyze_transaction(tx_data)
    return result


@app.get(
    "/api/ip-info",
    tags=["Sistema"],
    summary="IP e geolocalização do cliente",
    description="Retorna o IP detectado na requisição e sua geolocalização via ip-api.com. Útil para debug.",
    responses={200: {"content": {"application/json": {"example": {
        "ip": "189.40.12.55",
        "geolocation": {"country": "Brazil", "regionName": "São Paulo", "city": "São Paulo", "lat": -23.5, "lon": -46.6, "isp": "Claro S.A."},
    }}}}},
)
def get_client_ip(request: Request):
    client_ip = request.client.host if request.client else "unknown"
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()

    client_ip = fraud_engine.resolve_ip(client_ip)
    geo = fraud_engine.get_ip_geolocation(client_ip)
    return {"ip": client_ip, "geolocation": geo}


# ── Transações ───────────────────────────────────────────────────────────────
@app.get(
    "/api/transactions/pending",
    tags=["Transações"],
    summary="Fila de revisão manual",
    description="Lista todas as transações com decisão `REVISÃO MANUAL` aguardando aprovação ou rejeição.",
    responses={200: {"content": {"application/json": {"example": {
        "pending": {"TX-A1B2C3D4E5F6": {"transaction_id": "TX-A1B2C3D4E5F6", "decision": "REVISÃO MANUAL", "risk_score": 55, "alerts": ["Compra em horário de alto risco: 03:00"]}},
    }}}}},
)
def list_pending():
    return {"pending": fraud_engine.get_pending_transactions()}


@app.get(
    "/api/transactions/history",
    tags=["Transações"],
    summary="Histórico de transações",
    description="Retorna as últimas `limit` transações processadas (padrão: 100), da mais recente para a mais antiga.",
    responses={200: {"content": {"application/json": {"example": {
        "history": [{"transaction_id": "TX-A1B2C3D4E5F6", "timestamp": "2026-04-15T14:30:00", "amount": 299.90, "customer_name": "Maria Oliveira", "decision": "APROVADO", "risk_score": 15, "alert_count": 0}],
    }}}}},
)
def list_history(limit: int = 100):
    return {"history": fraud_engine.get_transaction_history(limit)}


@app.post(
    "/api/transactions/{tx_id}/release",
    tags=["Transações"],
    summary="Aprovar transação pendente",
    description="Move uma transação de `REVISÃO MANUAL` para `APROVADO (LIBERADO)`. Use após revisão humana.",
    responses={
        200: {"content": {"application/json": {"example": {"message": "Transação TX-A1B2C3D4E5F6 liberada", "transaction": {"transaction_id": "TX-A1B2C3D4E5F6", "decision": "APROVADO (LIBERADO)", "risk_score": 55}}}}},
        404: {"content": {"application/json": {"example": {"message": "Transação TX-000 não encontrada", "error": True}}}},
    },
)
def release_tx(tx_id: str):
    result = fraud_engine.release_transaction(tx_id)
    if result:
        return {"message": f"Transação {tx_id} liberada", "transaction": result}
    return {"message": f"Transação {tx_id} não encontrada", "error": True}


@app.post(
    "/api/transactions/{tx_id}/reject",
    tags=["Transações"],
    summary="Rejeitar transação pendente",
    description="Move uma transação de `REVISÃO MANUAL` para `REJEITADO`. Use após revisão humana.",
    responses={
        200: {"content": {"application/json": {"example": {"message": "Transação TX-A1B2C3D4E5F6 rejeitada", "transaction": {"transaction_id": "TX-A1B2C3D4E5F6", "decision": "REJEITADO", "risk_score": 55}}}}},
        404: {"content": {"application/json": {"example": {"message": "Transação TX-000 não encontrada", "error": True}}}},
    },
)
def reject_tx(tx_id: str):
    result = fraud_engine.reject_transaction(tx_id)
    if result:
        return {"message": f"Transação {tx_id} rejeitada", "transaction": result}
    return {"message": f"Transação {tx_id} não encontrada", "error": True}


# ── Bloqueios ────────────────────────────────────────────────────────────────
@app.post(
    "/api/block",
    tags=["Bloqueios"],
    summary="Bloquear email, CPF ou IP",
    description="Bloqueia uma entidade individual. Qualquer transação com esse valor terá `risk_score = 100` e decisão `BLOQUEADO`.",
    responses={200: {"content": {"application/json": {"example": {"message": "EMAIL 'fraud@tempmail.com' bloqueado", "type": "email", "value": "fraud@tempmail.com"}}}}},
)
def block_entity(req: BlockEntityRequest):
    fraud_engine.block_entity(req.entity_type, req.value, req.reason)
    return {
        "message": f"{req.entity_type.upper()} '{req.value}' bloqueado",
        "type": req.entity_type,
        "value": req.value,
    }


@app.delete(
    "/api/block/{entity_type}/{value}",
    tags=["Bloqueios"],
    summary="Desbloquear entidade",
    description="Remove o bloqueio de um email, CPF ou IP. `entity_type`: `email`, `cpf` ou `ip`.",
    responses={
        200: {"content": {"application/json": {"example": {"message": "EMAIL 'fraud@tempmail.com' desbloqueado"}}}},
        404: {"content": {"application/json": {"example": {"message": "EMAIL 'x@x.com' não encontrado", "error": True}}}},
    },
)
def unblock_entity(entity_type: str, value: str):
    if fraud_engine.unblock_entity(entity_type, value):
        return {"message": f"{entity_type.upper()} '{value}' desbloqueado"}
    return {"message": f"{entity_type.upper()} '{value}' não encontrado", "error": True}


@app.get(
    "/api/blocked",
    tags=["Bloqueios"],
    summary="Listar entidades bloqueadas",
    description="Retorna todos os emails, CPFs e IPs bloqueados individualmente.",
    responses={200: {"content": {"application/json": {"example": {
        "blocked": {
            "email": [{"value": "fraud@tempmail.com", "reason": "Chargeback confirmado", "created_at": "2026-04-15T10:00:00"}],
            "cpf": [],
            "ip": [],
        },
    }}}}},
)
def list_blocked():
    return {"blocked": fraud_engine.get_blocked_entities()}


@app.post(
    "/api/combos",
    tags=["Bloqueios"],
    summary="Criar bloqueio combinado",
    responses={200: {"content": {"application/json": {"example": {"message": "Bloqueio combinado criado", "combo_id": "abc123def456"}}}},
             422: {"content": {"application/json": {"example": {"error": True, "message": "Mínimo 2 campos para bloqueio combinado"}}}}},
    # NOTE: 422 above is a business-logic validation, not a FastAPI validation error
    description="""
Cria uma regra que bloqueia transações somente quando **todos** os campos especificados coincidirem simultaneamente.

**Diferença do bloqueio individual:** bloqueia apenas a combinação exata, sem afetar transações que usam apenas um dos campos isoladamente.

**Campos disponíveis em `conditions`:** `email`, `cpf`, `ip`, `card_last4`

**Exemplos:**
- `{"email": "x@x.com", "cpf": "52998224725"}` — bloqueia quando ambos coincidem
- `{"card_last4": "0001", "ip": "1.2.3.4", "email": "x@x.com"}` — bloqueia quando os três coincidem
""",
)
def block_combo_route(req: ComboBlockRequest):
    non_empty = {k: v for k, v in req.conditions.items() if v and str(v).strip()}
    if len(non_empty) < 2:
        return {"error": True, "message": "Mínimo 2 campos para bloqueio combinado"}
    combo_id = fraud_engine.block_combo(non_empty, req.reason)
    return {"message": "Bloqueio combinado criado", "combo_id": combo_id}


@app.delete(
    "/api/combos/{combo_id}",
    tags=["Bloqueios"],
    summary="Remover bloqueio combinado",
    description="Remove um bloqueio combinado pelo ID retornado na criação.",
    responses={
        200: {"content": {"application/json": {"example": {"message": "Combo abc123 desbloqueado"}}}},
        404: {"content": {"application/json": {"example": {"error": True, "message": "Combo abc123 não encontrado"}}}},
    },
)
def unblock_combo_route(combo_id: str):
    if fraud_engine.unblock_combo(combo_id):
        return {"message": f"Combo {combo_id} desbloqueado"}
    return {"error": True, "message": f"Combo {combo_id} não encontrado"}


@app.get(
    "/api/combos",
    tags=["Bloqueios"],
    summary="Listar bloqueios combinados",
    description="Retorna todas as regras de bloqueio combinado ativas.",
    responses={200: {"content": {"application/json": {"example": {
        "combos": {"abc123": {"conditions": {"email": "fraud@email.com", "cpf": "52998224725"}, "reason": "Fraudador conhecido", "created_at": "2026-04-15T10:00:00"}},
    }}}}},
)
def list_combos():
    return {"combos": fraud_engine.get_blocked_combos()}


# ── Países Permitidos ─────────────────────────────────────────────────────────
@app.get(
    "/api/countries",
    tags=["Países"],
    summary="Listar países permitidos",
    description="Retorna a lista de países aceitos. **Lista vazia = todos os países aceitos.** Use nomes em inglês (ex: `Brazil`, `Argentina`).",
    responses={200: {"content": {"application/json": {"example": {"allowed_countries": ["brazil"]}}}}},
)
def get_countries():
    return {"allowed_countries": fraud_engine.get_allowed_countries()}


@app.post(
    "/api/countries",
    tags=["Países"],
    summary="Substituir lista de países",
    description="Substitui completamente a lista de países permitidos. Envie `[]` para liberar todos os países.",
    responses={200: {"content": {"application/json": {"example": {"message": "Lista de países atualizada", "allowed_countries": ["brazil", "united states"]}}}}},
)
def set_countries(req: CountryListRequest):
    fraud_engine.set_allowed_countries(req.countries)
    return {"message": "Lista de países atualizada", "allowed_countries": fraud_engine.get_allowed_countries()}


@app.post(
    "/api/countries/{country}",
    tags=["Países"],
    summary="Adicionar país",
    description="Adiciona um país à allowlist. Use o nome em inglês conforme retornado pela geolocalização (ex: `Brazil`).",
    responses={200: {"content": {"application/json": {"example": {"message": "País 'Argentina' adicionado", "allowed_countries": ["brazil", "argentina"]}}}}},
)
def add_country(country: str):
    fraud_engine.add_allowed_country(country)
    return {"message": f"País '{country}' adicionado", "allowed_countries": fraud_engine.get_allowed_countries()}


@app.delete(
    "/api/countries/{country}",
    tags=["Países"],
    summary="Remover país",
    description="Remove um país da allowlist.",
    responses={
        200: {"content": {"application/json": {"example": {"message": "País 'Argentina' removido", "allowed_countries": ["brazil"]}}}},
        404: {"content": {"application/json": {"example": {"error": True, "message": "País 'Argentina' não encontrado"}}}},
    },
)
def remove_country(country: str):
    if fraud_engine.remove_allowed_country(country):
        return {"message": f"País '{country}' removido", "allowed_countries": fraud_engine.get_allowed_countries()}
    return {"error": True, "message": f"País '{country}' não encontrado"}


# ── Bancos suspeitos ─────────────────────────────────────────────────────────
@app.post(
    "/api/banks/flag",
    tags=["Bancos"],
    summary="Marcar banco como suspeito",
    responses={200: {"content": {"application/json": {"example": {"message": "Banco 'BANCO XYZ S.A.' marcado como suspeito"}}}}},
    description="""
Marca um banco emissor como suspeito. Transações com cartões desse banco terão o score de risco elevado.

O banco emissor é identificado automaticamente pelo BIN (primeiros 6–8 dígitos do cartão) via [HandyAPI](https://www.handyapi.com/bin-list).
Configure sua chave em `.env`: `HANDY_API_KEY=sua_chave`.

**Para saber o nome exato:** faça uma transação de teste e consulte `details.bin_lookup.issuer` na resposta.
""",
)
def flag_bank(bank: FlaggedBankRequest):
    fraud_engine.add_flagged_bank(bank.bank_name, bank.risk_level, bank.reason)
    return {"message": f"Banco '{bank.bank_name}' marcado como suspeito"}


@app.delete(
    "/api/banks/flag/{bank_name}",
    tags=["Bancos"],
    summary="Desmarcar banco suspeito",
    description="Remove um banco da lista de suspeitos.",
    responses={
        200: {"content": {"application/json": {"example": {"message": "Banco 'BANCO XYZ S.A.' removido"}}}},
        404: {"content": {"application/json": {"example": {"message": "Banco 'BANCO XYZ S.A.' não encontrado", "error": True}}}},
    },
)
def unflag_bank(bank_name: str):
    if fraud_engine.remove_flagged_bank(bank_name):
        return {"message": f"Banco '{bank_name}' removido"}
    return {"message": f"Banco '{bank_name}' não encontrado", "error": True}


@app.get(
    "/api/banks/flagged",
    tags=["Bancos"],
    summary="Listar bancos suspeitos",
    description="Retorna todos os bancos emissores marcados como suspeitos e seus níveis de risco.",
    responses={200: {"content": {"application/json": {"example": {
        "flagged_banks": {"BANCO XYZ S.A.": {"risk_level": "alto", "reason": "Alto índice de chargebacks", "created_at": "2026-04-15T10:00:00"}},
    }}}}},
)
def list_flagged_banks():
    return {"flagged_banks": fraud_engine.get_flagged_banks()}


# ── Sistema ──────────────────────────────────────────────────────────────────
@app.get(
    "/api/health",
    tags=["Sistema"],
    summary="Status da API",
    description="Verifica se a API está online, se o modelo ML está carregado e retorna contadores gerais.",
    responses={200: {"content": {"application/json": {"example": {
        "status": "online",
        "model_loaded": True,
        "timestamp": "2026-04-15T14:30:00.000000",
        "pending_transactions": 2,
        "total_transactions": 148,
        "blocked_entities": 5,
    }}}}},
)
def health_check():
    return {
        "status": "online",
        "model_loaded": fraud_engine._model is not None,
        "timestamp": datetime.now().isoformat(),
        "pending_transactions": len(fraud_engine._pending_transactions),
        "total_transactions": len(fraud_engine._transaction_history),
        "blocked_entities": sum(len(v) for v in fraud_engine._blocked_entities.values()),
    }


# ── Frontend ─────────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse, tags=["Frontend"], include_in_schema=False)
def checkout_page(request: Request):
    return templates.TemplateResponse("checkout.html", {"request": request})


@app.get("/admin", response_class=HTMLResponse, tags=["Frontend"], include_in_schema=False)
def admin_page(request: Request):
    return templates.TemplateResponse("admin.html", {"request": request})
