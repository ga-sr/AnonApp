"""Detecção automática de dados pessoais (LGPD) em colunas de um DataFrame."""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

import pandas as pd

# Categorias de risco
DIRECT = "Identificador direto"
QUASI = "Quase-identificador"
SENSITIVE = "Dado sensível (LGPD art. 5º, II)"
OTHER = "Outro"


def only_digits(value: str) -> str:
    return re.sub(r"\D", "", value)


def is_valid_cpf(value: str) -> bool:
    d = only_digits(value)
    if len(d) != 11 or d == d[0] * 11:
        return False
    for size in (9, 10):
        total = sum(int(d[i]) * (size + 1 - i) for i in range(size))
        check = (total * 10) % 11 % 10
        if check != int(d[size]):
            return False
    return True


def is_valid_cnpj(value: str) -> bool:
    d = only_digits(value)
    if len(d) != 14 or d == d[0] * 14:
        return False
    weights = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    for size in (12, 13):
        total = sum(int(d[i]) * weights[i + 13 - size] for i in range(size))
        rest = total % 11
        check = 0 if rest < 2 else 11 - rest
        if check != int(d[size]):
            return False
    return True


def luhn_ok(value: str) -> bool:
    d = only_digits(value)
    if not 13 <= len(d) <= 19:
        return False
    total = 0
    for i, ch in enumerate(reversed(d)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


_EMAIL = re.compile(r"^[\w.+-]+@[\w-]+(\.[\w-]+)+$")
_CPF = re.compile(r"^\d{3}\.?\d{3}\.?\d{3}-?\d{2}$")
_CNPJ = re.compile(r"^\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}$")
_PHONE = re.compile(r"^(\+?55\s?)?(\(?\d{2}\)?\s?)?9?\d{4}[-\s]?\d{4}$")
_CEP = re.compile(r"^\d{5}-?\d{3}$")
_CARD = re.compile(r"^(\d[\s-]?){13,19}$")
_IP = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_DATE = re.compile(r"^\d{1,4}[/-]\d{1,2}[/-]\d{1,4}$")
_TIME = re.compile(r"^\d{1,2}:\d{2}(:\d{2})?$")
_PLATE = re.compile(r"^[A-Za-z]{3}-?\d[A-Za-z0-9]\d{2}$")

# Ordem importa: validadores mais específicos primeiro
VALUE_PATTERNS: list[tuple[str, callable]] = [
    ("email", lambda v: bool(_EMAIL.match(v))),
    ("cpf", lambda v: bool(_CPF.match(v)) and is_valid_cpf(v)),
    ("cnpj", lambda v: bool(_CNPJ.match(v)) and is_valid_cnpj(v)),
    ("cartao", lambda v: bool(_CARD.match(v)) and luhn_ok(v)),
    ("cep", lambda v: bool(_CEP.match(v))),
    ("telefone", lambda v: bool(_PHONE.match(v)) and len(only_digits(v)) >= 8),
    ("ip", lambda v: bool(_IP.match(v))),
    ("data", lambda v: bool(_DATE.match(v))),
    ("hora", lambda v: bool(_TIME.match(v))),
    ("placa", lambda v: bool(_PLATE.match(v))),
]

# Pistas no nome da coluna: (palavras-chave, tipo, categoria)
NAME_HINTS: list[tuple[tuple[str, ...], str, str]] = [
    (("cpf",), "cpf", DIRECT),
    (("cnpj",), "cnpj", DIRECT),
    (("rg", "identidade"), "rg", DIRECT),
    (("email", "e-mail", "e_mail"), "email", DIRECT),
    (("telefone", "celular", "fone", "phone", "whatsapp"), "telefone", DIRECT),
    (("cartao", "card"), "cartao", DIRECT),
    (("nome", "name", "paciente", "cliente"), "nome", DIRECT),
    (("endereco", "logradouro", "rua", "address"), "endereco", DIRECT),
    (("placa",), "placa", DIRECT),
    (("ip",), "ip", DIRECT),
    (("cep", "zip"), "cep", QUASI),
    (("nascimento", "birth", "dt_nasc"), "data", QUASI),
    (("data", "date", "dt"), "data", QUASI),
    (("hora", "horario", "time"), "hora", QUASI),
    (("idade", "age"), "idade", QUASI),
    (("cidade", "municipio", "city"), "cidade", QUASI),
    (("estado", "uf"), "estado", QUASI),
    (("bairro",), "bairro", QUASI),
    (("sexo", "genero", "gender"), "categoria", QUASI),
    (("profissao", "ocupacao", "cargo"), "categoria", QUASI),
    (("salario", "renda", "income"), "numerico", QUASI),
    (("saude", "diagnostico", "doenca", "cid", "medic", "health", "exame"), "saude", SENSITIVE),
    (("raca", "etnia", "cor"), "categoria", SENSITIVE),
    (("religiao", "crenca"), "categoria", SENSITIVE),
    (("politic", "partido", "sindic"), "categoria", SENSITIVE),
    (("orientacao", "sexual"), "categoria", SENSITIVE),
    (("biometr", "genetic", "digital"), "categoria", SENSITIVE),
]

DIRECT_TYPES = {"email", "cpf", "cnpj", "cartao", "telefone", "nome", "endereco", "rg", "placa", "ip"}
QUASI_TYPES = {"cep", "data", "hora", "idade", "cidade", "estado", "bairro", "numerico"}

# Técnica sugerida por tipo detectado
SUGGESTIONS = {
    "cpf": "pseudonimo",
    "cnpj": "pseudonimo",
    "rg": "token",
    "email": "mascara",
    "telefone": "mascara",
    "cartao": "mascara",
    "nome": "pseudonimo",
    "endereco": "remover",
    "placa": "token",
    "ip": "token",
    "cep": "generalizar_cep",
    "data": "generalizar_data",
    "hora": "generalizar_hora",
    "idade": "generalizar_numero",
    "cidade": "agrupar_raros",
    "estado": "manter",
    "bairro": "agrupar_raros",
    "numerico": "ruido",
    "saude": "agrupar_raros",
    "categoria": "agrupar_raros",
}


@dataclass
class ColumnReport:
    column: str
    detected_type: str
    category: str
    confidence: float
    source: str
    suggestion: str
    sample: str

    def as_dict(self) -> dict:
        return {
            "Coluna": self.column,
            "Tipo detectado": self.detected_type,
            "Categoria": self.category,
            "Confiança": round(self.confidence, 2),
            "Origem": self.source,
            "Técnica sugerida": self.suggestion,
            "Exemplo": self.sample,
        }


def normalize(text: str) -> str:
    text = unicodedata.normalize("NFKD", str(text)).encode("ascii", "ignore").decode()
    return text.lower().strip()


def _name_hint(column: str):
    name = normalize(column)
    tokens = set(re.split(r"[^a-z0-9]+", name))
    # 1ª passada: palavra exata (evita "cidade" casar com "idade")
    for keywords, kind, category in NAME_HINTS:
        if any(kw in tokens for kw in keywords):
            return kind, category
    # 2ª passada: substring, apenas para palavras longas (evita "card" em "cardiaco")
    for keywords, kind, category in NAME_HINTS:
        if any(len(kw) > 4 and kw in name for kw in keywords):
            return kind, category
    return None


def _value_hint(series: pd.Series, sample_size: int = 500):
    values = series.dropna().astype(str).str.strip()
    values = values[values != ""]
    if values.empty:
        return None
    sample = values.sample(min(sample_size, len(values)), random_state=0)
    best = None
    for kind, check in VALUE_PATTERNS:
        ratio = sample.map(check).mean()
        if ratio >= 0.8 and (best is None or ratio > best[1]):
            best = (kind, float(ratio))
    return best


def _category_for(kind: str) -> str:
    if kind in DIRECT_TYPES:
        return DIRECT
    if kind in QUASI_TYPES:
        return QUASI
    if kind == "saude":
        return SENSITIVE
    return OTHER


def detect_column(series: pd.Series, column: str) -> ColumnReport:
    non_null = series.dropna()
    sample = str(non_null.iloc[0]) if len(non_null) else ""
    value = _value_hint(series)
    name = _name_hint(column)

    if value:
        kind, conf = value
        category = _category_for(kind)
        source = "valores"
        if name and name[0] == kind:
            conf, source = 1.0, "valores + nome"
        elif name and name[1] == SENSITIVE:
            category = SENSITIVE
    elif name:
        kind, category = name
        conf, source = 0.6, "nome da coluna"
    elif len(non_null) and (pd.api.types.is_numeric_dtype(series)
                            or pd.to_numeric(non_null, errors="coerce").notna().mean() > 0.95):
        kind, category, conf, source = "numerico", OTHER, 0.3, "tipo"
    else:
        kind, category, conf, source = "texto", OTHER, 0.0, "-"

    # Texto livre com alta cardinalidade tende a identificar o titular
    if kind == "texto" and len(non_null) and non_null.nunique() / len(non_null) > 0.9:
        kind, category, conf, source = "texto_unico", QUASI, 0.4, "cardinalidade"

    suggestion = SUGGESTIONS.get(kind, "token" if kind == "texto_unico" else "manter")
    if category == OTHER and kind == "numerico":
        suggestion = "manter"
    return ColumnReport(column, kind, category, conf, source, suggestion, sample[:40])


def detect_dataframe(df: pd.DataFrame) -> list[ColumnReport]:
    return [detect_column(df[c], c) for c in df.columns]
