"""Técnicas de anonimização e pseudonimização.

Cada técnica recebe uma `pd.Series`, um `Context` e parâmetros nomeados, e devolve
uma nova `pd.Series` (ou `None` para remover a coluna). Valores nulos são preservados.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Callable

import numpy as np
import pandas as pd

from .crypto import Cipher, hmac_hex, hmac_int, hmac_stream
from .detection import only_digits


@dataclass
class Context:
    key: str
    seed: int = 42
    df: pd.DataFrame | None = None
    _cipher: Cipher | None = field(default=None, repr=False)

    @property
    def cipher(self) -> Cipher:
        if self._cipher is None:
            self._cipher = Cipher(self.key)
        return self._cipher

    def rng(self, column: str) -> np.random.Generator:
        # Gerador reprodutível e independente por coluna
        return np.random.default_rng([self.seed, hmac_int("anonapp/rng", column) % (2**32)])


@dataclass
class Param:
    name: str
    label: str
    kind: str  # int | float | select | text | bool | column
    default: Any = None
    options: list | None = None
    min: float | None = None
    max: float | None = None
    help: str | None = None


@dataclass
class Technique:
    id: str
    label: str
    group: str
    description: str
    fn: Callable
    params: list[Param] = field(default_factory=list)
    reversible: bool = False

    def defaults(self) -> dict:
        return {p.name: p.default for p in self.params}


# --------------------------------------------------------------------------- helpers

def _map_unique(series: pd.Series, fn: Callable[[str], Any]) -> pd.Series:
    """Aplica `fn` uma vez por valor distinto não nulo, preservando nulos."""
    mask = series.notna()
    out = pd.Series([None] * len(series), index=series.index, dtype=object)
    if mask.any():
        values = series[mask].astype(str)
        mapping = {v: fn(v) for v in values.unique()}
        out[mask] = values.map(mapping).values
    return out


def _is_integer_like(values: pd.Series) -> bool:
    v = values.dropna()
    return len(v) > 0 and bool(np.all(np.isclose(v, np.round(v))))


def _fmt_num(x: float) -> str:
    return str(int(x)) if float(x).is_integer() else f"{x:g}"


# --------------------------------------------------------------------------- técnicas

def keep(series, ctx):
    return series


def remove(series, ctx):
    return None


def redact(series, ctx, text="[REMOVIDO]"):
    return _map_unique(series, lambda v: text)


def token(series, ctx, length=16, prefix="tok_"):
    """Tokenização com HMAC-SHA256 e chave secreta.

    Sem a chave, o token não pode ser recalculado por ataque de dicionário,
    diferente de um SHA-256 puro.
    """
    length = int(max(8, min(64, length)))
    return _map_unique(series, lambda v: prefix + hmac_hex(ctx.key, f"token|{v}")[:length])


def format_preserving(series, ctx, keep_start=0, keep_end=0):
    """Substitui dígitos por dígitos e letras por letras, mantendo o formato."""
    keep_start, keep_end = int(keep_start), int(keep_end)

    def sub(v: str) -> str:
        stream = hmac_stream(ctx.key, f"fpe|{v}", len(v))
        chars = list(v)
        for i, c in enumerate(chars):
            if i < keep_start or i >= len(chars) - keep_end:
                continue
            b = stream[i]
            if c.isdigit():
                chars[i] = str(b % 10)
            elif c.isascii() and c.isalpha():
                base = ord("A") if c.isupper() else ord("a")
                chars[i] = chr(base + b % 26)
        return "".join(chars)

    return _map_unique(series, sub)


FAKER_KINDS = {
    "nome": lambda f: f.name(),
    "primeiro_nome": lambda f: f.first_name(),
    "sobrenome": lambda f: f.last_name(),
    "email": lambda f: f.free_email(),
    "cpf": lambda f: f.cpf(),
    "cnpj": lambda f: f.cnpj(),
    "rg": lambda f: f.rg(),
    "telefone": lambda f: f.phone_number(),
    "endereco": lambda f: f"{f.street_name()}, {f.building_number()}",
    "cidade": lambda f: f.city(),
    "estado": lambda f: f.estado_nome(),
    "cep": lambda f: f.postcode(),
    "empresa": lambda f: f.company(),
    "placa": lambda f: f.license_plate(),
}


def pseudonym(series, ctx, kind="nome"):
    """Pseudônimo realista e consistente: o mesmo valor gera sempre o mesmo substituto.

    O substituto depende da chave secreta. Colisões são evitadas dentro do conjunto.
    """
    from faker import Faker

    fake = Faker("pt_BR")
    gen = FAKER_KINDS.get(kind, FAKER_KINDS["nome"])
    used: set[str] = set()

    def make(v: str) -> str:
        base = hmac_int(ctx.key, f"pseudo|{kind}|{v}")
        for attempt in range(50):
            fake.seed_instance(base + attempt)
            candidate = gen(fake)
            if candidate not in used:
                break
        used.add(candidate)
        return candidate

    mask = series.notna()
    out = pd.Series([None] * len(series), index=series.index, dtype=object)
    if mask.any():
        values = series[mask].astype(str)
        # Ordem estável para que colisões sejam resolvidas sempre igual
        mapping = {v: make(v) for v in sorted(values.unique())}
        out[mask] = values.map(mapping).values
    return out


def _mask_digits(v: str, keep_positions: set[int], char: str) -> str:
    out, idx = [], 0
    for c in v:
        if c.isdigit():
            out.append(c if idx in keep_positions else char)
            idx += 1
        else:
            out.append(c)
    return "".join(out)


def _mask_email(v: str, char: str) -> str:
    local, _, domain = v.partition("@")
    host, dot, tld = domain.rpartition(".")
    if not dot:
        host, tld = domain, ""
    m_local = local[:1] + char * max(len(local) - 1, 3)
    m_host = host[:1] + char * max(len(host) - 1, 3)
    return f"{m_local}@{m_host}{dot}{tld}"


def _mask_generic(v: str, keep_start: int, keep_end: int, char: str) -> str:
    n = len(v)
    if n <= keep_start + keep_end:
        # Valor curto: mascara tudo exceto o primeiro caractere
        return v[:1] + char * (n - 1)
    end = v[n - keep_end:] if keep_end else ""
    return v[:keep_start] + char * (n - keep_start - keep_end) + end


def mask_value(v: str, kind: str = "auto", char: str = "*", keep_start: int = 1, keep_end: int = 2) -> str:
    digits = only_digits(v)
    if kind == "auto":
        if "@" in v:
            kind = "email"
        elif len(digits) == 11 and len(v) <= 14 and not v.strip().startswith(("(", "+")) and ("." in v or len(v) == 11):
            kind = "cpf"
        elif len(digits) == 14 and "/" in v:
            kind = "cnpj"
        elif 13 <= len(digits) <= 19:
            kind = "cartao"
        elif 8 <= len(digits) <= 13 and len(digits) >= len(v) * 0.6:
            kind = "telefone"
        else:
            kind = "generico"

    if kind == "email" and "@" in v:
        return _mask_email(v, char)
    if kind == "cpf" and len(digits) == 11:
        # Padrão adotado pelo governo federal: ***.456.789-**
        return f"{char*3}.{digits[3:6]}.{digits[6:9]}-{char*2}"
    if kind == "cnpj" and len(digits) == 14:
        return f"{digits[:2]}.{char*3}.{char*3}/{digits[8:12]}-{char*2}"
    if kind == "cartao" and len(digits) >= 12:
        n = len(digits)
        return _mask_digits(v, set(range(n - 4, n)), char)
    if kind == "telefone" and len(digits) >= 8:
        n = len(digits)
        return _mask_digits(v, set(range(n - 4, n)), char)
    return _mask_generic(v, int(keep_start), int(keep_end), char)


def mask(series, ctx, kind="auto", char="*", keep_start=1, keep_end=2):
    char = (char or "*")[:1]
    return _map_unique(series, lambda v: mask_value(v, kind, char, keep_start, keep_end))


def generalize_number(series, ctx, bin_size=10.0, bottom=None, top=None):
    """Agrupa números em faixas (ex.: 30-39). Aplica limites inferior e superior."""
    nums = pd.to_numeric(series, errors="coerce")
    bin_size = float(bin_size) if bin_size else 10.0
    integer = _is_integer_like(nums) and float(bin_size).is_integer()

    def label(x):
        if pd.isna(x):
            return None
        if top not in (None, "") and x >= float(top):
            return f"{_fmt_num(float(top))}+"
        if bottom not in (None, "") and x < float(bottom):
            return f"<{_fmt_num(float(bottom))}"
        lo = math.floor(x / bin_size) * bin_size
        if integer:
            return f"{int(lo)}-{int(lo + bin_size - 1)}"
        return f"[{_fmt_num(lo)}, {_fmt_num(lo + bin_size)})"

    out = nums.map(label).astype(object)
    out[series.isna()] = None
    return out


def _parse_dates(series: pd.Series, dayfirst: bool = True) -> pd.Series:
    if pd.api.types.is_datetime64_any_dtype(series):
        return series
    text = series.astype(str).str.strip()
    iso = text.str.match(r"^\d{4}-\d{1,2}-\d{1,2}")
    out = pd.Series(pd.NaT, index=series.index, dtype="datetime64[ns]")
    if iso.any():
        out[iso] = pd.to_datetime(text[iso], errors="coerce", format="ISO8601")
    if (~iso).any():
        out[~iso] = pd.to_datetime(text[~iso], dayfirst=dayfirst, errors="coerce", format="mixed")
    out[series.isna()] = pd.NaT
    return out


MESES = ["janeiro", "fevereiro", "março", "abril", "maio", "junho", "julho",
         "agosto", "setembro", "outubro", "novembro", "dezembro"]


def generalize_date(series, ctx, level="mes_ano", dayfirst=True):
    dates = _parse_dates(series, dayfirst)

    def label(d):
        if pd.isna(d):
            return None
        if level == "ano":
            return str(d.year)
        if level == "decada":
            return f"{d.year // 10 * 10}s"
        if level == "semestre":
            return f"{d.year}-S{1 if d.month <= 6 else 2}"
        if level == "trimestre":
            return f"{d.year}-T{(d.month - 1) // 3 + 1}"
        if level == "mes":
            return MESES[d.month - 1]
        if level == "dia_semana":
            return ["segunda", "terça", "quarta", "quinta", "sexta", "sábado", "domingo"][d.weekday()]
        return f"{d.year}-{d.month:02d}"

    out = dates.map(label).astype(object)
    return out.where(dates.notna(), None)


def generalize_time(series, ctx, level="periodo"):
    parsed = pd.to_datetime(series.astype(str), errors="coerce", format="mixed")
    hours = parsed.dt.hour

    def label(h):
        if pd.isna(h):
            return None
        h = int(h)
        if level == "hora":
            return f"{h:02d}h"
        if level == "faixa_3h":
            lo = h // 3 * 3
            return f"{lo:02d}h-{lo + 2:02d}h"
        if 0 <= h < 6:
            return "madrugada"
        if h < 12:
            return "manhã"
        if h < 18:
            return "tarde"
        return "noite"

    out = hours.map(label).astype(object)
    return out.where(hours.notna(), None)


def generalize_cep(series, ctx, digits=5, char="*"):
    """Mantém os primeiros dígitos do CEP (região/setor) e oculta o restante."""
    digits = int(max(1, min(8, digits)))

    def gen(v):
        d = only_digits(v)
        if len(d) != 8:
            return None
        kept = d[:digits] + char * (8 - digits)
        return f"{kept[:5]}-{kept[5:]}"

    return _map_unique(series, gen)


def group_rare(series, ctx, min_freq=5, other_label="Outros"):
    """Substitui categorias com frequência menor que `min_freq` por um rótulo comum."""
    counts = series.value_counts(dropna=True)
    rare = set(counts[counts < int(min_freq)].index)
    out = series.astype(object).copy()
    out[series.isin(rare)] = other_label
    return out


def noise(series, ctx, mechanism="laplace", epsilon=1.0, sensitivity=1.0, relative_std=10.0,
          clip=True, decimals=-1):
    """Perturbação numérica.

    - laplace: mecanismo de privacidade diferencial, escala = sensibilidade / ε.
    - gaussiana: desvio-padrão igual a `relative_std`% do desvio da coluna.
    """
    nums = pd.to_numeric(series, errors="coerce").astype(float)
    rng = ctx.rng(str(series.name))
    if mechanism == "gaussiana":
        std = float(nums.std(skipna=True) or 0.0) * float(relative_std) / 100.0
        delta = rng.normal(0.0, std, len(nums))
    else:
        scale = float(sensitivity) / max(float(epsilon), 1e-9)
        delta = rng.laplace(0.0, scale, len(nums))
    out = nums + delta
    if clip and nums.notna().any():
        out = out.clip(nums.min(), nums.max())
    decimals = int(decimals)
    if decimals < 0:
        decimals = 0 if _is_integer_like(nums) else 2
    out = out.round(decimals)
    if decimals == 0:
        out = out.astype("Int64")
    out[nums.isna()] = pd.NA
    return out


def date_shift(series, ctx, max_days=30, group_column="", output_format="%d/%m/%Y", dayfirst=True):
    """Desloca datas em ±`max_days` dias.

    Com `group_column` (ex.: ID do paciente), todas as datas do mesmo titular recebem
    o mesmo deslocamento, preservando os intervalos entre eventos.
    """
    dates = _parse_dates(series, dayfirst)
    max_days = int(max_days)
    if group_column and ctx.df is not None and group_column in ctx.df.columns:
        groups = ctx.df[group_column].astype(str)
        offsets = groups.map(lambda g: hmac_int(ctx.key, f"shift|{g}") % (2 * max_days + 1) - max_days)
        offsets = offsets.astype(int).values
    else:
        offsets = ctx.rng(str(series.name)).integers(-max_days, max_days + 1, len(dates))
    shifted = dates + pd.to_timedelta(offsets, unit="D")
    out = shifted.dt.strftime(output_format).astype(object)
    out[dates.isna()] = None
    return out


def shuffle(series, ctx):
    """Embaralha os valores entre as linhas. Preserva a distribuição e quebra o vínculo."""
    rng = ctx.rng(str(series.name))
    values = series.to_numpy(copy=True)
    rng.shuffle(values)
    return pd.Series(values, index=series.index, name=series.name)


def encrypt(series, ctx):
    """Criptografia reversível com a chave secreta (Fernet/AES)."""
    cipher = ctx.cipher
    mask_ = series.notna()
    out = pd.Series([None] * len(series), index=series.index, dtype=object)
    out[mask_] = [cipher.encrypt(v) for v in series[mask_].astype(str)]
    return out


def decrypt(series, ctx):
    cipher = ctx.cipher
    return _map_unique(series, cipher.decrypt)


# --------------------------------------------------------------------------- registro

_CHAR = Param("char", "Caractere de máscara", "text", "*")

TECHNIQUES: dict[str, Technique] = {t.id: t for t in [
    Technique("manter", "Manter", "Nenhuma", "Mantém a coluna sem alterações.", keep),
    Technique("remover", "Remover coluna", "Supressão",
              "Exclui a coluna do resultado. Opção mais segura para dados desnecessários.", remove),
    Technique("suprimir", "Substituir por constante", "Supressão",
              "Troca todos os valores por um texto fixo, mantendo a coluna.", redact,
              [Param("text", "Texto", "text", "[REMOVIDO]")]),
    Technique("token", "Tokenização (HMAC-SHA256)", "Pseudonimização",
              "Gera um token irreversível e consistente com chave secreta. Resiste a ataques de dicionário.",
              token, [Param("length", "Tamanho do token", "int", 16, min=8, max=64),
                      Param("prefix", "Prefixo", "text", "tok_")]),
    Technique("pseudonimo", "Pseudônimo realista", "Pseudonimização",
              "Troca o valor por um dado fictício plausível (nome, CPF válido, e-mail etc.). Consistente entre linhas.",
              pseudonym, [Param("kind", "Tipo de dado", "select", "nome", options=list(FAKER_KINDS))]),
    Technique("formato", "Substituição com formato preservado", "Pseudonimização",
              "Troca dígitos por dígitos e letras por letras, mantendo pontuação e tamanho.",
              format_preserving, [Param("keep_start", "Manter caracteres no início", "int", 0, min=0, max=20),
                                  Param("keep_end", "Manter caracteres no final", "int", 0, min=0, max=20)]),
    Technique("criptografia", "Criptografia reversível (AES)", "Pseudonimização",
              "Cifra o valor com a chave secreta. Recuperável apenas com a mesma chave.", encrypt, reversible=True),
    Technique("mascara", "Mascaramento", "Mascaramento",
              "Oculta parte do valor. Detecta CPF, CNPJ, e-mail, telefone e cartão no modo automático.",
              mask, [Param("kind", "Formato", "select", "auto",
                           options=["auto", "cpf", "cnpj", "email", "telefone", "cartao", "generico"]),
                     _CHAR,
                     Param("keep_start", "Manter no início (genérico)", "int", 1, min=0, max=20),
                     Param("keep_end", "Manter no final (genérico)", "int", 2, min=0, max=20)]),
    Technique("generalizar_numero", "Generalização numérica (faixas)", "Generalização",
              "Agrupa valores em intervalos, ex.: idade 34 vira 30-39. Limites agregam extremos.",
              generalize_number, [Param("bin_size", "Tamanho da faixa", "float", 10.0, min=0.0001),
                                  Param("bottom", "Limite inferior (vazio = sem)", "text", ""),
                                  Param("top", "Limite superior (vazio = sem)", "text", "")]),
    Technique("generalizar_data", "Generalização de data", "Generalização",
              "Reduz a precisão da data para ano, semestre, trimestre, mês etc.",
              generalize_date, [Param("level", "Nível", "select", "mes_ano",
                                      options=["mes_ano", "ano", "decada", "semestre", "trimestre", "mes", "dia_semana"]),
                                Param("dayfirst", "Formato brasileiro (dia primeiro)", "bool", True)]),
    Technique("generalizar_hora", "Generalização de hora", "Generalização",
              "Converte horários em períodos do dia, faixas de 3 horas ou hora cheia.",
              generalize_time, [Param("level", "Nível", "select", "periodo", options=["periodo", "faixa_3h", "hora"])]),
    Technique("generalizar_cep", "Generalização de CEP", "Generalização",
              "Mantém apenas o prefixo regional do CEP, ex.: 01310-***.",
              generalize_cep, [Param("digits", "Dígitos mantidos", "int", 5, min=1, max=8), _CHAR]),
    Technique("agrupar_raros", "Agrupar categorias raras", "Generalização",
              "Valores com poucas ocorrências passam a 'Outros', reduzindo registros únicos.",
              group_rare, [Param("min_freq", "Frequência mínima", "int", 5, min=1),
                           Param("other_label", "Rótulo", "text", "Outros")]),
    Technique("ruido", "Ruído numérico (privacidade diferencial)", "Perturbação",
              "Adiciona ruído de Laplace (ε) ou gaussiano. Preserva estatísticas agregadas.",
              noise, [Param("mechanism", "Mecanismo", "select", "laplace", options=["laplace", "gaussiana"]),
                      Param("epsilon", "ε (Laplace, menor = mais privado)", "float", 1.0, min=0.01),
                      Param("sensitivity", "Sensibilidade (Laplace)", "float", 1.0, min=0.0),
                      Param("relative_std", "Desvio relativo % (gaussiana)", "float", 10.0, min=0.0),
                      Param("clip", "Limitar ao intervalo original", "bool", True),
                      Param("decimals", "Casas decimais (-1 = automático)", "int", -1, min=-1, max=10)]),
    Technique("deslocar_data", "Deslocamento de datas", "Perturbação",
              "Move cada data alguns dias. Com coluna de agrupamento, preserva intervalos do mesmo titular.",
              date_shift, [Param("max_days", "Deslocamento máximo (dias)", "int", 30, min=1),
                           Param("group_column", "Coluna de agrupamento (opcional)", "column", ""),
                           Param("output_format", "Formato de saída", "text", "%d/%m/%Y"),
                           Param("dayfirst", "Formato brasileiro (dia primeiro)", "bool", True)]),
    Technique("embaralhar", "Embaralhamento", "Perturbação",
              "Permuta os valores entre linhas. Mantém a distribuição e quebra a ligação com o titular.", shuffle),
]}
