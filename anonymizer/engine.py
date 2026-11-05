"""Motor de anonimização: aplica regras em sequência e gera relatório de auditoria."""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

import pandas as pd

from .crypto import key_fingerprint
from .risk import assess, enforce_k
from .techniques import TECHNIQUES, Context

CONFIG_VERSION = 1


@dataclass
class Rule:
    column: str
    technique: str
    params: dict = field(default_factory=dict)


@dataclass
class Config:
    rules: list[Rule] = field(default_factory=list)
    quasi_identifiers: list[str] = field(default_factory=list)
    sensitive: str | None = None
    target_k: int = 5
    enforce_k: bool = False
    enforce_mode: str = "suprimir_linhas"
    seed: int = 42

    def to_json(self) -> str:
        data = asdict(self)
        data["version"] = CONFIG_VERSION
        return json.dumps(data, ensure_ascii=False, indent=2)

    @classmethod
    def from_json(cls, text: str) -> "Config":
        data = json.loads(text)
        data.pop("version", None)
        rules = [Rule(**r) for r in data.pop("rules", [])]
        return cls(rules=rules, **data)


@dataclass
class Result:
    df: pd.DataFrame
    report: dict


def _stats(series: pd.Series | None) -> dict:
    if series is None:
        return {"nulos": None, "distintos": None}
    return {"nulos": int(series.isna().sum()), "distintos": int(series.nunique(dropna=True))}


def file_digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run(df: pd.DataFrame, config: Config, key: str, source_name: str = "", source_digest: str = "") -> Result:
    if not key:
        raise ValueError("Informe uma chave secreta.")

    original = df.copy()
    out = df.copy()
    ctx = Context(key=key, seed=config.seed, df=original)
    applied = []

    risk_before = assess(original, config.quasi_identifiers, config.sensitive, config.target_k)

    for rule in config.rules:
        if rule.column not in out.columns:
            continue
        tech = TECHNIQUES.get(rule.technique)
        if tech is None:
            raise ValueError(f"Técnica desconhecida: {rule.technique}")
        if tech.id == "manter":
            continue
        params = {**tech.defaults(), **(rule.params or {})}
        before = _stats(out[rule.column])
        result = tech.fn(out[rule.column], ctx, **params)
        if result is None:
            out = out.drop(columns=[rule.column])
        else:
            out[rule.column] = result.values
        applied.append({
            "coluna": rule.column,
            "tecnica": tech.id,
            "nome": tech.label,
            "reversivel": tech.reversible,
            "parametros": params,
            "antes": before,
            "depois": _stats(None if result is None else out[rule.column]),
        })

    qi_after = [c for c in config.quasi_identifiers if c in out.columns]
    suppressed = 0
    if config.enforce_k and qi_after:
        out, suppressed = enforce_k(out, qi_after, config.target_k, config.enforce_mode)

    risk_after = assess(out, qi_after, config.sensitive if config.sensitive in out.columns else None,
                        config.target_k)

    report = {
        "gerado_em": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "arquivo_origem": source_name,
        "sha256_origem": source_digest,
        "impressao_digital_chave": key_fingerprint(key),
        "semente": config.seed,
        "linhas_entrada": int(len(original)),
        "linhas_saida": int(len(out)),
        "colunas_entrada": list(map(str, original.columns)),
        "colunas_saida": list(map(str, out.columns)),
        "regras_aplicadas": applied,
        "k_anonimato": {
            "quase_identificadores": config.quasi_identifiers,
            "atributo_sensivel": config.sensitive,
            "aplicar": config.enforce_k,
            "modo": config.enforce_mode,
            "registros_suprimidos": suppressed,
            "antes": risk_before.as_dict(),
            "depois": risk_after.as_dict(),
        },
    }
    return Result(out, report)
