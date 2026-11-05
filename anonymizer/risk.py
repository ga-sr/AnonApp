"""Métricas de risco de reidentificação: k-anonimato, l-diversidade e risco do adversário."""
from __future__ import annotations

from dataclasses import dataclass

import pandas as pd


@dataclass
class RiskReport:
    records: int
    classes: int
    k: int
    unique_records: int
    records_below_k: int
    max_risk: float
    avg_risk: float
    l_diversity: int | None
    target_k: int

    def as_dict(self) -> dict:
        return {
            "registros": self.records,
            "classes_equivalencia": self.classes,
            "k_anonimato": self.k,
            "registros_unicos": self.unique_records,
            "registros_abaixo_de_k": self.records_below_k,
            "risco_maximo": round(self.max_risk, 4),
            "risco_medio": round(self.avg_risk, 4),
            "l_diversidade": self.l_diversity,
            "k_alvo": self.target_k,
        }


def _class_sizes(df: pd.DataFrame, qi: list[str]) -> pd.Series:
    keys = df[qi].astype(str)
    return keys.groupby(qi, dropna=False, sort=False)[qi[0]].transform("size")


def assess(df: pd.DataFrame, qi: list[str], sensitive: str | None = None, target_k: int = 5) -> RiskReport:
    """Avalia o risco considerando as colunas `qi` como quase-identificadores.

    - k-anonimato: tamanho da menor classe de equivalência.
    - Risco máximo (promotor): 1 / k.
    - Risco médio: nº de classes / nº de registros.
    - l-diversidade: menor nº de valores sensíveis distintos em uma classe.
    """
    qi = [c for c in qi if c in df.columns]
    n = len(df)
    if not qi or n == 0:
        return RiskReport(n, 1 if n else 0, n, 0, 0, 1 / n if n else 0.0, 1 / n if n else 0.0, None, target_k)

    keys = df[qi].astype(str)
    sizes = keys.value_counts(dropna=False)
    per_row = _class_sizes(df, qi)
    k = int(sizes.min())

    l_div = None
    if sensitive and sensitive in df.columns and sensitive not in qi:
        tmp = keys.copy()
        tmp["__s"] = df[sensitive].astype(str).values
        l_div = int(tmp.groupby(qi, dropna=False)["__s"].nunique().min())

    return RiskReport(
        records=n,
        classes=int(len(sizes)),
        k=k,
        unique_records=int((per_row == 1).sum()),
        records_below_k=int((per_row < target_k).sum()),
        max_risk=1.0 / k,
        avg_risk=len(sizes) / n,
        l_diversity=l_div,
        target_k=target_k,
    )


def class_size_distribution(df: pd.DataFrame, qi: list[str]) -> pd.DataFrame:
    """Quantidade de registros por tamanho de classe de equivalência."""
    qi = [c for c in qi if c in df.columns]
    if not qi or df.empty:
        return pd.DataFrame(columns=["Tamanho da classe", "Registros"])
    per_row = _class_sizes(df, qi)
    bins = [0, 1, 2, 4, 9, 19, 49, float("inf")]
    labels = ["1", "2", "3-4", "5-9", "10-19", "20-49", "50+"]
    cat = pd.cut(per_row, bins=bins, labels=labels)
    dist = cat.value_counts(sort=False).reset_index()
    dist.columns = ["Tamanho da classe", "Registros"]
    return dist


def enforce_k(df: pd.DataFrame, qi: list[str], k: int, mode: str = "suprimir_linhas",
              placeholder: str = "*") -> tuple[pd.DataFrame, int]:
    """Garante k-anonimato.

    - suprimir_linhas: remove registros em classes menores que k.
    - suprimir_valores: troca os quase-identificadores desses registros por `placeholder`.
    Retorna o DataFrame resultante e o número de registros afetados.
    """
    qi = [c for c in qi if c in df.columns]
    if not qi or df.empty or k <= 1:
        return df, 0
    per_row = _class_sizes(df, qi)
    risky = per_row < k
    affected = int(risky.sum())
    if mode == "suprimir_valores":
        out = df.copy()
        for c in qi:
            out[c] = out[c].astype(object)
            out.loc[risky, c] = placeholder
        return out, affected
    return df.loc[~risky].reset_index(drop=True), affected
