"""Interface legada. Mantida por compatibilidade; use o pacote `anonymizer`."""
from __future__ import annotations

import pandas as pd

from anonymizer.techniques import Context, generalize_date, generalize_time, mask, pseudonym, token


class Anonymization:
    def __init__(self, df: pd.DataFrame, key: str = "anonapp-default-key"):
        self.df = df
        self.ctx = Context(key=key, df=df)

    def token_info(self, cols):
        for c in cols:
            self.df[c] = token(self.df[c], self.ctx).values
        return self.df

    def pseudo(self, cols, kind: str = "nome"):
        for c in cols:
            self.df[c] = pseudonym(self.df[c], self.ctx, kind=kind).values
        return self.df

    def mask_df(self, cols):
        for c in cols:
            if c in self.df.columns:
                self.df[c] = mask(self.df[c], self.ctx).values
        return self.df

    def general_info(self, cols):
        for c in cols:
            if c == "hora":
                self.df["periodo"] = generalize_time(self.df[c], self.ctx).values
            elif c == "data":
                self.df["mes"] = generalize_date(self.df[c], self.ctx, level="mes").values
        return self.df

    def remove_col(self, cols):
        self.df.drop(columns=[c for c in cols if c in self.df.columns], inplace=True)
        return self.df
