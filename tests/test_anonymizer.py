import pandas as pd
import pytest

from anonymizer import Config, Context, Rule, assess, detect_dataframe, enforce_k, run
from anonymizer.detection import DIRECT, SENSITIVE, is_valid_cnpj, is_valid_cpf, luhn_ok
from anonymizer.techniques import (TECHNIQUES, date_shift, decrypt, encrypt, format_preserving,
                                   generalize_cep, generalize_date, generalize_number, generalize_time,
                                   group_rare, mask_value, noise, pseudonym, shuffle, token)

KEY = "chave-de-teste"


@pytest.fixture
def ctx():
    return Context(key=KEY, seed=1)


@pytest.fixture
def people():
    return pd.DataFrame({
        "Nome": ["Ana Souza", "Bruno Lima", "Ana Souza", "Carla Dias", None],
        "CPF": ["529.982.247-25", "111.444.777-35", "529.982.247-25", "390.533.447-05", None],
        "E-mail": ["ana@gmail.com", "bruno@uol.com.br", "ana@gmail.com", "carla@empresa.com", None],
        "Idade": ["34", "35", "34", "61", "40"],
        "CEP": ["01310-100", "01310-200", "01310-100", "20040-002", "30130-010"],
        "Cidade": ["São Paulo", "São Paulo", "São Paulo", "Rio de Janeiro", "Belo Horizonte"],
        "Diagnóstico": ["Asma", "Diabetes", "Asma", "Hipertensão", "Asma"],
    })


def test_validators():
    assert is_valid_cpf("529.982.247-25")
    assert not is_valid_cpf("529.982.247-26")
    assert not is_valid_cpf("111.111.111-11")
    assert is_valid_cnpj("11.222.333/0001-81")
    assert luhn_ok("4111 1111 1111 1111")


def test_detection(people):
    rep = {r.column: r for r in detect_dataframe(people)}
    assert rep["CPF"].detected_type == "cpf" and rep["CPF"].category == DIRECT
    assert rep["E-mail"].detected_type == "email"
    assert rep["Cidade"].detected_type == "cidade"
    assert rep["CEP"].detected_type == "cep"
    assert rep["Diagnóstico"].category == SENSITIVE


def test_token_is_keyed_and_consistent(ctx):
    s = pd.Series(["a", "b", "a", None])
    out = token(s, ctx)
    assert out[0] == out[2] != out[1]
    assert out[3] is None
    assert token(s, Context(key="outra"))[0] != out[0]


def test_pseudonym_consistent_unique_and_valid(ctx):
    s = pd.Series([f"{i:011d}" for i in range(300)] * 2)
    out = pseudonym(s, ctx, kind="cpf")
    assert out[:300].nunique() == 300
    assert (out[:300].values == out[300:].values).all()
    assert all(is_valid_cpf(v) for v in out)


def test_format_preserving(ctx):
    out = format_preserving(pd.Series(["(11) 98765-4321", "AB-12"]), ctx, keep_start=4)
    assert out[0].startswith("(11)") and len(out[0]) == 15 and out[0][10] == "-"
    assert out[1][2] == "-" and out[1][:2].isalpha() and out[1][3:].isdigit()


@pytest.mark.parametrize("value,expected", [
    ("529.982.247-25", "***.982.247-**"),
    ("52998224725", "***.982.247-**"),
    ("ana.souza@gmail.com", "a********@g****.com"),
    ("11.222.333/0001-81", "11.***.***/0001-**"),
    ("(11) 98765-4321", "(**) *****-4321"),
    ("4111 1111 1111 1111", "**** **** **** 1111"),
])
def test_mask(value, expected):
    assert mask_value(value) == expected


def test_generalizations(ctx):
    assert generalize_number(pd.Series(["34", "91", None]), ctx, top="90").tolist() == ["30-39", "90+", None]
    assert generalize_date(pd.Series(["15/03/1990", "2020-12-01"]), ctx, level="semestre").tolist() == \
        ["1990-S1", "2020-S2"]
    assert generalize_time(pd.Series(["08:30", "19:00", "02:10"]), ctx).tolist() == ["manhã", "noite", "madrugada"]
    assert generalize_cep(pd.Series(["01310-100"]), ctx, digits=3).tolist() == ["013**-***"]
    assert group_rare(pd.Series(["a", "a", "b"]), ctx, min_freq=2).tolist() == ["a", "a", "Outros"]


def test_noise_preserves_range_and_nulls(ctx):
    s = pd.Series([float(x) for x in range(100)] + [None], name="v")
    out = noise(s, ctx, epsilon=0.5, sensitivity=5)
    assert out.isna().sum() == 1
    assert out.min() >= 0 and out.max() <= 99
    assert not (out[:100].astype(float).values == s[:100].values).all()


def test_date_shift_preserves_intervals_by_group():
    df = pd.DataFrame({"id": [1, 1, 2], "d": ["01/01/2020", "11/01/2020", "05/05/2021"]})
    out = date_shift(df["d"], Context(KEY, df=df), max_days=20, group_column="id")
    d = pd.to_datetime(out, format="%d/%m/%Y")
    assert (d[1] - d[0]).days == 10


def test_shuffle_keeps_distribution(ctx):
    s = pd.Series(list(range(50)), name="x")
    assert sorted(shuffle(s, ctx)) == sorted(s)


def test_encrypt_roundtrip(ctx):
    s = pd.Series(["segredo", None, "ç"])
    enc = encrypt(s, ctx)
    assert enc[0] != "segredo"
    assert decrypt(enc, ctx).tolist() == ["segredo", None, "ç"]
    assert decrypt(enc, Context(key="errada"))[0] is None


def test_risk_and_enforce(people):
    qi = ["Idade", "Cidade"]
    r = assess(people, qi, "Diagnóstico", target_k=2)
    assert r.k == 1 and r.unique_records == 3 and r.l_diversity == 1
    out, n = enforce_k(people, qi, 2)
    assert n == 3 and len(out) == 2
    assert assess(out, qi, target_k=2).k >= 2


def test_engine_end_to_end(people):
    cfg = Config(
        rules=[Rule("Nome", "pseudonimo"), Rule("CPF", "mascara"), Rule("E-mail", "token"),
               Rule("Idade", "generalizar_numero", {"bin_size": 50}), Rule("CEP", "generalizar_cep", {"digits": 1}),
               Rule("Cidade", "remover")],
        quasi_identifiers=["Idade", "CEP", "Cidade"], sensitive="Diagnóstico", target_k=2, enforce_k=True,
    )
    res = run(people, cfg, KEY, "x.csv")
    assert "Cidade" not in res.df.columns
    assert res.report["k_anonimato"]["depois"]["k_anonimato"] >= 2
    assert people["Nome"][0] == "Ana Souza"  # entrada não é alterada
    assert Config.from_json(cfg.to_json()) == cfg


def test_all_techniques_run(people, ctx):
    ctx.df = people
    for tech in TECHNIQUES.values():
        out = tech.fn(people["Idade"], ctx, **tech.defaults())
        assert out is None or len(out) == len(people), tech.id


def test_engine_requires_key(people):
    with pytest.raises(ValueError):
        run(people, Config(), "")
