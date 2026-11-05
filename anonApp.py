"""Interface Streamlit do AnonApp."""
from __future__ import annotations

import io
import json

import pandas as pd
import streamlit as st

from anonymizer import (TECHNIQUES, Config, Context, Rule, assess, class_size_distribution,
                        detect_dataframe, generate_secret, key_fingerprint, run)
from anonymizer.detection import DIRECT, QUASI, SENSITIVE
from anonymizer.engine import file_digest
from anonymizer.techniques import decrypt

st.set_page_config(page_title="AnonApp", page_icon="🔒", layout="wide")

LABEL_TO_ID = {t.label: t.id for t in TECHNIQUES.values()}
ID_TO_LABEL = {t.id: t.label for t in TECHNIQUES.values()}


# --------------------------------------------------------------------------- leitura

@st.cache_data(show_spinner=False)
def load_file(data: bytes, name: str, as_text: bool) -> pd.DataFrame:
    dtype = str if as_text else None
    if name.lower().endswith((".xlsx", ".xls")):
        return pd.read_excel(io.BytesIO(data), dtype=dtype)
    last_error = None
    for enc in ("utf-8-sig", "latin-1"):
        try:
            return pd.read_csv(io.BytesIO(data), sep=None, engine="python", encoding=enc, dtype=dtype)
        except UnicodeDecodeError as exc:
            last_error = exc
    raise last_error


@st.cache_data(show_spinner=False)
def detect(df: pd.DataFrame) -> pd.DataFrame:
    return pd.DataFrame([r.as_dict() for r in detect_dataframe(df)])


def to_xlsx(df: pd.DataFrame) -> bytes:
    buf = io.BytesIO()
    with pd.ExcelWriter(buf, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="dados")
    return buf.getvalue()


def to_csv(df: pd.DataFrame) -> bytes:
    return df.to_csv(index=False).encode("utf-8-sig")


# --------------------------------------------------------------------------- parâmetros

def param_widget(param, key: str, default, columns: list[str]):
    help_ = param.help
    if param.kind == "int":
        return int(st.number_input(param.label, value=int(default), step=1, key=key, help=help_,
                                   min_value=None if param.min is None else int(param.min),
                                   max_value=None if param.max is None else int(param.max)))
    if param.kind == "float":
        return float(st.number_input(param.label, value=float(default), key=key, help=help_,
                                     min_value=None if param.min is None else float(param.min),
                                     format="%.4g"))
    if param.kind == "select":
        opts = param.options or []
        idx = opts.index(default) if default in opts else 0
        return st.selectbox(param.label, opts, index=idx, key=key, help=help_)
    if param.kind == "bool":
        return st.checkbox(param.label, value=bool(default), key=key, help=help_)
    if param.kind == "column":
        opts = [""] + columns
        idx = opts.index(default) if default in opts else 0
        return st.selectbox(param.label, opts, index=idx, key=key, help=help_,
                            format_func=lambda c: c or "(nenhuma)")
    return st.text_input(param.label, value="" if default is None else str(default), key=key, help=help_)


def risk_metrics(report, label: str = ""):
    c1, c2, c3, c4 = st.columns(4)
    c1.metric(f"k-anonimato {label}", report.k)
    c2.metric("Registros únicos", report.unique_records)
    c3.metric(f"Abaixo de k={report.target_k}", report.records_below_k)
    c4.metric("Risco máximo", f"{report.max_risk:.0%}")
    if report.l_diversity is not None:
        st.caption(f"l-diversidade: {report.l_diversity} · risco médio: {report.avg_risk:.1%} · "
                   f"classes de equivalência: {report.classes}")


# --------------------------------------------------------------------------- barra lateral

if "secret" not in st.session_state:
    st.session_state.secret = generate_secret()

with st.sidebar:
    st.header("🔑 Chave secreta")
    if st.button("Gerar nova chave"):
        st.session_state.secret = generate_secret()
    secret = st.text_input("Chave", type="password", key="secret",
                           help="Usada em tokens, pseudônimos, deslocamento de datas e criptografia. "
                                "A mesma chave gera os mesmos resultados.")
    if secret:
        st.caption(f"Impressão digital: `{key_fingerprint(secret)}`")
    st.warning("Guarde a chave em local seguro. Sem ela não há como reproduzir tokens nem "
               "descriptografar dados. Nunca a envie junto com o arquivo anonimizado.")
    seed = int(st.number_input("Semente aleatória", value=42, step=1,
                               help="Controla ruído, embaralhamento e deslocamentos sem agrupamento."))

    st.header("⚙️ Configuração")
    cfg_file = st.file_uploader("Importar configuração (.json)", type=["json"])
    imported: Config | None = None
    if cfg_file:
        try:
            imported = Config.from_json(cfg_file.getvalue().decode("utf-8"))
            st.success(f"{len(imported.rules)} regras importadas.")
        except Exception as exc:  # noqa: BLE001
            st.error(f"Configuração inválida: {exc}")
    as_text = st.checkbox("Ler colunas como texto", value=True,
                          help="Preserva zeros à esquerda em CPF, CEP e telefone.")


# --------------------------------------------------------------------------- principal

st.title("🔒 AnonApp")
st.caption("Anonimização e pseudonimização de dados pessoais em conformidade com a LGPD.")

data_file = st.file_uploader("Arquivo de dados", type=["csv", "xlsx"])

tab_dados, tab_tec, tab_risco, tab_res, tab_dec = st.tabs(
    ["1. Dados e detecção", "2. Técnicas", "3. Risco de reidentificação", "4. Resultado", "Descriptografar"])

if not data_file:
    with tab_dados:
        st.info("Envie um arquivo CSV ou XLSX para começar.")
        with st.expander("Técnicas disponíveis", expanded=True):
            for t in TECHNIQUES.values():
                if t.id != "manter":
                    st.markdown(f"**{t.label}** ({t.group}): {t.description}")

raw = data_file.getvalue() if data_file else b""
df = load_file(raw, data_file.name, as_text) if data_file else None

if df is not None:
    digest = file_digest(raw)
    columns = list(map(str, df.columns))
    df.columns = columns
    detection = detect(df)
    det_by_col = detection.set_index("Coluna")
    rules_in = {r.column: r for r in imported.rules} if imported else {}
    state_id = f"{digest[:12]}_{file_digest(cfg_file.getvalue())[:8] if cfg_file else 0}"

    # ------------------------------------------------------------------ 1. dados
    with tab_dados:
        c1, c2, c3 = st.columns(3)
        c1.metric("Registros", f"{len(df):,}".replace(",", "."))
        c2.metric("Colunas", len(columns))
        c3.metric("Colunas com dados pessoais",
                  int(detection["Categoria"].isin([DIRECT, QUASI, SENSITIVE]).sum()))
        st.subheader("Amostra")
        st.dataframe(df.head(50))
        st.subheader("Dados pessoais detectados")
        st.caption("Identificadores diretos apontam o titular sozinhos. Quase-identificadores "
                   "o apontam quando combinados. Dados sensíveis exigem proteção reforçada (LGPD art. 11).")
        st.dataframe(detection, hide_index=True)

    # ------------------------------------------------------------------ 2. técnicas
    with tab_tec:
        st.markdown("Escolha uma técnica para cada coluna. As sugestões vêm da detecção automática.")
        base = pd.DataFrame({
            "Coluna": columns,
            "Categoria": [det_by_col.loc[c, "Categoria"] for c in columns],
            "Técnica": [ID_TO_LABEL[rules_in[c].technique] if c in rules_in and rules_in[c].technique in ID_TO_LABEL
                        else ID_TO_LABEL[det_by_col.loc[c, "Técnica sugerida"]] for c in columns],
        })
        edited = st.data_editor(
            base, hide_index=True, key=f"editor_{state_id}",
            disabled=["Coluna", "Categoria"],
            column_config={"Técnica": st.column_config.SelectboxColumn(
                "Técnica", options=list(LABEL_TO_ID), required=True)},
        )

        rules: list[Rule] = []
        for _, row in edited.iterrows():
            col, tech = row["Coluna"], TECHNIQUES[LABEL_TO_ID[row["Técnica"]]]
            params = {}
            if tech.params:
                prev = rules_in[col].params if col in rules_in and rules_in[col].technique == tech.id else {}
                with st.expander(f"{col} · {tech.label}"):
                    st.caption(tech.description)
                    cols_ui = st.columns(min(3, len(tech.params)))
                    for i, p in enumerate(tech.params):
                        with cols_ui[i % len(cols_ui)]:
                            params[p.name] = param_widget(
                                p, f"p_{state_id}_{col}_{tech.id}_{p.name}", prev.get(p.name, p.default),
                                [c for c in columns if c != col])
            rules.append(Rule(col, tech.id, params))

    # ------------------------------------------------------------------ 3. risco
    with tab_risco:
        st.markdown("Quase-identificadores combinados permitem reidentificar pessoas. "
                    "O **k-anonimato** garante que cada combinação apareça em pelo menos *k* registros.")
        default_qi = imported.quasi_identifiers if imported else \
            detection.loc[detection["Categoria"] == QUASI, "Coluna"].tolist()
        qi = st.multiselect("Quase-identificadores", columns,
                            default=[c for c in default_qi if c in columns], key=f"qi_{state_id}")
        sens_opts = [""] + columns
        default_sens = imported.sensitive if imported and imported.sensitive else next(
            iter(detection.loc[detection["Categoria"] == SENSITIVE, "Coluna"]), "")
        sensitive = st.selectbox("Atributo sensível (para l-diversidade)", sens_opts,
                                 index=sens_opts.index(default_sens) if default_sens in sens_opts else 0,
                                 format_func=lambda c: c or "(nenhum)", key=f"sens_{state_id}")
        c1, c2, c3 = st.columns(3)
        target_k = int(c1.number_input("k alvo", min_value=2, value=imported.target_k if imported else 5,
                                       step=1, key=f"k_{state_id}"))
        do_enforce = c2.checkbox("Garantir k-anonimato após as técnicas",
                                 value=imported.enforce_k if imported else False, key=f"enf_{state_id}")
        mode = c3.radio("Tratamento dos registros de risco", ["suprimir_linhas", "suprimir_valores"],
                        format_func={"suprimir_linhas": "Remover linhas",
                                     "suprimir_valores": "Ocultar quase-identificadores"}.get,
                        key=f"mode_{state_id}")

        st.subheader("Risco no arquivo original")
        before = assess(df, qi, sensitive or None, target_k)
        risk_metrics(before)
        if qi:
            st.bar_chart(class_size_distribution(df, qi).set_index("Tamanho da classe"))
            if before.unique_records:
                st.warning(f"{before.unique_records} registros possuem combinação única de "
                           "quase-identificadores e podem ser reidentificados.")

    config = Config(rules=rules, quasi_identifiers=qi, sensitive=sensitive or None,
                    target_k=target_k, enforce_k=do_enforce, enforce_mode=mode, seed=seed)

    # ------------------------------------------------------------------ 4. resultado
    with tab_res:
        if st.button("🔒 Anonimizar", type="primary"):
            try:
                with st.spinner("Processando..."):
                    st.session_state.result = run(df, config, secret, data_file.name, digest)
                    st.session_state.result_id = state_id
            except Exception as exc:  # noqa: BLE001
                st.error(f"Erro ao anonimizar: {exc}")

        result = st.session_state.get("result")
        if result is not None and st.session_state.get("result_id") == state_id:
            rep = result.report
            k_info = rep["k_anonimato"]
            a, b = k_info["antes"], k_info["depois"]
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("k-anonimato", b["k_anonimato"], delta=b["k_anonimato"] - a["k_anonimato"])
            c2.metric("Registros únicos", b["registros_unicos"],
                      delta=b["registros_unicos"] - a["registros_unicos"], delta_color="inverse")
            c3.metric("Risco máximo", f"{b['risco_maximo']:.0%}",
                      delta=(f"{(b['risco_maximo'] - a['risco_maximo']) * 100:+.0f} p.p."
                             if b["risco_maximo"] != a["risco_maximo"] else None), delta_color="inverse")
            c4.metric("Linhas", rep["linhas_saida"], delta=rep["linhas_saida"] - rep["linhas_entrada"])
            if k_info["registros_suprimidos"]:
                share = k_info["registros_suprimidos"] / max(rep["linhas_entrada"], 1)
                msg = f"{k_info['registros_suprimidos']} registros ({share:.0%}) tratados para atingir k={target_k}."
                if share > 0.2:
                    st.warning(msg + " Perda alta: generalize mais os quase-identificadores "
                               "(faixas maiores, menos dígitos de CEP, agrupar categorias raras) "
                               "ou reduza o k alvo.")
                else:
                    st.info(msg)
            if any(r["reversivel"] for r in rep["regras_aplicadas"]):
                st.warning("Há colunas com criptografia reversível. O resultado é pseudonimizado, "
                           "não anônimo, e continua sujeito à LGPD.")

            left, right = st.columns(2)
            left.markdown("**Original**")
            left.dataframe(df.head(20))
            right.markdown("**Anonimizado**")
            right.dataframe(result.df.head(20))

            with st.expander("Relatório de auditoria"):
                st.json(rep)

            stem = data_file.name.rsplit(".", 1)[0]
            d1, d2, d3, d4 = st.columns(4)
            d1.download_button("⬇️ CSV", to_csv(result.df), f"{stem}_anonimizado.csv", "text/csv")
            d2.download_button("⬇️ Excel", to_xlsx(result.df), f"{stem}_anonimizado.xlsx",
                               "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
            d3.download_button("⬇️ Relatório", json.dumps(rep, ensure_ascii=False, indent=2, default=str),
                               f"{stem}_relatorio.json", "application/json")
            d4.download_button("⬇️ Configuração", config.to_json(), f"{stem}_config.json", "application/json")
        else:
            st.info("Revise as técnicas e o risco, depois clique em Anonimizar.")

# ------------------------------------------------------------------ descriptografar
with tab_dec:
    st.markdown("Recupera colunas cifradas com **Criptografia reversível (AES)**. Exige a mesma chave.")
    enc_file = st.file_uploader("Arquivo anonimizado", type=["csv", "xlsx"], key="dec_file")
    if enc_file:
        enc_df = load_file(enc_file.getvalue(), enc_file.name, True)
        enc_cols = st.multiselect("Colunas cifradas", list(map(str, enc_df.columns)))
        if st.button("Descriptografar") and enc_cols:
            ctx = Context(key=secret)
            out = enc_df.copy()
            failures = 0
            for c in enc_cols:
                dec = decrypt(out[c], ctx)
                failures += int((dec.isna() & out[c].notna()).sum())
                out[c] = dec.values
            if failures:
                st.error(f"{failures} valores não puderam ser descriptografados. Confira a chave.")
            st.dataframe(out.head(50))
            st.download_button("⬇️ CSV", to_csv(out), "descriptografado.csv", "text/csv")
