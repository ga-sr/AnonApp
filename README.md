# AnonApp

AnonApp é uma ferramenta de anonimização e pseudonimização de dados pessoais voltada à conformidade com a Lei Geral de Proteção de Dados (LGPD). O app detecta dados pessoais, aplica técnicas configuráveis por coluna, mede o risco de reidentificação e gera um relatório de auditoria.

## Funcionalidades

### Detecção automática de dados pessoais
- Reconhece CPF e CNPJ (com validação dos dígitos verificadores), e-mail, telefone, CEP, cartão (algoritmo de Luhn), IP, placa, datas e horários.
- Usa também o nome da coluna (ex.: `nome`, `endereco`, `idade`, `saude`, `religiao`).
- Classifica cada coluna como identificador direto, quase-identificador ou dado sensível (LGPD art. 5º, II) e sugere uma técnica.

### Técnicas

| Grupo | Técnica | Uso típico |
|---|---|---|
| Supressão | Remover coluna, substituir por constante | Endereço, observações livres |
| Pseudonimização | Tokenização HMAC-SHA256 com chave secreta | IDs, RG, placa, e-mail |
| Pseudonimização | Pseudônimo realista e consistente (Faker pt_BR) | Nome, CPF válido, telefone, empresa |
| Pseudonimização | Substituição com formato preservado | Códigos com formato fixo |
| Pseudonimização | Criptografia reversível (Fernet/AES) | Quando a reidentificação controlada é necessária |
| Mascaramento | Máscara por tipo: CPF `***.982.247-**`, e-mail `a***@g****.com`, telefone, cartão, CNPJ | Exibição parcial |
| Generalização | Faixas numéricas com limites, data (ano, semestre, trimestre, mês), hora (período), CEP (prefixo), agrupar categorias raras | Quase-identificadores |
| Perturbação | Ruído de Laplace (privacidade diferencial) ou gaussiano | Valores numéricos |
| Perturbação | Deslocamento de datas, consistente por titular | Datas de eventos |
| Perturbação | Embaralhamento entre linhas | Quebra de vínculo |

Tokens, pseudônimos e deslocamentos dependem da chave secreta. A mesma chave gera os mesmos resultados, o que permite cruzar bases anonimizadas sem expor o dado original. Sem a chave, um atacante não consegue recalcular tokens por dicionário, como acontece com SHA-256 puro.

### Risco de reidentificação
- k-anonimato, l-diversidade, risco máximo e médio, registros únicos.
- Distribuição dos tamanhos das classes de equivalência.
- Garantia opcional de k-anonimato por remoção de linhas ou ocultação dos quase-identificadores.

### Auditoria e reprodutibilidade
- Relatório JSON com SHA-256 do arquivo de origem, impressão digital da chave (a chave nunca é gravada), regras, parâmetros e risco antes e depois.
- Exportação e importação da configuração para repetir o processo em novos arquivos.
- Download do resultado em CSV ou Excel.
- Aba para descriptografar colunas cifradas com a mesma chave.

## Instalação

```bash
git clone https://github.com/ga-sr/AnonApp.git
cd AnonApp
python -m venv venv
source venv/bin/activate  # No Windows: venv\Scripts\activate
pip install -r requirements.txt
streamlit run anonApp.py
```

Acesse [http://localhost:8501](http://localhost:8501).

Para gerar um arquivo de exemplo com 100 registros fictícios:

```bash
python fakeriz.py
```

## Uso como biblioteca

```python
import pandas as pd
from anonymizer import Config, Rule, run

df = pd.read_csv("dados.csv", dtype=str)
config = Config(
    rules=[
        Rule("Nome", "pseudonimo", {"kind": "nome"}),
        Rule("CPF", "mascara"),
        Rule("Idade", "generalizar_numero", {"bin_size": 10, "top": "80"}),
        Rule("Endereço", "remover"),
    ],
    quasi_identifiers=["Idade", "Cidade"],
    target_k=5,
    enforce_k=True,
)
result = run(df, config, key="sua-chave-secreta")
result.df.to_csv("anonimizado.csv", index=False)
```

## Testes

```bash
pip install -r requirements-dev.txt
pytest
```

## Estrutura

```
anonymizer/
  crypto.py      HMAC, derivação de chave e criptografia
  detection.py   detecção de dados pessoais
  techniques.py  técnicas e registro de parâmetros
  risk.py        k-anonimato e l-diversidade
  engine.py      execução das regras e relatório
anonApp.py       interface Streamlit
anon.py          interface legada (compatibilidade)
tests/           testes automatizados
```

## Observações sobre a LGPD

Dados pseudonimizados (tokens, pseudônimos, criptografia) continuam sendo dados pessoais, pois a reidentificação é possível com a chave. Para obter dados anônimos, remova ou generalize os identificadores diretos, trate os quase-identificadores até atingir um k adequado e mantenha a chave fora do alcance de quem recebe o arquivo.

## Licença

Este projeto está licenciado sob a [MIT License](LICENSE).
