from faker import Faker
import pandas as pd

fake = Faker('pt_BR') 

infohealth = [
    "Hipertensão controlada",
    "Diabetes tipo 2",
    "Histórico de cirurgia cardíaca",
    "Asma leve",
    "Sem alergias conhecidas",
    "Histórico familiar de câncer",
    "Colesterol elevado",
    "Imunização completa",
    "Alergia a medicamentos (ex.: penicilina)",
    "Sem histórico de doenças crônicas",
    "Problemas de visão (usa óculos)",
    "Anemia leve",
    "Saúde mental estável",
    "Intolerância à lactose",
    "Histórico de fraturas ósseas",
    "Pressão arterial baixa",
    "Histórico de infecções respiratórias",
    "Uso de medicação contínua",
    "Artrite reumatoide",
    "Doença renal crônica",
    "Refluxo gastroesofágico",
    "Doença celíaca",
    "Hipotireoidismo",
    "Histórico de migrenas",
    "DPOC (Doença Pulmonar Obstrutiva Crônica)"
]

def gerar_dados_usuarios(quantidade):
    dados_usuarios = []

    for _ in range(quantidade):
        rua = fake.street_name()
        numero = fake.building_number()
        endereco = f"{rua}, {numero}"
        
        usuario = {
            "Nome": fake.name(),
            "Endereço": endereco,
            "Cidade": fake.city(),
            "Estado": fake.state(),
            "Número de Telefone": fake.phone_number(),
            "Idade": fake.random_int(min=18, max=90),
            "Informações de Saúde": fake.random_element(infohealth)  
        }
        dados_usuarios.append(usuario)

    return dados_usuarios

# Gerar dados para 100 usuários como exemplo
dados = gerar_dados_usuarios(100)

# Criar um DataFrame usando pandas e salvar em um arquivo CSV
df = pd.DataFrame(dados)
df.to_csv("dados_usuarios.csv", index=False, encoding='utf-8')

print("Conjunto de dados gerado e salvo em 'dados_usuarios.csv'")
