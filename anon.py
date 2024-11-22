import pandas as pd
import numpy as np
import os 
import hashlib
from cape_dataframes.pandas.transformations import Tokenizer
from cape_dataframes.pandas import dtypes


class Anonymization:

    def __init__(self,df): 
        self.df=df

    def token_info(self, cols):
        def hash_value(value): # define uma funcao ajudante para os valores hash
            return hashlib.sha256(value.encode('utf-8')).hexdigest()

        for column in cols: # processa cada coluna especificada
            self.df[column] = self.df[column].astype(str)
            self.df[column] = self.df[column].apply(hash_value) # aplica a funcao hash para cada valor na coluna

        return self.df

    def pseudo(self,cols): # pseudonomiza os dados da coluna
        for column in cols:
            self.df[column]=self.df[column].astype(str)
            rows = [] # inicializa lista de apoio
            for item in self.df[column].astype(str):
                pseudo = "" # inicializa variavel pseudo
                for c in item:
                    shift = 8 # variacao da pseudonomizacao
                    i = ord(c)
                    if (i >= 48 and i < 58): 
                        continue
                    elif (i >= 65 and i < 91): 
                        i = ((i - 65 + shift) % 26) + 65
                    elif (i >= 97 and i < 123): 
                        i = ((i - 97 + shift) % 26) + 97
                    pseudo += chr(i) # concatena os caracteres alterados
                rows.append(pseudo) # adiciona cada linha na lista de apoio
            self.df[column] = rows # salva os pseudonimos na coluna original
        return self.df

    @staticmethod
    def mask_info(text): # funcao apoio para mascarar
        if pd.isnull(text):
            return text  # se o valor é nulo, retorna ele mesmo
        text = str(text)
        if len(text) <= 5:
            # mascara todos os caracteres, exeto o primeiro e ultimo
            if len(text) > 2:
                return text[0] + '*' * (len(text) - 2) + text[-1]
            else:
                return text  # se a string tiver 2 caracteres ou menos, retornar a string original
        result = text[0] # mostra o primeiro caracter

        if "@" in text: # se a string for email
            index_at = text.find("@") # encontra o index de "@"
            result += "@" + text[index_at + 1] # mantem o "@" e o proximo caracter
            
            # mascara os caracteres restantes
            num_masked_before = index_at - 1
            num_masked_after = len(text) - len(result) - num_masked_before 
            masked_before = '*' * num_masked_before
            masked_after = '*' * num_masked_after

            result = result[0] + masked_before + result[1:] + masked_after
        else: 
            result += text[-4:] # adiciona os ultimos 4 caracteres
            # mascara dos caracteres restantes
            num_masked = len(text) - len(result)
            masked = '*' * num_masked

            result = result[0] + masked + result[1:]
        return result

    def mask_df(self,cols): # mascara os dados da coluna
        for column in cols:
            if column in self.df.columns:
                self.df[column] = self.df[column].apply(self.mask_info)
        return self.df

    def general_info(self, cols): # generaliza os dados da coluna para hora e data
        for column in cols:
            if column == 'hora':
                self.df['periodo'] = self.df['hora'].apply(self.get_term)
            elif column == 'data':
                self.df['mes'] = self.df['data'].apply(self.get_month)
        return self.df

    @staticmethod
    def get_term(hora): # verifica periodo
        hora_dt = pd.to_datetime(hora, format='%H:%M')
        if hora_dt.hour >= 4 and hora_dt.hour < 12:
            return 'manha'
        elif hora_dt.hour >= 12 and hora_dt.hour < 20:
            return 'tarde'
        else:
            return 'noite'

    @staticmethod
    def get_month(data): # verifica o mes
        data_dt = pd.to_datetime(data, format='%d/%m/%Y')
        meses = ['janeiro', 'fevereiro', 'março', 'abril', 'maio', 'junho', 'julho', 'agosto', 'setembro', 'outubro', 'novembro', 'dezembro']
        return meses[data_dt.month - 1]
    
    def remove_col(self, cols): # remove os dados da coluna
        for column in cols:
            if column in self.df.columns:
                #os.write(1, f"remover: {x}\n".encode())
                self.df.drop(columns=[column], inplace=True)
        return self.df
