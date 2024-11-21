from datetime import datetime
from numpy.core.defchararray import center
import streamlit as st
import pandas as pd
import numpy as np
from anon import Anonymization
import base64

def get_table_download_link(df):
    csv = df.to_csv(index=False)
    b64 = base64.b64encode(csv.encode()).decode()  # nessessario realizar a conversao strings <-> bytes para base64
    href = f'<a href="data:file/csv;base64,{b64}" download="resultado.csv">Download arquivo csv</a>'
    return href

st.markdown('# Aplicativo de Anonimização de Dados')

st.markdown('## Faça Upload do Arquivo (.csv,.xlsx)')
data_file=st.file_uploader('Arquivo',type=['csv','xlsx'])

df=[] # inicializa o dataframe

if data_file:
    if data_file.name[-3:]=='csv':
        df=pd.read_csv(data_file) # le o arquivo csv
    elif data_file.name[-4:]=='xlsx':
        df=pd.read_excel(data_file) # le o arquivo xlsx

    st.write(df.head()) # mostra as 5 primeiras linhas do arquivo
    #st.write(df) # mostra o arquivo como um todo
    st.markdown('### Selecione as variáveis a serem anonimizadas:')

    options = df.columns
    checkbox_1=np.zeros(len(options),dtype=bool)
    for i in range(len(options)): # cria as checkboxes para cada coluna do arquivo
        checkbox_1[i]=st.checkbox(str(options[i]),key='1_'+str(i))

    N_col=len(np.where(checkbox_1==True)[0])
    cols=options[np.where(checkbox_1==True)]

    if  N_col>0:
        st.markdown('### Variáveis selecionadas:')    
        st.markdown('##### '+'; '.join(cols)) # mostra as variaveis selecionadas

        st.markdown("### Selecione a técnica de anonimização:")
        left_column,token_column,pseudo_column,mask_column,general_column,remove_column=st.columns(6)

        # cria a tabela para as tecnicas de anonimizacao
        token_column.write('Tokenização')
        pseudo_column.write('Pseudo')
        mask_column.write('Máscara')
        general_column.write('Generalização')
        remove_column.write('Remover')

        checkbox_2_token=np.zeros(N_col,dtype=bool)
        checkbox_2_pseudo=np.zeros(N_col,dtype=bool)
        checkbox_2_mask=np.zeros(N_col,dtype=bool)
        checkbox_2_general=np.zeros(N_col,dtype=bool)
        checkbox_2_remove=np.zeros(N_col,dtype=bool)
        print(N_col,cols)
        
        left_column.write('')
        left_column.write('')
        
        # cria os checkboxes para cada tecnica de anonimizacao
        for i in range(N_col):
            left_column.write(cols[i])
            checkbox_2_token[i]=token_column.checkbox('token',key='2_token_'+str(i),label_visibility='hidden')
            checkbox_2_pseudo[i]=pseudo_column.checkbox('pseudo',key='2_pseudo_'+str(i),label_visibility='hidden')
            checkbox_2_mask[i]=mask_column.checkbox('mask',key='2_mask_'+str(i),label_visibility='hidden')
            checkbox_2_general[i]=general_column.checkbox('general',key='2_general_'+str(i),label_visibility='hidden')
            checkbox_2_remove[i]=remove_column.checkbox('remove',key='2_remove_'+str(i),label_visibility='hidden')

        # verifica quais checkboxes estao selecionadas
        token_info=cols[np.where(checkbox_2_token==True)]
        pseudo_info=cols[np.where(checkbox_2_pseudo==True)]
        mask_info=cols[np.where(checkbox_2_mask==True)]
        general_info=cols[np.where(checkbox_2_general==True)]
        remove_info=cols[np.where(checkbox_2_remove==True)]

        pressed=st.button('Anonimizar')
        if pressed:
            anony=Anonymization(df)
            anony.token_info(token_info)
            anony.pseudo(pseudo_info)
            anony.mask_df(mask_info)
            anony.general_info(general_info)
            anony.remove_col(remove_info)

            st.markdown("#### Preview:")
            
            st.write(df)
            # st.write(df.head())

            st.markdown(get_table_download_link(df), unsafe_allow_html=True) #download do arquivo anonimizado
