import os
import random
import urllib.request
import zipfile
from fpdf import FPDF
import string
from software.tools.logger import logger
from software.config.shared_config import GeneralConfig as gc


def calcPercentage(directory_count, counter):
    """Função para calcular a regra de 3"""
    v1 = directory_count  # numero de 100%
    v2 = 100  # 100%
    v3 = counter  # número a descobrir a porcentagem
    return v3 * v2 / v1


def returnPercentage(directory_count, counter, porcentage):
    """Função para retornar a porcentagem"""
    for i in range(100):
        counter = round(counter + 0.01, 2)
        if counter == round(directory_count * porcentage, 2):
            logger.debug(f"Working on {'deleting' if gc.delete_honeypots else 'creating'} honeypots: {round(calcPercentage(directory_count, counter))}%.")
            porcentage = round(porcentage + 0.1, 2)
    return counter, porcentage


def randomString(action):
    """Função para gerar uma string única e aleatória que ficará dentro de cada honeypot"""
    if action == "unique-hash":
        characters = string.ascii_letters + string.digits + string.punctuation
        random_string = ''.join(random.choice(characters) for i in range(50))
        return random_string
    if action == "unique-name":
        characters = string.ascii_letters + string.digits
        random_string = ''.join(random.choice(characters) for i in range(25))
        return random_string + gc.honeypot_file_extension


def generatePDFs(path):
    random_words = ['secret', 'bank', 'credit-card', 'data', 'password', 'finantial', 'money', 'personal', 'paypal', 'credentials']
    for i1 in range(0, int(gc.pdfs_to_generate / 100)):
        for i2 in range(0, int(gc.pdfs_to_generate / 100)):
            word = random.choice(random_words)
            unique_pdf = FPDF()
            unique_pdf.add_page()
            unique_pdf.set_font('Arial', 'B', 8)
            unique_pdf.cell(40, 10, f'{word}: {i1} - {i2}')
            unique_pdf.output(os.path.join(path, f'{word}-{i1}-{i2}.pdf'), 'F')


def downloadHandle():
    if os.path.exists(os.path.join(gc.PATH_TO_SYSINTERNALS_HANDLE_FOLDER, 'handle.exe')):
        pass

    else:
        handle_zip_url = 'https://download.sysinternals.com/files/Handle.zip'
        handle_zip_path = os.path.join(gc.PATH_TO_SYSINTERNALS_HANDLE_FOLDER, 'Handle.zip')

        try:
            urllib.request.urlretrieve(handle_zip_url, handle_zip_path)

        except:
            if not os.path.isfile(handle_zip_path):
                print('Could not Download SysInternals Handle (check you internet connection or firewall)')

        with zipfile.ZipFile(handle_zip_path, 'r') as zip_ref:
            zip_ref.extractall(path=gc.PATH_TO_SYSINTERNALS_HANDLE_FOLDER)
            zip_ref.close()

        os.remove(handle_zip_path)


def isHexStr(s):
    return set(s).issubset(string.hexdigits)
