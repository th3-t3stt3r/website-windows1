from genericpath import exists, isfile
import os
import random
import re
import string
import subprocess
import json
import time
import psutil
import wmi
from fpdf import FPDF
import urllib.request
import zipfile


def getAutorunProcesses():
    autorun_list = subprocess.check_output(["ls -1 /lib/systemd/system/*.service /etc/systemd/system/*.service"], shell=True, stderr=subprocess.DEVNULL).decode().rstrip().rsplit("\n")
    return autorun_list


def jsonTest():

    path = "/home/matheusheidemann/Documents/Github/Challenge/website-test/capyshield/software/config/capyshield-honeypot-hashes.json"
    event = "/home/matheusheidemann/Documents/Github/Challenge/website-test/ransomware-test/encrypt-test/folder47/subfolder12/.r4n50mw4r3-d373c70r.txt"
    start = time.perf_counter()

    with open(path, 'r', encoding='utf-8') as f:
        my_list = json.load(f)

        for idx, obj in enumerate(my_list):
            if obj['absolute_path'] == event:
                my_list.pop(idx)

    with open(path, 'w', encoding='utf-8') as f:
        f.write(json.dumps(my_list, indent=4))
    end = time.perf_counter()
    print(f"Updated JSON in {round(end - start, 3)}s")


def isin():

    event_paths = ['/home/matheusheidemann/Documents/Github/Challenge/website-test/ransomware-test/encrypt-test/.r4n50mw4r3-d373c70r.txt']
    json_file_data = [{'absolute_path': '/home/matheusheidemann/Documents/Github/Challenge/website-test/ransomware-test/encrypt-test/.r4n50mw4r3-d373c70r.txt', 'hash': '0cce0aa5dea5f77c612441a71a79afc84aabd1dc'},
                      {'absolute_path': '/home/matheusheidemann/Documents/Github/Challenge/website-test/ransomware-test/encrypt-test/folder1/.r4n50mw4r3-d373c70r.txt', 'hash': '5f98460b7032815ce25e40c4088bbf8b7ac60314'},
                      {'absolute_path': '/home/matheusheidemann/Documents/Github/Challenge/website-test/ransomware-test/encrypt-test/folder1/subfolder1/.r4n50mw4r3-d373c70r.txt', 'hash': '00cd5c2b7d6b1a1831aeb6c10a9ee6c5c858f330'},
                      {'absolute_path': '/home/matheusheidemann/Documents/Github/Challenge/website-test/ransomware-test/encrypt-test/folder1/subfolder2/.r4n50mw4r3-d373c70r.txt', 'hash': '53090460002c8ce7371e3bf5ea89336da8069bc5'},
                      {'absolute_path': '/home/matheusheidemann/Documents/Github/Challenge/website-test/ransomware-test/encrypt-test/folder2/.r4n50mw4r3-d373c70r.txt', 'hash': '9f6c00cea0ddf50b962019b984f30082826b3219'},
                      {'absolute_path': '/home/matheusheidemann/Documents/Github/Challenge/website-test/ransomware-test/encrypt-test/folder2/subfolder1/.r4n50mw4r3-d373c70r.txt', 'hash': 'aea3d2729832692948fc62603e02e1245838c235'},
                      {'absolute_path': '/home/matheusheidemann/Documents/Github/Challenge/website-test/ransomware-test/encrypt-test/folder2/subfolder2/.r4n50mw4r3-d373c70r.txt', 'hash': 'c4aabdcc705b5ef5d648aac1a23fd40fc3e72f86'}]

    maior = "/home/matheusheidemann/Documents/Github/Challenge/website-test/ransomware-test/encrypt-test/folder61/subfolder44/SMM1xQuoeMQ4G1ZXHyh3waLgn.capybara"
    menor = "/home/matheusheidemann/Documents/Github/Challenge/website-test/ransomware-test/encrypt-test/folder61/subfolder44/"

    if menor in maior:
        print('Yes')

    for el in json_file_data:
        for p in event_paths:
            if p in el['absolute_path']:
                print("TRUE")


def is_hex_str(s):
    return set(s).issubset(string.hexdigits)


def hextotest():
    # string = "/home/matheusheidemann/Documents/Github/Challenge/website-test/ransomware-test/encrypt-test/folder2 (copy 3)/b/"
    # string_to_hex = string.encode('utf-8').hex()
    # print(string_to_hex)

    hexstring = "2F686F6D652F6D61746865757368656964656D616E6E2F446F63756D656E74732F4769746875622F4368616C6C656E67652F776562736974652D746573742F72616E736F6D776172652D746573742F656E63727970742D746573742F666F6C646572322028636F70792032292F622F"
    hexstring_to_text = bytes.fromhex(hexstring).decode("ascii")
    print(hexstring_to_text)


def timetest():
    # print(time.time())
    # time.sleep(60)
    # print(time.time())
    print(1662427530.9781222 - 1662427470.918513)


def removefirstandlast():
    event_path = '"/home/matheusheidemann/Documents/Github/Challenge/website-test/ransomware-test/encrypt-test/folder61/subfolder1/sIb5OCEvteLVUCsHKGOoFpIBV.capybara"'
    print(event_path[1:-1])


def checkio():
    # 5188904
    # 4851438
    # 1000000
    # 8175396
    # 79706676
    p = psutil.Process(11296)
    start = p.io_counters()
    time.sleep(10)
    end = p.io_counters()
    print(start)
    print(end)
    print(end.write_bytes - start.write_bytes)


def trydelete():
    new_json_file_data = []
    to_delete = []

    json_file_data = ["PATO", "CACHORRO", "IGUANA", "FOCA", "CAPIVARA"]
    event_paths = ["CACHORRO", "IGUANA"]

    for element in json_file_data:
        for event_path in event_paths:
            if event_path in element:
                if event_path not in to_delete:
                    to_delete.append(element)

    for element in json_file_data:
        if element not in to_delete:
            new_json_file_data.append(element)

    print(new_json_file_data)


def isgreater():
    current = 1662962834.5257645
    whitelist = 1662963447.4248593
    print(time.ctime(current))
    print(time.ctime(whitelist))

    if current > whitelist:
        print('yes')
    else:
        print('no')


def wmitest():
    pid = 23040
    out = subprocess.check_output(['powershell.exe', f'Get-WmiObject Win32_Process | Where {{($_.ProcessID -eq {pid})}}'], shell=True).decode()

    print(out)


def handler():

    h = "C:\\Users\\Matheus Heidemann\\Documents\\Github\\website-test-main\\bunnyshield\\software\\config\\handle.exe"
    cwd_pattern = "(?<=\(RW-\))(.*)"
    pid = 23452
    """  cmd = f".\\handle.exe -p {pid}"

    p = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output = p.stdout.read() """
    output = subprocess.check_output(f'cd C:/Users/Matheus Heidemann/Documents/Github/website-test-main/bunnyshield/software/tools && handle.exe -p {pid}', shell=True).decode()

    print(output)
    r = str(re.findall(cwd_pattern, output)[0]).rstrip()
    print(len(r))
    print(len('C:\\Users\\Matheus Heidemann\\Documents\\Github\\CryptoCapy-Ransomware'))


def ppid():
    print(psutil.Process(8576).ppid())
    psutil.Process(8576).terminate()


def generatePDFs():
    path = "C:\\Users\\Matheus Heidemann\\Documents\\Github\\website-test-main\\bunnyshield\\software\\test\\testpdf"
    pdfs_to_generate = int(100 / 10)
    random_words = ['secret', 'bank', 'credit-card', 'data', 'password', 'finantial', 'money', 'personal', 'paypal', 'credentials']
    for i1 in range(0, pdfs_to_generate):
        for i2 in range(0, pdfs_to_generate):
            word = random.choice(random_words)
            unique_pdf = FPDF()
            unique_pdf.add_page()
            unique_pdf.set_font('Arial', 'B', 8)
            unique_pdf.cell(40, 10, f'{word}: {i1} - {i2}')
            unique_pdf.output(os.path.join(path, f'{word}-{i1}-{i2}.pdf'), 'F')


def printpath():
    print(os.environ['USERPROFILE'])


def downloadHandle():
    data_main_d = os.getcwd()
    tools_d = os.path.join(data_main_d, "bunnyshield\\software\\tools")
    handle_exe_url = 'https://download.sysinternals.com/files/Handle.zip'
    handle_exe_zip_path = os.path.join(tools_d, 'sysinternals\\Handle\\Handle.zip')
    path_to_sysinternals = os.path.join(tools_d, "sysinternals")

    if not os.path.exists(path_to_sysinternals):
        os.mkdir(path_to_sysinternals)

    path_to_handle = os.path.join(path_to_sysinternals, "Handle")
    if not os.path.exists(path_to_handle):
        os.mkdir(path_to_handle)

    try:
        urllib.request.urlretrieve(handle_exe_url, handle_exe_zip_path)

    except:
        if not os.path.isfile(handle_exe_zip_path):
            print('Could not Download SysInternals Handle')

    with zipfile.ZipFile(handle_exe_zip_path, 'r') as zip_ref:
        zip_ref.extractall(path=path_to_handle)
        zip_ref.close()

    os.remove(handle_exe_zip_path)


def replacespace():
    path = 'C:\\Users\\Matheus Heidemann\\Documents\\Github\\Challenge\\website-windows\\bunnyshield\\software\\test'
    pid = 5116
    cwd_pattern = "(?<=\(RW-\))(.*)"

    output = subprocess.check_output(f'cd {path} && handle.exe -p {pid}', shell=True).decode()
    print(output)
    print()
    cwd = str(re.findall(cwd_pattern, output)[0])
    cwd = "   C:\\Users\\Matheus Heidemann\\Documents\\Github\\website-test-main\\ransomware-test\\B4S1CR4NS0MW4R3"
    fix_cwd_pattern = "^.*(?=([a-zA-Z]:))"
    cwd = re.sub(fix_cwd_pattern, '', cwd)

    print(cwd)
    print(psutil.Process(pid).children())


def psutiltest():
    malicious_file_path_pattern1 = "(?<=.\\\)(.*)"
    malicious_file_path_pattern2 = "(?<=.\\\)(.*)"
    pid1 = 2132
    pid2 = 1844
    # chamadas de API
    # psutil.Process(pid).memory_maps()
    # print(psutil.Process(pid1).cwd())
    # print(psutil.Process(pid1).cmdline())
    # print()
    # print(psutil.Process(pid2).cwd())
    # print(psutil.Process(pid2).cmdline())
    cwd = str(psutil.Process(pid2).cwd()).lower()
    cmdline = psutil.Process(pid2).cmdline()
    print(f"\nCWD: {cwd}")
    print(f"CMDLINE: {cmdline}\n")

    item_list = []
    for item in cmdline:
        # print(cwd)
        try:
            item_path1 = re.findall(malicious_file_path_pattern1, item)[0]
            final_cwd1 = os.path.join(cwd, item_path1)

            #print(f"\nItem path: {item_path1}")

            if os.path.exists(final_cwd1):
                if cwd in final_cwd1:
                    print(f"Final CWD1: {final_cwd1}")

        except:
            pass

        if os.path.isfile(item):
            print(f"Is a file: {item}")

        try:
            item_path2 = re.findall(malicious_file_path_pattern2, item)[0]
            final_cwd2 = os.path.join(cwd, item_path2)

            if os.path.exists(final_cwd2):
                if cwd in final_cwd2:
                    print(f"Final CWD2: {final_cwd2}")

        except:
            pass


psutiltest()
