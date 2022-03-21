import hashlib
import PySimpleGUI as sg
import pyperclip


fileName = ''
md5_hash = None
sha1_hash = None
sha256_hash = None

hash_list = []

def md5(content):
    md5_hash = hashlib.md5()
    md5_hash.update(content)
    digest_md5 = md5_hash.hexdigest()
    return digest_md5


def sha1(content):
    sha1_hash = hashlib.sha1()
    sha1_hash.update(content)
    digest_sha1 = sha1_hash.hexdigest()
    return digest_sha1


def sha256(content):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(content)
    digest_sha256 = sha256_hash.hexdigest()
    return digest_sha256


def returnContent(name):
    file = open(name, 'rb')
    content = file.read()
    return content

def addWarning(problem):
    if problem == 1:
        window['warning'].update('No file was selected', text_color='white')
    elif problem == 2:
        window['warning'].update('Hash cant be completed, file not selected', text_color='white')
    elif problem == 3:
        window['warning'].update('Hash is not generated', text_color='white')

def removeWarning():
    window['warning'].update('', text_color='white')

hash_text_key = ['md5Field', 'sha1Field', 'sha256Field']
check_icon_key = ['md5Check', 'sha1Check', 'sha256Check']
copy_btn_key = ['md5Copy', 'sha1Copy', 'sha256Copy']
check_icon = '✓'

sg.theme('Dark Grey 7')

layout = [[sg.Text('File Path'), sg.Input(), sg.FileBrowse(), sg.Button('Ok')],
          [sg.Text('Check Hash'), sg.Input(), sg.Button('Check', disabled=True)],
          [sg.Text('Md5: ', size=(7, 1)), sg.Text(key = 'md5Field'), sg.Text(key='md5Check'), sg.Button('Copy', key='md5Copy', visible=False)],
          [sg.Text('Sha1: ', size=(7, 1)), sg.Text(key = 'sha1Field'), sg.Text(key='sha1Check'), sg.Button('Copy', key='sha1Copy', visible=False)],
          [sg.Text('Sha256: ', size=(7, 1)), sg.Text(key = 'sha256Field'), sg.Text(key='sha256Check'), sg.Button('Copy', key='sha256Copy', visible=False)],
          [sg.Button('Hash'), sg.Button('Reset'), sg.Text(key='warning')]]

window = sg.Window('Hash', layout)

while True:
    event, values = window.read()
    if event == sg.WIN_CLOSED:
        break
    elif event == 'Ok':
        try:
            fileName = values[0]
            content = returnContent(fileName)
            removeWarning()
        except Exception as e:
            if values[0] == '':
                addWarning(1)
            pass 

    elif event == 'Hash':
        try:
            
            md5_hash = md5(content)
            sha1_hash = sha1(content)
            sha256_hash = sha256(content)

            hash_list = [md5_hash, sha1_hash, sha256_hash]

            for x in range(0,3):
                window[hash_text_key[x]].update(hash_list[x])
            
            for btn in copy_btn_key:
                window[btn].update(visible=True)
            window['Check'].update(disabled=False)
        except Exception as e:
            addWarning(2)
            pass

    elif event == 'Reset':
        for key in check_icon_key:
            window[key].update('')
        
        for key in copy_btn_key:
            window[key].update(visible=False)
        
        for key in hash_text_key:
             window[key].update('')
        
        try:
            for x in range(0,3):
                hash_list[x] = None
            window['Check'].update(disabled=True)
        except Exception as e:
            pass
        removeWarning()

    elif event == 'Check':
        try:
            for x in range(0,3):
                if hash_list[x] == values[1]:
                    window[check_icon_key[x]].update(check_icon, text_color = 'white')
            removeWarning()
        except Exception as e:
            addWarning(3)
            pass

    elif event == 'md5Copy':
        pyperclip.copy(md5_hash)

    elif event == 'sha1Copy':
        pyperclip.copy(sha1_hash)

    elif event == 'sha256Copy':
        pyperclip.copy(sha256_hash)

window.close()