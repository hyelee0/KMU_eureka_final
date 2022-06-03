
from tkinter import *
from tkinter import messagebox as msgbox 
from tkinter import filedialog as fd
from pathlib import Path 
import webbrowser

from socket import *
from lib_DH import *
from hashlib import sha256
import time, os

import lib_AES256, lib_PIPO128


#================================================================================================================================================================================


client_socket = socket(AF_INET, SOCK_STREAM)
server_address = ('127.0.0.1', 9999)


root = Tk() 
root.title('◈ ENCRYPT your image file ◈ --------------------------------------------------------------------------------------------- ◈')  
root.geometry('900x600+400+300') 
root.config(background='#dbd8e3')
root.resizable(False, False)


#================================================================================================================================================================================


dir_DH, file_DH = '', ''


def clientDH():
    global dir_DH
    global file_DH
    
    if dir_DH != '':
        msgbox.showerror('✔ 주의', '키 교환이 완료된 상태입니다. 버튼을 통해 확인할 수 있습니다.')
        return
    
    client_socket.connect(server_address)

    data = client_socket.recv(1024)
    data = data.decode()
    p = int(data)

    data = client_socket.recv(1024)
    data = data.decode()
    g = int(data)

    data = client_socket.recv(1024)
    data = data.decode()
    A = int(data)

    time.sleep(0.25)
    y = secretGen(512)
    B = calExchange(g, y, p)
    data = str(B)
    client_socket.sendall(data.encode())

    shared_value = calShared(A, y, p)
    input_ = str(shared_value).encode()
    hash = sha256()
    hash.update(input_)
    output_ = hash.hexdigest()
    shared_key = int(output_, 16)

    dir_DH = os.getcwd() + '/client'
    while True:
        if os.path.exists(dir_DH) == True:
            dir_DH += '_'
            continue
        os.mkdir(dir_DH)
        file_DH = dir_DH + '/sharedkey.txt'           
        mkfile = open(file_DH, 'wt')
        mkfile.write(hex(shared_key))
        mkfile.close()
        break
    
    sign = client_socket.recv(1024)
    sign = sign.decode()

    time.sleep(1.2)
    DH_label.config(text='▶ DH is finished')


def checkDH():
    global dir_DH
    if dir_DH == '':
        msgbox.showerror('✔ 주의', 'DH 키 교환이 진행되지 않았습니다.')
    else:
        webbrowser.open(dir_DH)


connect_btn = Button(root, command=clientDH, padx=15, pady=9, text='연결 시작', font='나눔고딕 12', bg='#c2c9ea')
connect_btn.place(x=120, y=189)
key_btn = Button(root, command=checkDH, padx=5, pady=9, text='공유키 확인', font='나눔고딕 12', bg='#c2c9ea')
key_btn.place(x=670, y=189)


#================================================================================================================================================================================


Label(root, text='--------------------------------------------------- ◔ S E N D I N G ◔ -----------------------------------------------------', font='나눔고딕 15', bg='#dbd8e3').place(y=320)

aframe = Frame(root, padx=9, pady=8, relief='groove', bd=2)
aframe.place(x=340, y=40)
DH_label = Label(aframe, width=20, text='※ Key is NOT shared', font='나눔고딕 13')
DH_label.pack()

cframe = Frame(root, padx=4, pady=8, relief='groove', bd=2)
cframe.place(x=345, y=135)
Label(cframe, text='▶ CIPHER', font='나눔고딕 13').pack()
cipher_var = StringVar(value='iv')
cipher1 = Radiobutton(cframe, value='aes', variable=cipher_var, width=7, pady=7, text='AES', font='나눔고딕 11')
cipher2 = Radiobutton(cframe, value='pipo', variable=cipher_var, width=7, pady=7, text='PIPO', font='나눔고딕 11')
cipher1.pack()
cipher2.pack()
Label(cframe, pady=10, text='').pack()

mframe = Frame(root, padx=4, pady=8, relief='groove', bd=2)
mframe.place(x=450, y=135)
Label(mframe, text='▶ MODE', font='나눔고딕 13').pack()
mode_var = StringVar(value='iv')
mode1 = Radiobutton(mframe, value='ecb', variable=mode_var, width=7, pady=7, text='ECB', font='나눔고딕 11')
mode2 = Radiobutton(mframe, value='cbc', variable=mode_var, width=7, pady=7, text='CBC', font='나눔고딕 11')
mode3 = Radiobutton(mframe, value='ctr', variable=mode_var, width=7, pady=7, text='CTR', font='나눔고딕 11')
mode1.pack()
mode2.pack()
mode3.pack()


#================================================================================================================================================================================


in_file, client_path, send_path = '', '', ''
send_file, open_path = '', ''


def fileChoice():
    global in_file 
    global default
    while True:
        in_file = fd.askopenfilename(title='암호화하여 송신할 파일을 선택하세요', initialdir='C:/', \
            filetypes=[('모든 파일', '*.*')])
        if in_file == '':
            response = msgbox.askretrycancel('✔ 확인', '파일이 선택되지 않았습니다. 다시 선택하시겠습니까?')
            if response == True:
                continue
        showfc_lab.config(text=Path(in_file).name) 
        break


def pathChoice(): 
    global send_path
    while True:
        send_path = fd.askdirectory(title='파일을 암호화한 후 송신할 폴더를 선택하세요', initialdir='C:/')
        if send_path == '':
            response = msgbox.askretrycancel('✔ 확인', '폴더가 선택되지 않았습니다. 다시 선택하시겠습니까?')
            if response == True:
                continue
        elif send_path == 'C:/':
            showpc_lab.config(text='C드라이브')
        elif send_path == 'D:/':
            showpc_lab.config(text='D드라이브')
        else:
            showpc_lab.config(text=Path(send_path).name) 
        break


def clearChoice():
    global in_file
    global send_path 
    global open_path
    in_file, send_path, open_path = '', '', ''
    showfc_lab.config(text='')
    showpc_lab.config(text='')
    cipher_var.set('iv')
    mode_var.set('iv')
    state_label.config(text='【 현재 상태: 진행 전 】')


tframe = Frame(root, width=820, height=190, relief='groove', bd=3)
tframe.place(x=40, y=370)

fframe = Frame(root, padx=25, pady=23, relief='sunken', bd=4, bg='#e7e8f2')
fframe.place(x=75, y=398)
filechoice_btn = Button(fframe, command=fileChoice, width=12, pady=8, text='암호화 후\n송신할 파일', font='나눔고딕 12', bg='#b9bae3')
filechoice_btn.pack()
showfc_lab = Label(fframe, bg='#eaebf4')
showfc_lab.pack()

pframe = Frame(root, padx=25, pady=23, relief='sunken', bd=4, bg='#e7e8f2')
pframe.place(x=645, y=398)
pathchoice_btn = Button(pframe, command=pathChoice, width=12, pady=8, text='해당 파일을\n송신할 경로', font='나눔고딕 12', bg='#b9bae3')
pathchoice_btn.pack()
showpc_lab = Label(pframe, bg='#eaebf4')
showpc_lab.pack()

state_label = Label(tframe, text='【 현재 상태: 진행 전 】', font='나눔고딕 13')
state_label.place(x=330, y=150)

#================================================================================================================================================================================


def Client():
    global dir_DH
    global file_DH
    global askList
    global in_file
    global send_file
    global send_path
    global open_path
    global client_file
    
    time.sleep(1)
    fp_read = open(file_DH, 'rt')
    fp_data = fp_read.read()
    fp_read.close()
    shared_key = int(fp_data, 16)
    
    
    if askList[0] == 'aes':
        if askList[1] == 'ecb':
            client_file = dir_DH + '/enc_AESxECB' + Path(in_file).suffix
            lib_AES256.EncryptECB(in_file, client_file, shared_key)
        elif askList[1] == 'cbc':
            client_file = dir_DH + '/enc_AESxCBC' + Path(in_file).suffix
            lib_AES256.EncryptCBC(in_file, client_file, shared_key)
        elif askList[1] == 'ctr':
            client_file = dir_DH + '/enc_AESxCTR' + Path(in_file).suffix
            lib_AES256.EncryptCTR(in_file, client_file, shared_key)
    elif askList[0] == 'pipo':
        if askList[1] == 'ecb':
            client_file = dir_DH + '/enc_PIPOxECB' + Path(in_file).suffix
            lib_PIPO128.EncryptECB(in_file, client_file, shared_key)
        elif askList[1] == 'cbc':
            client_file = dir_DH + '/enc_PIPOxCBC' + Path(in_file).suffix
            lib_PIPO128.EncryptCBC(in_file, client_file, shared_key)
        elif askList[1] == 'ctr':
            client_file = dir_DH + '/enc_PIPOxCTR' + Path(in_file).suffix
            lib_PIPO128.EncryptCTR(in_file, client_file, shared_key)
    
    state_label.config(text='【 현재 상태: 암호화 완료 】')
    open_path = dir_DH
    
    msgbox.showinfo('✔ 알림', '암호화가 완료되었습니다.\n결과는 \'%s\' 폴더에 저장합니다. 열어보기로 확인하세요.' %Path(dir_DH).name)
    msgbox.showinfo('✔ 알림', '서버와의 연결을 대기합니다.')
    sign = client_socket.recv(1024)
    sign = sign.decode()
    
    time.sleep(1)
    msgbox.showinfo('✔ 알림', '파일 송신을 시작합니다.')
    
    time.sleep(0.5)
    client_socket.sendall(send_path.encode())
    
    time.sleep(0.5)
    client_socket.sendall(Path(client_file).suffix.encode())
    
    time.sleep(0.5)
    client_socket.sendall(askList[0].encode())
    
    time.sleep(0.5)
    client_socket.sendall(askList[1].encode())
    
    time.sleep(0.5)
    fp_read = open(client_file, 'rb')
    fp_data = fp_read.read()
    fp_read.close()
    
    hash_func = sha256()
    hash_func.update(fp_data)
    hash_value = '0x' + hash_func.hexdigest()
    
    fp_write = open(dir_DH + '/verifying.txt', 'wt')
    fp_write.write(hash_value)
    fp_write.close()
    
    index = 0 
    while index < len(fp_data):
        packet = bytes()
        packet += bytes(fp_data[index:index+1024])
        client_socket.sendall(packet)
        index += 1024 
        
    msgbox.showinfo('✔ 알림', '성공적으로 송신하였습니다.')
    state_label.config(text='【 현재 상태: 송신 완료 】')

#================================================================================================================================================================================


def startTCP():
    global dir_DH
    global in_file
    global send_path
    global askList

    if dir_DH == '':
        msgbox.showerror('✔ 주의', 'DH가 진행되지 않았습니다.')
        return
    
    if in_file == '' or send_path == '':
        msgbox.showerror('✔ 주의', '파일과 경로를 모두 선택하세요.')
        return
    
    askList = [cipher_var.get(), mode_var.get()]
    
    if 'iv' in askList:
        msgbox.showerror('✔ 주의', '모든 방식을 선택하세요.')
        return

    if msgbox.askyesno('✔ 확인', '파일을 암호화한 후 송신하시겠습니까?') == True:
        Client()

  
def openPath():
    global open_path
    if open_path == '':
        msgbox.showerror('✔ 주의', '암호화가 완료되지 않았습니다.')
    else:
        webbrowser.open(open_path)


start_btn = Button(root, command=startTCP, width=12, pady=15, text='START', font='나눔고딕 12', bg='#c2c9ea')
start_btn.place(x=385, y=390)

#accept_btn = Button(root, command=Accept, width=12, pady=15, text='요청받기', font='나눔고딕 12', bg='#c2c9ea')
#accept_btn.place(x=450, y=390)

#send_btn = Button(root, command=withAES, width=12, pady=15, text='송신하기', font='나눔고딕 12', bg='#c2c9ea')
#send_btn.place(x=450, y=390)

clear_btn = Button(root, command=clearChoice, width=12, pady=15, text='초기화', font='나눔고딕 12', bg='#dfe3f1')
clear_btn.place(x=319, y=453)

open_btn = Button(root, command=openPath, width=12, height=1, pady=15, text='암호화 파일\n열어보기', font='나눔고딕 12', bg='#dfe3f1')
open_btn.place(x=450, y=453)


root.mainloop()