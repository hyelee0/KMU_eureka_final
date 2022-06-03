
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


server_socket = socket(AF_INET, SOCK_STREAM)
server_address = ('127.0.0.1', 9999)
server_socket.bind(server_address)
server_socket.listen(5)


root = Tk() 
root.title('◈ DECRYPT your image file ◈ --------------------------------------------------------------------------------------------- ◈')  
root.geometry('900x600+400+300') 
root.config(background='#dbd8e3')
root.resizable(False, False)


#================================================================================================================================================================================


dir_DH, file_DH = '', ''


def serverDH():
    global client_socket
    global dir_DH
    global file_DH
    
    if msgbox.askyesno('✔ 확인', '키를 공유하시겠습니까?') == False:
        return
    
    if dir_DH != '':
        msgbox.showerror('✔ 주의', '키 교환이 완료된 상태입니다. 버튼을 통해 확인할 수 있습니다.')
        return
    
    msgbox.showinfo('✔ 알림', '클라이언트와의 연결을 대기합니다.')
    client_socket, client_address = server_socket.accept()
    
    time.sleep(1.5)
    msgbox.showinfo('✔ 알림', 'DH 키 교환을 시작합니다.')

    time.sleep(0.25)
    p = primeGen(512)
    g = intGen(32)
    x = secretGen(512)
    A = calExchange(g, x, p)     

    time.sleep(0.5)
    data = str(p)
    client_socket.sendall(data.encode())

    time.sleep(0.5)
    data = str(g)
    client_socket.sendall(data.encode())

    time.sleep(0.5)
    data = str(A)
    client_socket.sendall(data.encode())

    data = client_socket.recv(1024)
    data = data.decode()
    B = int(data)

    shared_value = calShared(B, x, p)
    input_ = str(shared_value).encode()
    hash = sha256()
    hash.update(input_)
    output_ = hash.hexdigest()
    shared_key = int(output_, 16)

    dir_DH = os.getcwd() + '/server'
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
    
    msgbox.showinfo('✔ 알림', '키 공유가 완료되었습니다.\n폴더를 열어 확인하세요.')
    client_socket.sendall('sign'.encode())
    
    time.sleep(1.2)    
    DH_label.config(text='▶ DH is finished')


def checkDH():
    global dir_DH
    if dir_DH == '':
        msgbox.showerror('✔ 주의', 'DH 키 교환이 진행되지 않았습니다.')
    else:
        webbrowser.open(dir_DH)


connect_btn = Button(root, command=serverDH, padx=18, pady=9, text='DH 시작', font='나눔고딕 12', bg='#c2c9ea')
connect_btn.place(x=120, y=189)
key_btn = Button(root, command=checkDH, padx=5, pady=9, text='공유키 확인', font='나눔고딕 12', bg='#c2c9ea')
key_btn.place(x=670, y=189)


#================================================================================================================================================================================


Label(root, text='                                          ▶ To start Diffie-Hellman key exchange ◀                                                 ', font='나눔고딕 15', bg='#dbd8e3').place(y=110)
Label(root, text='-------------------------------------------------- ◕ R E C E I V I N G ◕ --------------------------------------------------', font='나눔고딕 15', bg='#dbd8e3').place(y=320)
aframe = Frame(root, pady=8, relief='groove', bd=2)
aframe.place(x=340, y=40)
DH_label = Label(aframe, width=20, text='※ Key is NOT shared', font='나눔고딕 13')
DH_label.pack()                        


#================================================================================================================================================================================


recv_file, recv_path = '', ''
out_file, out_path, open_path = '', '', ''


def pathChoice(): 
    global out_path
    while True:
        out_path = fd.askdirectory(title='파일을 수신한 후 복호화하여 저장할 경로를 선택하세요.', initialdir='C:/')
        if out_path == '':
            response = msgbox.askretrycancel('✔ 확인', '폴더가 선택되지 않았습니다. 다시 선택하시겠습니까?')
            if response == True:
                continue
        elif out_path == 'C:/':
            showpc_lab.config(text='C드라이브')
        elif out_path == 'D:/':
            showpc_lab.config(text='D드라이브')
        else:
            showpc_lab.config(text=Path(out_path).name) 
        break


def openRecvPath():
    global recv_path
    if recv_path == '':
        msgbox.showerror('✔ 주의', '수신된 파일이 없습니다.')
    else:
        webbrowser.open(recv_path)


tframe = Frame(root, width=820, height=190, relief='groove', bd=3)
tframe.place(x=40, y=370)

fframe = Frame(root, padx=25, pady=23, relief='sunken', bd=4, bg='#e7e8f2')
fframe.place(x=75, y=398)
filechoice_btn = Button(fframe, command=openRecvPath, width=12, pady=8, text='수신한 파일\n확인하기', font='나눔고딕 12', bg='#b9bae3')
filechoice_btn.pack()
showfc_lab = Label(fframe, bg='#eaebf4')
showfc_lab.pack()

pframe = Frame(root, padx=25, pady=23, relief='sunken', bd=4, bg='#e7e8f2')
pframe.place(x=645, y=398)
pathchoice_btn = Button(pframe, command=pathChoice, width=12, pady=8, text='복호화 후\n저장할 경로', font='나눔고딕 12', bg='#b9bae3')
pathchoice_btn.pack()
showpc_lab = Label(pframe, bg='#eaebf4')
showpc_lab.pack()

state_label = Label(tframe, text='    【 현재 상태: 진행 전 】', font='나눔고딕 13')
state_label.place(x=300, y=142)


#================================================================================================================================================================================


#================================================================================================================================================================================



def Server():
    global client_socket
    global askList
    global file_DH
    global recv_file
    global recv_path
    global out_file
    global out_path
    global open_path

    askList = []
    
    client_socket.sendall('sign'.encode())
    
    recv_path = client_socket.recv(1024)
    recv_path = recv_path.decode()

    recv_ext = client_socket.recv(1024)
    recv_ext = recv_ext.decode()
    
    ask_cipher = client_socket.recv(1024)
    ask_cipher = ask_cipher.decode()
    askList.append(ask_cipher)
    
    ask_mode = client_socket.recv(1024)
    ask_mode = ask_mode.decode()
    askList.append(ask_mode)
    
    recv_file = recv_path + '/received' + recv_ext
    recv_data = bytes()
    while True:
        packet = client_socket.recv(1024)
        recv_data += packet
        if len(packet) != 1024:
            break
        
    fp_write = open(recv_file, 'wb')
    fp_write.write(recv_data) 
    fp_write.close()
    
    hash_func = sha256()
    hash_func.update(recv_data)
    hash_value = '0x' + hash_func.hexdigest()
    
    fp_write = open(dir_DH + '/verifying.txt', 'wt')
    fp_write.write(hash_value)
    fp_write.close()

    state_label.config(text='【 현재 상태: 수신 완료 】')
    showfc_lab.config(text=Path(recv_file).name)
    
    msgbox.showinfo('✔ 알림', '수신이 완료되었습니다.\n파일 복호화를 시작합니다.')
    
    fp_read = open(file_DH, 'rt')
    fp_data = fp_read.read()
    fp_read.close()
    shared_key = int(fp_data, 16)

    if askList[0] == 'aes':
        if askList[1] == 'ecb':
            out_file = dir_DH + '/dec_AESxECB' + Path(recv_file).suffix
            lib_AES256.DecryptECB(recv_file, out_file, shared_key)
        elif askList[1] == 'cbc':
            out_file = dir_DH + '/dec_AESxCBC' + Path(recv_file).suffix
            lib_AES256.DecryptCBC(recv_file, out_file, shared_key)
        elif askList[1] == 'ctr':
            out_file = dir_DH + '/dec_AESxCTR' + Path(recv_file).suffix
            lib_AES256.DecryptCTR(recv_file, out_file, shared_key)
    elif askList[0] == 'pipo':
        if askList[1] == 'ecb':
            out_file = dir_DH + '/dec_PIPOxECB' + Path(recv_file).suffix
            lib_PIPO128.DecryptECB(recv_file, out_file, shared_key)
        elif askList[1] == 'cbc':
            out_file = dir_DH + '/dec_PIPOxCBC' + Path(recv_file).suffix
            lib_PIPO128.DecryptCBC(recv_file, out_file, shared_key)
        elif askList[1] == 'ctr':
            out_file = dir_DH + '/dec_PIPOxCTR' + Path(recv_file).suffix
            lib_PIPO128.DecryptCTR(recv_file, out_file, shared_key)
        
    msgbox.showinfo('✔ 알림', '복호화가 완료되었습니다.\n파일을 열어 확인하세요.')
    state_label.config(text='【 현재 상태: 복호화 완료 】')
    open_path = out_path
    ask_label.config(text='▶ 복호화 방식: %s, %s' % (askList[0], askList[1]))
    

#================================================================================================================================================================================


ask_label = Label(root, text='   ▶ 복호화 방식: ? ? ?', font='나눔고딕 13')
ask_label.place(x=350, y=393)

def startTCP():
    global out_path
    
    if out_path == '':
        msgbox.showerror('✔ 주의', '파일을 수신한 후 복호화하여 저장할 경로가 선택되어야 합니다.')
        return
    Server()
        
def openDecPath():
    global open_path
    if open_path == '':
        msgbox.showerror('✔ 주의', '복호화가 완료되지 않았습니다.')
    else:
        webbrowser.open(open_path)

start_btn = Button(root, command=startTCP, width=12, pady=15, text='START', font='나눔고딕 12', bg='#c2c9ea')
start_btn.place(x=319, y=435)

#request_btn = Button(root, command=Request, width=12, pady=15, text='요청하기', font='나눔고딕 12', bg='#c2c9ea')
#request_btn.place(x=450, y=390)

#recv_btn = Button(root, command=recvTCP, width=12, pady=15, text='수신하기', font='나눔고딕 12', bg='#c2c9ea')
#recv_btn.place(x=450, y=390)

#clear_btn = Button(root, command=clearChoice, width=12, pady=15, text='초기화', font='나눔고딕 12', bg='#dfe3f1')
#clear_btn.place(x=319, y=453)

open_btn = Button(root, command=openDecPath, width=12, height=1, pady=15, text='복호화 파일\n열어보기', font='나눔고딕 12', bg='#dfe3f1')
open_btn.place(x=450, y=435)


root.mainloop()