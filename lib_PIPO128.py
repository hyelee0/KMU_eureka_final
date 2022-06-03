
import lib_PIPO
from hashlib import md5


int_iv = 0x23bfcc752db27a990c2d4953af99a5df
int_nonce = 0x5fa475f159c504b0


def len128(shared_key):
    input_ = str(shared_key).encode()
    hash = md5()
    hash.update(input_)
    output_ = hash.hexdigest()
    output_ = int(output_, 16)
    return output_   


def bytes2int(input):
    output = 0
    for i in range(len(input)):
        output = output << 8 | input[i]
    return output


def EncryptECB(in_file, out_file, shared_key):
    fp_read = open(in_file, 'rb')
    fp_data = fp_read.read() 
    fp_read.close() 

    int_key = len128(shared_key)    
    
    plainblock_list = []
    for i in range(0, len(fp_data), 8): 
        plaindata = fp_data[i:i+8]
        plainblock = bytes2int(plaindata)
        plainblock_list.append(plainblock)

    cipherblock_list = lib_PIPO.CipherECB(plainblock_list, int_key)
    cipherdata = []
    for cipherblock in cipherblock_list:
        for i in range(8):
            intdata = (cipherblock >> 8*(7-i)) & 0xff
            cipherdata.append(intdata)

    fp_write = open(out_file, 'wb')
    fp_write.write(bytes(cipherdata))
    fp_write.close()


def EncryptCBC(in_file, out_file, shared_key):
    fp_read = open(in_file, 'rb')
    fp_data = fp_read.read() 
    fp_read.close() 

    int_key = len128(shared_key)    
    
    plainblock_list = []
    for i in range(0, len(fp_data), 8): 
        plaindata = fp_data[i:i+8]
        plainblock = bytes2int(plaindata)
        plainblock_list.append(plainblock)

    cipherblock_list = lib_PIPO.CipherCBC(int_iv, plainblock_list, int_key)
    cipherdata = []
    for cipherblock in cipherblock_list:
        for i in range(8):
            intdata = (cipherblock >> 8*(7-i)) & 0xff
            cipherdata.append(intdata)

    fp_write = open(out_file, 'wb')
    fp_write.write(bytes(cipherdata))
    fp_write.close()


def EncryptCTR(in_file, out_file, shared_key):
    fp_read = open(in_file, 'rb')
    fp_data = fp_read.read() 
    fp_read.close() 

    int_key = len128(shared_key)    
    
    plainblock_list = []
    for i in range(0, len(fp_data), 8): 
        plaindata = fp_data[i:i+8]
        plainblock = bytes2int(plaindata)
        plainblock_list.append(plainblock)

    cipherblock_list = lib_PIPO.CommonCTR(int_nonce, plainblock_list, int_key)
    cipherdata = []
    for cipherblock in cipherblock_list:
        for i in range(8):
            intdata = (cipherblock >> 8*(7-i)) & 0xff
            cipherdata.append(intdata)

    fp_write = open(out_file, 'wb')
    fp_write.write(bytes(cipherdata))
    fp_write.close()


def DecryptECB(in_file, out_file, shared_key):
    fp_read = open(in_file, 'rb')
    fp_data = fp_read.read()
    fp_read.close()

    int_key = len128(shared_key)    

    cipherblock_list = []
    for i in range(0, len(fp_data), 8): 
        cipherdata = fp_data[i:i+8]
        cipherblock = bytes2int(cipherdata)
        cipherblock_list.append(cipherblock)

    decipherblock_list = lib_PIPO.DecipherECB(cipherblock_list, int_key)
    decipherdata = []
    for decipherblock in decipherblock_list:
        for i in range(8):
            intdata = (decipherblock >> 8*(7-i)) & 0xff
            decipherdata.append(intdata)
 
    fp_write = open(out_file, 'wb')
    fp_write.write(bytes(decipherdata))
    fp_write.close()
    

def DecryptCBC(in_file, out_file, shared_key):
    fp_read = open(in_file, 'rb')
    fp_data = fp_read.read()
    fp_read.close()

    int_key = len128(shared_key)    

    cipherblock_list = []
    for i in range(0, len(fp_data), 8): 
        cipherdata = fp_data[i:i+8]
        cipherblock = bytes2int(cipherdata)
        cipherblock_list.append(cipherblock)

    decipherblock_list = lib_PIPO.DecipherCBC(int_iv, cipherblock_list, int_key)
    decipherdata = []
    for decipherblock in decipherblock_list:
        for i in range(8):
            intdata = (decipherblock >> 8*(7-i)) & 0xff
            decipherdata.append(intdata)

    fp_write = open(out_file, 'wb')
    fp_write.write(bytes(decipherdata))
    fp_write.close()


def DecryptCTR(in_file, out_file, shared_key):
    fp_read = open(in_file, 'rb')
    fp_data = fp_read.read()
    fp_read.close()

    int_key = len128(shared_key)    

    cipherblock_list = []
    for i in range(0, len(fp_data), 8): 
        cipherdata = fp_data[i:i+8]
        cipherblock = bytes2int(cipherdata)
        cipherblock_list.append(cipherblock)

    decipherblock_list = lib_PIPO.CommonCTR(int_nonce, cipherblock_list, int_key)
    decipherdata = []
    for decipherblock in decipherblock_list:
        for i in range(8):
            intdata = (decipherblock >> 8*(7-i)) & 0xff
            decipherdata.append(intdata)

    fp_write = open(out_file, 'wb')
    fp_write.write(bytes(decipherdata))
    fp_write.close()