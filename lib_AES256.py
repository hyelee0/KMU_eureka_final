
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES


int_iv = 0x23bfcc752db27a990c2d4953af99a5df
bin_iv = int_iv.to_bytes(16, 'little')
int_nonce = 0x5fa475f159c504b0
bin_nonce = int_nonce.to_bytes(8, 'little')


def EncryptECB(in_file, out_file, shared_key):
    fp_read = open(in_file, 'rb')
    fp_data = fp_read.read()
    fp_read.close()
    
    bin_key = shared_key.to_bytes(32, 'little')
    
    ECB = AES.new(bin_key, AES.MODE_ECB)
    bin_ct = ECB.encrypt(pad(fp_data, AES.block_size))

    fp_write = open(out_file, 'wb')
    fp_write.write(bin_ct)
    fp_write.close()


def EncryptCBC(in_file, out_file, shared_key):
    fp_read = open(in_file, 'rb')
    fp_data = fp_read.read()
    fp_read.close()
    
    bin_key = shared_key.to_bytes(32, 'little')
    
    CBC = AES.new(bin_key, AES.MODE_CBC, iv=bin_iv)
    bin_ct = CBC.encrypt(pad(fp_data, AES.block_size))

    fp_write = open(out_file, 'wb')
    fp_write.write(bin_ct)
    fp_write.close()
   
    
def EncryptCTR(in_file, out_file, shared_key):
    fp_read = open(in_file, 'rb')
    fp_data = fp_read.read()
    fp_read.close()
    
    bin_key = shared_key.to_bytes(32, 'little')
    
    CTR = AES.new(bin_key, AES.MODE_CTR, nonce=bin_nonce)
    bin_ct = CTR.encrypt(pad(fp_data, AES.block_size))

    fp_write = open(out_file, 'wb')
    fp_write.write(bin_ct)
    fp_write.close()
  
    
def DecryptECB(in_file, out_file, shared_key): 
    fp_read = open(in_file, 'rb')
    fp_data = fp_read.read()
    fp_read.close()
    
    bin_key = shared_key.to_bytes(32, 'little') 
    
    ECB = AES.new(bin_key, AES.MODE_ECB)
    bin_pt = unpad(ECB.decrypt(fp_data), AES.block_size)
    
    fp_write = open(out_file, 'wb')
    fp_write.write(bin_pt)
    fp_write.close()


def DecryptCBC(in_file, out_file, shared_key): 
    fp_read = open(in_file, 'rb')
    fp_data = fp_read.read()
    fp_read.close()
    
    bin_key = shared_key.to_bytes(32, 'little') 
    
    CBC = AES.new(bin_key, AES.MODE_CBC, iv=bin_iv)
    bin_pt = unpad(CBC.decrypt(fp_data), AES.block_size)
    
    fp_write = open(out_file, 'wb')
    fp_write.write(bin_pt)
    fp_write.close()


def DecryptCTR(in_file, out_file, shared_key): 
    fp_read = open(in_file, 'rb')
    fp_data = fp_read.read()
    fp_read.close()
    
    bin_key = shared_key.to_bytes(32, 'little')
    
    CTR = AES.new(bin_key, AES.MODE_CTR, nonce=bin_nonce)
    bin_pt = unpad(CTR.decrypt(fp_data), AES.block_size)
    
    fp_write = open(out_file, 'wb')
    fp_write.write(bin_pt)
    fp_write.close()