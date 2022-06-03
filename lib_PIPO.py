
s_box = [0x5E, 0xF9, 0xFC, 0x00, 0x3F, 0x85, 0xBA, 0x5B, 0x18, 0x37, 0xB2, 0xC6, 0x71, 0xC3, 0x74, 0x9D,
   0xA7, 0x94, 0x0D, 0xE1, 0xCA, 0x68, 0x53, 0x2E, 0x49, 0x62, 0xEB, 0x97, 0xA4, 0x0E, 0x2D, 0xD0,
   0x16, 0x25, 0xAC, 0x48, 0x63, 0xD1, 0xEA, 0x8F, 0xF7, 0x40, 0x45, 0xB1, 0x9E, 0x34, 0x1B, 0xF2,
   0xB9, 0x86, 0x03, 0x7F, 0xD8, 0x7A, 0xDD, 0x3C, 0xE0, 0xCB, 0x52, 0x26, 0x15, 0xAF, 0x8C, 0x69,
   0xC2, 0x75, 0x70, 0x1C, 0x33, 0x99, 0xB6, 0xC7, 0x04, 0x3B, 0xBE, 0x5A, 0xFD, 0x5F, 0xF8, 0x81,
   0x93, 0xA0, 0x29, 0x4D, 0x66, 0xD4, 0xEF, 0x0A, 0xE5, 0xCE, 0x57, 0xA3, 0x90, 0x2A, 0x09, 0x6C,
   0x22, 0x11, 0x88, 0xE4, 0xCF, 0x6D, 0x56, 0xAB, 0x7B, 0xDC, 0xD9, 0xBD, 0x82, 0x38, 0x07, 0x7E,
   0xB5, 0x9A, 0x1F, 0xF3, 0x44, 0xF6, 0x41, 0x30, 0x4C, 0x67, 0xEE, 0x12, 0x21, 0x8B, 0xA8, 0xD5,
   0x55, 0x6E, 0xE7, 0x0B, 0x28, 0x92, 0xA1, 0xCC, 0x2B, 0x08, 0x91, 0xED, 0xD6, 0x64, 0x4F, 0xA2,
   0xBC, 0x83, 0x06, 0xFA, 0x5D, 0xFF, 0x58, 0x39, 0x72, 0xC5, 0xC0, 0xB4, 0x9B, 0x31, 0x1E, 0x77,
   0x01, 0x3E, 0xBB, 0xDF, 0x78, 0xDA, 0x7D, 0x84, 0x50, 0x6B, 0xE2, 0x8E, 0xAD, 0x17, 0x24, 0xC9,
   0xAE, 0x8D, 0x14, 0xE8, 0xD3, 0x61, 0x4A, 0x27, 0x47, 0xF0, 0xF5, 0x19, 0x36, 0x9C, 0xB3, 0x42,
   0x1D, 0x32, 0xB7, 0x43, 0xF4, 0x46, 0xF1, 0x98, 0xEC, 0xD7, 0x4E, 0xAA, 0x89, 0x23, 0x10, 0x65,
   0x8A, 0xA9, 0x20, 0x54, 0x6F, 0xCD, 0xE6, 0x13, 0xDB, 0x7C, 0x79, 0x05, 0x3A, 0x80, 0xBF, 0xDE,
   0xE9, 0xD2, 0x4B, 0x2F, 0x0C, 0xA6, 0x95, 0x60, 0x0F, 0x2C, 0xA5, 0x51, 0x6A, 0xC8, 0xE3, 0x96,
   0xB0, 0x9F, 0x1A, 0x76, 0xC1, 0x73, 0xC4, 0x35, 0xFE, 0x59, 0x5C, 0xB8, 0x87, 0x3D, 0x02, 0xFB]


def key_schedule(input): 
    output = [0 for i in range(14)]
    k0 = input & 0xffffffffffffffff
    k1 = input >> 64
    tmp = [k0, k1]
    for i in range(14):
        output[i] = tmp[i%2] ^ i
    return output 


def generate_state(input): 
    output = [0 for i in range(8)]
    for i in range(8):
        output[i] = (input >> (8*i)) & 0xff 
    return output 


def s_layer(input): 
    tmp = [0 for i in range(8)]
    output = [0 for i in range(8)]
    for i in range(8):
        tmp[i] = ((input[0] >> (7-i)) & 1) | (((input[1] >> (7-i)) & 1) << 1) | (((input[2] >> (7-i)) & 1) << 2) | (((input[3] >> (7-i)) & 1) << 3) | (((input[4] >> (7-i)) & 1) << 4) | (((input[5] >> (7-i)) & 1) << 5) | (((input[6] >> (7-i)) & 1) << 6) | (((input[7] >> (7-i)) & 1) << 7)
        tmp[i] = s_box[tmp[i]]
    for i in range(8):
        output[i] = (((tmp[0] >> i) & 1) << 7) | (((tmp[1] >> i) & 1) << 6) | (((tmp[2] >> i) & 1) << 5) | (((tmp[3] >> i) & 1) << 4) | (((tmp[4] >> i) & 1) << 3) | (((tmp[5] >> i) & 1) << 2) | (((tmp[6] >> i) & 1) << 1) | (((tmp[7] >> i) & 1) << 0)
    return output


def inv_s_box(num):
    for i in range(len(s_box)):
        if s_box[i] == num:
            return i
def inv_s_layer(input):
    tmp = [0 for i in range(8)]
    output = [0 for i in range(8)]
    for i in range(8):
        tmp[7-i] = (((input[0] >> i) & 1) << 0) | (((input[1] >> i) & 1) << 1) | (((input[2] >> i) & 1) << 2) | (((input[3] >> i) & 1) << 3) | (((input[4] >> i) & 1) << 4) | (((input[5] >> i) & 1) << 5) | (((input[6] >> i) & 1) << 6) | (((input[7] >> i) & 1) << 7)
    for i in range(8):
        tmp[i] = inv_s_box(tmp[i])
    for i in range(8):
        output[i] = (((tmp[0] >> i) & 1) << 7) | (((tmp[1] >> i) & 1) << 6) | (((tmp[2] >> i) & 1) << 5) | (((tmp[3] >> i) & 1) << 4) | (((tmp[4] >> i & 1)) << 3) | (((tmp[5] >> i & 1)) << 2) | (((tmp[6] >> i & 1)) << 1) | (((tmp[7] >> i) & 1) << 0)
    return output


def left_rotation(input, k):
    output = (input << k & 0xff) | (input >> 8-k & 0xff)
    return output 
def r_layer(input):
    input[1] = left_rotation(input[1], 7)
    input[2] = left_rotation(input[2], 4)
    input[3] = left_rotation(input[3], 3)
    input[4] = left_rotation(input[4], 6)
    input[5] = left_rotation(input[5], 5)
    input[6] = left_rotation(input[6], 1)
    input[7] = left_rotation(input[7], 2)
    return input 


def right_rotation(input, k): 
    output = (input >> k & 0xff) | (input << 8-k & 0xff)
    return output 
def inv_r_layer(input):
    input[1] = right_rotation(input[1], 7)
    input[2] = right_rotation(input[2], 4)
    input[3] = right_rotation(input[3], 3)
    input[4] = right_rotation(input[4], 6)
    input[5] = right_rotation(input[5], 5)
    input[6] = right_rotation(input[6], 1)
    input[7] = right_rotation(input[7], 2)
    return input 


def key_addition(input, roundkey): 
    roundkey_state = generate_state(roundkey)
    output = [0 for i in range(8)]
    for i in range(8):
        output[i] = input[i] ^ roundkey_state[i]
    return output 


def state2int(input):
    output = 0
    for i in range(8):
        input[i] = input[i] & 0b11111111
        output = output | (input[i] << (8 * i))
    return output


#---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

      
def CipherECB(plainblock_list, secretkey):
    cipherblock_list = []
    for plainblock in plainblock_list:
        state = generate_state(plainblock)
        roundkey_list = key_schedule(secretkey)
        state = key_addition(state, roundkey_list[0])
        for i in range(1, 14):
            state = s_layer(state)
            state = r_layer(state)
            state = key_addition(state, roundkey_list[i])
        cipherblock = state2int(state)
        cipherblock_list.append(cipherblock)
    return cipherblock_list


def CipherCBC(iv, plainblock_list, secretkey):
    cipherblock_list = []
    for i in range(len(plainblock_list)):
        if i == 0:
            plainblock_list[i] = iv ^ plainblock_list[i]
        else:
            plainblock_list[i] = cipherblock_list[i-1] ^ plainblock_list[i]
        state = generate_state(plainblock_list[i])
        roundkey_list = key_schedule(secretkey)
        state = key_addition(state, roundkey_list[0])
        for j in range(1, 14):
            state = s_layer(state)
            state = r_layer(state)
            state = key_addition(state, roundkey_list[j])
        cipherblock = state2int(state)
        cipherblock_list.append(cipherblock)
    return cipherblock_list


def DecipherECB(cipherblock_list, secretkey):
    decipherblock_list = []
    for cipherblock in cipherblock_list:
        state = generate_state(cipherblock)
        roundkey_list = key_schedule(secretkey)
        for i in range(13):
            state = key_addition(state, roundkey_list[13-i])
            state = inv_r_layer(state)
            state = inv_s_layer(state)
        state = key_addition(state, roundkey_list[0])
        decipherblock = state2int(state) 
        decipherblock_list.append(decipherblock) 
    return decipherblock_list


def DecipherCBC(iv, cipherblock_list, secretkey):
    decipherblock_list = []
    for i in range(len(cipherblock_list)):
        state = generate_state(cipherblock_list[i])
        roundkey_list = key_schedule(secretkey)
        for j in range(13):
            state = key_addition(state, roundkey_list[13-j])
            state = inv_r_layer(state)
            state = inv_s_layer(state)
        state = key_addition(state, roundkey_list[0])
        decipherblock = state2int(state)
        decipherblock_list.append(decipherblock)
        if i == 0:
            decipherblock_list[i] = iv ^ decipherblock_list[i]
        else:
            decipherblock_list[i] = cipherblock_list[i-1] ^ decipherblock_list[i]
    return decipherblock_list


def CommonCTR(nonce, in_block_list, secretkey):
    out_block_list = []
    for counter in range(len(in_block_list)):
        stream = nonce + counter 
        state = generate_state(stream)
        roundkey_list = key_schedule(secretkey)
        for j in range(1, 13):
            state = s_layer(state)
            state = r_layer(state)
            state = key_addition(state, roundkey_list[j])
        cipherstream = state2int(state) 
        out_block = cipherstream ^ in_block_list[counter]
        out_block_list.append(out_block)
    return out_block_list

