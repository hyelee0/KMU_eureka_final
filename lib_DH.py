
from secrets import randbits 


# 소수인지 확인
def isPrime(num):
    if num == 1:
        return False
    rot = int(num**(1/2))
    for i in range(2, rot+1):
        if num%i == 0:
            return False
        return True
    
# 정해진 길이만큼 소수 p를 생성
def primeGen(len):
    while 1:
        buf = randbits(len)
        if isPrime(buf) == True:
            break
    return buf

# 정수 g를 생성
def intGen(len):
    buf = randbits(len)
    return buf

# 비밀키 x, y를 생성
def secretGen(len):
    buf = randbits(len)
    return buf

# 교환할 값 g^x mod p, g^y mod p를 계산
def calExchange(g, secret, p):
    buf = pow(g, secret, p)
    return buf

# 나눠갖는 값 g^xy mod p를 계산
def calShared(exchanged, secret, p):
    buf = pow(exchanged, secret, p)
    return buf


def tmp():
    p = primeGen(512) # 앨리스: 크기가 512비트인 소수 p를 생성 -> 밥에게 보냄
    g = intGen(32) # 앨리스: 크기가 32비트인 정수 g를 생성 -> 밥에게 보냄

    x = secretGen(256) # 앨리스: 크기가 256비트인 비밀키 x를 생성
    y = secretGen(256) # 밥: 크기가 256비트인 비밀키 y를 생성

    A = calExchange(g, x, p) # 엘리스: A = g^x mod p를 게산 -> 밥에게 보냄
    B = calExchange(g, y, p) # 밥: B = g^y mod p를 계산 -> 앨리스에게 보냄

    Ashared = calShared(B, x, p) # 앨리스: B^x mod p = g^xy mod p를 계산 
    Bshared = calShared(A, y, p) # 밥: A^y mod p = g^xy mod p를 계산


# 두 사람이 나눠가진 값은 504비트~512비트 -> 해시함수 or 특정 비트를 자름 -> AES, PIPO의 비밀키로 사용