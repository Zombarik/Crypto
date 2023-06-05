import random
import math
import sys

"""
Генерація ключа:
1)генерується випадкове просте число p довжиною n.
2)вибирається число g, таке що:
    g^(f(p)) = 1(mod p)
    g^l != 1(mod p)
    при 1<=l<=f(p)-1, f(p)-функція ейлера
3)вибирається випадкове число x з інтервалу 1...p, взаємно просте з p-1
4) вираховується h = g^x mod p
відкритий ключ: (p, g, h)
закритий ключ: x
"""
class PrivateKey(object):
    def __init__(self, p=None, g=None, x=None, lenghinbits=0):
        self.p = p
        self.g = g
        self.x = x
        self.lenghinbits = lenghinbits

class PublicKey(object):
    def __init__(self, p=None, g=None, h=None, lenghinbits=0):
        self.p = p
        self.g = g
        self.h = h
        self.lenghinbits = lenghinbits

# найбільший спільний дільник
def gcd( a, b ):
    while b != 0:
        c = a % b
        a = b
        b = c
    return a


# тест соловея - штрассена
def SolovayStrassen( num, confidence ):
    for i in range(confidence):
        a = random.randint( 1, num-1 )
        if gcd( a, num ) > 1:
            return False
        if not jacobi( a, num ) % num == pow( a, (num-1)//2, num ):
            return False
    return True


#символ якобі з a, n
def jacobi( a, n ):
    if a == 0:
        if n == 1:
            return 1
        else:
            return 0
    elif a == -1:
        if n % 2 == 0:
            return 1
        else:
            return -1
    elif a == 1:
        return 1
    elif a == 2:
        if n % 8 == 1 or n % 8 == 7:
            return 1
        elif n % 8 == 3 or n % 8 == 5:
            return -1
    elif a >= n:
        return jacobi( a%n, n)
    elif a%2 == 0:
        return jacobi(2, n)*jacobi(a//2, n)
    else:
        if a % 4 == 3 and n%4 == 3:
            return -1 * jacobi( n, a)
        else:
            return jacobi(n, a )


# 1) Якщо p=2, вивести 1 і завершити. В іншому випадку встановіть a=2.
# 2) Обчислити прості дільники p-1: p_1...r
# 3) Якщо для кожно p_i a^((p-1)/p_i) != 1 (mod p), мизнайшли g
# 4) g = g+1 -> 3)
def find_g( p ):
    if p == 2:
        return 1
    p1 = 2
    p2 = (p-1) // p1

    while( 1 ):
        g = random.randint( 2, p-1 )
        if not (pow( g, (p-1)//p1, p ) == 1):
            if not pow( g, (p-1)//p2, p ) == 1:
                return g

# знаходимо n бітне просте число
def find_prime_number(lenghinbits, confidence):
    while(1):
        p = random.randint( 2**(lenghinbits-2), 2**(lenghinbits-1) )
        while( p % 2 == 0 ):
            p = random.randint(2**(lenghinbits-2),2**(lenghinbits-1))

        while( not SolovayStrassen(p, confidence) ):
            p = random.randint( 2**(lenghinbits-2), 2**(lenghinbits-1) )
            while( p % 2 == 0 ):
                p = random.randint(2**(lenghinbits-2), 2**(lenghinbits-1))

        p = p * 2 + 1
        if SolovayStrassen(p, confidence):
            return p

#кодуємо байти і цілі числа mod p.  зчитуємо байти
def encode(text, lenghinbits):
    byte_array = bytearray(text, 'utf-16')

    z = []
    k = lenghinbits//8
    j = -1 * k
    num = 0
    for i in range( len(byte_array) ):
        if i % k == 0:
            j += k
            num = 0
            z.append(0)
        z[j//k] += byte_array[i]*(2**(8*(i%k)))
    return z

#декодування
def decode(text, lenghinbits):
    bytes_array = []
    k = lenghinbits//8

    for num in text:
        for i in range(k):
            temp = num
            for j in range(i+1, k):
                temp = temp % (2**(8*j))
            letter = temp // (2**(8*i))
            bytes_array.append(letter)
            num = num - (letter*(2**(8*i)))
    decodedText = bytearray(b for b in bytes_array).decode('utf-16')

    return decodedText

#генератор бублічного і приватного ключа
def generate_keys(lenghinbits=256, confidence=32):
    # p просте число

    # g : g^(f(p)) = 1(mod p)
    #     g^l != 1(mod p)
    #     при 1<=l<=f(p)-1, f(p)-функція ейлера

    # x (1...p) взаємно просте з p
    # h = g^x * mod p
    p = find_prime_number(lenghinbits, confidence)
    g = find_g(p)
    g = pow( g, 2, p )
    x = random.randint( 1, (p - 1) // 2 )
    h = pow( g, x, p )

    publicKey = PublicKey(p, g, h, lenghinbits)
    privateKey = PrivateKey(p, g, x, lenghinbits)

    return {'privateKey': privateKey, 'publicKey': publicKey}


"""
шифруфання:
1) вибираєм випадкове секретне число к, взаємно просте з p-1
2) вираховуємо a = g^k mod p
    b = h^(k)M mod p
3) (a, b) - шифротекст
"""
def encrypt(key, text):
    z = encode(text, key.lenghinbits)

    cipher_pairs = []
    for i in z:
        y = random.randint( 0, key.p )
        c = pow( key.g, y, key.p )
        d = (i*pow( key.h, y, key.p)) % key.p
        cipher_pairs.append( [c, d] )

    encryptedString = ""
    for pair in cipher_pairs:
        encryptedString += str(pair[0]) + ' ' + str(pair[1]) + ' '

    return encryptedString

# M = b(a^x)^-1(mod p)  -  x -закритий ключ
def decrypt(key, cipher):

    plaintext = []

    cipherArray = cipher.split()
    if (not len(cipherArray) % 2 == 0):
        return "Malformed Cipher Text"
    for i in range(0, len(cipherArray), 2):
        c = int(cipherArray[i])
        d = int(cipherArray[i+1])

        s = pow( c, key.x, key.p )
        plain = (d*pow( s, key.p-2, key.p)) % key.p
        plaintext.append( plain )

    decryptedText = decode(plaintext, key.lenghinbits)

    #remove trailing null bytes
    decryptedText = "".join([ch for ch in decryptedText if ch != '\x00'])

    return decryptedText

if __name__ == "__main__":
    keys = generate_keys();
    print('encrypt me pleas');
    cipher = encrypt(keys['publicKey'], "encrypt me pleas");
    print(cipher);
    plaintext = decrypt(keys['privateKey'], cipher);
    print(plaintext);