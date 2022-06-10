from random import randint, choice
#import sympy
from base64 import b32encode, b32decode
from os import mkdir


def MRT(a): # Miller - Rabin Test
    n = a - 1
    s = 0
    while not n % 2: n, s = n // 2, s + 1
    k = 100
    while k > 0:
        flag, rand = False, randint(2, a - 2)
        x = pow(rand, n, a)
        if x == 1 or x == a - 1:
            k -= 1
            continue
        i = 0
        while i < s:
            x = (x * x) % a
            if x == 1: return False
            if x == a - 1: break
            i += 1
        k -= 1
        if x != a - 1: return False
    return True


def CleverGen(): # Generator of simple numbers
    flaq = False
    st, fin = 2 ** 100 + 1, 2 ** 101 - 1
    while True:
        p = randint(st, fin)
        if p % 4 == 3 and MRT(p): break #sympy.isprime(p)
    while True:
        q = randint(st, fin)
        if q % 4 == 3 and MRT(q): break #sympy.isprime(q)
    return p, q


def RabinRSA(logz, passw): # Creates user's public (RSA - signed) and private keys
    p, q = CleverGen()
    n = p * q
    openrsa, nrsa, secretrsa = SignRSA(1)
    pathz = input('Enter PATH to change the default key save folder. Else press Enter:')
    if len(pathz):
        try:
            f = open(pathz + logz + '_public_key.txt', 'w')
        except OSError:
            print('Wrong PATH. Try again.')
            return 0, 0
        else: print('Your PATH is correct.')
    else:
        try:
            f = open('users\\' + logz + '_public_key.txt', 'w')
        except OSError:
            mkdir('users')
            f = open('users\\' + logz + '_public_key.txt', 'w')
    f.write(str(n) + '.' + str(pow(n, secretrsa, nrsa)))
    f.close()
    if len(pathz): f = open(pathz + logz + '_private_key.txt', 'w')
    else: f = open('users\\' + logz + '_private_key.txt', 'w')
    f.write(str(p) + '.' + str(q))
    f.close()
    return p, q


def SignRSA(flag): # Creates public and private RSA-keys 
    if flag:
        try: 
            f = open('public_key_RSA.txt', 'r')
        except FileNotFoundError:
            print('Signature failed. New signature is created.')
            SignRSA(0)
        else:
            e, n = f.read().split('.')
            f.close()
            f = open('private_key_RSA.txt', 'r')
            d, n = f.read().split('.')
            f.close()
            return int(e), int(n), int(d)
    p, q = CleverGen()
    n = p * q
    fi = (p - 1) * (q - 1)
    f = open('primes_mod.txt', 'r')
    read_f = f.read().split()
    e = int(choice(read_f)[:-1])
    a, d, b = ExpEvk(e, fi)
    while d < 0:
        e = int(choice(read_f)[:-1])
        a, d, b = ExpEvk(e, fi)
    f.close()
    f = open('public_key_RSA.txt', 'w')
    f.write(str(e) + '.' + str(n))
    f.close()
    f = open('private_key_RSA.txt', 'w')
    f.write(str(d) + '.' + str(n))
    f.close()
    print('Done.')
    return e, n, d


def CheckRSA(m, s): # Checks the validity of the public key signature
    f = open('public_key_RSA.txt', 'r')
    e, n = map(int, f.read().split('.'))
    f.close()
    return not abs(m - pow(s, e, n)) % n


def CrypterRabin(login, message, openkey):
    f = open('master_baze.txt', 'r+')
    if login in f.read():
        print('This login is already taken. Try again.')
        return False
    f.write('\n' + login + '_')
    new_message = str(openkey)[-1]
    for i in range(len(message)):
        new_message += '0' * (ord(message[i]) < 100) + str(ord(message[i]))
    new_message += str(openkey)[-2]
    s = pow(int(new_message), 2, openkey)
    s = b32encode(str(s).encode('utf-8'))
    f.write(str(s))
    f.close()
    print('YOUR MASTER PASSWORD WAS ADDED TO THE BASE.')
    return True

    
def ExpEvk(a, b): # Extended Euclid algorithm
    if a == 0: return b, 0, 1
    d, x, y = ExpEvk(b % a, a)
    return (d, y - (b // a) * x, x)
    

def Regizter(logz, passw): # New user registration
    p, q = RabinRSA(logz, passw)
    if p == 0 and q == 0: return False
    return CrypterRabin(logz, passw, p * q)


def LoginCheck(login, masterpass, pathz): # Checks the validity of the login and password
    try:
        f = open(pathz, 'r')
    except OSError:
        print('Wrong PATH. Try again.')
        return False
    p, q = f.read().split('.')
    p, q = int(p), int(q)
    n = p * q
    f.close()
    f = open('master_baze.txt', 'r')
    s = f.readline().split()
    s = f.readline().split('_')
    while s[0] != login: s = f.readline().split('_')
    f.close()
    s = int(b32decode(bytes(s[1][2:-1], encoding = 'utf8')).decode('utf-8'))
    our_pass = ''
    checker1 = str(n)[-1]
    checker2 = str(n)[-2]
    gcd, yp, yq = ExpEvk(p, q)
    yp = q * pow(q, p - 2, p)
    yq = p * pow(p, q - 2, q)
    m1 = pow(s, (p + 1) // 4, p)
    m2 = -m1
    m3 = pow(s, (q + 1) // 4, q)
    m4 = -m3
    mout1 = str((yp * m1 + yq * m3) % n)
    mout2 = str((yp * m1 + yq * m4) % n)
    mout3 = str((yp * m2 + yq * m3) % n)
    mout4 = str((yp * m2 + yq * m4) % n)
    if mout1[0] == checker1 and mout1[-1] == checker2 and len(mout1) % 3 == 2: out_pass = mout1[1:-1]
    if mout2[0] == checker1 and mout2[-1] == checker2 and len(mout2) % 3 == 2: out_pass = mout2[1:-1]
    if mout3[0] == checker1 and mout3[-1] == checker2 and len(mout3) % 3 == 2: out_pass = mout3[1:-1]
    if mout4[0] == checker1 and mout4[-1] == checker2 and len(mout4) % 3 == 2: out_pass = mout4[1:-1]
    decoded = ''
    i = 0
    while i < len(out_pass):
        decoded += chr(int(out_pass[i:i + 3]))
        i += 3
    return decoded == masterpass
    
    
def Adder(login, open_path, secret_path): # Adds and encrypts new passwords
    f = open(open_path, 'r')
    n, _ = map(int, f.read().split('.'))
    f.close()
    if not CheckRSA(n, _): return False
    print('Your password is correct. Now you can add new passwords.')
    print('Write the description first. Then write your password. Enter "end" when finished.', end = ' ')
    print('or if you want to skip this step')
    try:
        f = open('bazez\\' + login + '_baze.txt', 'a')
    except OSError:
        mkdir('bazez\\')
        f = open('bazez\\' + login + '_baze.txt', 'a')
    descr = input('Description:')
    while descr != 'end':
        newpass = input('Enter password:')
        if len(newpass) < 10:
            print('Length of your passwords must be more then 10!')
            continue
        f.write('\n' + descr + '_')
        new_message = str(n)[-1]
        for i in range(len(newpass)): new_message += '0' * (ord(newpass[i]) < 100) + str(ord(newpass[i]))
        new_message += str(n)[-2]
        s = pow(int(new_message), 2, n)
        s = b32encode(str(s).encode('utf-8'))
        f.write(str(s))
        print('This is your encrypted password: ', str(s)[2:-1])
        descr = input('Description:')
    f.write('\n')
    f.close()
    print('All done.')
    print('If you want to see your personal database - enter 1, else enter any button to quit.')
    s = input('Type here:')
    if s == '1':
        f = open(secret_path, 'r')
        p, q = f.read().split('.')
        p, q = int(p), int(q)
        f.close()
        BazePrint(login, p, q)
    return True


def BazePrint(login, p, q): # Prints user's personal database
    f = open('bazez\\' + login + '_baze.txt', 'r')
    current_line = f.readline()
    i = 1
    mas_of_pass = []
    while len(current_line) > 0:
        if current_line == '\n':
            current_line = f.readline()
            continue
        current_line = current_line.split('_')
        print(str(i) + ' ' + current_line[0], end = '    ')
        print(current_line[1][:-1].replace('b', '').replace('|', '').replace("'", ''))
        print()
        mas_of_pass.append(current_line[1][:-1])
        i += 1
        current_line = f.readline()
    f.close()
    cycle = '1'
    while cycle == '1':
        ind_pass = input('You can enter index of string with needed password to decipher. Else enter "end":')
        if ind_pass == 'end': return
        s = mas_of_pass[int(ind_pass) - 1]
        n = p * q
        s = int(b32decode(bytes(s[2:-1], encoding = 'utf8')).decode('utf-8'))
        our_pass = ''
        checker1 = str(n)[-1]
        checker2 = str(n)[-2]
        gcd, yp, yq = ExpEvk(p, q)
        yp = q * pow(q, p - 2, p)
        yq = p * pow(p, q - 2, q)
        m1 = pow(s, (p + 1) // 4, p)
        m2 = -m1
        m3 = pow(s, (q + 1) // 4, q)
        m4 = -m3
        mout1 = str((yp * m1 + yq * m3) % n)
        mout2 = str((yp * m1 + yq * m4) % n)
        mout3 = str((yp * m2 + yq * m3) % n)
        mout4 = str((yp * m2 + yq * m4) % n)
        if mout1[0] == checker1 and mout1[-1] == checker2 and len(mout1) % 3 == 2: out_pass = mout1[1:-1]
        if mout2[0] == checker1 and mout2[-1] == checker2 and len(mout2) % 3 == 2: out_pass = mout2[1:-1]
        if mout3[0] == checker1 and mout3[-1] == checker2 and len(mout3) % 3 == 2: out_pass = mout3[1:-1]
        if mout4[0] == checker1 and mout4[-1] == checker2 and len(mout4) % 3 == 2: out_pass = mout4[1:-1]
        decoded = ''
        i = 0
        while i < len(out_pass):
            decoded += chr(int(out_pass[i:i + 3]))
            i += 3
        print('This is your password:', decoded)
        cycle = input('If you want to decipher another password - enter 1. Else press any button:')
    return 


s = '1'
print('Welcome to the Passcoder!\nLength of your passwords must be more then 10!')
while s in '123' and len(s):
    print('Menu:', '-' * 60, sep = '\n')
    print('Enter 1 to register.\n')
    print('Enter 2 to log in (if you are already registered). Then you can encrypt, decrypt passwords', end = ' ')
    print('and see your personal database.\n')
    print('Enter 3 to change program key.\n')
    print('Else enter any button to quit.')
    print('-' * 60)
    s = input('Type here:')
    if s == '1':
        login = input('Enter login:')
        passw = input('Enter password:')
        if len(passw) < 10:
            print('Length of your passwords must be more then 10!')
            continue
        if not Regizter(login, passw): continue
        print('Done. Now you have public and private keys in .txt', 'Please save them.', sep = '\n')
    elif s == '2':
        login = input('Enter login:')
        passw = input('Enter password:')
        secret_path = input('Enter PATH to your private key in .txt:')
        if not LoginCheck(login, passw, secret_path):
            print('Your login or password is incorrect. Try again or register.')
            continue
        check = input('Enter 4 if you want to encrypt some passwords:')
        if check == '4':
            open_path = input('Enter PATH to your public key in .txt:')
            try:
                f = open(open_path, 'r')
            except OSError:
                print('Wrong PATH. Try again.')
                continue
            else: print('Your PATH is correct.')
            if not CheckRSA(*map(int, f.read().split('.'))):
                print('Your signature is out of date. Please register again.')
                f.close()
            else:
                f.close()
                Adder(login, open_path, secret_path)
    elif s == '3': SignRSA(0)
print('Have a good day!')
