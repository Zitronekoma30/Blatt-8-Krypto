from Crypto.Util import number
import math

def generate_keys(bits=1024):
    e = 65537
    p = number.getPrime(bits)
    q = number.getPrime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    return (e, n), (d, n)

def sign(message, private_key):
    d, n = private_key
    message_int = int.from_bytes(message.encode('utf-8'), byteorder='big')
    signature = pow(message_int, d, n)
    return signature

def verify(message, signature, public_key):
    e, n = public_key
    message_int = int.from_bytes(message.encode('utf-8'), byteorder='big')
    signed_message_int = pow(signature, e, n) 
    return message_int == signed_message_int

def chosen_ciphertext_attack(public_key, private_key):
    m1 = "Hello"
    m2 = "World"

    # In numerische Blöcke konvertieren
    m1_int = int.from_bytes(m1.encode('utf-8'), byteorder='big')
    m2_int = int.from_bytes(m2.encode('utf-8'), byteorder='big')

    # Berechnen von numerischen m3 für späteres überpfüfen
    n = public_key[1]
    m3_int = (m1_int * m2_int) % n
    
    # An Alice "senden"

    # Alice signiert m1 und m2
    s1 = sign(m1, private_key)
    s2 = sign(m2, private_key)

    # Alice "sendet" zurück

    # Eve berechnet signiertes m3 aus s1 und s2
    s3 = (s1 * s2) % n

    # Überprüfen ob m3^d = m1^d * m2^d
    signed_message_int = pow(s3, public_key[0], n) # m^e*d = m
    is_valid = signed_message_int == m3_int
    print(f"Forged signature valid: {is_valid}")


public_key, private_key = generate_keys()
chosen_ciphertext_attack(public_key, private_key)
