'''set4 solutions for cryptopals'''
import secrets
import random
import time
from Crypto.Cipher import AES
from set1 import base64_to_bin
from set2 import generate_random_key, aes_ecb_encrypt
from set3 import aes_ctr

def read_ctr_cipher(ciphertext, key, offset, length, nonce=0):
    '''
    seeks into the cipherteext using the offset and
    returns the decrypted info with length specified
    '''
    nonce = nonce.to_bytes(8, byteorder='little')
    keystream = b''
    counter = 0
    while len(keystream) < offset + length:
        keystream += aes_ecb_encrypt(nonce + counter.to_bytes(8, byteorder='little'), key)
        counter += 1
    return bytes([a ^ b for a, b in zip(cipher[offset:offset + length], keystream[offset:])])

def edit_ctr_cipher(ciphertext, key, offset, newtext, nonce=0):
    '''
    seeks into the ciphertext using the offset and replaces
    part of the ciphertext with the encrypted newtext
    '''
    nonce = nonce.to_bytes(8, byteorder='little')
    keystream = b''
    counter = 0
    while len(keystream) < offset + len(newtext):
        keystream += aes_ecb_encrypt(nonce + counter.to_bytes(8, byteorder='little'), key)
        counter += 1
    keystream = keystream[offset:]
    newcipher = bytes([a ^ b for a, b in zip(newtext, keystream)])
    ciphertext = ciphertext[:offset] + newcipher + ciphertext[offset + len(newcipher):]
    return ciphertext

def break_ctr_api(plaintext, ctr_key=None):
    '''
    Imagine the "edit" function was exposed to attackers by means of an API call that didn't
    reveal the key or the original plaintext; the attacker has the ciphertext and controls the
    offset and "new text".

    Recover the original plaintext.

    ciphera = a_plaintext xor keystream
    cipherb = b_plaintext xor keystream
    ciphera xor cipherb = a_plaintext xor keystream xor b_plaintext xor keystream
    ciphera xor cipherb xor b_plaintext = a_plaintext
    '''
    if ctr_key is None:
        ctr_key = generate_random_key()
    ciphertext = aes_ctr(plaintext, ctr_key)

    def api(offset, newtext):
        return edit_ctr_cipher(ciphertext, ctr_key, offset, newtext)
    a_cipher = ciphertext
    b_plaintext = b'A' * len(ciphertext)
    b_cipher = api(0, b_plaintext)
    return bytes([a ^ b ^ c for a, b, c in zip(a_cipher, b_cipher, b_plaintext)])

if __name__ == '__main__':
    print("Begin set 4 solutions")
    print('Challenge 25')
    ctr_key = generate_random_key()
    data_blob = b''
    for line in open('data2_10.txt'):
        data_blob += base64_to_bin(line)

    print('did our attack work?:', data_blob == break_ctr_api(data_blob))
