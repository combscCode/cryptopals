'''set4 solutions for cryptopals'''
import secrets
import random
import time
from Crypto.Cipher import AES
from set1 import base64_to_bin
from set2 import generate_random_key, aes_ecb_encrypt, aes_cbc_encrypt, aes_cbc_decrypt
from set3 import aes_ctr, blockify

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

challenge_26_aes_key = generate_random_key()
def challenge_26_encrypt(string_in):
    to_return = 'comment1=cooking%20MCs;userdata=' + string_in.replace('=', '%3d').replace(';', '%3b') + ';comment2=%20like%20a%20pound%20of%20bacon'
    to_return = str.encode(to_return)
    
    return aes_ctr(to_return, challenge_26_aes_key)

def challenge_26_detect_admin(cipher):
    decrypted = aes_ctr(cipher, challenge_26_aes_key)
    return decrypted.count(b";admin=true") > 0

def ctr_bitflip_attack():
    '''
    We can just xor the ciphertext to get what we want when it's decrypted.
    If the attacker knows the plaintext and the location of the plaintext
    they can change the ciphertext to decrypt to anything they want.
    '''
    cipher = challenge_26_encrypt('_admin_true')
    cipher = bytearray(cipher)
    cipher[32] ^= ord('_') ^ ord(';')
    cipher[38] ^= ord('_') ^ ord('=')
    return challenge_26_detect_admin(cipher)

challenge_27_aes_key = generate_random_key()
def challenge_27_encrypt(string_in):
    for char_in in string_in:
        if ord(char_in) > 127:
            raise RuntimeError
    to_return = 'comment1=cooking%20MCs;userdata=' + string_in.replace('=', '%3d').replace(';', '%3b') + ';comment2=%20like%20a%20pound%20of%20bacon'
    to_return = str.encode(to_return)
    
    return aes_cbc_encrypt(to_return, challenge_27_aes_key, iv=challenge_27_aes_key)

def challenge_27_detect_admin(cipher):
    decrypted = aes_cbc_decrypt(cipher, challenge_27_aes_key, iv=challenge_27_aes_key)
    for decrypted_byte in decrypted:
        if decrypted_byte > 127:
            raise RuntimeError
    return decrypted.count(b";admin=true") > 0

def cbc_iv_is_key():
    message = "my name is j millz and i don't mean to be rudez."
    encrypted = challenge_27_encrypt(message)
    print("Unfinished")

# https://cedricvanrompay.gitlab.io/cryptopals/challenges/28-and-29.html used for
# verifying my sha1 implementation

def sha1_pad(message):
    """produces a valid MD PAD of the message given."""
    og_len = len(message).to_bytes(8, byteorder='big')
    message += b'\x80'
    while len(message) % 64 != 56:
        message += b'\x00'
    message += og_len
    assert len(message) % 64 == 0
    return message

def leftrotate(x, r, b=32):
    """Rotate integer x (b bits) to the left r times."""
    return ((x << r) | (x >> (b-r))) & (1 << b - 1)

def wordify(block, w=4):
    """split block into w byte words"""
    assert len(block) % w == 0
    return [int.from_bytes(block[i:i + w], byteorder='big') for i in range(0, len(block), w)]


def sha1_implementation(message):
    """Implements sha1, taken from https://en.wikipedia.org/wiki/SHA-1#SHA-1_pseudocode"""
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0
    message = sha1_pad(message)
    blocks = blockify(message, blocksize=64)
    for block in blocks:
        assert len(block) == 64
        words = wordify(block)
        for i in range(16, 80):
            words.append(leftrotate(words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16], 1))
        assert len(words) == 80
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
        for i in range(80):
            if i < 20:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif i < 40:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif i < 60:
                f = (b & c) | (b & d) | (c & d) 
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6
            temp = leftrotate(a, 5) + f + e + k + words[i]
            e = d
            d = c
            c = leftrotate(b, 32)
            b = a
            a = temp
        h0 = h0 + a
        h1 = h1 + b 
        h2 = h2 + c
        h3 = h3 + d
        h4 = h4 + e
    digest_int = (h0 << 128) | (h1 << 96) | (h2 << 64) | (h3 << 32) | h4
    return digest_int.to_bytes((digest_int.bit_length() + 7) // 8, byteorder='big')

def sha1_mac(key, message):
    return sha1_implementation(key + message)

if __name__ == '__main__':
    # print("Begin set 4 solutions")
    # print('Challenge 25')
    # ctr_key = generate_random_key()
    # data_blob = b''
    # for line in open('data2_10.txt'):
    #     data_blob += base64_to_bin(line)

    # print('did our attack work?:', data_blob == break_ctr_api(data_blob))

    # print('Challenge 26')
    # print(ctr_bitflip_attack())

    # print("Challenge 27")
    # cbc_iv_is_key()

    print("Challenge 28 + 29")
    secret = b'yellow submarine'
    msg = b'jmillz'
    print('Stopping here... moving onto set 5')
