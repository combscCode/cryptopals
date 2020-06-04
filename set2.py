'''set2 solutions for cryptopals'''
import secrets
import random
from Crypto.Cipher import AES
from set1 import bin_to_hex, hex_to_bin, hex_to_base64, base64_to_bin, encrypt_repeating_xor, aes_ecb_decrypt, fixed_xor

def pkcs7(input_bytes, block_length=16):
    '''pad the input bytes according to pkcs#7 to an
    even multiple of the block length given'''
    return input_bytes + b'\x04' * ((block_length - len(input_bytes)) % block_length)

def aes_ecb_encrypt(plaintext_blob, aes_key):
    cipher = AES.new(aes_key, AES.MODE_ECB)
    return cipher.encrypt(plaintext_blob)

def aes_cbc_encrypt(plaintext_blob, aes_key, iv=None):
    '''encrypts plaintext according to AES protocol in CBC mode'''
    if iv is None:
        iv = b'\x00' * 16
    ciphertext = b''
    plaintext_blocks = [plaintext_blob[i:i+16] for i in range(0, len(plaintext_blob), 16)]
    plaintext_blocks[-1] = pkcs7(plaintext_blocks[-1], 16)

    to_xor = iv
    for block in plaintext_blocks:
        xored = fixed_xor(to_xor, block)
        encrypted = aes_ecb_encrypt(xored, aes_key)
        ciphertext += encrypted
        to_xor = encrypted
    return ciphertext

def aes_cbc_decrypt(cipher_blob, aes_key, iv=None):
    '''decrypts ciphertext according to AES protocol in CBC mode'''
    if iv is None:
        iv = b'\x00' * 16
    plaintext = b''
    cipher_blocks = [cipher_blob[i:i+16] for i in range(0, len(cipher_blob), 16)]
    assert len(cipher_blocks[-1]) == 16

    to_xor = iv
    for block in cipher_blocks:
        deciphered = aes_ecb_decrypt(block, aes_key)
        plaintext += fixed_xor(to_xor, deciphered)
        to_xor = block
    return plaintext

def generate_random_key(nbytes=16):
    return secrets.token_bytes(nbytes)

def encryption_oracle(plaintext_blob):
    '''This function is described here: https://cryptopals.com/sets/2/challenges/11
    It's used to test our AES MODE oracle'''
    beginning_padding_length = random.randint(5, 10)
    ending_padding_length = random.randint(5, 10)
    beginning_bytes = secrets.token_bytes(beginning_padding_length)
    ending_bytes = secrets.token_bytes(ending_padding_length)
    plaintext_blob = beginning_bytes + plaintext_blob + ending_bytes
    random_key = generate_random_key()
    if random.randint(1,2) == 2:
        random_iv = secrets.token_bytes(16)
        return aes_cbc_encrypt(plaintext_blob, random_key, iv=random_iv), 'cbc'
    else:
        plaintext_blob = pkcs7(plaintext_blob)
        return aes_ecb_encrypt(plaintext_blob, random_key), 'ecb'

def detect_aes_mode(blackbox):
    '''This function takes in a encryption function and determines
    what mode of AES it is using'''
    plaintext = b'\x00' * 16 * 16
    ciphertext = blackbox(plaintext)
    cipherblocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
    repeats = len(cipherblocks) - len(set(cipherblocks))
    if repeats > 0:
        return 'ecb'
    else:
        return 'cbc'

GLOBAL_RANDOM_KEY = generate_random_key()
UNKNOWN_STRING = '''Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK'''

def vulnerable_oracle(plaintext_blob):
    '''This function is described here: https://cryptopals.com/sets/2/challenges/12'''
    plaintext_blob = plaintext_blob + base64_to_bin(UNKNOWN_STRING)
    plaintext_blob = pkcs7(plaintext_blob)
    random_key = GLOBAL_RANDOM_KEY
    return aes_ecb_encrypt(plaintext_blob, random_key)

def crack_vulnerable_oracle(vulnerable_blackbox):
    '''This function is used to crack a blackbox that returns a ciphertext
    in the following form: C = B(P|S, K) where S is a secret string.'''
    print("Cracking Vulnerable Oracle")
    print("Step 1: Determine the blocksize of the cipher")
    # Cracked by seeing how many bytes the ciphertext grows by
    cipher = vulnerable_blackbox(b'A')
    num_bytes = 1
    last_cipher_length = len(cipher)
    while len(cipher) == last_cipher_length:
        last_cipher_length = len(cipher)
        num_bytes += 1
        cipher = vulnerable_blackbox(b'A' * num_bytes)
    blocksize = len(cipher) - last_cipher_length
    print("    Blocksize found to be", blocksize)

    print("Step 2: Detect that the blackbox is in ECB mode")
    mode = detect_aes_mode(vulnerable_blackbox)
    if mode == 'ecb':
        print("    Blackbox uses ecb")
    else:
        print("    Blackbox doesn't use ecb")
        return

    print("Step 3: Find secret")
    known_secret = b''
    total_length = len(vulnerable_blackbox(b''))
    last_known_bytes = b'\x69' * (blocksize - 1)
    for secret_idx in range(total_length):
        # Put all possible key value pairs for the
        # (known block | unknown character, cipherblock) value
        # in a dictionary
        possible_dict = {}
        for possible_character in range(256):
            byte_string = last_known_bytes + bytes([possible_character])
            ciphertext = vulnerable_blackbox(byte_string)
            possible_dict[ciphertext[0:blocksize]] = byte_string
        # Now use the blackbox to get (known block | unknown chracter)
        # into an even block and check to see what bytestring the
        # cipher_block matches
        num_bytes_to_prepend = blocksize - 1 - (secret_idx % blocksize)
        ciphertext = vulnerable_blackbox(last_known_bytes[0:num_bytes_to_prepend])
        cipher_block_start = (secret_idx // blocksize) * blocksize
        cipher_block_end = cipher_block_start + blocksize
        cipher_block = ciphertext[cipher_block_start:cipher_block_end]
        unmasked_byte = bytes([possible_dict[cipher_block][-1]])
        known_secret += unmasked_byte
        last_known_bytes = last_known_bytes[1:] + unmasked_byte
    return known_secret



if __name__ == '__main__':
    print('Challenge 9')
    print(pkcs7(b'YELLOW SUBMARINE', 20))

    print('Challenge 10')
    encrypted_blob = b''
    for line in open('data2_10.txt'):
        encrypted_blob += base64_to_bin(line)
    print(aes_cbc_decrypt(encrypted_blob, b'YELLOW SUBMARINE'))

    print('Challenge 12')
    print(crack_vulnerable_oracle(vulnerable_oracle))
