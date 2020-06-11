'''set2 solutions for cryptopals'''
import secrets
import random
from Crypto.Cipher import AES
from set1 import bin_to_hex, hex_to_bin, hex_to_base64, base64_to_bin, encrypt_repeating_xor, aes_ecb_decrypt, fixed_xor, english_score
from set2 import pkcs7, validate_pkcs7, blockify, aes_cbc_encrypt, aes_cbc_decrypt, aes_ecb_encrypt, generate_random_key, unpad

GLOBAL_RANDOM_KEY = generate_random_key()
challenge_17_strings = [
    b"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    b"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    b"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    b"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    b"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    b"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    b"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    b"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    b"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    b"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
]
def serve_cookie(iv=None):
    '''
    This function approximates AES-CBC encryption on a webserver. It serves up
    a "new" cookie to the user so when they make a request on the server the server
    can figure out who is talking to it.
    '''
    string_to_encode = challenge_17_strings[random.randint(0, len(challenge_17_strings) - 1)]
    return aes_cbc_encrypt(string_to_encode, GLOBAL_RANDOM_KEY, iv=iv), iv

def consume_cookie(cipher, iv=None):
    '''
    This function approximates AES-CBC encryption on a webserver. It models the server's
    consumption of an encrypted session token, as if it were a cookie. Note, it simply
    checks to see if the data it was given CAN be a valid cookie, it does not guarantee that the
    data actually CORRESPONDS to a cookie that the server has given out.
    '''
    decrypted = aes_cbc_decrypt(cipher, GLOBAL_RANDOM_KEY, iv=iv)
    try:
        validate_pkcs7(decrypted)
        return True
    except ValueError:
        return False

def decrypt_cookie(validator, iv=None):
    '''
    This function figures out what the cookie on the server is. CBC padding oracle attack.
    P[i] = D_k(C[i]) ^ C[i-1]
    on a block level, or more specifically for each byte within each block
    0 < i < num blocks
    0 < j < 16
    P[i][j] = D_k(C[i])[j] ^ C[i-1][j]
    Therefore, we can take advantage of the bitflipping nature of CBC to perform an attack.
    We can use the bitflipping property to manipulate the last byte of the ciphertext until
    the validation function tells us that it is valid padding.
    If s is the secret byte of the plaintext and v is the value of C[i-1][j] then we know that
    s = \x01
    D_k(C[i])[j] ^ v = s
    D_k(C[i])[j] = v ^ s

    We can then build this out until eventually we have some vector V st
    C[i-1] = V
    \x10 * 16 = D_k(C[i]) ^ V

    Now what can we do with this? We're trying to figure out the plaintext...
    Trying to find the value of P[i]... We know that P is D_k() ^ C[i-1], and we
    know that D_k() ^ V = \x10 * 16, so that means if we take the difference
    between V and C[i-1], we can find P? I think?

    P[i] = D_k(C[i]) ^ C[i-1]
    P[i] ^ (\x10 * 16) = D_k(C[i]) ^ C[i-1] ^ D_k(C[i]) ^ V
    P[i] ^ (\x10 * 16) = C[i-1] ^ V
    P[i] = C[i-1] ^ V ^ (\x10 * 16)

    WOW I did it I think! So once we construct V using our padding validation function,
    we have a formula to determine what P[i] is. I know there's no way to verify this but
    I really did figure this out by myself by just thinking about the bitflipping property
    and the hints given on cryptopals.
    '''
    cipher, iv = serve_cookie(iv=iv)
    cipher = bytearray(cipher)
    if iv is None:
        iv = b'\x00' * 16
    iv = bytearray(iv)
    cipher_blocks = blockify(cipher)
    # Crack blocks in reverse order
    plaintext = b''
    for block_idx in reversed(range(len(cipher_blocks))):
        V = bytearray(b'\x00' * 16)
        cipher_blocks_copy = cipher_blocks[:block_idx + 1]
        assert len(cipher_blocks_copy) == block_idx + 1
        iv_copy = iv.copy()
        for byte_idx in reversed(range(16)):
            # Edit V st everything after this byte will pad successfully
            # iff V[byte_idx] = \x(16-byte_idx)
            for i in range(byte_idx + 1, 16):
                # V[i] ^= previous pad ^ desired pad
                V[i] ^= (16 - byte_idx - 1) ^ (16 - byte_idx)
            found_byte = False
            for byte in range(256):
                # bitflip until we find V[byte_idx] that has valid padding
                V[byte_idx] = byte
                if block_idx > 0:
                    cipher_blocks_copy[block_idx-1] = V
                else:
                    iv_copy = V
                if validator(b''.join(cipher_blocks_copy), iv=iv_copy):
                    found_byte = True
                    break
            if not found_byte:
                print("CBC Padding Oracle Attack Failed")
                raise RuntimeError
        previous_block = cipher_blocks[block_idx - 1] if block_idx > 0 else iv
        # XOR everything together and prepend the chunk to our deciphered plaintext
        plaintext_chunk = bytes([i ^ j ^ k for i, j, k in zip(previous_block, V, bytearray(b'\x10' * 16))])
        plaintext = plaintext_chunk + plaintext
    return plaintext

def aes_ctr(binary_blob, aes_key, nonce=0):
    '''
    Implements stream cipher mode AES
    '''
    nonce = nonce.to_bytes(8, byteorder='little')
    keystream = b''
    counter = 0
    while len(keystream) < len(binary_blob):
        keystream += aes_ecb_encrypt(nonce + counter.to_bytes(8, byteorder='little'), aes_key)
        counter += 1
    return bytes([a ^ b for a, b in zip(binary_blob, keystream)])


if __name__ == '__main__':
    print('Challenge 17')
    print(unpad(decrypt_cookie(consume_cookie, iv=generate_random_key())))

    print('Challenge 18')
    secret_string = 'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='
    print(aes_ctr(base64_to_bin(secret_string), b'YELLOW SUBMARINE'))
    for thing in [b'yellowsubmarinepotato', b'bellowsubmarinepotato', b'my names j millz dont mean to be rude no better way than me to conclude']:
        print(aes_ctr(thing, b'YELLOW SUBMARINE'))
        print(aes_ctr(aes_ctr(thing, b'YELLOW SUBMARINE'), b'YELLOW SUBMARINE'))

    print('Challenge 19')
    ciphers = []
    random_key = generate_random_key()
    for line in open('data3_19.txt'):
        ciphers.append(aes_ctr(base64_to_bin(line), random_key))

    max_cipher_length = max([len(cipher) for cipher in ciphers])
    first_guess_keystream = b''
    for cipher_idx in range(max_cipher_length):
        scores = []
        for candidate_byte in range(256):
            cipher_slice = [cipher[cipher_idx] for cipher in ciphers if cipher_idx < len(cipher)]
            scores.append( (english_score(b''.join([bytes([cipher_byte ^ candidate_byte]) for cipher_byte in cipher_slice])), candidate_byte))
        scores = sorted(scores, reverse=True)
        first_guess_keystream += bytes([scores[0][1]])
    print("First guess for our keystream:", first_guess_keystream)
    for cipher in ciphers:
        print(b''.join([bytes([a ^ b]) for a, b in zip(cipher, first_guess_keystream)]))
