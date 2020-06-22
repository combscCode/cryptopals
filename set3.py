'''set2 solutions for cryptopals'''
import secrets
import random
import time
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

def crack_aes_ctr_bad_nonce(ciphers):
    '''
    This function statistically cracks ciphers generated by an aes_ctr stream
    that is reusing nonces.
    '''
    max_cipher_length = max([len(cipher) for cipher in ciphers])
    keystream = b''
    for cipher_idx in range(max_cipher_length):
        scores = []
        for candidate_byte in range(256):
            cipher_slice = [cipher[cipher_idx] for cipher in ciphers if cipher_idx < len(cipher)]
            scores.append( (english_score(b''.join([bytes([cipher_byte ^ candidate_byte]) for cipher_byte in cipher_slice])), candidate_byte))
        scores = sorted(scores, key=lambda x:(x[0], x[1]), reverse=True)
        keystream += bytes([scores[0][1]])
    return keystream

def mersenne_twister_generator(seed, w=32, n=624, m=397, r=31, a=0x9908b0df, b=0x9d2c5680, c=0xefc60000, s=7, t=15, u=11, d=0xffffffff, l=18):
    '''
    This function implements the MT19937 Mersenne Twister as described on wikipedia.
    This function returns a PRNG, when called it will return an integer.

        w: word size (in bits)
        n: degree of recurrence
        m: middle word, an offset used in the recurrence relation defining the series x, 1 ≤ m < n
        r: separation point of one word, or the number of bits of the lower bitmask, 0 ≤ r ≤ w - 1
        a: coefficients of the rational normal form twist matrix
        b, c: TGFSR(R) tempering bitmasks
        s, t: TGFSR(R) tempering bit shifts
        u, d, l: additional Mersenne Twister tempering bit shifts/masks
    '''

    # Initialization
    f = 1812433253
    state = [0 for _ in range(n)]
    index = n + 1
    upper_bitmask = ((1 << w) - 1) - ((1 << r) +  - 1)
    lower_bitmask = ((1 << r) - 1)

    def seed_mt(s):
        nonlocal index
        index = n
        state[0] = s
        for i in range(1, n):
            state[i] = ((1 << w) - 1) & (f * (state[i-1] ^ (state[i-1] >> (w-2))) + i)

    def extract_number():
        nonlocal index
        if index == n:
            twist()
        y = state[index]
        y = y ^ ((y >> u) & d)
        y = y ^ ((y << s) & b)
        y = y ^ ((y << t) & c)
        y = y ^ (y >> l)

        index += 1
        return ((1 << w) - 1) & y
    
    def twist():
        nonlocal index
        for i in range(n):
            x = (state[i] & upper_bitmask) + (state[(i + 1) % n] & lower_bitmask)
            xA = x >> 1
            if x % 2 != 0:
                xA ^= a
            state[i] = state[(i + m) % n] ^ xA
        index = 0
    
    seed_mt(seed)
    return extract_number


def wait_and_seed_twister(min_time = 1, max_time = 10):
    print("Starting wait at", int(time.time()))
    time_to_wait = random.randint(min_time, max_time)
    time.sleep(time_to_wait)
    return mersenne_twister_generator(int(time.time()))

def temper(y, w=32, b=0x9d2c5680, c=0xefc60000, s=7, t=15, u=11, d=0xffffffff, l=18):
        y = y ^ ((y >> u) & d)
        y = y ^ ((y << s) & b)
        y = y ^ ((y << t) & c)
        y = y ^ (y >> l)

        return ((1 << w) - 1) & y

# Borrowed from https://cypher.codes/writing/cryptopals-challenge-set-3
# I really just could not figure out how to inverse some of these functions... I am dumb :c
def unshift_right_xor(value, shift):
    result = 0
    for i in range(32 // shift + 1):
        result ^= value >> (shift * i)
    return result

def unshift_left_mask_xor(value, shift, mask):
    result = 0
    for i in range(0, 32 // shift + 1):
        part_mask = (0xffffffff >> (32 - shift)) << (shift * i)
        part = value & part_mask
        value ^= (part << shift) & mask
        result |= part
    return result

def untemper(y):
    value = y
    value = unshift_right_xor(value, 18)
    value = unshift_left_mask_xor(value, 15, 4022730752)
    value = unshift_left_mask_xor(value, 7, 2636928640)
    value = unshift_right_xor(value, 11)
    return value

def clone_mt19937(prng, w=32, n=624, m=397, r=31, a=0x9908b0df, b=0x9d2c5680, c=0xefc60000, s=7, t=15, u=11, d=0xffffffff, l=18):
    '''
    This function takes in a function that implements mt19937
    and clones the internal state. prng is assumed to be a function
    that we can call like prng() to extract a number
    '''
    state = []
    for i in range(n):
        state.append(untemper(prng()))

    # Initialization
    index = n
    upper_bitmask = ((1 << w) - 1) - ((1 << r) +  - 1)
    lower_bitmask = ((1 << r) - 1)

    def extract_number():
        nonlocal index
        if index == n:
            twist()
        y = state[index]
        y = y ^ ((y >> u) & d)
        y = y ^ ((y << s) & b)
        y = y ^ ((y << t) & c)
        y = y ^ (y >> l)

        index += 1
        return ((1 << w) - 1) & y
    
    def twist():
        nonlocal index
        for i in range(n):
            x = (state[i] & upper_bitmask) + (state[(i + 1) % n] & lower_bitmask)
            xA = x >> 1
            if x % 2 != 0:
                xA ^= a
            state[i] = state[(i + m) % n] ^ xA
        index = 0
    
    return extract_number

def mt19937_encrypt(binary_blob, seed):
    prng = mersenne_twister_generator(seed)
    keystream = bytearray()
    while len(keystream) < len(binary_blob):
        val = prng()
        for _ in range(4):
            keystream.append(val % 256)
            val //= 256
    return bytes([a ^ b for a, b in zip(binary_blob, keystream)])


def crack_mt19937_encryption():
    '''
    recovers seed from a bad encryption
    '''
    secret_seed = random.randint(0, 2**16 - 1)
    num_of_rand_chars = random.randint(0, 100)
    print('secret seed is', secret_seed)
    known_plaintext = b'A' * 14
    random_chars = secrets.token_bytes(num_of_rand_chars)
    ciphertext = mt19937_encrypt(random_chars + known_plaintext, secret_seed)

    # We're just gonna brute force it...
    for seed in range(2**16):
        decrypted = mt19937_encrypt(ciphertext, seed)
        if decrypted[-14:] == known_plaintext:
            print('found secret seed to be', seed)
            return seed
    return -1

def generate_bad_token():
    '''
    generates a 'password reset token' using mt19937 seeded with the
    current unix time
    '''
    return mersenne_twister_generator(int(time.time()))()

def check_bad_mt(val, seed):
    '''
    checks to see if the value was generated with a mt19937 seeded with
    the given seed
    '''
    return val == mersenne_twister_generator(seed)()

if __name__ == '__main__':
    # print('Challenge 17')
    # print(unpad(decrypt_cookie(consume_cookie, iv=generate_random_key())))

    # print('Challenge 18')
    # secret_string = 'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='
    # print(aes_ctr(base64_to_bin(secret_string), b'YELLOW SUBMARINE'))
    # for thing in [b'yellowsubmarinepotato', b'bellowsubmarinepotato', b'my names j millz dont mean to be rude no better way than me to conclude']:
    #     print(aes_ctr(thing, b'YELLOW SUBMARINE'))
    #     print(aes_ctr(aes_ctr(thing, b'YELLOW SUBMARINE'), b'YELLOW SUBMARINE'))

    # print('Challenge 19')
    # ciphers = []
    # random_key = generate_random_key()
    # for line in open('data3_19.txt'):
    #     ciphers.append(aes_ctr(base64_to_bin(line), random_key))

    # max_cipher_length = max([len(cipher) for cipher in ciphers])
    # first_guess_keystream = b''
    # for cipher_idx in range(max_cipher_length):
    #     scores = []
    #     for candidate_byte in range(256):
    #         cipher_slice = [cipher[cipher_idx] for cipher in ciphers if cipher_idx < len(cipher)]
    #         scores.append( (english_score(b''.join([bytes([cipher_byte ^ candidate_byte]) for cipher_byte in cipher_slice])), candidate_byte))
    #     scores = sorted(scores, reverse=True)
    #     first_guess_keystream += bytes([scores[0][1]])
    # print("First guess for our keystream:", first_guess_keystream)
    # for cipher in ciphers:
    #     print(b''.join([bytes([a ^ b]) for a, b in zip(cipher, first_guess_keystream)]))

    # ok so it turns out my previous approach is just what they wanted for challenge 20... I guess I'll just turn it into a function?
    # this statistical analysis seems way easier once I already have the english score function written. Guessing and checking
    # is a waste of my time...
    # print('Challenge 20')
    # ciphers = []
    # ctr_key = b'YELLOW SUBMARINE'
    # for line in open('data3_20.txt'):
    #     ciphers.append(aes_ctr(base64_to_bin(line), ctr_key))
    # keystream = crack_aes_ctr_bad_nonce(ciphers)
    # print(keystream)
    # # Not quite right though... going to go through and fix the end of the text where there is little data for
    # # the statistical approach to be correct.
    # keystream = bytearray(keystream)
    # #keystream[0] += 32
    # #Worse than a nightmare, you don't have to sleep a wink / The pain's a migraine every time ya thi
    # # turn 96 from an i to an n, thiik should be think
    # keystream[96] ^= 105 ^ 110

    # # paid in fuyl
    # # ya think
    # # this should be paid in full
    # keystream[101] ^= ord('Y') ^ ord('l')

    # # me rest in peact
    # # paid in full
    # # peact should be peace
    # keystream[105] ^= ord('t') ^ ord('e')
    # # Looked up the lyrics on google, two lines of ciphertext is not enough
    # # information to find the plaintext by statistical analysis alone.
    # keystream[107] ^= ord('T') ^ ord('t')
    # keystream[108] ^= ord('e') ^ ord('h')
    # keystream[109] ^= ord(' ') ^ ord('e')
    # keystream[111] ^= ord('l') ^ ord('m')
    # keystream[112] ^= ord('E') ^ ord('o')
    # keystream[113] ^= ord('E') ^ ord('n')
    # keystream[114] ^= ord('E') ^ ord('e')
    # keystream[115] ^= ord('t') ^ ord('y')

    # keystream = bytes(keystream)
    # plaintexts = []
    # for cipher in ciphers:
    #     plaintexts.append(b''.join([bytes([a ^ b]) for a, b in zip(cipher, keystream)]))
    # print("Keystream:", keystream)
    # print("Plaintexts:")
    # for plaintext in plaintexts:
    #     print(plaintext)

    # print('Challenge 22')
    # min_time = 40
    # max_time = 1000
    # prng = wait_and_seed_twister(min_time, max_time)
    # time.sleep(random.randint(min_time, max_time))
    # print("here's the number:", prng())
    # '''
    # Generated number: 1897012445
    # time that we started waiting: 1592151524
    # '''
    # looking_for = 1897012445
    # for t in range(1592151524, (1592151524 + 3000)):
    #     prng = mersenne_twister_generator(t)
    #     if prng() == looking_for:
    #         print("seed we're looking for is", t)
    #         break
    # print(mersenne_twister_generator(1592152524)())

    # print('Challenge 23')
    # prng = mersenne_twister_generator(500)
    # cloned = clone_mt19937(prng)
    # for _ in range(5):
    #     print(prng())
    #     print(cloned())

    print('Challenge 24')
    print(mt19937_encrypt(mt19937_encrypt(b'yellow submarine is in the oceans', 15), 15))
    crack_mt19937_encryption()

    val = generate_bad_token()
    print(check_bad_mt(val, int(time.time())))
