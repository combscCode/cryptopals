'''set2 solutions for cryptopals'''
import secrets
import random
from Crypto.Cipher import AES
from set1 import bin_to_hex, hex_to_bin, hex_to_base64, base64_to_bin, encrypt_repeating_xor, aes_ecb_decrypt, fixed_xor

def pkcs7(input_bytes, block_length=16):
    '''pad the input bytes according to pkcs#7 to an
    even multiple of the block length given'''
    padding_to_add = block_length - len(input_bytes) % block_length
    return input_bytes + bytes([padding_to_add]) * padding_to_add

def blockify(cipher, blocksize=16):
    return [cipher[i:i+blocksize] for i in range(0, len(cipher), blocksize)]

def unpad(padded_bytes):
    for i in range(1, 17):
        if padded_bytes[-i:].count(bytes([i])) == i:
            return padded_bytes.strip(bytes([i]))
    return padded_bytes

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
GLOBAL_UNKNOWN_STRING = '''Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK'''

def vulnerable_oracle(plaintext_blob):
    '''This function is described here: https://cryptopals.com/sets/2/challenges/12'''
    plaintext_blob = plaintext_blob + base64_to_bin(GLOBAL_UNKNOWN_STRING)
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
        if cipher_block not in possible_dict:
            # We've hit the padding
            return known_secret
        unmasked_byte = bytes([possible_dict[cipher_block][-1]])
        known_secret += unmasked_byte
        last_known_bytes = last_known_bytes[1:] + unmasked_byte
    return known_secret

def decode_url_to_dict(to_parse):
    '''When given a string that contains key value pairs
    seperated by '&' and joined by '=' creates a dictionary
    containing those key value pairs'''
    pairs = {}
    list_of_pairs = to_parse.split('&')
    for pair in list_of_pairs:
        pair = pair.split('=')
        pairs[pair[0]] = pair[1]
    return pairs

def encode_dict_to_url(dict_in):
    protected_chars = ['=', '&']
    to_append = []
    for k, v in dict_in.items():
        for prot in protected_chars:
            k = str(k).replace(prot, '')
            v = str(v).replace(prot, '')
        to_append.append(k + '=' + v)
    return '&'.join(to_append)

def profile_for(email):
    profile = {}
    profile['email'] = email
    profile['uid'] = 10
    profile['role'] = 'user'
    return encode_dict_to_url(profile)

def profile_for_oracle(email):
    encoded = profile_for(email).encode('ascii')
    encoded = pkcs7(encoded)
    return aes_ecb_encrypt(encoded, GLOBAL_RANDOM_KEY)

def profile_decode_oracle(ciphertext):
    decrypted = unpad(aes_ecb_decrypt(ciphertext, GLOBAL_RANDOM_KEY))
    return decode_url_to_dict(decrypted.decode('ascii'))

def create_profile_ciphertext(blackbox, preferred_email='buo@umich.edu'):
    '''This function is used to break the profile_for function.
    blackbox is a function which takes in user input to profile_for()
    and returns the ciphertext encrypted under AES ECB.
    This function looks to abuse a decoding function that turns encrypted
    user profile strings into a user_profile object. The goal is to find a
    ciphertext that allows us to have admin permissions.'''
    # Because the 'role' aspect is on the back of the ciphertext
    # we just have to figure out what the blocksize of the cipher
    # is and what bytes are used to pad.
    # Step 1: Find the blocksize of the algorithm
    cipher = blackbox('A')
    num_bytes = 1
    last_cipher_length = len(cipher)
    while len(cipher) == last_cipher_length:
        last_cipher_length = len(cipher)
        num_bytes += 1
        cipher = blackbox('A' * num_bytes)
    blocksize = len(cipher) - last_cipher_length
    # We want to line up the last block such that it starts with
    # what the role is equal to. st the last block is user + padding.
    # we know by inserting num_bytes we get a new block of cipher text, so
    # we need to do num_bytes + 4 to get the offset we want.
    default_role = 'user'
    bad_email = preferred_email
    if len(bad_email) > num_bytes + len(default_role):
        bad_email = bad_email[:num_bytes + len(default_role)]
    if len(bad_email) < num_bytes + len(default_role):
        bad_email += 'i' * (num_bytes + len(default_role) - len(bad_email))
    # put adminpadding into block 2 (offset in the beginning to get around email=)
    cipher = blackbox(bad_email)
    cipher_blocks = [cipher[i:i+blocksize] for i in range(0, len(cipher), blocksize)]
    payload = b'\x10' * (blocksize - 6) + b'admin' + b'\x0b' * (blocksize - 5)
    new_cipher = blackbox(payload.decode('ascii'))
    # replace the last block of the ciphertext with our admin padding block
    cipher_blocks[-1] = new_cipher[blocksize:blocksize*2]
    cipher = b''.join(cipher_blocks)
    return cipher

def harder_vulnerable_oracle(plaintext_blob):
    '''This function is described here: https://cryptopals.com/sets/2/challenges/14
    OK after looking at another solution I think I misunderstood the problem... Oh
    well my problem was harder soooooo whatever'''
    random_prefix = secrets.token_bytes(random.randint(0, 17))
    return vulnerable_oracle(random_prefix + plaintext_blob)

def crack_harder_vulnerable_oracle(blackbox):
    '''Please note, I misunderstood the question and broke a HARDER problem than challenge 14.
    Instead of using a constant random prefix, the random prefix is calculated everytime the
    oracle is called. This makes cracking the secret significantly harder and requires more
    time'''
    # Step 1, find the blocksize of the algorithm
    # Since the number of random bytes has no bound this algorithm is
    # not guaranteed to get the correct blocksize. Getting 1000 random
    # samples makes it pretty likely for any reasonable expected number
    # of random bytes
    cipher_lengths = set()
    for _ in range(1000):
        cipher = blackbox(b'')
        cipher_lengths.add(len(cipher))
    cipher_lengths = sorted(list(cipher_lengths))
    cipher_differences = [cipher_lengths[i+1] - cipher_lengths[i] for i in range(len(cipher_lengths) - 1)]
    if len(cipher_lengths) == 1:
        blocksize = 16
    else:
        blocksize = min(cipher_differences)

    # Step 2, find the start of the secret. We do this by making our message
    # just the same byte over and over for enough blocks to differentiate between
    # it and the secret.
    
    check_message = b''
    cipher = blackbox(check_message)
    cipher_blocks = [cipher[i:i + blocksize] for i in range(0, len(cipher), blocksize)]
    # Find the number of repeat blocks in the cipher text. This is the maximum
    # possible amount that can be in the secret message we're looking to get.
    # Example, if there are 2 blocks that have the same val we want num_identifying_repeat_blocks
    # to be 3. 
    num_repeat_blocks_needed = len(cipher_blocks) - len(set(cipher_blocks)) + 2
    known_chars = b'i' * (blocksize - 1)
    secret = b''
    secret_idx = 0
    # Since we don't know the length of the secret we must stay in this
    # loop until we can tell that we've hit the padding
    while True:
        print(secret)
        # Construct dict of possible values that we can extract
        possible_dict = {}
        for possible_byte in range(256):
            payload = known_chars + bytes([possible_byte])
            # Now we need to put the repeating blocks into the payload.
            # This should be structured st when there are num_repeat_blocks_needed
            # repeating blocks in the cipher, we KNOW that the payload fits in a block
            repeat_byte = 0 if possible_byte != 0 else 1
            payload += bytes([repeat_byte]) * blocksize * num_repeat_blocks_needed + bytes([repeat_byte + 1])
            # Now we need to give this payload to the blackbox until we get the block alignment we want
            got_a_hit = False
            while not got_a_hit:
                cipher = blackbox(payload)
                cipher_blocks = [cipher[i:i+blocksize] for i in range(0, len(cipher), blocksize)]
                # Check to see if the number of repeating blocks is what we want
                for block_idx in reversed(range(len(cipher_blocks) - num_repeat_blocks_needed)):
                    # If we find the number of repeating blocks that we need
                    if len(set(cipher_blocks[block_idx:block_idx + num_repeat_blocks_needed])) == 1:
                        payload_idx = block_idx - 1
                        possible_dict[cipher_blocks[payload_idx]] = bytes([possible_byte])
                        got_a_hit = True
                        break
        # We now have constructed a dict of possible values that we can extract
        # Need to actually see what the secret char is now...
        # We're going to ping the blackbox with our attack message until we get the
        # number of repeating blocks in the cipher ST the payload fits in a block
        num_of_known_char_bytes_to_include = (blocksize - secret_idx - 1) % blocksize
        chars_to_include = known_chars[:num_of_known_char_bytes_to_include]

        repeat_byte = 0 if known_chars[0] != 0 else 1
        attack_message = bytes([repeat_byte + 1]) * blocksize + bytes([repeat_byte]) * blocksize * num_repeat_blocks_needed + chars_to_include
        got_a_hit = False
        while not got_a_hit:
            cipher = blackbox(attack_message)
            cipher_blocks = [cipher[i:i+blocksize] for i in range(0, len(cipher), blocksize)]
            # Check to see if the number of repeating blocks is what we want
            for block_idx in reversed(range(len(cipher_blocks) - num_repeat_blocks_needed)):
                # If we find the number of repeating blocks that we need
                if len(set(cipher_blocks[block_idx:block_idx + num_repeat_blocks_needed])) == 1:
                    # We know that the known_chars block is at the end of the repeating blocks
                    payload_block_idx = block_idx + num_repeat_blocks_needed + (secret_idx // blocksize)
                    payload_block = cipher_blocks[payload_block_idx]
                    if payload_block not in possible_dict:
                        # This can happen when we've hit the padding. Since the padding values will change
                        # the payload block will not be in the possible_dict and so we can return our secret.
                        return secret[:-1]
                    secret_byte = possible_dict[payload_block]
                    got_a_hit = True
                    secret_idx += 1
                    secret += secret_byte
                    known_chars = known_chars[1:] + secret_byte
                    # We know that the secret has been completely extracted if we're at the end of the cipher
                    if block_idx + num_repeat_blocks_needed + (secret_idx // blocksize) == len(cipher_blocks):
                        secret_extracted = True
                    break
    return secret

def validate_pkcs7(string_to_validate, blocksize=16):
    '''This function throws an exception if
    the string does not have valid padding'''
    blocks = [string_to_validate[i:i + blocksize] for i in range(0, len(string_to_validate), blocksize)]
    invalid = True
    for i in range(1, blocksize + 1):
        #print(blocks[-1][-i:])
        if blocks[-1][-i:] == (bytes([i]) * i):
            invalid = False
    if invalid:
        print(string_to_validate)
        raise ValueError()

challenge_16_aes_key = generate_random_key()
def challenge_16_encrypt(string_in):
    to_return = 'comment1=cooking%20MCs;userdata=' + string_in.replace('=', '%3d').replace(';', '%3b') + ';comment2=%20like%20a%20pound%20of%20bacon'
    to_return = str.encode(to_return)
    
    return aes_cbc_encrypt(to_return, challenge_16_aes_key)

def challenge_16_detect_admin(cipher):
    decrypted = aes_cbc_decrypt(cipher, challenge_16_aes_key)
    return decrypted.count(b";admin=true") > 0

def cbc_bitflip_attack():
    '''
    In this function we use the bitflip property of CBC encryption to construct a message
    in the plaintext by editing the ciphertext we are given from the encryption function.
    userdata= happens to fall on a blockbreak. If we give the encrypt function the string
    'true', we now have the plaintext decrypt to something + ;userdata=true + something_else.
    Since we know what the plaintext decrypts to and we know what we want it to decrypt to,
    we can use the bitflipping attack by fiddling with the block prior to ;userdata= in order
    to turn it into ;admin=.
    Anything that we want to edit in one block means the block prior must be turned to gibberish.
    This technique means we cannot have 2 contiguous blocks that we edit meaningfully (although
    we could have 2 seperate blocks that we edit as long as they are not next to each other)
    This technique also requires us to know the exact string that is being encrypted. If we did not know
    we could theoretically try all bitflip possibilities until we got the decrypted value we wanted, but this
    would grow O(2^n) where n is the bitlength of the message we want to construct in the plaintext.

    I could also construct the message entirely in the string_in parameter, that'd probably be better
    in the future since my current attack relies on knowing where the block boundaries lie. I can
    better control this by giving the encryption function my own string of any length.
    '''
    cipher = challenge_16_encrypt('true')
    cipher = bytearray(cipher)
    starting = bytearray('erdata'.encode('ascii'))
    looking_to_build = bytearray(';admin'.encode('ascii'))
    idx = 9
    for a, b in zip(starting, looking_to_build):
        cipher[idx] = cipher[idx] ^ (a ^ b)
        idx += 1
    return cipher

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

    print('Challenge 13')
    cipher = create_profile_ciphertext(profile_for_oracle)
    print( profile_decode_oracle(cipher) )

    print('Challenge 14')
    possible = crack_harder_vulnerable_oracle(harder_vulnerable_oracle)
    print(possible)

    print('Challenge 16')
    print(challenge_16_detect_admin(cbc_bitflip_attack()))
