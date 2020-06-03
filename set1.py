'''This module contains functions necessary to complete
set1 of the challenges described by cryptopals. I used
asserts for my functions so that I can keep track of what
object each function acts upon (keeping strings and bytes
and byte encodings straight is hard).'''
import codecs
import base64
import operator
from Crypto.Cipher import AES

def bin_to_hex(bin_in):
    return bin_in.hex()

def hex_to_bin(hex_in):
    return bytes.fromhex(hex_in)

def base64_to_bin(base64_in):
    return base64.b64decode(base64_in)

def hex_to_base64(hex_in):
    '''Convert a hex-encoded string to base64-encoded string '''
    assert isinstance(hex_in, (str))
    # Note, codecs.decode goes from string to binary
    # codecs.encode takes binary and encodes that binary using
    # the encoding specified (but puts it in binary still????)
    # codecs.decode goes from a string to binary, assuming the string has
    # the encoding that was specified
    # bytes.decode() just goes from binary to an ASCII string
    return codecs.encode(bytes.fromhex(hex_in), 'base64').decode()

def fixed_xor(buf1, buf2):
    '''Takes two equal sized binary buffers and returns their XOR combination'''
    assert isinstance(buf1, (bytes, bytearray))
    assert isinstance(buf2, (bytes, bytearray))
    xor = b''
    for byte_x, byte_y in zip(buf1, buf2):
        xor += (bytes([byte_x ^ byte_y]))
    # returns a string
    return xor

def xor_single_char(buf1, char_given):
    '''Takes a binary buffer and returns its XOR with the char given'''
    assert isinstance(buf1, (bytes, bytearray))
    assert isinstance(char_given, int)
    xord_bytes = b''
    for byte1 in buf1:
        xord_bytes += (bytes([byte1 ^ char_given]))
    return xord_bytes, char_given

def english_score(input_bytes):
    '''scores the input_bytes based on how close it is to english'''
    character_frequencies = {
        'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253,
        'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094,
        'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025,
        'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
        'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
        'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
        'y': .01974, 'z': .00074, ' ': .13000
    }
    penalty = 1
    num_wrong_chars = 0
    byte_frequencies = {}
    for byte in input_bytes.lower():
        character = chr(byte)
        if character in character_frequencies.keys():
            byte_frequencies[character] = byte_frequencies.get(character, 0) + (1/len(input_bytes))
        else:
            num_wrong_chars += 1
    return sum([1 - (frequency - character_frequencies[character])**2 for
                character, frequency in byte_frequencies.items()]) - penalty * num_wrong_chars


def find_xor_cipher_key(cipher):
    '''tries to find the single char cipher key'''
    scores = []
    for i in range(256):
        deciphered, _ = xor_single_char(bytes.fromhex(cipher), i)
        score = english_score(deciphered)
        scores.append((score, deciphered, i))
    return sorted(scores, reverse=True)

def encrypt_repeating_xor(plaintext, key):
    '''takes in plaintext and encrypts using the key provided.'''
    cipher_bytes = b''
    while len(key) < len(plaintext):
        key += key
    for byte1, byte2 in zip(str.encode(plaintext), str.encode(key)):
        cipher_bytes += bytes([byte1 ^ byte2])
    return cipher_bytes.hex()

def hamming_distance(bin1, bin2):
    '''returns the hamming distance between two binary strings'''
    assert len(bin1) == len(bin2)
    distance = 0
    for byte1, byte2 in zip(bin1, bin2):
        byte1 = format(byte1, '08b')
        byte2 = format(byte2, '08b')
        distance += sum([bit1 != bit2 for bit1, bit2 in zip(byte1, byte2)])
    return distance

def find_keysize_distances(bin_blob, keysize_min=2, keysize_max=40):
    '''Returns a list of hamming distances for the possible keysizes given
    on a binary blob. This is used for cracking a Viginere cipher'''
    distances = []
    for keysize in range(keysize_min, keysize_max + 1):
        binary_chunks = [bin_blob[i:i+keysize] for i in range(0, len(bin_blob), keysize)]
        distance = []
        for i in range(len(binary_chunks) - 2):
            distance.append(hamming_distance(binary_chunks[i], binary_chunks[i+1])/keysize)
        distances.append((sum(distance)/len(distance), keysize))
    return sorted(distances)

def transpose_blocks(blocks):
    '''Takes in a list of binary blocks and returns a list of transposed blocks'''
    transposed_blocks = []
    for byte_index in range(len(blocks[0])):
        transposed_block = b''
        for block in blocks:
            if len(block) > byte_index:
                transposed_block += bytes([block[byte_index]])
        transposed_blocks.append(transposed_block)
    return transposed_blocks

def aes_ecb_decrypt(cipher_blob, aes_key):
    cipher = AES.new(aes_key, AES.MODE_ECB)
    return cipher.decrypt(cipher_blob)

def aes_ecb_detect(cipher_blob):
    '''Splits the cipher blob given into 16 byte chunks and counts the
    number of times each chunk occurs. For AES in ECB mode we'd expect
    to have a lot of the blobs be the same value since each 16 byte part
    of the plaintext is encrypted in the exact same way. Returns the maximum
    number of times some chunk was seen'''
    chunks = [cipher_blob[i:i+16] for i in range(0, len(cipher_blob), 16)]
    reps = len(chunks) - len(set(chunks))
    return reps

if __name__ == '__main__':
    print('Challenge 1:')
    print(hex_to_base64(
        '49276d206b696c6c696e6720796f757220627261696e2'
        '06c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    ))

    print('Challenge 2')
    print(fixed_xor(hex_to_bin('1c0111001f010100061a024b53535009181c'),
                    hex_to_bin('686974207468652062756c6c277320657965')))

    print('Challenge 3')
    print(find_xor_cipher_key(
        '1b37373331363f78151b7f2b783431'
        '333d78397828372d363c78373e783a393b3736')[0])

    print('Challenge 4')
    info = []
    for line in open('data1_4.txt'):
        score, deciphered_bytes, cipher_key = find_xor_cipher_key(line[:-1])[0]
        info.append((score, deciphered_bytes, cipher_key))
    print(sorted(info, reverse=True)[0])

    print('Challenge 5')
    print(encrypt_repeating_xor("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", 'ICE'))

    print('Challenge 6')
    bin_blob = b''
    for line in open('data1_6.txt'):
        bin_blob += base64_to_bin(line)
    distances = find_keysize_distances(bin_blob)
    # going to take the first 3 keysizes
    for d in range(3):
        _, keysize = distances[d]
        blocks = [bin_blob[i:i+keysize] for i in range(0, len(bin_blob), keysize)]
        transposed_blocks = transpose_blocks(blocks)
        cipher_key = ''
        for block in transposed_blocks:
            _, _, cipher_char = find_xor_cipher_key(bin_to_hex(block))[0]
            cipher_key += chr(cipher_char)
        print(cipher_key)
    # found the key, it's "Terminator X: Bring the noise"

    print('Challenge 7')
    aes_key = b'YELLOW SUBMARINE'
    encrypted_blob = b''
    for line in open('data1_7.txt'):
        encrypted_blob += base64_to_bin(line)
    print(aes_ecb_decrypt(encrypted_blob, aes_key))

    print('Challenge 8')
    vals = [ aes_ecb_detect(hex_to_bin(line[:-1])) for line in (open('data1_8.txt'))]
    max_val = 0
    max_i = -1
    for i, val in enumerate(vals):
        if val > max_val:
            max_val = val
            max_i = i
    print(max_val, max_i)
