'''This module contains functions necessary to complete
set1 of the challenges described by cryptopals. I used
asserts for my functions so that I can keep track of what
object each function acts upon (keeping strings and bytes
and byte encodings straight is hard).'''
import codecs
from itertools import cycle

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
    '''Takes two equal sized hex buffers and returns their XOR combination'''
    assert isinstance(buf1, (bytes, bytearray))
    assert isinstance(buf2, (bytes, bytearray))
    xor = b''
    for byte_x, byte_y in zip(buf1, buf2):
        xor += (bytes([byte_x ^ byte_y]))
    # returns a string
    return xor.hex()

def xor_single_char(buf1, char_given):
    '''Takes a hex buffer and returns its XOR with the char given'''
    assert isinstance(buf1, (bytes, bytearray))
    assert isinstance(char_given, int)
    xord_bytes = b''
    for byte1 in buf1:
        xord_bytes += (bytes([byte1 ^ char_given]))
    return xord_bytes, char_given


def find_xor_cipher_key(cipher):
    '''tries to find the single char cipher key'''
    for i in range(256):
        deciphered, _ = xor_single_char(bytes.fromhex(cipher), i)
        print(deciphered, i)

def encrypt_repeating_xor(plaintext, key):
    '''takes in plaintext and encrypts using the key provided.'''
    cipher_bytes = b''
    while len(key) < len(plaintext):
        key += key
    for byte1, byte2 in zip(str.encode(plaintext), str.encode(key)):
        cipher_bytes += bytes([byte1 ^ byte2])
    return cipher_bytes.hex()

if __name__ == '__main__':
    print('Challenge 1:')
    print(hex_to_base64(
        '49276d206b696c6c696e6720796f757220627261696e2'
        '06c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    ))

    print('Challenge 2')
    print(fixed_xor(codecs.decode('1c0111001f010100061a024b53535009181c', encoding='hex'),
                    codecs.decode('686974207468652062756c6c277320657965', encoding='hex')))

    print('Challenge 3')
    print(xor_single_char(
        bytes.fromhex('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'), 88
    ))

    print('Challenge 4')
    print(encrypt_repeating_xor("""Burning 'em, if you ain't quick and nimble
    print(encrypt_repeating_xor("I go crazy when I hear a cymbal""", 'ICE'))