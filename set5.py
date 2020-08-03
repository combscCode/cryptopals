"""My solutions to set 5 of the cryptopals challenge."""
import secrets
import random
import hashlib

default_p = int(
    'ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024'
    'e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd'
    '3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec'
    '6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f'
    '24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361'
    'c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552'
    'bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff'
    'fffffffffffff', 16)
def dh(p=default_p, g=2):
    """My implementation of the diffie-hellman algorithm."""
    a = random.randint(0, p - 1)
    A = pow(g, a, p)
    b = random.randint(0, p - 1)
    B = pow(g, b, p)
    s = pow(B, a, p)
    assert s == pow(A, b, p)
    m = hashlib.sha256()
    m.update(s.to_bytes((int.bit_length(s) + 7) // 8, byteorder="big"))
    return a, A, b, B, m.digest()

if __name__ == "__main__":
    print("Challenge 33")
    print(default_p)
    print(dh())

