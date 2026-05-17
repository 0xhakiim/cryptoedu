"""
crypto/asymmetric.py — RSA (pure Python) and ECDH (via cryptography lib).
Pure-Python RSA is intentionally small (educational); use pycryptodome for production.
"""
import random
import hashlib

# ── Pure-Python RSA ────────────────────────────────────────────────────────────

def _is_prime(n: int, k: int = 6) -> bool:
    if n < 2: return False
    if n == 2: return True
    if n % 2 == 0: return False
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2; r += 1
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1): continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1: break
        else:
            return False
    return True


def _gen_prime(bits: int) -> int:
    while True:
        n = random.getrandbits(bits) | (1 << bits - 1) | 1
        if _is_prime(n):
            return n


def rsa_generate(bits: int = 512) -> dict:
    """
    Generate an RSA key pair.
    Returns {"n", "e", "d", "p", "q", "bits"}.
    """
    p, q = _gen_prime(bits // 2), _gen_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = pow(e, -1, phi)
    return {"n": n, "e": e, "d": d, "p": p, "q": q, "bits": bits}


def rsa_encrypt(m: int, key: dict) -> int:
    """Textbook RSA encryption: C = M^e mod n."""
    return pow(m, key["e"], key["n"])


def rsa_decrypt(c: int, key: dict) -> int:
    """Textbook RSA decryption: M = C^d mod n."""
    return pow(c, key["d"], key["n"])


# ── ECDH (via cryptography) ────────────────────────────────────────────────────

try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    ECDH_AVAILABLE = True
except ImportError:
    ECDH_AVAILABLE = False


def ecdh_exchange() -> dict:
    """
    Simulate a full ECDH key exchange on P-256.
    Returns all public values + derived AES-256 session key.
    """
    if not ECDH_AVAILABLE:
        raise RuntimeError("cryptography library not installed")

    a_priv = ec.generate_private_key(ec.SECP256R1())
    b_priv = ec.generate_private_key(ec.SECP256R1())
    a_pub  = a_priv.public_key()
    b_pub  = b_priv.public_key()

    secret_a = a_priv.exchange(ec.ECDH(), b_pub)
    secret_b = b_priv.exchange(ec.ECDH(), a_pub)

    enc = serialization.Encoding.X962
    fmt = serialization.PublicFormat.UncompressedPoint

    return {
        "a_pub_bytes":  a_pub.public_bytes(enc, fmt),
        "b_pub_bytes":  b_pub.public_bytes(enc, fmt),
        "secret_a":     secret_a,
        "secret_b":     secret_b,
        "match":        secret_a == secret_b,
        "session_key":  hashlib.sha256(secret_a).digest(),
        # Keep private key objects for chat use
        "_a_priv": a_priv,
        "_b_priv": b_priv,
    }
