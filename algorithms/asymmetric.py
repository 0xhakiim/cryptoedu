"""
crypto/asymmetric.py — Implémentations avancées pour le TP 3.
DH (avec MITM & ECDSA), RSA (Hybride & Benchmark), ElGamal (Malléabilité), ECC (Pédagogique & ECIES).
"""

import random
import hashlib
import time
import os

try:
    from cryptography.hazmat.primitives.asymmetric import (
        rsa,
        padding as asym_padding,
        ec,
    )
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

# ── Outils Mathématiques Génériques (Miller-Rabin & Inversion) ─────────────────


def _is_prime(n: int, k: int = 6) -> bool:
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_prime(bits: int) -> int:
    while True:
        n = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if _is_prime(n):
            return n


# ── EXERCICE 3.1 : Diffie-Hellman (DH) & MITM ──────────────────────────────────


def run_dh_standard(bits: int = 512):
    """Génère p, g et effectue un échange standard entre Alice et Bob."""
    p = _gen_prime(bits)
    g = 2  # Générateur standard pratique

    # Secrets privés
    a = random.getrandbits(bits - 2)
    b = random.getrandbits(bits - 2)

    # Clés publiques
    A = pow(g, a, p)
    B = pow(g, b, p)

    # Clés partagées
    K_A = pow(B, a, p)
    K_B = pow(A, b, p)

    return {"p": p, "g": g, "a": a, "b": b, "A": A, "B": B, "KA": K_A, "KB": K_B}


def run_dh_mitm(bits: int = 512):
    """Simule l'attaque Man-in-the-Middle sur Diffie-Hellman."""
    p = _gen_prime(bits)
    g = 2

    # Secrets privés
    a = random.getrandbits(bits - 2)
    b = random.getrandbits(bits - 2)
    e = random.getrandbits(bits - 2)  # Ève l'attaquante

    # Clés publiques légitimes
    A = pow(g, a, p)
    B = pow(g, b, p)

    # Clés publiques injectées par Ève
    A_prime = pow(g, e, p)  # Ève envoie A' à Bob en se faisant passer pour Alice
    B_prime = pow(g, e, p)  # Ève envoie B' à Alice en se faisant passer pour Bob

    # Calcul des clés de session interceptées
    K_Alice_Eve = pow(B_prime, a, p)
    K_Eve_Alice = pow(A, e, p)

    K_Bob_Eve = pow(A_prime, b, p)
    K_Eve_Bob = pow(B, e, p)

    return {
        "p": p,
        "g": g,
        "A": A,
        "B": B,
        "A_prime": A_prime,
        "B_prime": B_prime,
        "K_Alice": K_Alice_Eve,
        "K_Eve_A": K_Eve_Alice,
        "K_Bob": K_Bob_Eve,
        "K_Eve_B": K_Eve_Bob,
    }


# ── EXERCICE 3.2 : RSA & Chiffrement Hybride ───────────────────────────────────


def run_rsa_demo(bits: int):
    """Génère, chiffre (32 octets), déchiffre et exporte via cryptography."""
    if not CRYPTOGRAPHY_AVAILABLE:
        return None

    # 1. Génération
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    public_key = private_key.public_key()

    # Export des clés au format PEM (chaînes de caractères)
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    # 2. Chiffrement (32 octets)
    msg = b"MessageSecretDe32OctetsExacts!!!"
    padding_oaep = asym_padding.OAEP(
        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )
    ciphertext = public_key.encrypt(msg, padding_oaep)

    # 3. Déchiffrement
    decrypted = private_key.decrypt(ciphertext, padding_oaep)

    return {
        "priv": priv_pem,
        "pub": pub_pem,
        "ct_len": len(ciphertext),
        "decrypted": decrypted,
    }


def run_hybrid_benchmark():
    """Chiffrement hybride RSA-2048 + AES-256 sur 1 Mo de données."""
    if not CRYPTOGRAPHY_AVAILABLE:
        return None

    # Préparation données 1 Mo
    data = os.urandom(1024 * 1024)
    aes_key = os.urandom(32)
    iv = os.urandom(16)

    # Génération clé RSA
    priv_rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_rsa = priv_rsa.public_key()

    # --- Chronométrage RSA (Clé AES uniquement) ---
    t0_rsa = time.perf_counter()
    enc_key = pub_rsa.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    t1_rsa = time.perf_counter()
    t_rsa = (t1_rsa - t0_rsa) * 1000

    # --- Chronométrage AES (1 Mo entier) ---
    from cryptography.hazmat.primitives.padding import PKCS7

    padder = PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    t0_aes = time.perf_counter()
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct_aes = encryptor.update(padded_data) + encryptor.finalize()
    t1_aes = time.perf_counter()
    t_aes = (t1_aes - t0_aes) * 1000

    return {
        "t_rsa": t_rsa,
        "t_aes": t_aes,
        "key_len": len(enc_key),
        "ct_aes_len": len(ct_aes),
    }


# ── EXERCICE 3.3 : Chiffrement ElGamal ─────────────────────────────────────────


def elgamal_keygen(bits: int = 512):
    p = _gen_prime(bits)
    g = 2
    x = random.randint(2, p - 2)  # Clé privée
    y = pow(g, x, p)  # Clé publique
    return {"p": p, "g": g, "x": x, "y": y}


def elgamal_encrypt(m: int, pub_key: dict) -> tuple[int, int]:
    p, g, y = pub_key["p"], pub_key["g"], pub_key["y"]
    k = random.randint(2, p - 2)  # Aléa éphémère
    c1 = pow(g, k, p)
    c2 = (m * pow(y, k, p)) % p
    return c1, c2


def elgamal_decrypt(c: tuple[int, int], priv_key: dict, pub_key: dict) -> int:
    c1, c2 = c
    p = pub_key["p"]
    x = priv_key["x"]
    s = pow(c1, x, p)
    s_inv = pow(s, -1, p)
    return (c2 * s_inv) % p


def forge_elgamal_multiply_by_2(c: tuple[int, int], pub_key: dict) -> tuple[int, int]:
    """Forgerie sans connaître la clé privée ni M pour obtenir E(2M)."""
    c1, c2 = c
    p = pub_key["p"]
    # Nouvelle enveloppe chiffrée malléable : (c1, 2 * c2 mod p)
    return c1, (2 * c2) % p


# ── EXERCICE 3.4 : Cryptographie sur Courbes Elliptiques ───────────────────────


class ShortWeierstrassPendant:
    """Courbe pédagogique y² = x³ + 7 mod 97."""

    def __init__(self):
        self.a = 0
        self.b = 7
        self.p = 97

    def is_on_curve(self, P):
        if P is None:
            return True
        x, y = P
        return (y**2 - (x**3 + self.a * x + self.b)) % self.p == 0

    def add(self, P, Q):
        if P is None:
            return Q
        if Q is None:
            return P
        x1, y1 = P
        x2, y2 = Q

        if x1 == x2 and (y1 + y2) % self.p == 0:
            return None  # Point à l'infini

        if x1 != x2:
            num = (y2 - y1) % self.p
            den = pow((x2 - x1) % self.p, -1, self.p)
            lam = (num * den) % self.p
        else:  # Tangente P == Q
            num = (3 * x1**2 + self.a) % self.p
            den = pow((2 * y1) % self.p, -1, self.p)
            lam = (num * den) % self.p

        x3 = (lam**2 - x1 - x2) % self.p
        y3 = (lam * (x1 - x3) - y1) % self.p
        return (x3, y3)

    def multiply(self, k, P):
        """Multiplication scalaire (Double-and-Add)."""
        R = None
        if P is None:
            return None
        k = k % self.p  # Ordre cyclique approximé pour l'exercice
        for bit in bin(k)[2:]:
            R = self.add(R, R)
            if bit == "1":
                R = self.add(R, P)
        return R


def run_ecdh_p256_standard():
    """ECDH Standard via l'API cryptography conforme à l'exercice 3.4.2."""
    if not CRYPTOGRAPHY_AVAILABLE:
        return None

    # Paires de clés
    a_priv = ec.generate_private_key(ec.SECP256R1())
    b_priv = ec.generate_private_key(ec.SECP256R1())

    # Secret partagé
    secret_a = a_priv.exchange(ec.ECDH(), b_priv.public_key())
    secret_b = b_priv.exchange(ec.ECDH(), a_priv.public_key())

    # Dérivation AES-256 via SHA256
    aes_key = hashlib.sha256(secret_a).digest()
    return {"secret": secret_a, "aes_key": aes_key, "match": secret_a == secret_b}


def run_ecies_simplified(msg: bytes):
    """Implémentation ECIES simplifiée (Chiffrement hybride ECDH+AES)."""
    if not CRYPTOGRAPHY_AVAILABLE:
        return None

    # 1. Clés à long terme du destinataire (Bob)
    bob_priv = ec.generate_private_key(ec.SECP256R1())
    bob_pub = bob_priv.public_key()

    # 2. CHIFFREMENT (Par Alice utilisant bob_pub)
    alice_ephemeral_priv = ec.generate_private_key(ec.SECP256R1())
    alice_ephemeral_pub = alice_ephemeral_priv.public_key()

    # Secret partagé ECDH éphémère
    shared_secret_enc = alice_ephemeral_priv.exchange(ec.ECDH(), bob_pub)
    aes_key = hashlib.sha256(shared_secret_enc).digest()

    # Chiffrement AES-CBC du message
    iv = os.urandom(16)
    from cryptography.hazmat.primitives.padding import PKCS7

    padder = PKCS7(128).padder()
    padded_msg = padder.update(msg) + padder.finalize()

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_msg) + encryptor.finalize()

    # Alice transmet sa clé éphémère publique, l'IV et le cryptogramme
    ephemeral_pub_bytes = alice_ephemeral_pub.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )

    # 3. DÉCHIFFREMENT (Par Bob utilisant sa clé privée)
    alice_pub_obj = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), ephemeral_pub_bytes
    )
    shared_secret_dec = bob_priv.exchange(ec.ECDH(), alice_pub_obj)
    aes_key_dec = hashlib.sha256(shared_secret_dec).digest()

    cipher_dec = Cipher(algorithms.AES(aes_key_dec), modes.CBC(iv))
    decryptor = cipher_dec.decryptor()
    padded_pt = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_pt) + unpadder.finalize()

    return {
        "ephemeral_key": ephemeral_pub_bytes.hex()[:40],
        "ciphertext": ciphertext.hex()[:40],
        "plaintext": plaintext.decode(),
    }
