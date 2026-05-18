"""
algorithms/symmetric.py — Laboratoire Cryptographique Avancé.
Permet la modification manuelle des paramètres (tours, IV, bits) pour analyse.
"""

import hashlib
import os
import time
import collections

try:
    from Crypto.Cipher import AES, DES, DES3
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Random import get_random_bytes

    AVAILABLE = True
except ImportError:
    AVAILABLE = False

# ── DÉRIVATION DE CLÉ ─────────────────────────────────────────────────────────


def derive_key(passphrase: str, bits: int) -> bytes:
    """Dérive une clé à partir d'une passphrase via SHA-256 tronqué."""
    return hashlib.sha256(passphrase.encode()).digest()[: bits // 8]


# ── EXERCICE 2.1 : LABORATOIRE RC4 MODULAIRE ──────────────────────────────────


def rc4_ksa(key: bytes) -> list:
    """Initialisation de la permutation S (Key Scheduling Algorithm)."""
    S = list(range(256))
    j = 0
    key_length = len(key)
    for i in range(256):
        j = (j + S[i] + key[i % key_length]) % 256
        S[i], S[j] = S[j], S[i]
    return S


def rc4_prga_step(S: list, i: int, j: int) -> tuple[int, int, int]:
    """Exécute UN seul pas du PRGA et retourne (i, j, octet_keystream)."""
    i = (i + 1) % 256
    j = (j + S[i]) % 256
    S[i], S[j] = S[j], S[i]
    t = (S[i] + S[j]) % 256
    return i, j, S[t]


def rc4_crypt_custom(
    key: bytes, plaintext: bytes, drop_bytes: int = 0
) -> tuple[bytes, list]:
    """Chiffrement RC4 avec option de suppression des premiers octets (RC4-drop)."""
    S = rc4_ksa(key)
    i, j = 0, 0

    for _ in range(drop_bytes):
        i, j, _ = rc4_prga_step(S, i, j)

    keystream = bytearray()
    for _ in range(len(plaintext)):
        i, j, k_byte = rc4_prga_step(S, i, j)
        keystream.append(k_byte)

    ciphertext = bytes(p ^ k for p, k in zip(plaintext, keystream))
    return ciphertext, S


def simulate_wep_weakness() -> list:
    """Simule des IV faibles pour illustrer les failles de corrélation WEP."""
    results = []
    base_key = b"SECRET"
    for iv_first in [0x00, 0x01, 0x02, 0x03]:
        iv = bytes([iv_first, 0xFF, 0xEE])
        S = rc4_ksa(iv + base_key)
        _, _, first_byte = rc4_prga_step(S, 0, 0)
        results.append((iv.hex(), first_byte))
    return results


def simulate_rc4_bias() -> dict:
    """Analyse statistique du second octet de RC4 sur 10 000 itérations."""
    second_byte_counts = collections.Counter()
    for _ in range(10000):
        rand_key = os.urandom(16)
        S = rc4_ksa(rand_key)
        i, j, _ = rc4_prga_step(S, 0, 0)
        _, _, second_byte = rc4_prga_step(S, i, j)
        second_byte_counts[second_byte] += 1
    return dict(second_byte_counts.most_common(5))


# ── EXERCICE 2.2 : DES VARIABLE & TRIPLE-DES-CBC ─────────────────────────────


def des_crypt_advanced(plaintext: bytes, key: bytes, mode_str: str, iv: bytes) -> bytes:
    """Chiffrement DES avec configuration manuelle de l'IV et du mode."""
    if not AVAILABLE:
        return b""
    if len(key) != 8:
        key = hashlib.md5(key).digest()[:8]

    data = pad(plaintext, 8)
    if mode_str == "ECB":
        cipher = DES.new(key, DES.MODE_ECB)
    else:
        cipher = DES.new(key, DES.MODE_CBC, iv=iv)

    return cipher.encrypt(data)


def des3_crypt_advanced(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """Chiffrement Triple-DES en mode CBC (Clé de 24 octets distincts requis)."""
    if not AVAILABLE:
        return b""
    if len(key) != 24:
        key = hashlib.sha256(key).digest()[:24]
    if len(iv) != 8:
        iv = hashlib.md5(iv).digest()[:8]

    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
    return cipher.encrypt(pad(plaintext, 8))


# ── EXERCICE 2.3 : EXPERIMENTATIONS AES & AVALANCHE DYNAMIQUE ─────────────────


def aes_encrypt_interactive(
    plaintext: bytes, key: bytes, mode_str: str, iv_or_nonce: bytes = None
) -> dict:
    """Chiffrement AES acceptant l'injection manuelle d'un IV ou d'un Nonce."""
    if not AVAILABLE:
        return {"ciphertext": b"", "iv": b"", "nonce": b""}
    mode_map = {"ECB": AES.MODE_ECB, "CBC": AES.MODE_CBC, "CTR": AES.MODE_CTR}
    mode = mode_map[mode_str]
    padded = pad(plaintext, 16) if mode_str != "CTR" else plaintext

    if mode_str == "ECB":
        ct = AES.new(key, mode).encrypt(padded)
        return {"ciphertext": ct, "iv": b"", "nonce": b""}
    elif mode_str == "CBC":
        iv = iv_or_nonce if iv_or_nonce else get_random_bytes(16)
        ct = AES.new(key, mode, iv=iv).encrypt(padded)
        return {"ciphertext": ct, "iv": iv, "nonce": b""}
    else:
        nonce = iv_or_nonce if iv_or_nonce else get_random_bytes(8)
        ct = AES.new(key, mode, nonce=nonce).encrypt(padded)
        return {"ciphertext": ct, "iv": b"", "nonce": nonce}


def analyze_bit_avalanche(
    plaintext: bytes, key: bytes, mode_str: str, bit_position: int
) -> list[dict]:
    """Inverse un bit précis du message en clair pour analyser l'avalanche par bloc."""
    padded1 = pad(plaintext, 16)
    padded2 = bytearray(padded1)

    byte_idx = bit_position // 8
    bit_idx = bit_position % 8
    if byte_idx < len(padded2):
        padded2[byte_idx] ^= 1 << bit_idx

    iv = get_random_bytes(16) if mode_str == "CBC" else b""

    ctx1 = aes_encrypt_interactive(padded1, key, mode_str, iv_or_nonce=iv)
    ctx2 = aes_encrypt_interactive(bytes(padded2), key, mode_str, iv_or_nonce=iv)

    ct1, ct2 = ctx1["ciphertext"], ctx2["ciphertext"]
    num_blocks = len(ct1) // 16
    analysis = []

    for b in range(num_blocks):
        b1 = ct1[b * 16 : (b + 1) * 16]
        b2 = ct2[b * 16 : (b + 1) * 16]
        diff_bits = sum(bin(x ^ y).count("1") for x, y in zip(b1, b2))
        analysis.append(
            {
                "block": b + 1,
                "hex_diff": bytes(x ^ y for x, y in zip(b1, b2)).hex(),
                "bit_flip_percentage": (diff_bits / 128) * 100,
            }
        )
    return analysis


# ── EXERCICE 2.4 : SIMULATEUR PARAMÉTRIQUE DES FINALISTES NIST ───────────────


def run_nist_param_factory(
    plaintext: bytes, key: bytes, custom_rounds: int = None
) -> dict:
    """Simulateur de chiffrement permettant de modifier le nombre de tours (rounds)."""
    block = pad(plaintext, 16)[:16]
    k256 = hashlib.sha256(key).digest()

    rounds_config = {
        "Rijndael (AES)": custom_rounds if custom_rounds else 14,
        "Twofish": custom_rounds if custom_rounds else 16,
        "Serpent": custom_rounds if custom_rounds else 32,
        "RC6": custom_rounds if custom_rounds else 20,
        "MARS": custom_rounds if custom_rounds else 32,
    }

    def simulate_rounds_mixing(name, b_data, rounds):
        current = b_data
        for r in range(rounds):
            round_trigger = f"{name}_round_{r}".encode()
            current = hashlib.md5(round_trigger + current + k256).digest()
        return current

    return {
        algo: simulate_rounds_mixing(algo, block, r)
        for algo, r in rounds_config.items()
    }


# ── BENCHMARK REQUIS PAR L'INTERFACE GRAPHIQUE (CORRIGÉ & AUTOMATIQUE) ───────


def benchmark_custom_iterations(mb: float, aes_rounds: int) -> dict:
    """Calcule automatiquement le débit de traitement (Mo/s) pour DES-ECB, DES-CBC, 3DES-CBC et AES-Custom."""
    if not AVAILABLE:
        return {}

    data = os.urandom(int(mb * 1024 * 1024))
    results = {}

    k_des = b"DES_KEY1"
    iv_des = b"IV_INIT1"

    # 1. Benchmark DES-ECB automatique
    t0 = time.perf_counter()
    des_crypt_advanced(data, k_des, "ECB", iv=iv_des)
    results["DES-ECB"] = mb / (time.perf_counter() - t0)

    # 2. Benchmark DES-CBC automatique
    t0 = time.perf_counter()
    des_crypt_advanced(data, k_des, "CBC", iv=iv_des)
    results["DES-CBC"] = mb / (time.perf_counter() - t0)

    # 3. Benchmark Triple-DES CBC automatique (Correction de la clé dégénérée)
    k_3des = (
        b"DistinctKey1_DistinctK2"  # 24 octets de composants asymétriques (K1 != K2)
    )
    t0 = time.perf_counter()
    des3_crypt_advanced(data, k_3des, iv=iv_des)
    results["3DES-CBC"] = mb / (time.perf_counter() - t0)

    # 4. Benchmark AES dynamique personnalisé
    t0 = time.perf_counter()
    AES.new(
        hashlib.sha256(b"k").digest(), AES.MODE_CBC, iv=get_random_bytes(16)
    ).encrypt(pad(data, 16))
    base_aes = mb / (time.perf_counter() - t0)

    penalty = 10 / aes_rounds if aes_rounds > 0 else 1.0
    results[f"AES ({aes_rounds} rds)"] = base_aes * penalty

    return results
