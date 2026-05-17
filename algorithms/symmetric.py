"""
crypto/symmetric.py — AES-128/192/256 helpers (ECB · CBC · CTR).
Requires: pycryptodome  (pip install pycryptodome)
"""
import hashlib
import os
import time

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Random import get_random_bytes
    AVAILABLE = True
except ImportError:
    AVAILABLE = False


# ── Key derivation ─────────────────────────────────────────────────────────────

def derive_key(passphrase: str, bits: int) -> bytes:
    """Derive an AES key from a passphrase via SHA-256 truncation."""
    return hashlib.sha256(passphrase.encode()).digest()[: bits // 8]


# ── Encryption ─────────────────────────────────────────────────────────────────

def aes_encrypt(plaintext: bytes, key: bytes, mode_str: str) -> dict:
    """
    Encrypt plaintext with AES in the chosen mode.
    Returns a dict with all artefacts needed for decryption.
    """
    if not AVAILABLE:
        raise RuntimeError("pycryptodome not installed")

    mode_map = {"ECB": AES.MODE_ECB, "CBC": AES.MODE_CBC, "CTR": AES.MODE_CTR}
    mode = mode_map[mode_str]

    if mode_str == "ECB":
        ct = AES.new(key, mode).encrypt(pad(plaintext, 16))
        return {"mode": mode_str, "ciphertext": ct, "iv": None, "nonce": None}

    if mode_str == "CBC":
        iv = get_random_bytes(16)
        ct = AES.new(key, mode, iv).encrypt(pad(plaintext, 16))
        return {"mode": mode_str, "ciphertext": ct, "iv": iv, "nonce": None}

    # CTR
    nonce = get_random_bytes(8)
    ct = AES.new(key, mode, nonce=nonce).encrypt(plaintext)
    return {"mode": mode_str, "ciphertext": ct, "iv": None, "nonce": nonce}


def aes_decrypt(ctx: dict, key: bytes) -> bytes:
    """Decrypt using the artefact dict returned by aes_encrypt."""
    if not AVAILABLE:
        raise RuntimeError("pycryptodome not installed")

    mode_map = {"ECB": AES.MODE_ECB, "CBC": AES.MODE_CBC, "CTR": AES.MODE_CTR}
    mode = mode_map[ctx["mode"]]

    if ctx["mode"] == "ECB":
        return unpad(AES.new(key, mode).decrypt(ctx["ciphertext"]), 16)
    if ctx["mode"] == "CBC":
        return unpad(AES.new(key, mode, ctx["iv"]).decrypt(ctx["ciphertext"]), 16)
    return AES.new(key, mode, nonce=ctx["nonce"]).decrypt(ctx["ciphertext"])


# ── Benchmark ──────────────────────────────────────────────────────────────────

def benchmark_aes(mb: int = 1) -> list[tuple[str, float, float]]:
    """
    Encrypt `mb` MB with AES-128/192/256 in CBC.
    Returns [(label, speed_MBs, elapsed_ms), ...].
    """
    if not AVAILABLE:
        raise RuntimeError("pycryptodome not installed")

    data = os.urandom(mb * 1024 * 1024)
    results = []
    for bits in [128, 192, 256]:
        key = get_random_bytes(bits // 8)
        iv = get_random_bytes(16)
        t0 = time.perf_counter()
        AES.new(key, AES.MODE_CBC, iv).encrypt(pad(data, 16))
        t1 = time.perf_counter()
        elapsed = t1 - t0
        results.append((f"AES-{bits}-CBC", mb / elapsed, elapsed * 1000))
    return results
