"""
crypto/classical.py — Pure-Python implementations of classical ciphers.
No third-party dependencies. Covered algorithms: César, Vigenère.
"""

import math

# ── César ──────────────────────────────────────────────────────────────────────


def caesar_encrypt(text: str, k: int) -> str:
    """Shift each alpha character by k positions (mod 26)."""
    return "".join(
        chr((ord(c) - 65 + k) % 26 + 65) if c.isalpha() else c for c in text.upper()
    )


def caesar_decrypt(text: str, k: int) -> str:
    return caesar_encrypt(text, -k)


def caesar_brute_force(ciphertext: str) -> list[tuple[int, str]]:
    """Return all 26 candidate plaintexts as (key, plaintext) pairs."""
    return [(k, caesar_decrypt(ciphertext, k)) for k in range(26)]


def frequency_index(text: str) -> float:
    """Compute the Index of Coincidence. French IC ≈ 0.074."""
    letters = [c for c in text.upper() if c.isalpha()]
    n = len(letters)
    if n < 2:
        return 0.0
    from collections import Counter

    counts = Counter(letters)
    return sum(f * (f - 1) for f in counts.values()) / (n * (n - 1))


# ── Vigenère ───────────────────────────────────────────────────────────────────


def vigenere_encrypt(text: str, key: str) -> str:
    text, key = text.upper(), key.upper()
    out, ki = [], 0
    for c in text:
        if c.isalpha():
            shift = ord(key[ki % len(key)]) - 65
            out.append(chr((ord(c) - 65 + shift) % 26 + 65))
            ki += 1
        else:
            out.append(c)
    return "".join(out)


def vigenere_decrypt(text: str, key: str) -> str:
    text, key = text.upper(), key.upper()
    out, ki = [], 0
    for c in text:
        if c.isalpha():
            shift = ord(key[ki % len(key)]) - 65
            out.append(chr((ord(c) - 65 - shift) % 26 + 65))
            ki += 1
        else:
            out.append(c)
    return "".join(out)


def kasiski_test(ciphertext: str, ngram: int = 3) -> dict:
    """
    Find repeated n-grams and their distances.
    Returns {ngram: [distance, ...]} for repetitions found.
    """
    ct = "".join(c for c in ciphertext.upper() if c.isalpha())
    found: dict[str, list[int]] = {}
    for i in range(len(ct) - ngram):
        gram = ct[i : i + ngram]
        for j in range(i + ngram, len(ct) - ngram + 1):
            if ct[j : j + ngram] == gram:
                found.setdefault(gram, []).append(j - i)
    return found


def probable_key_length(kasiski_result: dict) -> int:
    """GCD of all distances — most likely key length."""
    from math import gcd
    from functools import reduce

    distances = [d for dists in kasiski_result.values() for d in dists]
    if not distances:
        return 0
    return reduce(gcd, distances)


# ─── ONE-TIME PAD (OTP) ───────────────────────────────────────────────────────


def otp_encrypt(plain_text: str, key: str) -> str:
    """Encrypts text using One-Time Pad (XOR method for uppercase ASCII)."""
    pt = "".join(c.upper() for c in plain_text if c.isalpha())
    k = "".join(c.upper() for c in key if c.isalpha())

    if len(k) < len(pt):
        raise ValueError("La clé doit être au moins aussi longue que le message.")

    ct = []
    for p_char, k_char in zip(pt, k):
        # Shift-based OTP: (P + K) mod 26
        p_val = ord(p_char) - ord("A")
        k_val = ord(k_char) - ord("A")
        c_val = (p_val + k_val) % 26
        ct.append(chr(c_val + ord("A")))
    return "".join(ct)


def otp_decrypt(cipher_text: str, key: str) -> str:
    """Decrypts text encrypted via One-Time Pad."""
    ct = "".join(c.upper() for c in cipher_text if c.isalpha())
    k = "".join(c.upper() for c in key if c.isalpha())

    if len(k) < len(ct):
        raise ValueError("La clé doit être au moins aussi longue que le texte chiffré.")

    pt = []
    for c_char, k_char in zip(ct, k):
        c_val = ord(c_char) - ord("A")
        k_val = ord(k_char) - ord("A")
        p_val = (c_val - k_val) % 26
        pt.append(chr(p_val + ord("A")))
    return "".join(pt)


# ─── HILL CIPHER (2x2) ────────────────────────────────────────────────────────


def hill_encrypt(plain_text: str, matrix: list) -> str:
    """Encrypts text using a 2x2 Hill Cipher matrix [[a, b], [c, d]]."""
    pt = "".join(c.upper() for c in plain_text if c.isalpha())
    if len(pt) % 2 != 0:
        pt += "X"  # Padding character

    a, b, c, d = matrix[0][0], matrix[0][1], matrix[1][0], matrix[1][1]

    # Check if key matrix is valid (invertible mod 26)
    det = (a * d - b * c) % 26
    if math.gcd(det, 26) != 1:
        raise ValueError(
            f"Matrice invalide: déterminant ({det}) n'est pas inversible mod 26."
        )

    ct = []
    for i in range(0, len(pt), 2):
        p1 = ord(pt[i]) - ord("A")
        p2 = ord(pt[i + 1]) - ord("A")

        c1 = (a * p1 + b * p2) % 26
        c2 = (c * p1 + d * p2) % 26

        ct.append(chr(c1 + ord("A")))
        ct.append(chr(c2 + ord("A")))

    return "".join(ct)


def hill_decrypt(cipher_text: str, matrix: list) -> str:
    """Decrypts text using a 2x2 Hill Cipher matrix by finding its modular inverse."""
    ct = "".join(c.upper() for c in cipher_text if c.isalpha())
    if len(ct) % 2 != 0:
        raise ValueError("Le texte chiffré Hill doit avoir une longueur paire.")

    a, b, c, d = matrix[0][0], matrix[0][1], matrix[1][0], matrix[1][1]
    det = (a * d - b * c) % 26

    # Find modular multiplicative inverse of determinant modulo 26
    det_inv = -1
    for x in range(1, 26):
        if (det * x) % 26 == 1:
            det_inv = x
            break

    if det_inv == -1:
        raise ValueError("Matrice non inversible mod 26.")

    # Adjugate matrix values scaled by determinant inverse mod 26
    inv_a = (d * det_inv) % 26
    inv_b = (-b * det_inv) % 26
    inv_c = (-c * det_inv) % 26
    inv_d = (a * det_inv) % 26

    pt = []
    for i in range(0, len(ct), 2):
        c1 = ord(ct[i]) - ord("A")
        c2 = ord(ct[i + 1]) - ord("A")

        p1 = (inv_a * c1 + inv_b * c2) % 26
        p2 = (inv_c * c1 + inv_d * c2) % 26

        pt.append(chr(p1 + ord("A")))
        pt.append(chr(p2 + ord("A")))

    return "".join(pt)
