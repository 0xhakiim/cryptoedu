"""
crypto/classical.py — Pure-Python implementations of classical ciphers.
No third-party dependencies. Covered algorithms: César, Vigenère.
"""


# ── César ──────────────────────────────────────────────────────────────────────

def caesar_encrypt(text: str, k: int) -> str:
    """Shift each alpha character by k positions (mod 26)."""
    return ''.join(
        chr((ord(c) - 65 + k) % 26 + 65) if c.isalpha() else c
        for c in text.upper()
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
    return ''.join(out)


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
    return ''.join(out)


def kasiski_test(ciphertext: str, ngram: int = 3) -> dict:
    """
    Find repeated n-grams and their distances.
    Returns {ngram: [distance, ...]} for repetitions found.
    """
    ct = ''.join(c for c in ciphertext.upper() if c.isalpha())
    found: dict[str, list[int]] = {}
    for i in range(len(ct) - ngram):
        gram = ct[i:i + ngram]
        for j in range(i + ngram, len(ct) - ngram + 1):
            if ct[j:j + ngram] == gram:
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
