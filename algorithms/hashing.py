"""
crypto/hashing.py — Hash comparison, avalanche demo, HMAC, benchmark.
Uses stdlib only (hashlib, hmac, os, time).
"""
import hashlib
import hmac as _hmac
import os
import time


ALGORITHMS = {
    "MD5":      hashlib.md5,
    "SHA-1":    hashlib.sha1,
    "SHA-256":  hashlib.sha256,
    "SHA-512":  hashlib.sha512,
    "SHA3-256": hashlib.sha3_256,
    "SHA3-512": hashlib.sha3_512,
    "BLAKE2b":  hashlib.blake2b,
}

SECURITY_NOTES = {
    "MD5":      ("128", "⚠️  Collisions pratiques (Wang 2004) — ne pas utiliser"),
    "SHA-1":    ("160", "⚠️  SHAttered (2017) — déprécié TLS/Git"),
    "SHA-256":  ("256", "✅  Standard: Bitcoin, TLS, Git, JWT, apt"),
    "SHA-512":  ("512", "✅  Plus rapide sur CPU 64-bit"),
    "SHA3-256": ("256", "✅  Construction éponge — immune length-extension"),
    "SHA3-512": ("512", "✅  Alternative post-SHA-2"),
    "BLAKE2b":  ("512", "✅  Plus rapide que MD5, sécurité SHA-3"),
}


def hash_all(message: str) -> dict[str, str]:
    """Return {algo_name: hex_digest} for every supported algorithm."""
    m = message.encode()
    return {name: fn(m).hexdigest() for name, fn in ALGORITHMS.items()}


def avalanche(message: str) -> list[tuple[str, str, str, int, int, float]]:
    """
    Flip bit-0 of the first byte, compare digests.
    Returns [(name, h1_hex, h2_hex, bits_different, total_bits, pct), ...].
    """
    m1 = message.encode()
    ba = bytearray(m1); ba[0] ^= 0x01
    m2 = bytes(ba)
    results = []
    for name, fn in ALGORITHMS.items():
        h1 = fn(m1).digest()
        h2 = fn(m2).digest()
        diff = sum(bin(a ^ b).count("1") for a, b in zip(h1, h2))
        total = len(h1) * 8
        results.append((name, h1.hex(), h2.hex(), diff, total, 100 * diff / total))
    return results


def compute_hmac(message: str, key: str, algo_name: str) -> str:
    fn = ALGORITHMS[algo_name]
    return _hmac.new(key.encode(), message.encode(), fn).hexdigest()


def verify_hmac(message: str, key: str, algo_name: str, expected: str) -> bool:
    computed = compute_hmac(message, key, algo_name)
    return _hmac.compare_digest(computed, expected)


def benchmark(mb: int = 10) -> list[tuple[str, float, float]]:
    """
    Hash `mb` MB with every algorithm.
    Returns [(name, speed_MBs, elapsed_ms), ...] sorted fastest→slowest.
    """
    data = os.urandom(mb * 1024 * 1024)
    results = []
    for name, fn in ALGORITHMS.items():
        t0 = time.perf_counter()
        fn(data).hexdigest()
        t1 = time.perf_counter()
        results.append((name, mb / (t1 - t0), (t1 - t0) * 1000))
    return sorted(results, key=lambda x: x[1], reverse=True)
