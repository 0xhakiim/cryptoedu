"""
algorithms/ecdsa_lab.py
Educational ECDSA implementation exposing internals.
"""

from hashlib import sha256
from ecdsa import NIST256p, ellipticcurve
from random import randint


class EducationalECDSA:

    def __init__(self):

        self.curve = NIST256p

        self.G = self.curve.generator
        self.n = self.curve.order

        self.d = None
        self.Q = None

    # ---------------------------------------------------------
    # KEY GENERATION
    # ---------------------------------------------------------

    def generate_keys(self, private=None):

        if private is None:
            self.d = randint(1, self.n - 1)
        else:
            self.d = private

        self.Q = self.d * self.G

        return {
            "private_key": self.d,
            "public_key": (self.Q.x(), self.Q.y()),
        }

    # ---------------------------------------------------------
    # HASH
    # ---------------------------------------------------------

    def hash_message(self, message):

        h = sha256(message.encode()).hexdigest()

        return {
            "message": message,
            "hash_hex": h,
            "hash_int": int(h, 16),
        }

    # ---------------------------------------------------------
    # SIGN
    # ---------------------------------------------------------

    def sign(self, message, nonce=None):

        h = int(sha256(message.encode()).hexdigest(), 16)

        if nonce is None:
            k = randint(1, self.n - 1)
        else:
            k = nonce

        R = k * self.G

        r = R.x() % self.n

        k_inv = pow(k, -1, self.n)

        s = (k_inv * (h + self.d * r)) % self.n

        return {
            "message": message,
            "hash": h,
            "nonce_k": k,
            "k_inverse": k_inv,
            "R_point": (R.x(), R.y()),
            "r": r,
            "s": s,
            "signature": (r, s),
        }

    # ---------------------------------------------------------
    # VERIFY
    # ---------------------------------------------------------

    def verify(self, message, signature):

        r, s = signature

        h = int(sha256(message.encode()).hexdigest(), 16)

        s_inv = pow(s, -1, self.n)

        u1 = (h * s_inv) % self.n
        u2 = (r * s_inv) % self.n

        P = u1 * self.G + u2 * self.Q

        valid = (P.x() % self.n) == r

        return {
            "hash": h,
            "s_inverse": s_inv,
            "u1": u1,
            "u2": u2,
            "computed_point": (P.x(), P.y()),
            "computed_r": P.x() % self.n,
            "expected_r": r,
            "valid": valid,
        }
