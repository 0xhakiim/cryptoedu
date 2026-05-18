"""
Educational signature algorithms collection.
Contains:
- EducationalECDSA
- RSAPSSDemo
- DSADemo
- ElGamalSignature
"""

from hashlib import sha256
from random import randint
from math import gcd

from ecdsa import NIST256p

from cryptography.hazmat.primitives.asymmetric import (
    rsa,
    padding,
    dsa,
)

from cryptography.hazmat.primitives import hashes

# =========================================================
# ECDSA
# =========================================================


class EducationalECDSA:

    def __init__(self):

        self.curve = NIST256p

        self.G = self.curve.generator
        self.n = self.curve.order

        self.d = None
        self.Q = None

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

    def hash_message(self, message):

        h = sha256(message.encode()).hexdigest()

        return {
            "message": message,
            "hash_hex": h,
            "hash_int": int(h, 16),
        }

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


# =========================================================
# RSA-PSS
# =========================================================


class RSAPSSDemo:

    @staticmethod
    def keygen():

        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

    @staticmethod
    def sign(private_key, message: bytes):

        return private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

    @staticmethod
    def verify(public_key, signature, message: bytes):

        try:
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True

        except Exception:
            return False


# =========================================================
# DSA
# =========================================================


class DSADemo:

    @staticmethod
    def keygen():

        return dsa.generate_private_key(key_size=2048)

    @staticmethod
    def sign(private_key, message: bytes):

        return private_key.sign(
            message,
            hashes.SHA256(),
        )

    @staticmethod
    def verify(public_key, signature, message: bytes):

        try:
            public_key.verify(
                signature,
                message,
                hashes.SHA256(),
            )
            return True

        except Exception:
            return False


# =========================================================
# ELGAMAL SIGNATURE
# =========================================================


class ElGamalSignature:

    def __init__(self):

        self.p = 467
        self.g = 2

        self.x = randint(1, self.p - 2)

        self.y = pow(self.g, self.x, self.p)

    def sign(self, message: bytes):

        h = int(sha256(message).hexdigest(), 16)

        while True:

            k = randint(1, self.p - 2)

            if gcd(k, self.p - 1) == 1:
                break

        r = pow(self.g, k, self.p)

        k_inv = pow(k, -1, self.p - 1)

        s = ((h - self.x * r) * k_inv) % (self.p - 1)

        return (r, s)

    def verify(self, message: bytes, signature):

        r, s = signature

        h = int(sha256(message).hexdigest(), 16)

        left = pow(self.g, h, self.p)

        right = (pow(self.y, r, self.p) * pow(r, s, self.p)) % self.p

        return left == right
