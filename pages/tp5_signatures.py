"""
pages/tp5_signatures.py
"""

import customtkinter as ctk

from pages.base import Page
from ui.theme import C, font
from ui.widgets import (
    make_tabview,
    info_label,
    labeled_entry,
    output_box,
    write,
    btn_row,
    action_btn,
    separator,
    key_size_selector,
    mode_selector,
)
from algorithms.signatures import (
    EducationalECDSA,
    RSAPSSDemo,
    DSADemo,
    ElGamalSignature,
)


class TP5Page(Page):

    def __init__(self, parent):

        super().__init__(
            parent,
            title="TP5 Interactive Signature Lab",
            subtitle="ECDSA / RSA-PSS / DSA / ElGamal",
        )

        tv = make_tabview(
            self,
            [
                "ECDSA Lab",
                "RSA-PSS Lab",
                "DSA Lab",
                "ElGamal Lab",
            ],
        )

        self.ecdsa = EducationalECDSA()
        self.rsa = RSAPSSDemo()
        self.dsa = DSADemo()
        self.elgamal = ElGamalSignature()

        self._build_ecdsa_lab(tv.tab("ECDSA Lab"))
        self._build_rsa_lab(tv.tab("RSA-PSS Lab"))
        self._build_dsa_lab(tv.tab("DSA Lab"))
        self._build_elgamal_lab(tv.tab("ElGamal Lab"))

    # -----------------------------------------------------
    # UI
    # -----------------------------------------------------

    def _build_ecdsa_lab(self, parent):

        info_label(
            self,
            "Interactive ECDSA laboratory. Modify parameters and observe computations.",
        )

        self.msg = labeled_entry(self, "Message", "Transfer 5 BTC")

        self.priv = labeled_entry(self, "Private key d (optional)", "")

        self.nonce = labeled_entry(self, "Nonce k (optional)", "")

        btn_row(
            self,
            ("Generate Keys", self.keygen, C["warn"], "black"),
            ("Hash", self.hash_message, C["accent"]),
            ("Sign", self.sign, C["success"]),
            ("Verify", self.verify, C["success"]),
            ("Tamper", self.tamper, C["danger"]),
        )

        self.out = output_box(self, 500)

        self.signature = None

    # -----------------------------------------------------
    # ACTIONS
    # -----------------------------------------------------

    def keygen(self):

        d = self.priv.get().strip()

        if d:
            result = self.ecdsa.generate_keys(int(d))
        else:
            result = self.ecdsa.generate_keys()

        write(
            self.out,
            f"""
=== KEY GENERATION ===

Private key d:
{result['private_key']}

Public key Q = dG:

Qx:
{result['public_key'][0]}

Qy:
{result['public_key'][1]}
""",
        )

    def hash_message(self):

        result = self.ecdsa.hash_message(self.msg.get())

        write(
            self.out,
            f"""
=== HASHING ===

Message:
{result['message']}

SHA-256:
{result['hash_hex']}

Integer representation:
{result['hash_int']}
""",
        )

    def sign(self):

        k = self.nonce.get().strip()

        if k:
            result = self.ecdsa.sign(self.msg.get(), int(k))
        else:
            result = self.ecdsa.sign(self.msg.get())

        self.signature = result["signature"]

        write(
            self.out,
            f"""
=== SIGNATURE GENERATION ===

Hash H(m):
{result['hash']}

Nonce k:
{result['nonce_k']}

k inverse:
{result['k_inverse']}

R = kG:

Rx:
{result['R_point'][0]}

Ry:
{result['R_point'][1]}

r = Rx mod n:
{result['r']}

s = k⁻¹(H(m)+dr) mod n:
{result['s']}

Final signature:
(r,s)

({result['r']},
 {result['s']})
""",
        )

    def verify(self):

        if self.signature is None:
            write(self.out, "Generate signature first")
            return

        result = self.ecdsa.verify(self.msg.get(), self.signature)

        write(
            self.out,
            f"""
=== VERIFICATION ===

s inverse:
{result['s_inverse']}

u1:
{result['u1']}

u2:
{result['u2']}

Computed point P:

Px:
{result['computed_point'][0]}

Py:
{result['computed_point'][1]}

Computed r:
{result['computed_r']}

Expected r:
{result['expected_r']}

VALID:
{result['valid']}
""",
        )

    def tamper(self):

        if self.signature is None:
            write(self.out, "Generate signature first")
            return

        tampered = self.msg.get() + " hacked"

        result = self.ecdsa.verify(tampered, self.signature)

        write(
            self.out,
            f"""
=== TAMPERING TEST ===

Original message:
{self.msg.get()}

Tampered message:
{tampered}

Verification result:
{result['valid']}

Signature invalid because hash changed.
""",
        )

    # -----------------------------------------------------
    # ELGAMAL LAB
    # -----------------------------------------------------

    def _build_elgamal_lab(self, parent):

        info_label(parent, "Interactive ElGamal signature laboratory")

        self.elg_msg = labeled_entry(parent, "Message", "Hello ElGamal")

        btn_row(
            parent,
            ("Show Parameters", self.elgamal_params, C["warn"], "black"),
            ("Sign", self.elgamal_sign, C["accent"]),
            ("Verify", self.elgamal_verify, C["success"]),
            ("Tamper", self.elgamal_tamper, C["danger"]),
        )

        self.elg_out = output_box(parent, 500)

        self.elg_sig = None

    def elgamal_params(self):

        write(
            self.elg_out,
            f"""
=== ELGAMAL PARAMETERS ===

Prime p:
{self.elgamal.p}

Generator g:
{self.elgamal.g}

Private key x:
{self.elgamal.x}

Public key y = g^x mod p:
{self.elgamal.y}
""",
        )

    def elgamal_sign(self):

        msg = self.elg_msg.get().encode()

        self.elg_sig = self.elgamal.sign(msg)

        write(
            self.elg_out,
            f"""
=== ELGAMAL SIGNATURE ===

Message:
{msg.decode()}

r:
{self.elg_sig[0]}

s:
{self.elg_sig[1]}

Signature:
{self.elg_sig}
""",
        )

    def elgamal_verify(self):

        if self.elg_sig is None:
            write(self.elg_out, "Sign first")
            return

        valid = self.elgamal.verify(self.elg_msg.get().encode(), self.elg_sig)

        write(
            self.elg_out,
            f"""
=== ELGAMAL VERIFICATION ===

Check:

g^H(m) ?= y^r * r^s mod p

Verification result:
{valid}
""",
        )

    def elgamal_tamper(self):

        if self.elg_sig is None:
            write(self.elg_out, "Sign first")
            return

        tampered = self.elg_msg.get().encode() + b" hacked"

        valid = self.elgamal.verify(tampered, self.elg_sig)

        write(
            self.elg_out,
            f"""
=== ELGAMAL TAMPERING ===

Tampered message:
{tampered.decode()}

Verification:
{valid}
""",
        )

    # -----------------------------------------------------
    # RSA-PSS LAB
    # -----------------------------------------------------

    def _build_rsa_lab(self, parent):

        info_label(parent, "Interactive RSA-PSS signature laboratory")

        self.rsa_msg = labeled_entry(parent, "Message", "Hello RSA-PSS")

        btn_row(
            parent,
            ("Generate Keys", self.rsa_keygen, C["warn"], "black"),
            ("Sign", self.rsa_sign, C["accent"]),
            ("Verify", self.rsa_verify, C["success"]),
            ("Tamper", self.rsa_tamper, C["danger"]),
        )

        self.rsa_out = output_box(parent, 500)

        self.rsa_key = None
        self.rsa_sig = None

    def rsa_keygen(self):

        self.rsa_key = self.rsa.keygen()

        numbers = self.rsa_key.private_numbers()

        write(
            self.rsa_out,
            f"""
=== RSA-PSS KEY GENERATION ===

Modulus n:
{numbers.public_numbers.n}

Public exponent e:
{numbers.public_numbers.e}

Private exponent d:
{numbers.d}

Prime p:
{numbers.p}

Prime q:
{numbers.q}
""",
        )

    def rsa_sign(self):

        if self.rsa_key is None:
            write(self.rsa_out, "Generate keys first")
            return

        msg = self.rsa_msg.get().encode()

        self.rsa_sig = self.rsa.sign(self.rsa_key, msg)

        write(
            self.rsa_out,
            f"""
=== RSA-PSS SIGNATURE ===

Message:
{msg.decode()}

SHA-256 hash used

PSS padding applied

Signature bytes:
{self.rsa_sig.hex()}

Signature size:
{len(self.rsa_sig)} bytes
""",
        )

    def rsa_verify(self):

        if self.rsa_sig is None:
            write(self.rsa_out, "Sign first")
            return

        valid = self.rsa.verify(
            self.rsa_key.public_key(), self.rsa_sig, self.rsa_msg.get().encode()
        )

        write(
            self.rsa_out,
            f"""
=== RSA-PSS VERIFICATION ===

Recovered using:

sig^e mod n

Verification result:
{valid}
""",
        )

    def rsa_tamper(self):

        if self.rsa_sig is None:
            write(self.rsa_out, "Sign first")
            return

        tampered = self.rsa_msg.get() + " hacked"

        valid = self.rsa.verify(
            self.rsa_key.public_key(), self.rsa_sig, tampered.encode()
        )

        write(
            self.rsa_out,
            f"""
=== RSA-PSS TAMPERING ===

Tampered message:
{tampered}

Verification:
{valid}
""",
        )
        # -----------------------------------------------------

    # DSA LAB
    # -----------------------------------------------------

    def _build_dsa_lab(self, parent):

        info_label(parent, "Interactive DSA laboratory")

        self.dsa_msg = labeled_entry(parent, "Message", "Hello DSA")

        btn_row(
            parent,
            ("Generate Keys", self.dsa_keygen, C["warn"], "black"),
            ("Sign", self.dsa_sign, C["accent"]),
            ("Verify", self.dsa_verify, C["success"]),
            ("Tamper", self.dsa_tamper, C["danger"]),
        )

        self.dsa_out = output_box(parent, 500)

        self.dsa_key = None
        self.dsa_sig = None

    def dsa_keygen(self):

        self.dsa_key = self.dsa.keygen()

        numbers = self.dsa_key.private_numbers()

        write(
            self.dsa_out,
            f"""
=== DSA PARAMETERS ===

p:
{numbers.public_numbers.parameter_numbers.p}

q:
{numbers.public_numbers.parameter_numbers.q}

g:
{numbers.public_numbers.parameter_numbers.g}

Private key x:
{numbers.x}

Public key y:
{numbers.public_numbers.y}
""",
        )

    def dsa_sign(self):

        if self.dsa_key is None:
            write(self.dsa_out, "Generate keys first")
            return

        msg = self.dsa_msg.get().encode()

        self.dsa_sig = self.dsa.sign(self.dsa_key, msg)

        write(
            self.dsa_out,
            f"""
=== DSA SIGNATURE ===

Message:
{msg.decode()}

SHA-256(message)

Signature:
{self.dsa_sig.hex()}
""",
        )

    def dsa_verify(self):

        if self.dsa_sig is None:
            write(self.dsa_out, "Sign first")
            return

        valid = self.dsa.verify(
            self.dsa_key.public_key(), self.dsa_sig, self.dsa_msg.get().encode()
        )

        write(
            self.dsa_out,
            f"""
=== DSA VERIFICATION ===

Verification result:
{valid}
""",
        )

    def dsa_tamper(self):

        if self.dsa_sig is None:
            write(self.dsa_out, "Sign first")
            return

        tampered = self.dsa_msg.get() + " hacked"

        valid = self.dsa.verify(
            self.dsa_key.public_key(), self.dsa_sig, tampered.encode()
        )

        write(
            self.dsa_out,
            f"""
=== DSA TAMPERING ===

Tampered message:
{tampered}

Verification:
{valid}
""",
        )
