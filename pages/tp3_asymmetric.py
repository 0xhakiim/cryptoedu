"""
pages/tp3_asymmetric.py — TP 3: RSA (pure Python) and ECDH (P-256).
Covers key generation, encrypt/decrypt, and shared-secret exchange.
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
    key_size_selector,
    separator,
)
from algorithms.asymmetric import (
    rsa_generate,
    rsa_encrypt,
    rsa_decrypt,
    ecdh_exchange,
    ECDH_AVAILABLE,
)


class TP3Page(Page):
    def __init__(self, parent):
        super().__init__(
            parent,
            title="TP 3 — Cryptographie Asymétrique",
            subtitle="RSA  ·  ECDH P-256",
        )
        tv = make_tabview(self, ["RSA", "ECDH P-256"])
        self._build_rsa(tv.tab("RSA"))
        self._build_ecdh(tv.tab("ECDH P-256"))

    # ── RSA ────────────────────────────────────────────────────────────────────

    def _build_rsa(self, parent):
        info_label(
            parent,
            "ℹ️  RSA: n = p × q,  φ(n) = (p-1)(q-1),  e = 65537,  d = e⁻¹ mod φ(n).  "
            "Chiffrer: C = Mᵉ mod n.   Déchiffrer: M = Cᵈ mod n.  "
            "Sécurité: factoriser n en p et q est calculatoirement infaisable "
            "pour n ≥ 2048 bits.  En pratique on utilise le chiffrement hybride "
            "RSA+AES car RSA ne peut chiffrer que M < n.",
        )

        self._rks = key_size_selector(parent, ["256", "512", "1024"], "512")
        self._rmsg = labeled_entry(parent, "Message M (entier, doit être < n)", "42")

        btn_row(
            parent,
            ("🔑 Générer paire RSA", self._r_keygen, C["warn"], "black"),
            ("🔒 Chiffrer", self._r_enc, C["accent"]),
            ("🔓 Déchiffrer", self._r_dec, C["success"]),
        )
        ctk.CTkLabel(parent, text="Résultat", font=font(12), text_color=C["sub"]).pack(
            anchor="w", padx=14
        )
        self._rout = output_box(parent, 240)
        self._rkey: dict | None = None
        self._rct: int | None = None

        separator(parent)
        info_label(
            parent,
            "⚠️  Sécurité actuelle (NIST 2024): RSA-2048 ≈ 112 bits, RSA-3072 ≈ 128 bits.  "
            "RSA-512 et RSA-1024 sont cassables (usage démonstratif uniquement).  "
            "Padding OAEP obligatoire en production — RSA textbook est malléable.",
            color=C["warn"],
        )

    def _r_keygen(self):
        write(self._rout, "⏳ Génération en cours (Miller-Rabin)...")
        bits = int(self._rks.get())
        self.after(50, lambda: self._do_keygen(bits))

    def _do_keygen(self, bits: int):
        try:
            self._rkey = rsa_generate(bits)
            self._rct = None
            k = self._rkey
            write(
                self._rout,
                f"✅  RSA-{bits} généré!\n\n"
                f"p ({bits//2} bits): {str(k['p'])[:40]}...\n"
                f"q ({bits//2} bits): {str(k['q'])[:40]}...\n\n"
                f"n = p × q ({bits} bits):\n  {str(k['n'])[:64]}...\n\n"
                f"e = {k['e']}  (Fermat F4, standard)\n"
                f"d = e⁻¹ mod φ(n):\n  {str(k['d'])[:64]}...\n\n"
                f"💡  Révéler p, q ou d compromet immédiatement la clé!\n"
                f"   φ(n) = (p-1)(q-1) doit rester secret.",
            )
        except Exception as e:
            write(self._rout, f"Erreur: {e}")

    def _r_enc(self):
        if self._rkey is None:
            write(self._rout, "Générez d'abord une paire de clés!")
            return
        try:
            M = int(self._rmsg.get())
            if M >= self._rkey["n"]:
                write(
                    self._rout, f"M doit être strictement < n!\nn = {self._rkey['n']}"
                )
                return
            self._rct = rsa_encrypt(M, self._rkey)
            write(
                self._rout,
                f"M (message)   = {M}\n"
                f"C = Mᵉ mod n  = {self._rct}\n\n"
                f"({self._rct.bit_length()} bits)",
            )
        except Exception as e:
            write(self._rout, f"Erreur: {e}")

    def _r_dec(self):
        if self._rct is None:
            write(self._rout, "Chiffrez d'abord!")
            return
        M = rsa_decrypt(self._rct, self._rkey)
        write(
            self._rout,
            f"C (chiffré) = {self._rct}\n"
            f"M = Cᵈ mod n = {M}\n\n"
            f"✅  Message retrouvé: {M}",
        )

    # ── ECDH ───────────────────────────────────────────────────────────────────

    def _build_ecdh(self, parent):
        if not ECDH_AVAILABLE:
            info_label(
                parent, "⚠️  cryptography requis: pip install cryptography", C["danger"]
            )
            return

        info_label(
            parent,
            "ℹ️  ECDH sur P-256: Alice génère (a, A=a·G), Bob génère (b, B=b·G).  "
            "Alice calcule a·B = a·b·G, Bob calcule b·A = a·b·G → même secret.  "
            "ECDLP: connaître A=a·G et G ne permet pas de retrouver a.  "
            "ECC-256 ≈ RSA-3072 en sécurité, mais clé 4× plus petite.",
        )

        action_btn(parent, "🔑 Simuler échange ECDH P-256", self._run_ecdh, C["accent"])
        ctk.CTkLabel(
            parent, text="Trace du protocole", font=font(12), text_color=C["sub"]
        ).pack(anchor="w", padx=14)
        self._ecdh_out = output_box(parent, 300)

        separator(parent)
        info_label(
            parent,
            "💡  ECDH est utilisé dans TLS 1.3 (ECDHE éphémère → Perfect Forward Secrecy), "
            "Signal, WhatsApp, iMessage.  "
            "La clé de session AES est dérivée du secret ECDH via SHA-256 ou HKDF.",
            color=C["warn"],
        )

    def _run_ecdh(self):
        try:
            r = ecdh_exchange()
            write(
                self._ecdh_out,
                "═" * 54 + "\n"
                "   ECDH — Courbe P-256 (SECP256R1, NIST)\n"
                "═" * 54 + "\n\n"
                f"Courbe: y² = x³ - 3x + b mod p  (p ≈ 2²⁵⁶)\n\n"
                f"Alice pub ({len(r['a_pub_bytes'])} octets):\n"
                f"  {r['a_pub_bytes'].hex()[:56]}...\n\n"
                f"Bob   pub ({len(r['b_pub_bytes'])} octets):\n"
                f"  {r['b_pub_bytes'].hex()[:56]}...\n\n"
                f"Secret Alice (a·B): {r['secret_a'].hex()[:40]}...\n"
                f"Secret Bob   (b·A): {r['secret_b'].hex()[:40]}...\n\n"
                f"✅  Secrets identiques: {r['match']}\n\n"
                f"Clé AES-256 = SHA-256(secret):\n"
                f"  {r['session_key'].hex()}\n\n"
                f"💡  Un espion voit A et B mais ne peut pas calculer\n"
                f"   a·b·G sans résoudre le problème du logarithme discret\n"
                f"   sur la courbe elliptique (ECDLP).",
            )
        except Exception as e:
            write(self._ecdh_out, f"Erreur: {e}")
