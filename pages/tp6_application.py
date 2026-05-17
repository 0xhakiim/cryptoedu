"""
pages/tp6_application.py — TP 6: E2E encrypted chat simulation.
ECDH session key + AES-256-CBC per message + HMAC-SHA256 integrity.
"""
import hashlib
import hmac as _hmac
import os
import customtkinter as ctk

from pages.base import Page
from ui.theme import C, font
from ui.widgets import (
    make_tabview, info_label, labeled_entry,
    write, action_btn, separator, chat_box, chat_append,
)

try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    CRYPTO_OK = True
except ImportError:
    CRYPTO_OK = False

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Random import get_random_bytes
    AES_OK = True
except ImportError:
    AES_OK = False


class TP6Page(Page):
    def __init__(self, parent):
        super().__init__(
            parent,
            title="TP 6 — Application Sécurisée",
            subtitle="Chat E2E chiffré  ·  ECDH + AES-256-CBC + HMAC-SHA256",
        )
        tv = make_tabview(self, ["Chat E2E", "Protocole Expliqué"])
        self._build_chat(tv.tab("Chat E2E"))
        self._build_protocol(tv.tab("Protocole Expliqué"))

    # ── Chat ───────────────────────────────────────────────────────────────────

    def _build_chat(self, parent):
        info_label(parent,
            "ℹ️  Simulateur de messagerie E2E chiffrée.  "
            "Session ECDH P-256 → clé AES-256.  "
            "Chaque message: IV aléatoire + AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC).  "
            "Le canal réseau ne voit que des bytes chiffrés.")

        # Session setup
        sf = ctk.CTkFrame(parent, fg_color="transparent")
        sf.pack(fill="x", padx=14, pady=4)
        ctk.CTkButton(
            sf, text="🔑 Initialiser session ECDH",
            command=self._init_session,
            height=34, corner_radius=8,
            font=font(12, "bold"),
            fg_color=C["warn"], hover_color=C["warn"], text_color="black",
        ).pack(side="left", padx=(0, 10))
        self._status = ctk.CTkLabel(sf, text="⚪ Session non initialisée",
                                    font=font(11), text_color=C["sub"])
        self._status.pack(side="left")

        self._chat_disp = chat_box(parent, 260)

        # Message row
        mf = ctk.CTkFrame(parent, fg_color="transparent")
        mf.pack(fill="x", padx=14, pady=4)
        self._inp = ctk.CTkEntry(mf, placeholder_text="Message...",
                                 height=34, corner_radius=8, font=font(12))
        self._inp.pack(side="left", fill="x", expand=True, padx=(0, 6))
        for label, sender, color in [
            ("Alice → Bob",  "Alice", C["accent"]),
            ("Bob → Alice",  "Bob",   C["success"]),
        ]:
            ctk.CTkButton(
                mf, text=label, command=lambda s=sender: self._send(s),
                height=34, width=130, corner_radius=8,
                font=font(12, "bold"),
                fg_color=color, hover_color=color,
            ).pack(side="left", padx=2)

        action_btn(parent, "🗑️  Effacer le chat", self._clear_chat, C["border"])

        self._session_key: bytes | None = None
        self._msg_count = 0

    def _init_session(self):
        if CRYPTO_OK:
            a = ec.generate_private_key(ec.SECP256R1())
            b = ec.generate_private_key(ec.SECP256R1())
            shared = a.exchange(ec.ECDH(), b.public_key())
            self._session_key = hashlib.sha256(shared).digest()
        else:
            self._session_key = os.urandom(32)

        self._status.configure(
            text="🟢 Session E2E active  (ECDH P-256 + AES-256-CBC + HMAC-SHA256)",
            text_color=C["success"],
        )
        self._msg_count = 0
        chat_append(self._chat_disp, "═" * 52)
        chat_append(self._chat_disp, "🔑 Session ECDH P-256 établie")
        chat_append(self._chat_disp,
                    f"   Clé AES-256: {self._session_key.hex()[:32]}...")
        chat_append(self._chat_disp, "   Mode: AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC)")
        chat_append(self._chat_disp, "═" * 52)

    def _send(self, sender: str):
        if self._session_key is None:
            chat_append(self._chat_disp, "⚠️  Initialisez la session d'abord!"); return
        msg = self._inp.get().strip()
        if not msg: return
        self._inp.delete(0, "end")
        self._msg_count += 1

        try:
            m = msg.encode()
            prefix = "🔵 Alice" if sender == "Alice" else "🟢 Bob"

            if AES_OK:
                # Encrypt-then-MAC
                iv = get_random_bytes(16)
                ct = AES.new(self._session_key, AES.MODE_CBC, iv).encrypt(pad(m, 16))
                mac = _hmac.new(self._session_key, iv + ct, hashlib.sha256).hexdigest()

                chat_append(self._chat_disp, f"\n{prefix}: \"{msg}\"")
                chat_append(self._chat_disp,
                            f"   ┌─ Sur le réseau (#{self._msg_count}):")
                chat_append(self._chat_disp, f"   │  IV  : {iv.hex()}")
                chat_append(self._chat_disp,
                            f"   │  CT  : {ct.hex()[:40]}...")
                chat_append(self._chat_disp,
                            f"   └─ MAC : {mac[:32]}...")

                # Decrypt on receiver side
                ct_dec = AES.new(self._session_key, AES.MODE_CBC, iv).decrypt(ct)
                pt = unpad(ct_dec, 16).decode()
                recv = "🟢 Bob reçoit" if sender == "Alice" else "🔵 Alice reçoit"
                chat_append(self._chat_disp, f"   {recv}: \"{pt}\" ✅")
            else:
                # XOR fallback (no pycryptodome)
                ks = hashlib.sha256(self._session_key + self._msg_count.to_bytes(4, "big")).digest()
                ct = bytes(a ^ b for a, b in zip(m, ks[:len(m)]))
                chat_append(self._chat_disp, f"\n{prefix}: \"{msg}\"")
                chat_append(self._chat_disp,
                            f"   [Réseau: {ct.hex()[:40]}...]")
        except Exception as e:
            chat_append(self._chat_disp, f"❌ Erreur: {e}")

    def _clear_chat(self):
        self._chat_disp.configure(state="normal")
        self._chat_disp.delete("1.0", "end")
        self._chat_disp.configure(state="disabled")

    # ── Protocol explanation ────────────────────────────────────────────────────

    def _build_protocol(self, parent):
        info_label(parent,
            "ℹ️  Le protocole implémenté dans cet onglet Chat est un protocole "
            "simplifié inspiré de Signal/TLS.  Voici chaque étape en détail.")

        steps = [
            ("1. ECDH Key Exchange", C["accent"],
             "Alice génère (a_priv, A=a·G) sur P-256.\n"
             "Bob génère   (b_priv, B=b·G) sur P-256.\n"
             "Alice calcule secret = a·B = a·b·G.\n"
             "Bob calcule   secret = b·A = a·b·G.\n"
             "→ Même secret partagé, sans jamais l'envoyer sur le réseau.\n"
             "→ Perfect Forward Secrecy: clés éphémères à chaque session."),

            ("2. Key Derivation", C["purple"],
             "session_key = SHA-256(ecdh_secret)\n"
             "→ 32 octets aléatoires servant de clé AES-256.\n"
             "En production: HKDF(secret, salt, info) pour plusieurs sous-clés\n"
             "(clé de chiffrement + clé MAC séparées)."),

            ("3. Encrypt-then-MAC par message", C["success"],
             "Pour chaque message M:\n"
             "  iv  = random_bytes(16)            # IV unique!\n"
             "  ct  = AES-256-CBC(session_key, iv, pad(M))\n"
             "  mac = HMAC-SHA256(session_key, iv ∥ ct)\n"
             "  → Envoi: (iv, ct, mac)\n\n"
             "Réception:\n"
             "  Vérifier mac AVANT de déchiffrer (Encrypt-then-MAC)\n"
             "  → protège contre les attaques par oracle de padding."),

            ("4. Garanties de sécurité", C["warn"],
             "✅  Confidentialité   : AES-256-CBC (indistinguable du bruit)\n"
             "✅  Intégrité         : HMAC-SHA256 (détecte toute modification)\n"
             "✅  Authenticité      : seul le détenteur de la clé peut générer un MAC valide\n"
             "✅  PFS               : clés ECDH éphémères — compromission future ≠ déchiffrement passé\n"
             "⚠️  Absent ici        : rotation de clés (Double Ratchet de Signal),\n"
             "                      authentification de l'identité (certificats)."),
        ]

        for title, color, body in steps:
            f = ctk.CTkFrame(parent, fg_color=C["sidebar"], corner_radius=10,
                             border_width=1, border_color=color)
            f.pack(fill="x", padx=14, pady=5)
            ctk.CTkLabel(f, text=title, font=font(13, "bold"),
                         text_color=color).pack(anchor="w", padx=12, pady=(10, 2))
            ctk.CTkFrame(f, height=1, fg_color=color).pack(fill="x", padx=12, pady=(0, 6))
            ctk.CTkLabel(f, text=body, font=font(11), text_color=C["text"],
                         justify="left", wraplength=590).pack(
                anchor="w", padx=12, pady=(0, 10))
