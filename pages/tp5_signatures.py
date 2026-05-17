"""
pages/tp5_signatures.py — TP 5: ECDSA on P-256.
Sign, verify, tamper detection, and non-repudiation demo.
"""
import customtkinter as ctk

from pages.base import Page
from ui.theme import C, font
from ui.widgets import (
    make_tabview, info_label, labeled_entry, output_box,
    write, btn_row, action_btn, separator,
)

try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes, serialization
    ECDSA_AVAILABLE = True
except ImportError:
    ECDSA_AVAILABLE = False


class TP5Page(Page):
    def __init__(self, parent):
        super().__init__(
            parent,
            title="TP 5 — Signatures Numériques",
            subtitle="ECDSA P-256  ·  Authenticité · Intégrité · Non-répudiation",
        )
        tv = make_tabview(self, ["ECDSA", "Non-répudiation"])
        self._build_ecdsa(tv.tab("ECDSA"))
        self._build_nonrep(tv.tab("Non-répudiation"))

    # ── ECDSA ──────────────────────────────────────────────────────────────────

    def _build_ecdsa(self, parent):
        if not ECDSA_AVAILABLE:
            info_label(parent, "⚠️  cryptography requis: pip install cryptography", C["danger"])
            return

        info_label(parent,
            "ℹ️  ECDSA P-256: signer = Sign(clé_privée, SHA-256(M)) → (r, s).  "
            "Vérifier = Verify(clé_publique, M, (r,s)) → ✓/✗.  "
            "Sécurité: ECDLP sur P-256 (128-bit security level).  "
            "Utilisé dans: Bitcoin, TLS 1.3 certificates, JWT ES256, "
            "FIDO2/WebAuthn, passeport électronique (ICAO).")

        self._msg = labeled_entry(parent,
            "Message à signer",
            "Blockchain transaction: 1 BTC → Alice — bloc #880000")

        btn_row(parent,
            ("🔑 Générer paire ECDSA P-256", self._keygen, C["warn"],    "black"),
            ("✍️  Signer",                   self._sign,   C["accent"]),
            ("✅ Vérifier",                  self._verify, C["success"]),
            ("❌ Tamper + Vérifier",         self._tamper, C["danger"]),
        )
        ctk.CTkLabel(parent, text="Résultat", font=font(12),
                     text_color=C["sub"]).pack(anchor="w", padx=14)
        self._out = output_box(parent, 280)

        self._key: object = None
        self._sig: bytes  = None
        self._signed_msg: bytes = None

        separator(parent)
        info_label(parent,
            "⚠️  Comme DSA, ECDSA exige un nonce k UNIQUE et SECRET par signature.  "
            "Réutiliser k permet de retrouver la clé privée: x = (s·k - H(M)) · r⁻¹ mod q.  "
            "Cas réel: Sony PS3 (2010) signait avec k = constante → clé privée extraite.",
            color=C["warn"])

    def _keygen(self):
        if not ECDSA_AVAILABLE: return
        try:
            self._key = ec.generate_private_key(ec.SECP256R1())
            self._sig = None; self._signed_msg = None
            pub = self._key.public_key()
            pb = pub.public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint,
            )
            write(self._out,
                f"✅  Paire ECDSA P-256 générée!\n\n"
                f"Clé publique ({len(pb)} octets):\n{pb.hex()}\n\n"
                f"💡  Taille comparée:\n"
                f"   ECDSA P-256 pub : {len(pb)} octets\n"
                f"   RSA-2048   pub  : ~256 octets  (4× plus grand)\n"
                f"   RSA-3072   pub  : ~384 octets  (≈ même sécurité)\n\n"
                f"Courbe: SECP256R1, ordre q ≈ 2²⁵⁶\n"
                f"Sécurité: 128-bit (symétrique AES-128 équivalent)")
        except Exception as e:
            write(self._out, f"Erreur: {e}")

    def _sign(self):
        if self._key is None:
            write(self._out, "Générez d'abord une paire de clés!"); return
        try:
            m = self._msg.get().encode()
            self._signed_msg = m
            self._sig = self._key.sign(m, ec.ECDSA(hashes.SHA256()))
            write(self._out,
                f"Message  : {self._msg.get()}\n"
                f"Hash     : SHA-256 (intégré dans ECDSA)\n\n"
                f"Signature ECDSA ({len(self._sig)} octets, encodage DER):\n"
                f"{self._sig.hex()}\n\n"
                f"✅  Document signé avec la clé privée!\n"
                f"   (r, s) encodés en DER — chaque valeur ≈ 32 octets")
        except Exception as e:
            write(self._out, f"Erreur: {e}")

    def _verify(self):
        if self._sig is None:
            write(self._out, "Signez d'abord!"); return
        try:
            self._key.public_key().verify(self._sig, self._signed_msg,
                                          ec.ECDSA(hashes.SHA256()))
            write(self._out,
                f"Message : {self._signed_msg.decode()}\n\n"
                f"✅  SIGNATURE ECDSA VALIDE\n"
                f"   Authenticité  : message vient bien du propriétaire de la clé privée\n"
                f"   Intégrité     : message non modifié depuis la signature\n"
                f"   Non-répudiation: le signataire ne peut pas nier avoir signé")
        except Exception as e:
            write(self._out, f"❌  SIGNATURE INVALIDE\n    {e}")

    def _tamper(self):
        if self._sig is None:
            write(self._out, "Signez d'abord!"); return
        try:
            tampered = self._signed_msg + b" [FALSIFIE]"
            self._key.public_key().verify(self._sig, tampered,
                                          ec.ECDSA(hashes.SHA256()))
            write(self._out, "VALIDE (anomalie inattendue!)")
        except Exception as e:
            write(self._out,
                f"Message original  : {self._signed_msg.decode()}\n"
                f"Message tamperisé : {self._signed_msg.decode()} [FALSIFIE]\n\n"
                f"❌  FALSIFICATION DÉTECTÉE PAR ECDSA!\n\n"
                f"    {e}\n\n"
                f"💡  La signature (r,s) lie cryptographiquement le hash\n"
                f"    SHA-256(M) à la clé privée.  Modifier M d'un seul\n"
                f"    bit change complètement SHA-256(M) → signature invalide.")

    # ── Non-repudiation demo ───────────────────────────────────────────────────

    def _build_nonrep(self, parent):
        info_label(parent,
            "ℹ️  Non-répudiation: le signataire ne peut pas nier avoir signé car "
            "seul le propriétaire de la clé privée peut produire une signature valide.  "
            "Contrairement à HMAC (clé symétrique partagée), une signature numérique "
            "est vérifiable par n'importe qui possédant la clé publique.")

        info_label(parent,
            "Scénario: Alice signe un contrat. Bob vérifie avec la clé publique d'Alice.\n"
            "Alice ne peut pas prétendre ne pas avoir signé.",
            color=C["accent"])

        self._nr_contract = labeled_entry(parent,
            "Contrat (Alice signe)",
            "Je soussignée Alice, m'engage à livrer 100 unités — 17/05/2026")

        btn_row(parent,
            ("🔑 Clé privée Alice", self._nr_keygen, C["warn"],    "black"),
            ("✍️  Alice signe",     self._nr_sign,   C["accent"]),
            ("🔍 Bob vérifie",      self._nr_verify,  C["success"]),
        )
        ctk.CTkLabel(parent, text="Trace du protocole", font=font(12),
                     text_color=C["sub"]).pack(anchor="w", padx=14)
        self._nr_out = output_box(parent, 260)
        self._nr_key = None; self._nr_sig = None; self._nr_msg = None

    def _nr_keygen(self):
        if not ECDSA_AVAILABLE:
            write(self._nr_out, "cryptography requis!"); return
        self._nr_key = ec.generate_private_key(ec.SECP256R1())
        pub = self._nr_key.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        write(self._nr_out,
            "🔑 Infrastructure à clés publiques:\n\n"
            f"Alice conserve sa clé PRIVÉE (secrète)\n"
            f"Alice publie sa clé PUBLIQUE:\n  {pub.hex()[:60]}...\n\n"
            "Bob (et le tribunal!) peuvent utiliser cette clé publique\n"
            "pour vérifier toute signature d'Alice.")

    def _nr_sign(self):
        if self._nr_key is None:
            write(self._nr_out, "Générez d'abord les clés!"); return
        m = self._nr_contract.get().encode()
        self._nr_msg = m
        self._nr_sig = self._nr_key.sign(m, ec.ECDSA(hashes.SHA256()))
        write(self._nr_out,
            f"✍️  Alice signe le contrat:\n«{m.decode()}»\n\n"
            f"Signature ({len(self._nr_sig)} octets):\n{self._nr_sig.hex()[:72]}...\n\n"
            "Alice envoie (contrat + signature) à Bob.\n"
            "Sa clé privée ne quitte jamais son appareil.")

    def _nr_verify(self):
        if self._nr_sig is None:
            write(self._nr_out, "Alice doit d'abord signer!"); return
        try:
            self._nr_key.public_key().verify(self._nr_sig, self._nr_msg,
                                             ec.ECDSA(hashes.SHA256()))
            write(self._nr_out,
                f"🔍 Bob vérifie avec la CLÉ PUBLIQUE d'Alice:\n\n"
                f"Contrat : {self._nr_msg.decode()}\n\n"
                f"✅  SIGNATURE VALIDE — Bob peut prouver devant un tribunal que:\n"
                f"   1. Alice a bien signé ce contrat exact\n"
                f"   2. Le contrat n'a pas été modifié depuis\n"
                f"   3. Alice ne peut pas nier (non-répudiation)\n\n"
                f"💡  Seule Alice possède la clé privée correspondante.")
        except Exception as e:
            write(self._nr_out, f"❌  Vérification échouée: {e}")
