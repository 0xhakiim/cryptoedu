"""
pages/tp2_symmetric.py — TP 2: AES-128/192/256 in ECB, CBC, CTR.
Demonstrates encryption, decryption, nonce-reuse attack, and benchmark.
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
from algorithms.symmetric import (
    AVAILABLE,
    derive_key,
    aes_encrypt,
    aes_decrypt,
    benchmark_aes,
)


class TP2Page(Page):
    def __init__(self, parent):
        super().__init__(
            parent,
            title="TP 2 — Cryptographie Symétrique",
            subtitle="AES-128 / 192 / 256  ·  Modes ECB · CBC · CTR",
        )
        tv = make_tabview(
            self, ["AES Chiffrement", "Attaque Nonce-Reuse CTR", "Benchmark"]
        )
        self._build_aes(tv.tab("AES Chiffrement"))
        self._build_nonce(tv.tab("Attaque Nonce-Reuse CTR"))
        self._build_bench(tv.tab("Benchmark"))

    # ── AES Encrypt / Decrypt ──────────────────────────────────────────────────

    def _build_aes(self, parent):
        if not AVAILABLE:
            info_label(
                parent, "⚠️  pycryptodome requis: pip install pycryptodome", C["danger"]
            )
            return

        info_label(
            parent,
            "ℹ️  AES (Rijndael): bloc 128 bits, 10/12/14 tours selon la taille de clé.  "
            "ECB: chaque bloc chiffré indépendamment → motifs visibles (insécure).  "
            "CBC: XOR avec le bloc précédent (ou IV) → diffusion.  "
            "CTR: transforme AES en chiffrement de flot via un compteur.",
        )

        self._msg = labeled_entry(
            parent, "Message", "Hello, AES World! — TP Crypto 2026"
        )
        self._pass = labeled_entry(
            parent, "Passphrase (dérivée en clé via SHA-256)", "MaPassPhrase2026"
        )
        self._ks = key_size_selector(parent, ["128", "192", "256"], "256")
        self._mode = mode_selector(parent, ["ECB", "CBC", "CTR"], "CBC")

        btn_row(
            parent,
            ("🔒 Chiffrer", self._enc, C["accent"]),
            ("🔓 Déchiffrer", self._dec, C["success"]),
        )
        ctk.CTkLabel(parent, text="Résultat", font=font(12), text_color=C["sub"]).pack(
            anchor="w", padx=14
        )
        self._out = output_box(parent, 180)
        self._ctx: dict | None = None

    def _enc(self):
        try:
            bits = int(self._ks.get())
            key = derive_key(self._pass.get(), bits)
            m = self._msg.get().encode()
            mode = self._mode.get()
            self._ctx = aes_encrypt(m, key, mode)
            ct = self._ctx["ciphertext"]
            out = f"Clé AES-{bits}: {key.hex()}\n" f"Mode        : {mode}\n"
            if self._ctx["iv"]:
                out += f"IV          : {self._ctx['iv'].hex()}\n"
            if self._ctx["nonce"]:
                out += f"Nonce       : {self._ctx['nonce'].hex()}\n"
            out += f"Chiffré     : {ct.hex()}"
            if mode == "ECB":
                out += "\n\n⚠️  ECB: blocs identiques en clair → blocs identiques chiffrés!"
            write(self._out, out)
        except Exception as e:
            write(self._out, f"Erreur: {e}")

    def _dec(self):
        if self._ctx is None:
            write(self._out, "Chiffrez d'abord!")
            return
        try:
            bits = int(self._ks.get())
            key = derive_key(self._pass.get(), bits)
            pt = aes_decrypt(self._ctx, key)
            write(self._out, f"Déchiffré: {pt.decode(errors='replace')}")
        except Exception as e:
            write(self._out, f"Erreur: {e}")

    # ── Nonce-reuse attack ─────────────────────────────────────────────────────

    def _build_nonce(self, parent):
        info_label(
            parent,
            "ℹ️  AES-CTR avec le même nonce sur deux messages différents:  "
            "C1 = M1 ⊕ keystream,   C2 = M2 ⊕ keystream  "
            "→  C1 ⊕ C2 = M1 ⊕ M2  (le keystream s'annule).  "
            "Un attaquant récupère M1⊕M2 sans connaître la clé!  "
            "Même vulnérabilité qu'OTP réutilisé.",
        )

        self._nr_m1 = labeled_entry(parent, "Message M1", "TRANSFERT 5000 EUR VERS BOB")
        self._nr_m2 = labeled_entry(
            parent, "Message M2 (même nonce!)", "SALAIRE ALICE CONFIDENTIEL"
        )
        self._nr_key = labeled_entry(parent, "Clé (partagée)", "cle_aes_partagee")

        action_btn(
            parent, "💥 Simuler l'attaque nonce-reuse", self._nonce_attack, C["danger"]
        )
        ctk.CTkLabel(
            parent, text="Résultat de l'attaque", font=font(12), text_color=C["sub"]
        ).pack(anchor="w", padx=14)
        self._nr_out = output_box(parent, 220)

    def _nonce_attack(self):
        if not AVAILABLE:
            write(self._nr_out, "pycryptodome requis!")
            return
        try:
            from Crypto.Cipher import AES

            key = derive_key(self._nr_key.get(), 256)
            m1 = self._nr_m1.get().encode()
            m2 = self._nr_m2.get().encode()
            n = min(len(m1), len(m2))
            m1, m2 = m1[:n], m2[:n]

            # Both use the SAME nonce — this is the vulnerability
            from Crypto.Random import get_random_bytes

            nonce = get_random_bytes(8)
            c1 = AES.new(key, AES.MODE_CTR, nonce=nonce).encrypt(m1)
            c2 = AES.new(key, AES.MODE_CTR, nonce=nonce).encrypt(m2)

            xor = bytes(a ^ b for a, b in zip(c1, c2))
            ascii_xor = "".join(chr(b) if 32 <= b < 127 else "." for b in xor)

            out = f"Nonce (même pour C1 et C2): {nonce.hex()}\n\n"
            out += f"C1 (hex): {c1.hex()}\n"
            out += f"C2 (hex): {c2.hex()}\n\n"
            out += f"C1 ⊕ C2 = M1 ⊕ M2:\n"
            out += f"  hex  : {xor.hex()}\n"
            out += f"  ASCII: {ascii_xor}\n\n"
            out += "💡  Un attaquant qui connaît M1 retrouve M2 = (C1⊕C2) ⊕ M1\n"
            out += "   sans jamais avoir accès à la clé AES!\n\n"
            out += "🛡️  Contre-mesure: nonce UNIQUE par message (random 96-bit)\n"
            out += "   ou utiliser AES-GCM (intégrité + confidentialité)."
            write(self._nr_out, out)
        except Exception as e:
            write(self._nr_out, f"Erreur: {e}")

    # ── Benchmark ──────────────────────────────────────────────────────────────

    def _build_bench(self, parent):
        info_label(
            parent,
            "ℹ️  Mesure le débit (Mo/s) d'AES-128/192/256 en mode CBC sur 1 Mo.  "
            "Sur les processeurs modernes, AES-NI réduit l'écart entre les tailles de clé "
            "(10 vs 14 tours) à moins de 30%.",
        )
        action_btn(
            parent, "⚡ Lancer le benchmark AES (1 Mo)", self._run_bench, C["accent"]
        )
        ctk.CTkLabel(parent, text="Résultats", font=font(12), text_color=C["sub"]).pack(
            anchor="w", padx=14
        )
        self._bench_out = output_box(parent, 160)

    def _run_bench(self):
        if not AVAILABLE:
            write(self._bench_out, "pycryptodome requis!")
            return
        write(self._bench_out, "⏳ Benchmark en cours...")
        self.after(50, self._do_bench)

    def _do_bench(self):
        try:
            results = benchmark_aes(mb=1)
            mx = results[0][1]
            out = "⚡ AES-CBC — 1 Mo:\n\n"
            medals = ["🥇", "🥈", "🥉"]
            for i, (label, speed, ms) in enumerate(results):
                bar = "█" * int(28 * speed / mx)
                out += (
                    f"  {medals[i]} {label}:  {speed:6.1f} Mo/s  ({ms:.1f} ms)  {bar}\n"
                )
            out += (
                "\n💡  La différence vient du nombre de tours: 10 (128) vs 14 (256).\n"
            )
            out += "   Avec AES-NI matériel, l'écart est < 30%."
            write(self._bench_out, out)
        except Exception as e:
            write(self._bench_out, f"Erreur: {e}")
