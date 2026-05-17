"""
pages/tp4_hashing.py — TP 4: Hash comparison, avalanche effect, HMAC.
Uses stdlib only (no third-party dependencies).
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
    mode_selector,
)
from algorithms.hashing import (
    hash_all,
    SECURITY_NOTES,
    avalanche,
    compute_hmac,
    verify_hmac,
    benchmark,
)


class TP4Page(Page):
    def __init__(self, parent):
        super().__init__(
            parent,
            title="TP 4 — Fonctions de Hachage Cryptographique",
            subtitle="Comparaison  ·  Effet Avalanche  ·  HMAC",
        )
        tv = make_tabview(self, ["Comparaison", "Effet Avalanche", "HMAC & Benchmark"])
        self._build_compare(tv.tab("Comparaison"))
        self._build_avalanche(tv.tab("Effet Avalanche"))
        self._build_hmac(tv.tab("HMAC & Benchmark"))

    # ── Compare ────────────────────────────────────────────────────────────────

    def _build_compare(self, parent):
        info_label(
            parent,
            "ℹ️  Une bonne fonction de hachage H doit être: à sens unique (preimage), "
            "résistante aux secondes préimages, et résistante aux collisions (paradoxe des anniversaires: "
            "2^(n/2) opérations pour trouver une collision dans un hash n-bit).",
        )

        self._cm_msg = labeled_entry(parent, "Message", "Cryptographie Appliquée 2026")
        action_btn(parent, "🧮 Calculer tous les hashs", self._do_compare, C["accent"])
        ctk.CTkLabel(parent, text="Résultats", font=font(12), text_color=C["sub"]).pack(
            anchor="w", padx=14
        )
        self._cm_out = output_box(parent, 320)

    def _do_compare(self):
        results = hash_all(
            self.cm_msg.get() if hasattr(self, "cm_msg") else self._cm_msg.get()
        )
        # use self._cm_msg
        msg = self._cm_msg.get()
        results = hash_all(msg)
        lines = [f'Message: "{msg}"\n{"─" * 72}']
        for name, digest in results.items():
            bits, note = SECURITY_NOTES[name]
            lines.append(f"\n{name:10} ({bits:>3} bits) {note}")
            lines.append(digest)
        write(self._cm_out, "\n".join(lines))

    # ── Avalanche ──────────────────────────────────────────────────────────────

    def _build_avalanche(self, parent):
        info_label(
            parent,
            "ℹ️  Effet avalanche: modifier un seul bit du message doit modifier "
            "environ 50% des bits du condensé.  C'est une propriété fondamentale "
            "des fonctions de hachage robustes (et des chiffrements par blocs).  "
            "Si l'avalanche est < 40% ou > 60%, la fonction est suspecte.",
        )

        self._av_msg = labeled_entry(parent, "Message original", "Hello, World!")
        action_btn(
            parent,
            "⚡ Flip bit-0 et comparer les hashs",
            self._do_avalanche,
            C["accent"],
        )
        ctk.CTkLabel(
            parent,
            text="Résultat (modification: bit-0 du 1er octet inversé)",
            font=font(12),
            text_color=C["sub"],
        ).pack(anchor="w", padx=14)
        self._av_out = output_box(parent, 300)

    def _do_avalanche(self):
        msg = self._av_msg.get()
        results = avalanche(msg)
        ba = bytearray(msg.encode())
        ba[0] ^= 0x01
        lines = [
            f'Original : "{msg}"',
            f'Modifié  : "{ba.decode(errors="replace")}"  (bit 0 inversé)',
            f'{"─" * 66}',
        ]
        for name, h1, h2, diff, total, pct in results:
            bar = "█" * int(20 * pct / 100)
            rest = "░" * (20 - len(bar))
            lines.append(
                f"\n{name:10}: {diff:3d}/{total} bits = {pct:5.1f}%  [{bar}{rest}]"
            )
            lines.append(f"  H(orig) : {h1[:52]}...")
            lines.append(f"  H(modif): {h2[:52]}...")
        write(self._av_out, "\n".join(lines))

    # ── HMAC + Benchmark ───────────────────────────────────────────────────────

    def _build_hmac(self, parent):
        info_label(
            parent,
            "ℹ️  HMAC(K, M) = H((K⊕opad) ∥ H((K⊕ipad) ∥ M)).  "
            "Garantit authentification + intégrité.  Utilisé dans: "
            "API REST (AWS SigV4), JWT, TLS record layer, IPsec, SSH.",
        )

        self._hm_msg = labeled_entry(parent, "Message", "Virement: 5000 DZD → Bob")
        self._hm_key = labeled_entry(parent, "Clé secrète", "cle_banque_secrete_2026")
        self._hm_algo = mode_selector(
            parent, ["MD5", "SHA-256", "SHA-512"], "SHA-256", "Algorithme de hachage"
        )

        btn_row(
            parent,
            ("🔐 Calculer HMAC", self._do_hmac, C["accent"]),
            ("✅ Vérifier (bonne clé)", self._ok_hmac, C["success"]),
            ("❌ Vérifier (mauvaise clé)", self._bad_hmac, C["danger"]),
        )
        ctk.CTkLabel(
            parent, text="Résultat HMAC", font=font(12), text_color=C["sub"]
        ).pack(anchor="w", padx=14)
        self._hm_out = output_box(parent, 140)
        self._hmac_val: str | None = None

        separator(parent)
        action_btn(
            parent,
            "⚡ Benchmark — tous les algos sur 10 Mo",
            self._run_bench,
            C["warn"],
            "black",
        )
        ctk.CTkLabel(
            parent, text="Résultats benchmark", font=font(12), text_color=C["sub"]
        ).pack(anchor="w", padx=14)
        self._bench_out = output_box(parent, 180)

    def _do_hmac(self):
        algo = self._hm_algo.get()
        self._hmac_val = compute_hmac(self._hm_msg.get(), self._hm_key.get(), algo)
        write(
            self._hm_out,
            f"Message       : {self._hm_msg.get()}\n"
            f"Clé           : {self._hm_key.get()}\n"
            f"HMAC-{algo:6}  : {self._hmac_val}\n\n"
            f"💡  Sans la clé secrète, impossible de forger ce MAC.\n"
            f"    Modifier le message ou la clé → HMAC complètement différent.",
        )

    def _ok_hmac(self):
        if self._hmac_val is None:
            write(self._hm_out, "Calculez d'abord un HMAC!")
            return
        algo = self._hm_algo.get()
        ok = verify_hmac(self._hm_msg.get(), self._hm_key.get(), algo, self._hmac_val)
        write(
            self._hm_out,
            f"HMAC attendu : {self._hmac_val}\n"
            f"HMAC calculé : {compute_hmac(self._hm_msg.get(), self._hm_key.get(), algo)}\n\n"
            + (
                "✅  VALIDE — Intégrité et authenticité confirmées!"
                if ok
                else "❌  INVALIDE (ne devrait pas arriver ici)!"
            ),
        )

    def _bad_hmac(self):
        if self._hmac_val is None:
            write(self._hm_out, "Calculez d'abord un HMAC!")
            return
        algo = self._hm_algo.get()
        wrong_key = self._hm_key.get() + "_attaquant"
        got = compute_hmac(self._hm_msg.get(), wrong_key, algo)
        ok = verify_hmac(self._hm_msg.get(), wrong_key, algo, self._hmac_val)
        write(
            self._hm_out,
            f"Clé utilisée : «{wrong_key}»  (mauvaise!)\n"
            f"HMAC attendu : {self._hmac_val}\n"
            f"HMAC calculé : {got}\n\n"
            + (
                "❌  INVALIDE — Falsification détectée!"
                if not ok
                else "VALIDE (anomalie!)"
            ),
        )

    def _run_bench(self):
        write(self._bench_out, "⏳ Benchmark en cours (10 Mo)...")
        self.after(50, self._do_bench)

    def _do_bench(self):
        results = benchmark(mb=10)
        mx = results[0][1]
        medals = ["🥇", "🥈", "🥉"] + ["  "] * 10
        out = "⚡ Benchmark sur 10 Mo (trié par débit):\n\n"
        for i, (name, speed, ms) in enumerate(results):
            bar = "█" * int(28 * speed / mx)
            out += (
                f"  {medals[i]} {name:10}  {speed:7.1f} Mo/s  ({ms:5.1f} ms)  {bar}\n"
            )
        write(self._bench_out, out)
