import tkinter as tk
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
)
from algorithms.classical import (
    caesar_encrypt,
    caesar_decrypt,
    caesar_brute_force,
    frequency_index,
    vigenere_encrypt,
    vigenere_decrypt,
    kasiski_test,
    probable_key_length,
    # New imports
    hill_encrypt,
    hill_decrypt,
    otp_encrypt,
    otp_decrypt,
)


class TP1Page(Page):
    def __init__(self, parent):
        super().__init__(
            parent,
            title="TP 1 — Chiffrement Classique",
            subtitle="César  ·  Vigenère  ·  Hill  ·  OTP",
        )
        # Added Hill and OTP to the tabs list
        tv = make_tabview(self, ["César", "Vigenère", "Hill", "One-Time Pad"])
        self._build_cesar(tv.tab("César"))
        self._build_vigenere(tv.tab("Vigenère"))
        self._build_hill(tv.tab("Hill"))
        self._build_otp(tv.tab("One-Time Pad"))

    # ── César ──────────────────────────────────────────────────────────────────

    def _build_cesar(self, parent):
        info_label(
            parent,
            "ℹ️  C = (M + k) mod 26 — substitution monoalphabétique.  "
            "Seulement 26 clés possibles → attaque par force brute triviale.  "
            "L'Indice de Coïncidence (IC ≈ 0.074 pour le français) permet "
            "de retrouver k sans tester toutes les clés.",
        )

        self._c_msg = labeled_entry(parent, "Message", "HELLO WORLD")

        # Key slider
        ctk.CTkLabel(
            parent, text="Clé  k  (0 – 25)", font=font(12), text_color=C["sub"]
        ).pack(anchor="w", padx=14, pady=(6, 1))
        slider_row = ctk.CTkFrame(parent, fg_color="transparent")
        slider_row.pack(fill="x", padx=14, pady=(0, 6))
        self._c_kv = tk.IntVar(value=3)
        self._c_klbl = ctk.CTkLabel(
            slider_row,
            text=" 3",
            width=30,
            font=font(13, "bold"),
            text_color=C["accent"],
        )
        self._c_klbl.pack(side="left")
        ctk.CTkSlider(
            slider_row,
            from_=0,
            to=25,
            number_of_steps=25,
            variable=self._c_kv,
            command=lambda v: self._c_klbl.configure(text=f"{int(float(v)):2d}"),
        ).pack(side="left", fill="x", expand=True, padx=8)

        btn_row(
            parent,
            ("🔒 Chiffrer", self._c_enc, C["accent"]),
            ("🔓 Déchiffrer", self._c_dec, C["success"]),
        )

        ctk.CTkLabel(parent, text="Résultat", font=font(12), text_color=C["sub"]).pack(
            anchor="w", padx=14
        )
        self._c_out = output_box(parent, 52)

        separator(parent)

        # Brute-force + IC
        action_btn(
            parent,
            "🔍 Force brute — 26 déclinaisons",
            self._c_brute,
            C["warn"],
            "black",
        )
        ctk.CTkLabel(
            parent,
            text="Toutes les clés (cherchez la ligne lisible):",
            font=font(12),
            text_color=C["sub"],
        ).pack(anchor="w", padx=14)
        self._c_brute_out = output_box(parent, 200)

        action_btn(
            parent, "📊 Indice de Coïncidence du chiffré", self._c_ic, C["purple"]
        )
        self._c_ic_out = output_box(parent, 60)

    def _c_enc(self):
        write(self._c_out, caesar_encrypt(self._c_msg.get(), self._c_kv.get()))

    def _c_dec(self):
        write(self._c_out, caesar_decrypt(self._c_msg.get(), self._c_kv.get()))

    def _c_brute(self):
        lines = [
            f"k={k:2d}  →  {pt}" for k, pt in caesar_brute_force(self._c_msg.get())
        ]
        write(self._c_brute_out, "\n".join(lines))

    def _c_ic(self):
        ct = self._c_msg.get()
        ic = frequency_index(ct)
        fr_ic = 0.074
        verdict = (
            "≈ IC français (texte naturel)"
            if abs(ic - fr_ic) < 0.01
            else "≠ IC français (texte chiffré/aléatoire)"
        )
        write(
            self._c_ic_out,
            f"IC du texte  : {ic:.4f}\n"
            f"IC du français: {fr_ic:.4f}\n"
            f"Verdict      : {verdict}",
        )

    # ── Vigenère ───────────────────────────────────────────────────────────────

    def _build_vigenere(self, parent):
        info_label(
            parent,
            "ℹ️  Ci = (Mi + Ki) mod 26 — poly-alphabétique.  "
            "Plus solide que César, mais le test de Kasiski révèle la longueur de clé, "
            "puis une analyse de fréquences par sous-séquence retrouve chaque lettre.  "
            "Quand |clé| = |message| → One-Time Pad (sécurité parfaite de Shannon).",
        )

        self._v_msg = labeled_entry(parent, "Message", "ATTACKATDAWN")
        self._v_key = labeled_entry(parent, "Clé (mot alphabétique)", "LEMON")

        btn_row(
            parent,
            ("🔒 Chiffrer", self._v_enc, C["accent"]),
            ("🔓 Déchiffrer", self._v_dec, C["success"]),
        )
        ctk.CTkLabel(parent, text="Résultat", font=font(12), text_color=C["sub"]).pack(
            anchor="w", padx=14
        )
        self._v_out = output_box(parent, 52)

        separator(parent)

        info_label(
            parent,
            "💡  Test de Kasiski: chercher des trigrammes répétés dans le chiffré.  "
            "La distance entre répétitions est un multiple de la longueur de clé.  "
            "Le GCD des distances donne la longueur probable.",
            color=C["warn"],
        )

        self._v_ct = labeled_entry(
            parent, "Texte chiffré à analyser (Kasiski)", "LXFOPVEFRNHRLXFOPVEFRNHR"
        )
        action_btn(parent, "🔬 Lancer le test de Kasiski", self._v_kasiski, C["purple"])
        self._v_kasiski_out = output_box(parent, 130)

    def _v_enc(self):
        try:
            write(self._v_out, vigenere_encrypt(self._v_msg.get(), self._v_key.get()))
        except Exception as e:
            write(self._v_out, f"Erreur: {e}")

    def _v_dec(self):
        try:
            write(self._v_out, vigenere_decrypt(self._v_msg.get(), self._v_key.get()))
        except Exception as e:
            write(self._v_out, f"Erreur: {e}")

    def _v_kasiski(self):
        ct = self._v_ct.get()
        result = kasiski_test(ct, ngram=3)
        if not result:
            write(
                self._v_kasiski_out,
                "Aucun trigramme répété trouvé (texte trop court ou aléatoire).",
            )
            return
        key_len = probable_key_length(result)
        lines = [f"Texte analysé: {ct}\n", "Trigrammes répétés:\n"]
        for gram, dists in list(result.items())[:6]:
            lines.append(f"  {gram}  →  distances: {dists}")
        lines.append(f"\nGCD des distances = {key_len}")
        lines.append(f"→ Longueur de clé probable : {key_len}")
        write(self._v_kasiski_out, "\n".join(lines))

    # ── Hill (2x2) ─────────────────────────────────────────────────────────────

    def _build_hill(self, parent):
        info_label(
            parent,
            "ℹ️  Chiffrement par blocs linéaires (substitution polygraphique). "
            "Un bloc de n lettres est multiplié par une matrice n×n inversible mod 26. "
            "Ici implanté avec une matrice 2×2. Si le message est impair, un 'X' est ajouté.",
        )

        self._h_msg = labeled_entry(parent, "Message", "CODE")

        # Grid layout for 2x2 Matrix entries
        ctk.CTkLabel(
            parent, text="Matrice Key K (2x2)", font=font(12), text_color=C["sub"]
        ).pack(anchor="w", padx=14, pady=(6, 2))

        grid_frame = ctk.CTkFrame(parent, fg_color="transparent")
        grid_frame.pack(anchor="w", padx=14, pady=(0, 10))

        # Matrix inputs: defaults to [[9, 4], [5, 7]] (invertible mod 26, det=43 = 17 mod 26)
        self._h_m11 = ctk.CTkEntry(grid_frame, width=50, justify="center")
        self._h_m11.insert(0, "9")
        self._h_m11.grid(row=0, column=0, padx=4, pady=4)

        self._h_m12 = ctk.CTkEntry(grid_frame, width=50, justify="center")
        self._h_m12.insert(0, "4")
        self._h_m12.grid(row=0, column=1, padx=4, pady=4)

        self._h_m21 = ctk.CTkEntry(grid_frame, width=50, justify="center")
        self._h_m21.insert(0, "5")
        self._h_m21.grid(row=1, column=0, padx=4, pady=4)

        self._h_m22 = ctk.CTkEntry(grid_frame, width=50, justify="center")
        self._h_m22.insert(0, "7")
        self._h_m22.grid(row=1, column=1, padx=4, pady=4)

        btn_row(
            parent,
            ("🔒 Chiffrer", self._h_enc, C["accent"]),
            ("🔓 Déchiffrer", self._h_dec, C["success"]),
        )

        ctk.CTkLabel(parent, text="Résultat", font=font(12), text_color=C["sub"]).pack(
            anchor="w", padx=14
        )
        self._h_out = output_box(parent, 52)

    def _get_hill_matrix(self):
        try:
            return [
                [int(self._h_m11.get()), int(self._h_m12.get())],
                [int(self._h_m21.get()), int(self._h_m22.get())],
            ]
        except ValueError:
            raise ValueError("Tous les champs de la matrice doivent être des entiers.")

    def _h_enc(self):
        try:
            matrix = self._get_hill_matrix()
            write(self._h_out, hill_encrypt(self._h_msg.get(), matrix))
        except Exception as e:
            write(self._h_out, f"Erreur: {e}")

    def _h_dec(self):
        try:
            matrix = self._get_hill_matrix()
            write(self._h_out, hill_decrypt(self._h_msg.get(), matrix))
        except Exception as e:
            write(self._h_out, f"Erreur: {e}")

    # ── One-Time Pad (OTP) ─────────────────────────────────────────────────────

    def _build_otp(self, parent):
        info_label(
            parent,
            "ℹ️  Le masque jetable offre une sécurité théorique parfaite (Shannon) "
            "si et seulement si la clé est aussi longue que le message, purement aléatoire, "
            "et utilisée une unique fois. Le chiffrement est effectué ici par addition mod 26.",
        )

        self._o_msg = labeled_entry(parent, "Message", "SECRET")
        self._o_key = labeled_entry(parent, "Clé Secrète (Même longueur)", "XMCKLN")

        btn_row(
            parent,
            ("🔒 Chiffrer", self._o_enc, C["accent"]),
            ("🔓 Déchiffrer", self._o_dec, C["success"]),
        )

        ctk.CTkLabel(parent, text="Résultat", font=font(12), text_color=C["sub"]).pack(
            anchor="w", padx=14
        )
        self._o_out = output_box(parent, 52)

    def _o_enc(self):
        try:
            write(self._o_out, otp_encrypt(self._o_msg.get(), self._o_key.get()))
        except Exception as e:
            write(self._o_out, f"Erreur: {e}")

    def _o_dec(self):
        try:
            write(self._o_out, otp_decrypt(self._o_msg.get(), self._o_key.get()))
        except Exception as e:
            write(self._o_out, f"Erreur: {e}")
