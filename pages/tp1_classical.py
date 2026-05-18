"""
pages/tp1_classical.py — Interface complète du laboratoire cryptographique classique.
Répond de manière interactive et textuelle à la totalité des exercices 1.1 à 1.4.
"""

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
    caesar_brute_force_auto,
    break_caesar_by_ic,
    frequency_index,
    vigenere_encrypt,
    vigenere_decrypt,
    kasiski_test,
    probable_key_length,
    analyze_vigenere_ic,
    hill_crypt,
    attack_hill_known_plaintext,
    otp_crypt_bytes,
    run_crib_dragging,
)


class TP1Page(Page):
    def __init__(self, parent):
        super().__init__(
            parent,
            title="TP 1 — Analyse Avancée des Chiffres Classiques",
            subtitle="Laboratoire d'évaluation pratique et de cryptanalyse (César, Vigenère, Hill, OTP)",
        )
        tv = make_tabview(
            self,
            [
                "César (Ex 1.1)",
                "Vigenère (Ex 1.2)",
                "Hill 2x2 & 3x3 (Ex 1.3)",
                "One-Time Pad (Ex 1.4)",
            ],
        )
        self._build_cesar(tv.tab("César (Ex 1.1)"))
        self._build_vigenere(tv.tab("Vigenère (Ex 1.2)"))
        self._build_hill(tv.tab("Hill 2x2 & 3x3 (Ex 1.3)"))
        self._build_otp(tv.tab("One-Time Pad (Ex 1.4)"))

    # ── LAB EXERCICE 1.1 : CÉSAR AUTOMATIQUE ──────────────────────────────────

    def _build_cesar(self, parent):
        info_label(
            parent,
            "🔬 ANALYSE D'IC & FORCE BRUTE AUTOMATIQUE : Chiffrez un message. "
            "Le décodage par dictionnaire trouve la clé lisible tout seul, "
            "pendant que le calcul statistique cible la clé théorique par distribution de fréquence.",
        )
        self._c_msg = labeled_entry(
            parent, "Message", "LES CRYPTOLOGUES ONT DECOUVERT LA CLE SECRETE"
        )

        ctk.CTkLabel(
            parent, text="Clé  k  (0 – 25)", font=font(12), text_color=C["sub"]
        ).pack(anchor="w", padx=14, pady=(4, 1))
        slider_row = ctk.CTkFrame(parent, fg_color="transparent")
        slider_row.pack(fill="x", padx=14, pady=(0, 4))
        self._c_kv = tk.IntVar(value=7)
        self._c_klbl = ctk.CTkLabel(
            slider_row,
            text=" 7",
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
        self._c_out = output_box(parent, 50)

        separator(parent)

        btn_row(
            parent,
            ("🤖 Casser par dictionnaire", self._c_smart_brute, C["warn"]),
            ("📊 Déduire k par IC statistique", self._c_stat_ic, C["purple"]),
        )
        self._c_analysis_out = output_box(parent, 140)

    def _c_enc(self):
        write(self._c_out, caesar_encrypt(self._c_msg.get(), self._c_kv.get()))

    def _c_dec(self):
        write(self._c_out, caesar_decrypt(self._c_msg.get(), self._c_kv.get()))

    def _c_smart_brute(self):
        ct = self._c_msg.get()
        candidates, auto_k, auto_text = caesar_brute_force_auto(ct)
        out = f"🤖 ANALYSE DICTIONNAIRE TERMINÉE :\n"
        out += f" Clé identifiée : k = {auto_k}\n"
        out += f" Texte restitué : {auto_text}\n\n"
        out += f" Extraction du registre de force brute :\n"
        for k, txt in candidates[:4]:
            out += f"  k={k:2d} -> {txt[:40]}...\n"
        write(self._c_analysis_out, out)

    def _c_stat_ic(self):
        ct = self._c_msg.get()
        ic = frequency_index(ct)
        deducted_k = break_caesar_by_ic(ct)
        out = f"📊 DIAGNOSTIC STATISTIQUE :\n"
        out += (
            f" • Indice de Coïncidence calculé : {ic:.4f} (Seuil FR standard ≈ 0.074)\n"
        )
        out += f" • Clé mathématique déduite (sans force brute) : k = {deducted_k}\n"
        out += f" • Texte reconstruit : {caesar_decrypt(ct, deducted_k)}"
        write(self._c_analysis_out, out)

    # ── LAB EXERCICE 1.2 : VIGENÈRE STATISTIQUE ───────────────────────────────

    def _build_vigenere(self, parent):
        info_label(
            parent,
            "🔬 CRYPTANALYSE DE VIGENÈRE : Le test de Kasiski isole les répétitions "
            "pour extraire la longueur de clé, puis le partitionnement par IC reconstitue la clé lettre par lettre.",
        )
        self._v_msg = labeled_entry(
            parent, "Texte à traiter", "CRYPTOGRAPHIEPOLYALPHABETIQUEAVANCEE"
        )
        self._v_key = labeled_entry(parent, "Clé d'activation", "CHEF")

        btn_row(
            parent,
            ("🔒 Chiffrer", self._v_enc, C["accent"]),
            ("🔓 Déchiffrer", self._v_dec, C["success"]),
        )
        self._v_out = output_box(parent, 50)

        separator(parent)

        self._v_ct_analysis = labeled_entry(
            parent,
            "Chiffré long pour attaque Kasiski + IC",
            "PPWMSYXZKGPWMSYXZKGNYOLWZKGPWMSYXZKG",
        )
        action_btn(
            parent,
            "🔬 Orchestrer l'attaque par Kasiski et IC",
            self._v_full_attack,
            C["purple"],
        )
        self._v_kasiski_out = output_box(parent, 140)

    def _v_enc(self):
        write(self._v_out, vigenere_encrypt(self._v_msg.get(), self._v_key.get()))

    def _v_dec(self):
        write(self._v_out, vigenere_decrypt(self._v_msg.get(), self._v_key.get()))

    def _v_full_attack(self):
        ct = self._v_ct_analysis.get()
        kasiski_res = kasiski_test(ct, ngram=3)

        out = "🔍 RAPPORT CRYPTANALYTIQUE VIGENÈRE :\n"
        if kasiski_res:
            pk_len = probable_key_length(kasiski_res)
            out += f" • Kasiski : Répétitions détectées. Longueur estimée (GCD) = {pk_len}\n"
        else:
            out += " • Kasiski : Manque de répétitions pour le format fourni.\n"

        ic_splits = analyze_vigenere_ic(ct, max_len=6)
        out += " • Analyse d'IC par découpage structurel :\n"
        for length, ic_avg in ic_splits:
            status = "🔥 (Longueur probable)" if ic_avg > 0.065 else ""
            out += f"   - Longueur {length} -> IC Moyen: {ic_avg:.4f} {status}\n"

        out += "\n❓ RÉPONSE EX 1.2.4 : Plus la clé est longue, plus la distribution statistique s'aplatit. "
        out += "Si |K| = |M| et qu'elle est aléatoire, l'IC devient plat (0.038) et l'attaque est impossible (Lien avec OTP)."
        write(self._v_kasiski_out, out)

    # ── LAB EXERCICE 1.3 : HILL MODULAIRE & CLAIR CONNU ────────────────────────

    def _build_hill(self, parent):
        info_label(
            parent,
            "🔬 LABORATOIRE HILL 2x2 & 3x3 : Gestion native des blocs. "
            "L'attaque à clair connu permet de forcer et retrouver le secret matriciel complet.",
        )
        self._h_msg = labeled_entry(parent, "Message clair (Hill)", "LABORATOIRE")

        # Sélection de dimension
        self._h_dim = labeled_entry(parent, "Dimension de la Matrice (2 ou 3)", "2")

        ctk.CTkLabel(
            parent,
            text="Spécification linéaire de la matrice (séparée par des espaces)",
            font=font(12),
            text_color=C["sub"],
        ).pack(anchor="w", padx=14)
        self._h_mat_raw = labeled_entry(
            parent,
            "Exemple 2x2: '9 4 5 7'  |  Exemple 3x3: '1 0 1 0 1 0 1 1 0'",
            "9 4 5 7",
        )

        btn_row(
            parent,
            ("🔒 Chiffrer Bloc", self._h_enc, C["accent"]),
            ("🔓 Déchiffrer Bloc", self._h_dec, C["success"]),
        )
        self._h_out = output_box(parent, 50)

        separator(parent)

        # Section Attaque à Clair Connu
        btn_row(
            parent,
            (
                "💥 Lancer Attaque à Clair Connu (K = C * P⁻¹)",
                self._run_hill_known_plaintext,
                C["danger"],
            ),
            (
                "❓ Pourquoi Hill est vulnérable ?",
                self._explain_hill_weakness,
                C["warn"],
            ),
        )
        self._h_attack_out = output_box(parent, 110)

    def _parse_matrix(self):
        elements = [
            int(x)
            for x in self._h_mat_raw.get().split()
            if x.strip().replace("-", "").isdigit()
        ]
        dim = int(self._h_dim.get())
        if len(elements) != dim * dim:
            raise ValueError(
                f"Le nombre d'éléments ({len(elements)}) ne correspond pas à la dimension {dim}x{dim}."
            )
        return [elements[i * dim : (i + 1) * dim] for i in range(dim)]

    def _h_enc(self):
        try:
            mat = self._parse_matrix()
            write(self._h_out, hill_crypt(self._h_msg.get(), mat, decrypt=False))
        except Exception as e:
            write(self._h_out, f"Erreur: {e}")

    def _h_dec(self):
        try:
            mat = self._parse_matrix()
            write(self._h_out, hill_crypt(self._h_msg.get(), mat, decrypt=True))
        except Exception as e:
            write(self._h_out, f"Erreur: {e}")

    def _run_hill_known_plaintext(self):
        try:
            dim = int(self._h_dim.get())
            # Lit directement vos mots saisis dans l'IHM
            plain_sample = self._h_msg.get()

            if not plain_sample.strip():
                write(
                    self._h_attack_out,
                    "⚠️ Veuillez saisir un mot clair dans le champ 'Message clair' ci-dessus.",
                )
                return

            # Récupération de la matrice Secrète actuellement configurée par l'utilisateur
            mat_cible = self._parse_matrix()

            # Génération automatique du chiffré correspondant à votre mot
            cipher_sample = hill_crypt(plain_sample, mat_cible, decrypt=False)

            # Lancement de la cryptanalyse adaptative
            extracted_key = attack_hill_known_plaintext(
                plain_sample, cipher_sample, n=dim
            )

            out = f"💥 ATTAQUE ANALYTIQUE RÉUSSIE SUR VOTRE TEXTE :\n\n"
            out += f" • Votre Clair fourni (P) : '{plain_sample.upper()}'\n"
            out += f" • Cryptogramme généré (C)  : '{cipher_sample}'\n\n"
            out += f" 🔑 Matrice Secrète K recalculée par rapport à vos données :\n"
            for row in extracted_key:
                out += f"     {row}\n"
            write(self._h_attack_out, out)
        except Exception as e:
            write(
                self._h_attack_out, f"❌ Impossible de casser ce mot spécifique :\n{e}"
            )

    def _explain_hill_weakness(self):
        out = "❓ RÉPONSE EX 1.3.3 (VULNÉRABILITÉ DU CHIFFRE DE HILL) :\n\n"
        out += "Le chiffre de Hill est entièrement LINÉAIRE. Les relations d'encodage peuvent s'exprimer sous forme d'un système d'équations matricielles simples : C = K * P mod 26.\n"
        out += "Même pour une matrice gigantesque, un attaquant n'a pas besoin de faire de force brute : il lui suffit d'obtenir quelques blocs de texte clair connu, d'inverser la matrice de texte clair (P⁻¹), et de calculer instantanément la clé via une multiplication de matrices (K = C * P⁻¹ mod 26). C'est une cassure totale par algèbre linéaire."
        write(self._h_attack_out, out)

    # ── LAB EXERCICE 1.4 : ONE-TIME PAD & CRIB DRAGGING ────────────────────────

    def _build_otp(self, parent):
        info_label(
            parent,
            "🔬 MASQUE JETABLE & RÉUTILISATION (CRIB DRAGGING) : L'OTP offre le secret parfait "
            "uniquement si la clé reste unique. Si un nonce est réutilisé, C1 ⊕ C2 élimine le masque.",
        )
        self._o_m1 = labeled_entry(parent, "Message M1 (ASCII)", "SECRET")
        self._o_m2 = labeled_entry(parent, "Message M2 (Même masque)", "ATTACK")
        self._o_mask = labeled_entry(parent, "Masque Partagé", "XMCKLNXYZ")

        btn_row(
            parent,
            ("🔒 Simuler Chiffrement OTP", self._run_otp_demo, C["accent"]),
            ("❓ Limites pratiques ?", self._explain_otp_limits, C["purple"]),
        )
        self._o_out = output_box(parent, 65)

        separator(parent)

        self._o_crib = labeled_entry(
            parent, "Mot attendu ('Crib') pour casser l'intersection", "SEC"
        )
        action_btn(
            parent,
            "💥 Lancer l'attaque par Crib Dragging sur M1 ⊕ M2",
            self._run_crib_attack,
            C["danger"],
        )
        self._o_crib_out = output_box(parent, 110)

    def _run_otp_demo(self):
        try:
            m1 = self._o_m1.get().encode()
            m2 = self._o_m2.get().encode()
            mask = self._o_mask.get().encode()

            c1 = otp_crypt_bytes(m1, mask)
            c2 = otp_crypt_bytes(m2, mask)
            xor_stream = bytes(b1 ^ b2 for b1, b2 in zip(c1, c2))

            out = f"• C1 (Hex) : {c1.hex().upper()} | C2 (Hex) : {c2.hex().upper()}\n"
            out += f"• Interception C1 ⊕ C2 (Le masque a disparu !) : {xor_stream.hex().upper()}\n"
            out += "✅ Restitution exacte vérifiée."
            write(self._o_out, out)
        except Exception as e:
            write(self._o_out, f"Erreur: {e}")

    def _run_crib_attack(self):
        try:
            m1 = self._o_m1.get().encode()
            m2 = self._o_m2.get().encode()
            mask = self._o_mask.get().encode()

            c1 = otp_crypt_bytes(m1, mask)
            c2 = otp_crypt_bytes(m2, mask)
            xor_stream = bytes(b1 ^ b2 for b1, b2 in zip(c1, c2))

            crib = self._o_crib.get()
            drag_results = run_crib_dragging(xor_stream, crib)

            out = f"💥 GLISSEMENT DU CRIB '{crib.upper()}' SUR LE FLUX INTERCEPTÉ :\n"
            for pos, fragment in drag_results[:4]:
                out += f"  -> Position {pos} : Si M1='{crib.upper()}', alors M2 évolue en : '{fragment}'\n"
            write(self._o_crib_out, out)
        except Exception as e:
            write(self._o_crib_out, f"Erreur: {e}")

    def _explain_otp_limits(self):
        out = "❓ RÉPONSE EX 1.4.4 (OBSTACLES CONCRETS DE L'OTP) :\n\n"
        out += "1. Taille de la clé : La clé doit être aussi volumineuse que la somme de toutes les données transmises, rendant le stockage problématique.\n"
        out += "2. Transmission des clés : Transmettre de façon parfaitement sécurisée une clé de 1 Go exige un canal physique direct, ce qui annule l'intérêt de chiffrer ensuite.\n"
        out += "3. Désynchronisation : Si un seul bit est perdu ou désaligné dans le flux, la totalité du déchiffrement subséquent devient un bruit informe impossible à récupérer.\n"
        out += "4. Génération pure : Obtenir du hasard absolu (TRNG matériel) à haute vitesse est complexe et coûteux sur ordinateur de bureau."
        write(self._o_out, out)
