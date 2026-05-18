"""
pages/tp2_symmetric.py — Interface Laboratoire de Modification des Algorithmes.
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
)
from algorithms.symmetric import (
    AVAILABLE,
    derive_key,
    rc4_crypt_custom,
    simulate_wep_weakness,
    simulate_rc4_bias,
    des_crypt_advanced,
    des3_crypt_advanced,
    analyze_bit_avalanche,
    run_nist_param_factory,
    benchmark_custom_iterations,
)
import hashlib


class TP2Page(Page):
    def __init__(self, parent):
        super().__init__(
            parent,
            title="Laboratoire d'Analyse Algorithmique Symétrique",
            subtitle="Modifiez manuellement les paramètres internes et observez les vulnérabilités",
        )
        tv = make_tabview(
            self,
            [
                "Lab 1: RC4 & Biais",
                "Lab 2: DES & 3DES",
                "Lab 3: AES & Avalanche",
                "Lab 4: NIST & Tours",
                "Lab 5: Performances",
            ],
        )
        self._build_rc4_lab(tv.tab("Lab 1: RC4 & Biais"))
        self._build_des_lab(tv.tab("Lab 2: DES & 3DES"))
        self._build_aes_lab(tv.tab("Lab 3: AES & Avalanche"))
        self._build_nist_lab(tv.tab("Lab 4: NIST & Tours"))
        self._build_bench_lab(tv.tab("Lab 5: Performances"))

    # ── LAB 1 : RC4 ───────────────────────────────────────────────────────────

    def _build_rc4_lab(self, parent):
        info_label(
            parent,
            "🧪 PARAMÈTRES RC4 : Modifiez la clé ou augmentez le 'Drop Bytes' pour purger "
            "les premiers octets biaisés du flux (méthode de protection face aux attaques WEP).",
        )
        self._rc4_key = labeled_entry(
            parent, "Clé de chiffrement (ASCII)", "CleSecreteRC4"
        )
        self._rc4_drop = labeled_entry(
            parent, "Octets jetés du Keystream (RC4-Drop)", "0"
        )
        self._rc4_plain = labeled_entry(
            parent, "Texte clair à traiter", "Message Chiffré par Flot"
        )

        btn_row(
            parent,
            ("🔑 Exécuter RC4 & Analyser S", self._run_rc4_experiment, C["success"]),
            ("📊 Lancer Test Biais (10k)", self._run_rc4_biases, C["accent"]),
        )
        self._rc4_out = output_box(parent, 180)

    def _run_rc4_experiment(self):
        k_input = self._rc4_key.get().encode()
        drop = int(self._rc4_drop.get() if self._rc4_drop.get().isdigit() else 0)
        plain = self._rc4_plain.get().encode()

        ct, final_S = rc4_crypt_custom(k_input, plain, drop_bytes=drop)
        wep_weak = simulate_wep_weakness()

        out = f"📊 RÉSULTATS DE L'EXPÉRIMENTATION RC4 :\n\n"
        out += f"• Cryptogramme produit (Hex) : {ct.hex()}\n"
        out += f"• État initial partiel de S : {final_S[:12]}...\n"
        out += f"• Statut RC4-Drop : {'❌ Vulnérable (Aucun octet jeté)' if drop == 0 else f'✅ Sécurisé ({drop} octets jetés)'}\n\n"
        out += "❌ Corrélation clés/IV faibles (Simulation WEP) :\n"
        for iv, fb in wep_weak:
            out += f"  - IV Faible: {iv} -> 1er octet généré: {hex(fb)}\n"
        write(self._rc4_out, out)

    def _run_rc4_biases(self):
        biases = simulate_rc4_bias()
        out = (
            "📊 Échantillonnage statistique du 2e octet (10 000 clés aléatoires) :\n\n"
        )
        for val, count in biases.items():
            out += f"  - Valeur {hex(val)} : Occurence {count} fois\n"
        out += "\n💡 Note de cours : Le second octet a une probabilité de dérive vers 0x00 doublée. Raison de son bannissement total dans TLS 1.3."
        write(self._rc4_out, out)

    # ── LAB 2 : DES & 3DES-CBC ────────────────────────────────────────────────

    def _build_des_lab(self, parent):
        info_label(
            parent,
            "🧪 PARAMÈTRES DES & 3DES : Injectez un IV (8 octets). "
            "Basculez sur '3DES-CBC' pour exécuter la triple passe (K1, K2, K3) en mode CBC.",
        )
        self._des_mode = labeled_entry(
            parent, "Algorithme et Mode (ECB / CBC / 3DES-CBC)", "3DES-CBC"
        )
        self._des_iv = labeled_entry(
            parent, "Vecteur d'Initialisation (IV) - 8 octets", "12345678"
        )
        self._des_plain = labeled_entry(
            parent,
            "Texte clair à chiffrer (128 octets recommandés)",
            "CYBERSECURITY_LAB_TEST_3DES_CBC_MODE_PASSPHRASE",
        )

        action_btn(
            parent,
            "🔬 Exécuter et Analyser les Blocs",
            self._run_des_experiment,
            C["accent"],
        )
        self._des_out = output_box(parent, 180)

    def _run_des_experiment(self):
        mode = self._des_mode.get().upper().strip()
        iv = self._des_iv.get().encode()
        plain = self._des_plain.get().encode()

        if len(iv) != 8:
            write(
                self._des_out,
                "⚠️ Erreur : L'IV doit faire exactement 8 octets pour DES et Triple-DES.",
            )
            return

        if mode == "3DES-CBC":
            k_3des = derive_key("master_key_3des", 192)
            ct = des3_crypt_advanced(plain, k_3des, iv)
        else:
            k_des = derive_key("key_des", 64)
            ct = des_crypt_advanced(plain, k_des, mode, iv)

        out = f"📊 ANALYSE STRUCTURELLE (Option sélectionnée: {mode}) :\n\n"
        out += f"• Cryptogramme (Hex) : {ct.hex()}\n\n"
        out += "• Découpage par blocs de 64-bits (8 octets) :\n"
        for i in range(0, len(ct), 8):
            out += f"  -> Bloc {i//8 + 1} : {ct[i:i+8].hex()}\n"

        if mode == "ECB":
            out += "\n⚠️ Constat : En mode ECB, les motifs identiques se répètent à l'identique dans le chiffrement."
        elif mode == "3DES-CBC":
            out += "\n✅ Avantage : Le mode 3DES-CBC applique l'enchaînement des blocs (CBC) combiné à un chiffrement-déchiffrement-chiffrement (EDE) qui repousse la vulnérabilité du DES standard."
        write(self._des_out, out)

    # ── LAB 3 : AES & AVALANCHE PAR BIT ───────────────────────────────────────

    def _build_aes_lab(self, parent):
        info_label(
            parent,
            "🧪 EFFET D'AVALANCHE : Indiquez précisément l'indice du bit à inverser (0 à 127) "
            "au sein du premier bloc pour mesurer l'impact de la diffusion selon le mode.",
        )
        self._aes_mode = labeled_entry(
            parent, "Sélection du Mode (ECB / CBC / CTR)", "CBC"
        )
        self._aes_bit = labeled_entry(
            parent, "Position du bit à corrompre (0-127)", "0"
        )
        self._aes_plain = labeled_entry(
            parent,
            "Message (Min. 32 caractères requis)",
            "Laboratoire de verification de la diffusion AES 2026",
        )

        action_btn(
            parent,
            "💥 Injecter la corruption et mesurer l'impact",
            self._run_aes_avalanche_lab,
            C["danger"],
        )
        self._aes_out = output_box(parent, 180)

    def _run_aes_avalanche_lab(self):
        mode = self._aes_mode.get().upper().strip()
        bit_pos = int(self._aes_bit.get() if self._aes_bit.get().isdigit() else 0)
        plain = self._aes_plain.get().encode()
        key = hashlib.sha256(b"lab_key").digest()

        analysis = analyze_bit_avalanche(plain, key, mode, bit_pos)

        out = f"📊 COMPORTEMENT DE L'AVALANCHE AES (Mode: {mode}) :\n"
        out += f"Inversion chirurgicale du bit unique n°{bit_pos} du bloc d'entrée.\n\n"

        for res in analysis:
            bar = "█" * int(res["bit_flip_percentage"] / 4)
            out += f"  [Bloc {res['block']}] Mutation: {res['bit_flip_percentage']:5.1f}% | {bar}\n"
            out += f"         Masque XOR de différence : {res['hex_diff'][:32]}...\n"

        write(self._aes_out, out)

    # ── LAB 4 : NIST FINALISTES & TOURS ───────────────────────────────────────

    def _build_nist_lab(self, parent):
        info_label(
            parent,
            "🧪 RÉGLAGE DES TOURS (ROUNDS) : Diminuez le nombre de tours de calcul pour évaluer "
            "le seuil de diffusion minimal des finalistes du concours NIST.",
        )
        self._nist_rounds = labeled_entry(
            parent, "Nombre personnalisé de tours (Rounds)", "3"
        )
        self._nist_plain = labeled_entry(
            parent, "Bloc de test (16 octets)", "DonneesTestNist26"
        )

        action_btn(
            parent,
            "🔍 Simuler le traitement architectural des candidats",
            self._run_nist_rounds_lab,
            C["accent"],
        )
        self._nist_out = output_box(parent, 180)

    def _run_nist_rounds_lab(self):
        rounds = int(
            self._nist_rounds.get() if self._nist_rounds.get().isdigit() else 4
        )
        plain = self._nist_plain.get().encode()
        key = b"eval_key_2026"

        ciphertexts = run_nist_param_factory(plain, key, custom_rounds=rounds)

        out = f"📊 ÉTAT DES SIGNATURES DES FINALISTES (Tours simulés: {rounds}) :\n\n"
        for algo, ct in ciphertexts.items():
            out += f"  🔹 {algo:15} -> [Bloc Sortie]: {ct.hex()}\n"
        write(self._nist_out, out)

    # ── LAB 5 : PERFORMANCE BENCHMARK (AUTOMATISÉ POUR TOUS LES MODES) ────────

    def _build_bench_lab(self, parent):
        info_label(
            parent,
            "🧪 BENCHMARK COMPARATIF GLOBAL : Calcule et compare automatiquement les performances "
            "de DES-ECB, DES-CBC et Triple-DES (3DES-CBC) face à l'AES.",
        )
        self._bench_mb = labeled_entry(
            parent, "Volume de données à traiter (Mo)", "1.0"
        )
        self._bench_rounds = labeled_entry(
            parent, "Nombre de tours AES pour le test", "14"
        )

        action_btn(
            parent,
            "⚡ Lancer le Benchmark Simultané",
            self._run_custom_bench,
            C["success"],
        )
        self._bench_out = output_box(parent, 180)

    def _run_custom_bench(self):
        try:
            mb = float(self._bench_mb.get())
            rounds = int(self._bench_rounds.get())

            write(
                self._bench_out,
                "⏳ Calcul des débits en cours pour l'ensemble des primitives...",
            )
            self.after(50, lambda: self._do_custom_bench(mb, rounds))
        except Exception as e:
            write(self._bench_out, f"Erreur de paramètres : {e}")

    def _do_custom_bench(self, mb, rounds):
        bench_results = benchmark_custom_iterations(mb, rounds)
        out = f"⚡ RÉSULTATS DU BENCHMARK COMPLÈT (Données d'évaluation: {mb} Mo) :\n\n"
        for name, speed in bench_results.items():
            bar = "█" * int(min(25, speed * 2))
            out += f"  {name:22} : {speed:6.1f} Mo/s  {bar}\n"
        out += "\n💡 Constatations pédagogiques :\n"
        out += " - DES-ECB et DES-CBC affichent des vitesses proches, mais CBC apporte la sécurité de l'enchaînement.\n"
        out += " - 3DES-CBC est ~3x plus lent que le DES standard en raison du cycle d'exécution triple (EDE)."
        write(self._bench_out, out)
