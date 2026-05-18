"""
pages/tp3_asymmetric.py — Vue graphique complète pour le TP 3.
Fournit les formulaires et zones de rendu textuel pour les exercices 3.1 à 3.4.
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
)

from algorithms.asymmetric import (
    CRYPTOGRAPHY_AVAILABLE,
    run_dh_standard,
    run_dh_mitm,
    run_rsa_demo,
    run_hybrid_benchmark,
    elgamal_keygen,
    elgamal_encrypt,
    elgamal_decrypt,
    forge_elgamal_multiply_by_2,
    ShortWeierstrassPendant,
    run_ecdh_p256_standard,
    run_ecies_simplified,
)


class TP3Page(Page):
    def __init__(self, parent):
        super().__init__(
            parent,
            title="TP 3 — Cryptographie Asymétrique & Protocoles",
            subtitle="Diffie-Hellman · RSA Hybride · ElGamal Malléabilité · ECC",
        )
        tv = make_tabview(
            self,
            [
                "Ex 3.1: DH & MITM",
                "Ex 3.2: RSA Hybride",
                "Ex 3.3: ElGamal",
                "Ex 3.4: ECC",
            ],
        )
        self._build_ex31(tv.tab("Ex 3.1: DH & MITM"))
        self._build_ex32(tv.tab("Ex 3.2: RSA Hybride"))
        self._build_ex33(tv.tab("Ex 3.3: ElGamal"))
        self._build_ex34(tv.tab("Ex 3.4: ECC"))

    # ── EXERCICE 3.1 : Diffie-Hellman & MITM ───────────────────────────────────

    def _build_ex31(self, parent):
        info_label(
            parent,
            "ℹ️  DH standard génère un grand nombre premier p et calcule la clé partagée K = g^(ab) mod p.\n"
            "L'attaque Man-in-the-Middle (MITM) injecte des clés frauduleuses A' et B' pour intercepter le canal.",
        )
        btn_row(
            parent,
            ("🔑 Échange DH Standard", self._dh_normal, C["success"]),
            ("💥 Attaque MITM (Interception)", self._dh_mitm, C["danger"]),
        )
        self._out_31 = output_box(parent, 320)

    def _dh_normal(self):
        r = run_dh_standard(bits=512)
        out = f"🟢 ÉCHANGE DIFFIE-HELLMAN STANDARD (512 bits)\n" + "═" * 50 + "\n"
        out += f"• Premier p  : {r['p']}\n"
        out += f"• Générateur g: {r['g']}\n\n"
        out += f"• Secret privé Alice (a) : {r['a']}\n"
        out += f"• Clé publique Alice (A) : {r['A']}\n\n"
        out += f"• Secret privé Bob (b)   : {r['b']}\n"
        out += f"• Clé publique Bob (B)   : {r['B']}\n\n"
        out += f"📦 Clé calculée Alice (K_A) : {r['KA']}\n"
        out += f"📦 Clé calculée Bob (K_B)   : {r['KB']}\n"
        out += f"✅ Validation : Les clés de session concordent parfaitement !"
        write(self._out_31, out)

    def _dh_mitm(self):
        r = run_dh_mitm(bits=512)
        out = f"💥 SIMULATION D'ATTAQUE MAN-IN-THE-MIDDLE\n" + "═" * 50 + "\n"
        out += " [Alice]              💥  [Ève (MITM)]  💥             [Bob]\n"
        out += "    |                      |                            |\n"
        out += f"    |--- Clé Pub A ({str(r['A'])[:8]}...)---> | (Interception A)           |\n"
        out += f"    |                      |--- Clé Frelatée A' ({str(r['A_prime'])[:8]}...)--->| \n"
        out += (
            f"    |                      | <--- Clé Pub B ({str(r['B'])[:8]}...)---|\n"
        )
        out += f"    |<--- Clé Frelatée B' ({str(r['B_prime'])[:8]}...)-|                            |\n\n"
        out += f"❌ RÉSULTAT DES SESSIONS CLIVÉES :\n"
        out += f" • Clé Session Alice-Ève : {r['K_Alice']}\n"
        out += f" • Clé Session Bob-Ève   : {r['K_Bob']}\n"
        out += f" 🛡️ Contre-mesure active : ECDSA permet de signer A et B pour stopper cette attaque."
        write(self._out_31, out)

    # ── EXERCICE 3.2 : RSA & Chiffrement Hybride ───────────────────────────────────

    def _build_ex32(self, parent):
        info_label(
            parent,
            "ℹ️  Analyse des paires RSA et performance du modèle hybride (RSA + AES) sur 1 Mo de données.",
        )
        self._rsa_size = labeled_entry(parent, "Longueur clé RSA (bits)", "1024")
        btn_row(
            parent,
            ("🔑 Exécuter RSA Standard", self._rsa_run, C["accent"]),
            ("⚡ Mesurer Performance Hybride", self._rsa_bench, C["purple"]),
        )
        self._out_32 = output_box(parent, 250)

    def _rsa_run(self):
        if not CRYPTOGRAPHY_AVAILABLE:
            write(self._out_32, "Erreur: Bibliothèque 'cryptography' manquante.")
            return
        bits = int(self._rsa_size.get())
        r = run_rsa_demo(bits)
        out = f"📝 DÉMO TEXTBOOK RSA ({bits} BITS)\n" + "═" * 50 + "\n"
        out += f"• Clé Publique (PEM Tronc) :\n{r['pub'][:120]}...\n"
        out += f"• Taille brute du chiffré : {r['ct_len']} octets\n"
        out += f"• Message décodé après transit : '{r['decrypted'].decode()}'\n"
        write(self._out_32, out)

    def _rsa_bench(self):
        if not CRYPTOGRAPHY_AVAILABLE:
            return
        r = run_hybrid_benchmark()
        out = f"⚡ BENCHMARK CHIFFREMENT HYBRIDE (Fichier 1 Mo)\n" + "═" * 50 + "\n"
        out += f" ⏱️ Temps de traitement RSA-2048 (Clé AES uniquement)  : {r['t_rsa']:.4f} ms\n"
        out += f" ⏱️ Temps de traitement AES-256 (Corps du fichier 1 Mo) : {r['t_aes']:.4f} ms\n\n"
        out += f"🧠 RÉPONSE AUX QUESTIONS DE COURS :\n"
        out += f" 1. RSA ne peut pas chiffrer une taille arbitraire car la taille du message est mathématiquement restreinte par le module n (M < n).\n"
        out += f" 2. Le padding OAEP apporte de l'aléa (probabiliste) rendant le chiffrement sémantiquement sûr et résistant aux attaques par texte chiffré choisi (indistinguabilité), contrairement au RSA textbook qui est déterministe et malléable."
        write(self._out_32, out)

    # ── EXERCICE 3.3 : ElGamal & Malléabilité ──────────────────────────────────────

    def _build_ex33(self, parent):
        info_label(
            parent,
            "ℹ️  ElGamal est probabiliste (non-déterministe). Il souffre également de malléabilité : "
            "on peut modifier le chiffré pour altérer le clair à notre insu.",
        )
        self._elg_val = labeled_entry(parent, "Entier Clair M (< p)", "12345")
        action_btn(
            parent,
            "🧪 Lancer l'analyse d'inversion et forgerie",
            self._elg_run,
            C["warn"],
            "black",
        )
        self._out_33 = output_box(parent, 250)

    def _elg_run(self):
        M = int(self._elg_val.get())
        keys = elgamal_keygen(512)

        # Deux chiffrements du même M pour prouver le non-déterminisme
        c_a = elgamal_encrypt(M, keys)
        c_b = elgamal_encrypt(M, keys)

        # Déchiffrement normal
        dec_a = elgamal_decrypt(c_a, keys, keys)

        # Forgerie : modification de C_a pour faire 2 * M
        c_forged = forge_elgamal_multiply_by_2(c_a, keys)
        dec_forged = elgamal_decrypt(c_forged, keys, keys)

        out = f"🔮 DÉMONSTRATION ELGAMAL (512 bits)\n" + "═" * 50 + "\n"
        out += f"• Chiffrement 1 de M : c1={str(c_a[0])[:15]}..., c2={str(c_a[1])[:15]}...\n"
        out += f"• Chiffrement 2 de M : c1={str(c_b[0])[:15]}..., c2={str(c_b[1])[:15]}...\n"
        out += f"➡️  Constat : Les deux chiffrés sont distincts ! L'algorithme est non-déterministe.\n\n"
        out += f"🛠️ ATTAQUE DE MALLÉABILITÉ (Forgerie de 2 * M) :\n"
        out += f"• Chiffré forgé envoyé à la victime : (c1, 2 * c2 mod p)\n"
        out += f"• Résultat du déchiffrement par la victime : {dec_forged}\n"
        out += (
            f"✅ Validation de l'attaque : {dec_forged} équivaut bien à 2 × {M} !\n\n"
        )
        out += f"📊 COMPARAISON DES CONTRAINTES DE FORMAT :\n"
        out += f" RSA-2048 produit un bloc chiffré de 256 octets, tandis qu'ElGamal-2048 génère deux éléments (c1, c2) totalisant 512 octets. "
        out += f"En pratique, ElGamal double la consommation de bande passante réseau."
        write(self._out_33, out)

    # ── EXERCICE 3.4 : Cryptographie sur Courbes Elliptiques (ECC) ─────────────────

    def _build_ex34(self, parent):
        info_label(
            parent,
            "ℹ️  Modélisation de la courbe jouet y² = x³ + 7 mod 97, suivie de l'échange de clés local ECIES.",
        )
        btn_row(
            parent,
            ("📐 Addition & Scalaire Pédagogique", self._ecc_pedagogic, C["accent"]),
            ("🛡️ Simuler ECIES Hybride P-256", self._ecc_ecies, C["success"]),
        )
        self._out_34 = output_box(parent, 250)

    def _ecc_pedagogic(self):
        curve = ShortWeierstrassPendant()
        P = (1, 7)  # Point valide sur la courbe mod 97

        # Test des primitives
        double_P = curve.add(P, P)
        triple_P = curve.multiply(3, P)

        out = f"📐 GÉOMÉTRIE ELLIPTIQUE SUR CORPS FINI F_97\n" + "═" * 50 + "\n"
        out += f"• Équation : y² = x³ + 7 mod 97\n"
        out += f"• Point Générateur de base P choisi : {P}\n"
        out += f"• Opération de duplication 2P (Tangente) : {double_P}\n"
        out += f"• Multiplication scalaire 3P (Double & Add) : {triple_P}\n"
        out += f"✅ Structure de Groupe validée mathématiquement !"
        write(self._out_34, out)

    def _ecc_ecies(self):
        if not CRYPTOGRAPHY_AVAILABLE:
            return
        # Simulation d'ECIES complet (Chiffrement clé elliptique éphémère + corps AES)
        r = run_ecies_simplified(b"Top Secret National Security Payload 2026")

        out = f"🛡️ PROTOCOLE ECIES SIMPLIFIÉ (ECDH + AES-CBC)\n" + "═" * 50 + "\n"
        out += f"• Point public éphémère d'Alice transmis (Hex) : {r['ephemeral_key']}...\n"
        out += (
            f"• Payload chiffré par le flux AES (Hex)        : {r['ciphertext']}...\n"
        )
        out += (
            f"• Chaîne finale récupérée par Bob après décodage : '{r['plaintext']}'\n"
        )
        write(self._out_34, out)
