"""
pages/tp6_application.py — Laboratoire applicatif avancé (TP 6).
Fournit un environnement d'expérimentation réseau interactif pour les démonstrations.
"""

import customtkinter as ctk
import threading
import time
import random
import hashlib
import hmac as hmac_lib
import socket
import json
import os

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
    paillier_keygen,
    paillier_encrypt,
    paillier_decrypt,
    CRYPTOGRAPHY_AVAILABLE,
)

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.backends import default_backend

    AES_AVAILABLE = True
except ImportError:
    AES_AVAILABLE = False


class TP6Page(Page):
    def __init__(self, parent):
        super().__init__(
            parent,
            title="TP 6 — Suite de Sécurisation Applicative Interactive",
            subtitle="Laboratoire d'expérimentation pour démonstration réseau & cryptographique",
        )

        tv = make_tabview(
            self,
            [
                "🟢 6.1 Sockets TCP",
                "🔵 6.2 Bluetooth (Sim)",
                "📡 6.3 Chat Wi-Fi (UDP Réel)",
                "🗳️ 6.4 Scrutin Homomorphe",
            ],
        )

        self._build_ex61(tv.tab("🟢 6.1 Sockets TCP"))
        self._build_ex62(tv.tab("🔵 6.2 Bluetooth (Sim)"))
        self._build_ex63(tv.tab("📡 6.3 Chat Wi-Fi (UDP Réel)"))
        self._build_ex64(tv.tab("🗳️ 6.4 Scrutin Homomorphe"))

        # Clés symétriques partagées pour le chat
        self.k_enc = b"0123456789abcdef0123456789abcdef"
        self.k_mac = b"secret_mac_shared_key_established"

    # ── EXERCICE 6.1 : Sockets TCP/IP Sécurisés ──────────
    def _build_ex61(self, parent):
        info_label(
            parent,
            "🕹️  TCP RÉEL : Ouvre un vrai socket serveur sur 127.0.0.1:8443 en arrière-plan.\n"
            "Note: SSL n'est pas encapsulé ici pour éviter les crashs de certificats locaux manquants.",
        )
        self._ssl_msg = labeled_entry(
            parent, "Charge utile", "GET /index.html HTTP/1.1"
        )
        btn_row(
            parent,
            ("1. Démarrer Serveur", self._start_real_tcp_server, C["accent"]),
            ("2. Connecter & Envoyer", self._send_real_tcp_client, C["success"]),
        )
        self._out_61 = output_box(parent, 250)
        self.tcp_server_ready = False

    def _start_real_tcp_server(self):
        if self.tcp_server_ready:
            return

        def server_loop():
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", 8443))
                s.listen()
                self.tcp_server_ready = True
                write(
                    self._out_61,
                    "🟢 [SERVEUR] En écoute sur 127.0.0.1:8443 (Vrai Thread)...\n",
                )
                while True:
                    conn, addr = s.accept()
                    with conn:
                        data = conn.recv(1024)
                        write(
                            self._out_61,
                            f"📥 [SERVEUR] Reçu de {addr}: {data.decode()}\n",
                        )

        threading.Thread(target=server_loop, daemon=True).start()

    def _send_real_tcp_client(self):
        if not self.tcp_server_ready:
            write(self._out_61, "❌ Démarrez d'abord le serveur.\n")
            return
        payload = self._ssl_msg.get()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(("127.0.0.1", 8443))
                s.sendall(payload.encode())
                write(self._out_61, f"📤 [CLIENT] Données envoyées au port 8443.\n")
        except ConnectionRefusedError:
            write(self._out_61, "❌ Connexion refusée.\n")

    # ── EXERCICE 6.2 : Sécurisation Bluetooth (Simulation) ─────────
    def _build_ex62(self, parent):
        info_label(
            parent,
            "🕹️  SIMULATEUR BLUETOOTH : Le matériel Bluetooth varie trop pour garantir une exécution PyBluez stable.\n"
            "Ceci simule la négociation de la Link Key.",
        )
        self._bt_mac = labeled_entry(parent, "Adresse MAC", "B4:E6:2A:89:11:0C")
        btn_row(
            parent,
            ("Appairer (Simulé)", self._bt_connect, C["success"]),
        )
        self._out_62 = output_box(parent, 200)

    def _bt_connect(self):
        mac = self._bt_mac.get().strip()
        link_key = hashlib.md5(f"{mac}-secret-link".encode()).hexdigest().upper()
        write(self._out_62, f"🔗 [RFCOMM SSP] Comparaison numérique avec {mac}...\n")
        write(
            self._out_62,
            f"🔑 [LINK KEY] Générée : E3:{link_key[:2]}:{link_key[2:4]}:...:{link_key[-2:]}\n\n",
        )

    # ── EXERCICE 6.3 : Chat UDP Réel & Bidirectionnel ──────────
    def _build_ex63(self, parent):
        info_label(
            parent,
            "🕹️  CHAT RÉEL : Alice et Bob tournent sur de vrais sockets UDP locaux (Ports 5001 et 5002).\n"
            "Basculez entre les onglets pour voir le canal en clair et le trafic intercepté chiffré.",
        )

        # Sous-onglets pour la vue POV
        self.chat_tv = make_tabview(
            parent, ["👩 Alice (5001)", "🕵️ Canal (Réseau)", "👨 Bob (5002)"]
        )

        # --- UI ALICE ---
        tab_alice = self.chat_tv.tab("👩 Alice (5001)")
        self._alice_out = output_box(tab_alice, 200)
        self._alice_entry = labeled_entry(
            tab_alice, "Message pour Bob", "Salut Bob, clé reçue ?"
        )
        action_btn(
            tab_alice,
            "Envoyer à Bob",
            lambda: self._send_udp("Alice", self._alice_entry, self._alice_out, 5002),
            C["purple"],
        )

        # --- UI BOB ---
        tab_bob = self.chat_tv.tab("👨 Bob (5002)")
        self._bob_out = output_box(tab_bob, 200)
        self._bob_entry = labeled_entry(
            tab_bob, "Message pour Alice", "Oui, AES-256 actif !"
        )
        action_btn(
            tab_bob,
            "Envoyer à Alice",
            lambda: self._send_udp("Bob", self._bob_entry, self._bob_out, 5001),
            C["accent"],
        )

        # --- UI CANAL / SNIFFER ---
        tab_net = self.chat_tv.tab("🕵️ Canal (Réseau)")
        self._net_out = output_box(tab_net, 280)

        # Setup Vrais Sockets
        self.sock_alice = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock_alice.bind(("127.0.0.1", 5001))

        self.sock_bob = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock_bob.bind(("127.0.0.1", 5002))

        # Threads d'écoute persistants
        threading.Thread(
            target=self._listen_udp,
            args=(self.sock_alice, "Alice", self._alice_out),
            daemon=True,
        ).start()
        threading.Thread(
            target=self._listen_udp,
            args=(self.sock_bob, "Bob", self._bob_out),
            daemon=True,
        ).start()

    def _pack_secure_payload(self, msg):
        """Chiffre et signe le message (Encrypt-then-MAC)"""
        iv_bytes = os.urandom(16)
        iv_hex = iv_bytes.hex()

        if AES_AVAILABLE:
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(msg.encode()) + padder.finalize()
            cipher = Cipher(
                algorithms.AES(self.k_enc),
                modes.CBC(iv_bytes),
                backend=default_backend(),
            )
            encryptor = cipher.encryptor()
            ciphertext_hex = (
                encryptor.update(padded_data) + encryptor.finalize()
            ).hex()
        else:
            ciphertext_hex = hashlib.sha256(msg.encode() + iv_bytes).hexdigest()

        data_to_sign = iv_hex.encode() + ciphertext_hex.encode()
        mac = hmac_lib.new(self.k_mac, data_to_sign, hashlib.sha256).hexdigest()

        return json.dumps(
            {"iv": iv_hex, "ciphertext": ciphertext_hex, "mac": mac}
        ).encode()

    def _unpack_secure_payload(self, payload_bytes):
        """Vérifie la signature et déchiffre (Encrypt-then-MAC)"""
        try:
            packet = json.loads(payload_bytes.decode())
            iv_hex = packet["iv"]
            ciphertext_hex = packet["ciphertext"]
            received_mac = packet["mac"]

            data_to_sign = iv_hex.encode() + ciphertext_hex.encode()
            expected_mac = hmac_lib.new(
                self.k_mac, data_to_sign, hashlib.sha256
            ).hexdigest()

            if not hmac_lib.compare_digest(expected_mac, received_mac):
                return None, False  # HMAC Invalide

            if AES_AVAILABLE:
                cipher = Cipher(
                    algorithms.AES(self.k_enc),
                    modes.CBC(bytes.fromhex(iv_hex)),
                    backend=default_backend(),
                )
                decryptor = cipher.decryptor()
                padded_data = (
                    decryptor.update(bytes.fromhex(ciphertext_hex))
                    + decryptor.finalize()
                )
                unpadder = padding.PKCS7(128).unpadder()
                msg = (unpadder.update(padded_data) + unpadder.finalize()).decode()
            else:
                msg = "[Mode Dégradé] Empreinte validée, chiffrement non supporté sans 'cryptography'."

            return msg, True
        except Exception as e:
            return str(e), False

    def _send_udp(self, sender_name, entry_widget, out_widget, target_port):
        msg = entry_widget.get()
        if not msg:
            return

        # Affichage POV expéditeur
        write(out_widget, f"➡️ [Moi] {msg}\n")
        entry_widget.delete(0, "end")

        # Préparation et envoi sur le vrai socket
        payload_bytes = self._pack_secure_payload(msg)
        sock = self.sock_alice if sender_name == "Alice" else self.sock_bob
        sock.sendto(payload_bytes, ("127.0.0.1", target_port))

        # Sniffing sur le canal
        packet = json.loads(payload_bytes.decode())
        write(
            self._net_out, f"📦 [WIFI CAPTURE] {sender_name} -> Port {target_port} :\n"
        )
        write(self._net_out, f"   ┣ IV  : {packet['iv'][:16]}...\n")
        write(self._net_out, f"   ┣ AES : {packet['ciphertext'][:32]}...\n")
        write(self._net_out, f"   ┗ MAC : {packet['mac']}\n\n")

    def _listen_udp(self, sock, receiver_name, out_widget):
        while True:
            try:
                data, addr = sock.recvfrom(4096)
                msg, is_valid = self._unpack_secure_payload(data)

                if is_valid:
                    sender = "Alice" if receiver_name == "Bob" else "Bob"
                    write(out_widget, f"✅ [{sender}] {msg}\n")
                else:
                    write(
                        out_widget,
                        f"❌ [ALERTE] Paquet corrompu ou falsifié ignoré depuis {addr}.\n",
                    )
            except Exception:
                pass

    # ── EXERCICE 6.4 : Scrutin Électronique Homomorphe ─────────────
    def _build_ex64(self, parent):
        info_label(parent, "🕹️  SCRUTIN HOMOMORPHE : Agrégation aveugle.")
        self._vote_count = labeled_entry(parent, "Nombre d'électeurs", "150")
        action_btn(
            parent, "🗳️ Démarrer Scrutin", self._run_paillier, C["warn"], "black"
        )
        self._out_64 = output_box(parent, 250)

    def _run_paillier(self):
        # Code Paillier identique à l'itération précédente (fonctionnel mathématiquement)
        try:
            total = int(self._vote_count.get())
            if total <= 0:
                raise ValueError
        except ValueError:
            write(self._out_64, "❌ Entier valide requis.\n")
            return

        keys = paillier_keygen(bits=64)
        voix_oui = 0
        bulletins = []
        for i in range(total):
            choix = random.choice([0, 1])
            voix_oui += choix
            bulletins.append(paillier_encrypt(choix, keys))

        produit = 1
        for c in bulletins:
            produit = (produit * c) % keys["nsq"]

        total_recupere = paillier_decrypt(produit, keys, keys)
        write(self._out_64, f"🗳️ Votes générés : {total}\n")
        write(
            self._out_64,
            f"🧮 Agrégation chiffrée (C1 * C2 mod n²) : {str(produit)[:30]}...\n",
        )
        write(
            self._out_64,
            f"🔓 Déchiffrement : {total_recupere} OUI (Attendu: {voix_oui})\n\n",
        )
