"""
crypto/classical.py — Implémentations pures de cryptographie classique.
Répond aux exigences des exercices 1.1, 1.2, 1.3 et 1.4.
"""

import math
from collections import Counter

# Mini dictionnaire de mots fréquents français pour automatiser le décodage César
DICT_FRANCAIS = {
    "LE",
    "LA",
    "LES",
    "DES",
    "UN",
    "UNE",
    "EST",
    "ET",
    "QUE",
    "QUI",
    "DANS",
    "POUR",
    "PAR",
    "AVEC",
    "PLUS",
}

# ── EXERCICE 1.1 : CÉSAR AVANCÉ ───────────────────────────────────────────────


def caesar_encrypt(text: str, k: int) -> str:
    """Décale chaque caractère alphabétique de k positions (mod 26)."""
    return "".join(
        chr((ord(c) - 65 + k) % 26 + 65) if c.isalpha() else c for c in text.upper()
    )


def caesar_decrypt(text: str, k: int) -> str:
    return caesar_encrypt(text, -k)


def caesar_brute_force_auto(ciphertext: str) -> tuple[list[tuple[int, str]], int, str]:
    """
    Teste les 26 clés et identifie automatiquement le texte français valide
    en comptant les occurrences de mots courants du dictionnaire.
    """
    candidates = []
    best_key = 0
    max_score = -1
    best_text = ""

    for k in range(26):
        decrypted = caesar_decrypt(ciphertext, k)
        candidates.append((k, decrypted))

        # Évaluation par dictionnaire
        words = set(decrypted.split())
        score = sum(1 for w in words if w in DICT_FRANCAIS)

        if score > max_score:
            max_score = score
            best_key = k
            best_text = decrypted

    return candidates, best_key, best_text


def frequency_index(text: str) -> float:
    """Calcule l'Indice de Coïncidence (IC). IC Français ≈ 0.074."""
    letters = [c for c in text.upper() if c.isalpha()]
    n = len(letters)
    if n < 2:
        return 0.0
    counts = Counter(letters)
    return sum(f * (f - 1) for f in counts.values()) / (n * (n - 1))


def break_caesar_by_ic(ciphertext: str) -> int:
    """Retrouve la clé de César en cherchant le décalage qui maximise l'alignement sur le français."""
    letters = [c for c in ciphertext.upper() if c.isalpha()]
    if not letters:
        return 0

    # Fréquences théoriques du Français (A-Z)
    freq_fr = [
        0.0815,
        0.0090,
        0.0326,
        0.0367,
        0.1473,
        0.0107,
        0.0087,
        0.0074,
        0.0752,
        0.0061,
        0.0007,
        0.0545,
        0.0297,
        0.0709,
        0.0581,
        0.0252,
        0.0136,
        0.0669,
        0.0795,
        0.0724,
        0.0637,
        0.0184,
        0.0005,
        0.0043,
        0.0043,
        0.0013,
    ]

    best_k = 0
    min_diff = float("inf")

    for k in range(26):
        decrypted = caesar_decrypt("".join(letters), k)
        counts = Counter(decrypted)
        n = len(decrypted)

        # Somme des carrés des écarts de distribution
        diff = 0.0
        for i in range(26):
            expected = freq_fr[i]
            observed = counts[chr(65 + i)] / n
            diff += (expected - observed) ** 2

        if diff < min_diff:
            min_diff = diff
            best_k = k

    return best_k


# ── EXERCICE 1.2 : VIGENÈRE AVANCÉ & IC ANALYSIS ─────────────────────────────


def vigenere_encrypt(text: str, key: str) -> str:
    text, key = text.upper(), key.upper()
    out, ki = [], 0
    for c in text:
        if c.isalpha():
            shift = ord(key[ki % len(key)]) - 65
            out.append(chr((ord(c) - 65 + shift) % 26 + 65))
            ki += 1
        else:
            out.append(c)
    return "".join(out)


def vigenere_decrypt(text: str, key: str) -> str:
    text, key = text.upper(), key.upper()
    out, ki = [], 0
    for c in text:
        if c.isalpha():
            shift = ord(key[ki % len(key)]) - 65
            out.append(chr((ord(c) - 65 - shift) % 26 + 65))
            ki += 1
        else:
            out.append(c)
    return "".join(out)


def kasiski_test(ciphertext: str, ngram: int = 3) -> dict:
    """Trouve les n-grammes répétés et calcule leurs distances réciproques."""
    ct = "".join(c for c in ciphertext.upper() if c.isalpha())
    found = {}
    for i in range(len(ct) - ngram):
        gram = ct[i : i + ngram]
        for j in range(i + ngram, len(ct) - ngram + 1):
            if ct[j : j + ngram] == gram:
                found.setdefault(gram, []).append(j - i)
    return found


def probable_key_length(kasiski_result: dict) -> int:
    """Détermine la longueur probable via le GCD (PGCD) des distances."""
    from functools import reduce

    distances = [d for dists in kasiski_result.values() for d in dists]
    if not distances:
        return 0
    return reduce(math.gcd, distances)


def analyze_vigenere_ic(ciphertext: str, max_len: int = 10) -> list[tuple[int, float]]:
    """Découpe le texte en sous-séquences pour calculer l'IC moyen par longueur de clé potentielle."""
    ct = "".join(c for c in ciphertext.upper() if c.isalpha())
    results = []

    for k in range(1, max_len + 1):
        ic_sum = 0.0
        for i in range(k):
            sub_seq = ct[i::k]
            ic_sum += frequency_index(sub_seq)
        results.append((k, ic_sum / k))
    return results

    # ── EXERCICE 1.3 : HILL MODULAIRE 2x2 ET 3x3 ──────────────────────────────────


def modular_inverse(matrix: list[list[int]], mod: int = 26) -> list[list[int]]:
    """Calcule l'inverse matriciel modulaire via det⁻¹ * adj(K) mod 26."""
    n = len(matrix)
    if n == 2:
        a, b, c, d = matrix[0][0], matrix[0][1], matrix[1][0], matrix[1][1]
        det = (a * d - b * c) % mod
    elif n == 3:
        m = matrix
        det = (
            m[0][0] * m[1][1] * m[2][2]
            + m[0][1] * m[1][2] * m[2][0]
            + m[0][2] * m[1][0] * m[2][1]
            - m[0][2] * m[1][1] * m[2][0]
            - m[0][0] * m[1][2] * m[2][1]
            - m[0][1] * m[1][0] * m[2][2]
        ) % mod
    else:
        raise ValueError("Dimensions supportées : 2x2 ou 3x3.")
    # Trouver l'inverse du déterminant mod 26
    det_inv = -1
    for x in range(1, mod):
        if (det * x) % mod == 1:
            det_inv = x
            break
    if det_inv == -1:
        raise ValueError(
            f"Matrice non inversible mod {mod} (Déterminant {det} non premier avec {mod})."
        )
    # Construction de la comatrice transposée (Adjointe)
    if n == 2:
        adj = [
            [matrix[1][1], (-matrix[0][1]) % mod],
            [(-matrix[1][0]) % mod, matrix[0][0]],
        ]
    else:
        m = matrix
        adj = [[0] * 3 for _ in range(3)]
        for r in range(3):
            for c_idx in range(3):
                sub = [
                    row[:c_idx] + row[c_idx + 1 :]
                    for row_idx, row in enumerate(m)
                    if row_idx != r
                ]
                sign = 1 if (r + c_idx) % 2 == 0 else -1
                minor_det = sub[0][0] * sub[1][1] - sub[0][1] * sub[1][0]
                adj[c_idx][r] = (sign * minor_det) % mod  # Transposition directe
    # Multiplier l'adjointe par det_inv
    inv_matrix = [[(adj[r][c] * det_inv) % mod for c in range(n)] for r in range(n)]
    return inv_matrix


def hill_crypt(text: str, matrix: list[list[int]], decrypt: bool = False) -> str:
    """Chiffrement et Déchiffrement Hill (N x N) avec convention Vecteur Colonne."""
    n = len(matrix)
    pt = "".join(c.upper() for c in text if c.isalpha())

    # Padding si nécessaire
    while len(pt) % n != 0:
        pt += "X"

    op_matrix = modular_inverse(matrix) if decrypt else matrix
    out = []

    # Découpage et multiplication
    for i in range(0, len(pt), n):
        vector = [ord(pt[i + j]) - ord("A") for j in range(n)]
        # Multiplication : Matrice * Vecteur
        res = [
            sum(op_matrix[r][c] * vector[c] for c in range(n)) % 26 for r in range(n)
        ]
        out.extend(chr(v + ord("A")) for v in res)

    return "".join(out)


def attack_hill_known_plaintext(plain: str, cipher: str, n: int = 2) -> list[list[int]]:
    """
    Attaque à clair connu robuste par élimination de Gauss-Jordan mod 26.
    Résout C = K * P en cherchant des blocs de vecteurs linéairement indépendants
    dans le texte fourni par l'utilisateur.
    """
    p_clean = "".join(c.upper() for c in plain if c.isalpha())
    c_clean = "".join(c.upper() for c in cipher if c.isalpha())

    if len(p_clean) < n * n or len(c_clean) < n * n:
        raise ValueError(f"L'attaque requiert au moins {n*n} lettres.")

    # 1. Extraction de tous les vecteurs colonnes disponibles
    num_blocks = min(len(p_clean), len(c_clean)) // n
    all_P_cols = []
    all_C_cols = []

    for b in range(num_blocks):
        p_col = [ord(p_clean[b * n + i]) - ord("A") for i in range(n)]
        c_col = [ord(c_clean[b * n + i]) - ord("A") for i in range(n)]
        all_P_cols.append(p_col)
        all_C_cols.append(c_col)

    # 2. Recherche d'une combinaison de 'n' colonnes formant une matrice P inversible
    import itertools

    found_valid_submatrix = False
    P_matrix = []
    C_matrix = []

    for indices in itertools.combinations(range(num_blocks), n):
        # Construire les matrices candidates N x N (les blocs choisis forment les colonnes)
        P_cand = [[all_P_cols[idx][row] for idx in indices] for row in range(n)]
        C_cand = [[all_C_cols[idx][row] for idx in indices] for row in range(n)]

        # Vérifier l'inversibilité du candidat via son déterminant mod 26
        if n == 2:
            det = (P_cand[0][0] * P_cand[1][1] - P_cand[0][1] * P_cand[1][0]) % 26
        else:
            m = P_cand
            det = (
                m[0][0] * m[1][1] * m[2][2]
                + m[0][1] * m[1][2] * m[2][0]
                + m[0][2] * m[1][0] * m[2][1]
                - m[0][2] * m[1][1] * m[2][0]
                - m[0][0] * m[1][2] * m[2][1]
                - m[0][1] * m[1][0] * m[2][2]
            ) % 26

        if det % 2 != 0 and det % 13 != 0:
            P_matrix = P_cand
            C_matrix = C_cand
            found_valid_submatrix = True
            break

    if not found_valid_submatrix:
        raise ValueError(
            "Impossible d'extraire des blocs indépendants mod 26 de votre texte.\n"
            "💡 Suggestion : Fournissez un texte un peu plus long (ex: 12-16 lettres) "
            "contenant des paires de lettres plus variées."
        )

    # 3. Résolution de K = C * P⁻¹ mod 26
    P_inv = modular_inverse(P_matrix, mod=26)
    K = [[0] * n for _ in range(n)]
    for r in range(n):
        for c in range(n):
            K[r][c] = sum(C_matrix[r][i] * P_inv[i][c] for i in range(n)) % 26

    return K


# ── EXERCICE 1.4 : ONE-TIME PAD MODULATION & CRIB DRAGGING ───────────────────


def otp_crypt_bytes(msg_bytes: bytes, key_bytes: bytes) -> bytes:
    """Traitement cryptographique XOR octet à octet pour OTP d'exercice."""
    if len(key_bytes) < len(msg_bytes):
        raise ValueError(
            "Le masque doit posséder une longueur supérieure ou égale au message."
        )
    return bytes(b1 ^ b2 for b1, b2 in zip(msg_bytes, key_bytes))


def run_crib_dragging(c1_xor_c2: bytes, crib: str) -> list[tuple[int, str]]:
    """
    Méthode du Crib Dragging : Glisse un mot connu ('crib') sur le flux XOR
    pour extraire des bribes claires lisibles de l'autre message.
    """
    crib_bytes = crib.upper().encode()
    results = []

    for pos in range(len(c1_xor_c2) - len(crib_bytes) + 1):
        segment = c1_xor_c2[pos : pos + len(crib_bytes)]
        decrypted_fragment = bytes(b1 ^ b2 for b1, b2 in zip(segment, crib_bytes))

        # Filtrage des caractères pour affichage
        readable = "".join(
            chr(b) if (32 <= b < 127) else "." for b in decrypted_fragment
        )
        results.append((pos, readable))

    return results
