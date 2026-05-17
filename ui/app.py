"""
ui/app.py — Main application window: sidebar + page router.
Instantiates one Page per TP and keeps them all in memory (fast switching).
"""

import customtkinter as ctk
from ui.theme import C, font
from pages.tp1_classical import TP1Page
from pages.tp2_symmetric import TP2Page
from pages.tp3_asymmetric import TP3Page
from pages.tp4_hashing import TP4Page
from pages.tp5_signatures import TP5Page
from pages.tp6_application import TP6Page

NAV = [
    ("tp1", "🏛️   TP1  — Chiffrement Classique"),
    ("tp2", "🔒   TP2  — Crypto Symétrique"),
    ("tp3", "🔑   TP3  — Crypto Asymétrique"),
    ("tp4", "🧮   TP4  — Fonctions de Hachage"),
    ("tp5", "✍️    TP5  — Signatures Numériques"),
    ("tp6", "🌐   TP6  — Application Sécurisée"),
]

PAGE_CLASSES = {
    "tp1": TP1Page,
    "tp2": TP2Page,
    "tp3": TP3Page,
    "tp4": TP4Page,
    "tp5": TP5Page,
    "tp6": TP6Page,
}


class CryptoEduApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("CryptoEdu — Cryptographie Appliquée · Ing3 Cybersécurité 2026")
        self.geometry("1200x760")
        self.minsize(960, 600)
        self.configure(fg_color=C["bg"])

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._sidebar()
        self._content()
        self._show("tp1")

    # ── Sidebar ────────────────────────────────────────────────────────────────

    def _sidebar(self):
        sb = ctk.CTkFrame(self, width=230, fg_color=C["sidebar"], corner_radius=0)
        sb.grid(row=0, column=0, sticky="nsew")
        sb.grid_rowconfigure(20, weight=1)  # push footer to bottom

        # Logo
        ctk.CTkLabel(
            sb, text="🔐  CryptoEdu", font=font(20, "bold"), text_color=C["accent"]
        ).grid(row=0, column=0, padx=20, pady=(24, 2))
        ctk.CTkLabel(
            sb, text="Cryptographie Appliquée", font=font(11), text_color=C["sub"]
        ).grid(row=1, column=0, padx=20, pady=(0, 18))

        ctk.CTkFrame(sb, height=1, fg_color=C["border"]).grid(
            row=2, column=0, sticky="ew", padx=12, pady=(0, 14)
        )

        # Nav buttons
        self._nav_btns: dict[str, ctk.CTkButton] = {}
        for row_idx, (pid, label) in enumerate(NAV, start=3):
            b = ctk.CTkButton(
                sb,
                text=label,
                anchor="w",
                font=font(12),
                height=44,
                corner_radius=8,
                fg_color="transparent",
                hover_color=C["card"],
                text_color=C["text"],
                command=lambda p=pid: self._show(p),
            )
            b.grid(row=row_idx, column=0, padx=10, pady=2, sticky="ew")
            self._nav_btns[pid] = b

        # Footer
        ctk.CTkLabel(
            sb,
            text="Ing 3  ·  Cybersécurité  ·  2026",
            font=font(10),
            text_color=C["sub"],
        ).grid(row=20, column=0, padx=20, pady=16, sticky="s")

    # ── Content area ───────────────────────────────────────────────────────────

    def _content(self):
        cf = ctk.CTkFrame(self, fg_color=C["bg"], corner_radius=0)
        cf.grid(row=0, column=1, sticky="nsew")
        cf.grid_rowconfigure(0, weight=1)
        cf.grid_columnconfigure(0, weight=1)
        self._cf = cf

        self._pages: dict[str, ctk.CTkScrollableFrame] = {}
        for pid, cls in PAGE_CLASSES.items():
            # Instantiate them, but DO NOT call .grid() here anymore!
            page = cls(cf)
            self._pages[pid] = page

    # ── Routing ────────────────────────────────────────────────────────────────

    def _show(self, pid: str):
        print("Switching to:", pid)
        for p, b in self._nav_btns.items():
            if p == pid:
                b.configure(fg_color=C["accent"], text_color="white")
            else:
                b.configure(fg_color="transparent", text_color=C["text"])
        for page in self._pages.values():
            page.grid_forget()

        # 3. Explicitly bring the target page into the grid layout
        self._pages[pid].grid(row=0, column=0, sticky="nsew")
