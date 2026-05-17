"""
ui/theme.py — Centralised design tokens for CryptoEdu.
Import C (colours) and FONTS anywhere in the app.
"""
import customtkinter as ctk

# ── Appearance ────────────────────────────────────────────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# ── Colour palette ─────────────────────────────────────────────────────────────
C = {
    "bg":      "#0d1117",
    "sidebar": "#161b22",
    "card":    "#1c2128",
    "border":  "#30363d",
    # Semantic
    "accent":  "#58a6ff",
    "success": "#3fb950",
    "warn":    "#d29922",
    "danger":  "#f85149",
    "purple":  "#bc8cff",
    "orange":  "#f0883e",
    # Text
    "text":    "#e6edf3",
    "sub":     "#8b949e",
    # Code output
    "code_bg": "#010409",
    "code_fg": "#79c0ff",
}

# ── Font helpers ───────────────────────────────────────────────────────────────
def font(size=12, weight="normal"):
    return ctk.CTkFont(size=size, weight=weight)

def mono(size=11):
    return ctk.CTkFont(family="Courier New", size=size)
