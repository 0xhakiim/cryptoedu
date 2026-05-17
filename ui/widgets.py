"""
ui/widgets.py — Reusable widget factory functions.
All page modules import from here; nothing is duplicated.
"""
import customtkinter as ctk
from ui.theme import C, font, mono


# ── Layout helpers ─────────────────────────────────────────────────────────────

def make_tabview(parent, names: list[str]) -> ctk.CTkTabview:
    tv = ctk.CTkTabview(
        parent,
        fg_color=C["card"],
        segmented_button_fg_color=C["sidebar"],
        segmented_button_selected_color=C["accent"],
        segmented_button_selected_hover_color=C["accent"],
        segmented_button_unselected_color=C["sidebar"],
        corner_radius=12,
    )
    tv.pack(fill="both", expand=True, padx=16, pady=(0, 16))
    for n in names:
        tv.add(n)
    return tv


def separator(parent):
    ctk.CTkFrame(parent, height=1, fg_color=C["border"]).pack(
        fill="x", padx=14, pady=8
    )


# ── Atomic widgets ─────────────────────────────────────────────────────────────

def info_label(parent, text: str, color: str | None = None, wrap: int = 620):
    ctk.CTkLabel(
        parent, text=text,
        font=font(11),
        text_color=color or C["sub"],
        wraplength=wrap, justify="left",
    ).pack(anchor="w", padx=14, pady=(6, 4))


def section_label(parent, text: str):
    ctk.CTkLabel(parent, text=text, font=font(12), text_color=C["sub"]).pack(
        anchor="w", padx=14, pady=(6, 1)
    )


def labeled_entry(parent, label: str, default: str = "", placeholder: str = "") -> ctk.CTkEntry:
    section_label(parent, label)
    e = ctk.CTkEntry(parent, placeholder_text=placeholder, height=34,
                     corner_radius=8, font=font(12))
    e.pack(fill="x", padx=14, pady=(0, 4))
    if default:
        e.insert(0, default)
    return e


def output_box(parent, height: int = 100) -> ctk.CTkTextbox:
    box = ctk.CTkTextbox(
        parent, height=height, corner_radius=8,
        font=mono(11),
        fg_color=C["code_bg"], text_color=C["code_fg"],
        border_width=1, border_color=C["border"],
    )
    box.pack(fill="x", padx=14, pady=(2, 10))
    box.configure(state="disabled")
    return box


def write(box: ctk.CTkTextbox, text: str):
    """Replace the content of an output_box."""
    box.configure(state="normal")
    box.delete("1.0", "end")
    box.insert("1.0", text)
    box.configure(state="disabled")


def chat_box(parent, height: int = 220) -> ctk.CTkTextbox:
    box = ctk.CTkTextbox(
        parent, height=height, corner_radius=8,
        font=mono(11),
        fg_color=C["code_bg"], text_color=C["text"],
        border_width=1, border_color=C["border"],
    )
    box.pack(fill="x", padx=14, pady=4)
    box.configure(state="disabled")
    return box


def chat_append(box: ctk.CTkTextbox, text: str):
    box.configure(state="normal")
    box.insert("end", text + "\n")
    box.see("end")
    box.configure(state="disabled")


# ── Button helpers ─────────────────────────────────────────────────────────────

def action_btn(parent, text: str, cmd, color: str | None = None,
               text_color: str = "white") -> ctk.CTkButton:
    b = ctk.CTkButton(
        parent, text=text, command=cmd,
        height=34, corner_radius=8,
        font=font(12, "bold"),
        fg_color=color or C["accent"],
        hover_color=color or C["accent"],
        text_color=text_color,
    )
    b.pack(fill="x", padx=14, pady=2)
    return b


def btn_row(parent, *specs):
    """
    specs: tuples of (label, command, color) or (label, command, color, text_color)
    All buttons share the row equally.
    """
    row = ctk.CTkFrame(parent, fg_color="transparent")
    row.pack(fill="x", padx=14, pady=4)
    for spec in specs:
        label, cmd, color = spec[0], spec[1], spec[2]
        tc = spec[3] if len(spec) > 3 else "white"
        ctk.CTkButton(
            row, text=label, command=cmd,
            height=34, corner_radius=8,
            font=font(12, "bold"),
            fg_color=color, hover_color=color, text_color=tc,
        ).pack(side="left", expand=True, padx=2)
    return row


def key_size_selector(parent, values: list[str], default: str) -> ctk.CTkSegmentedButton:
    section_label(parent, "Taille de clé (bits)")
    seg = ctk.CTkSegmentedButton(parent, values=values, font=font(12))
    seg.set(default)
    seg.pack(fill="x", padx=14, pady=(0, 6))
    return seg


def mode_selector(parent, values: list[str], default: str, label: str = "Mode") -> ctk.CTkSegmentedButton:
    section_label(parent, label)
    seg = ctk.CTkSegmentedButton(parent, values=values, font=font(12))
    seg.set(default)
    seg.pack(fill="x", padx=14, pady=(0, 6))
    return seg
