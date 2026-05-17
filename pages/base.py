"""
pages/base.py — Base class shared by all TP pages.
Each TP subclasses Page and calls super().__init__(parent, title, subtitle).
"""

import customtkinter as ctk
from ui.theme import C, font


class Page(ctk.CTkScrollableFrame):
    def __init__(self, parent, title: str, subtitle: str):
        super().__init__(
            parent,
            fg_color=C["bg"],
            corner_radius=0,
            scrollbar_button_color=C["border"],
            scrollbar_button_hover_color=C["accent"],
        )
        ctk.CTkLabel(
            self,
            text=title,
            font=font(22, "bold"),
            text_color=C["text"],
        ).pack(anchor="w", padx=24, pady=(20, 2))
        ctk.CTkLabel(
            self,
            text=subtitle,
            font=font(13),
            text_color=C["sub"],
        ).pack(anchor="w", padx=24, pady=(0, 14))
