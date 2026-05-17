#!/usr/bin/env python3
"""
main.py — CryptoEdu entry point.
Run:  python main.py
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ui.app import CryptoEduApp

if __name__ == "__main__":
    app = CryptoEduApp()
    app.mainloop()
