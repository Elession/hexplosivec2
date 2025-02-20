import os
import sys

def open_calculator():
    if sys.platform == "win32":
        os.system("calc")  # Windows

open_calculator()