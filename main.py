#!/usr/bin/env python3
"""Entry point."""

import sys
from core import warn
from app import App

def Symbol():
    # Prints the tool's ASCII banner
    print("\n")
    try:
        import pyfiglet
        text = "Evil SQLi"
        ascii_art = pyfiglet.figlet_format(text, font="graffiti", width=200, justify="left")
    except Exception:
        ascii_art = " Evil SQLi "
    warning1 = "[!] WARNING: This tool should only be used on systems you own or have explicit permission to test."
    warning2 = "[!] Unauthorized testing is illegal and unethical."
    colors_hex = [
        "#FF0000", "#FF4500", "#FF6347", "#FF1493", "#6A0DAD", "#8A2BE2",
        "#0ABDE3", "#00BFFF", "#00FF7F", "#00FFC6", "#00FF00", "#32CD32",
        "#3A0071", "#8B008B",
    ]
    def hex_to_rgb(h):
        h = h.lstrip("#")
        return tuple(int(h[i:i+2], 16) for i in (0, 2, 4))
    colors = [hex_to_rgb(c) for c in colors_hex]
    def lerp(c1, c2, t):
        return tuple(int(a + (b - a) * t) for a, b in zip(c1, c2))
    def get_cosmic_color(pos):
        if pos <= 0: return colors[0]
        if pos >= 1: return colors[-1]
        seg_len = 1 / (len(colors) - 1)
        idx = int(pos / seg_len)
        t = (pos - seg_len * idx) / seg_len
        return lerp(colors[idx], colors[idx + 1], t)
    def rgb_escape(r, g, b):
        return f"\033[38;2;{r};{g};{b}m"
    visible_chars = [c for c in ascii_art if c not in [" ", "\n"]]
    total_visible = max(1, len(visible_chars))
    output, char_index = "", 0
    for ch in ascii_art:
        if ch == "\n":
            output += "\n"
        elif ch == " ":
            output += " "
        else:
            pos = char_index / total_visible
            r, g, b = get_cosmic_color(pos)
            output += rgb_escape(r, g, b) + ch
            char_index += 1
    output += "\033[0m"
    print(output)
    red_color = "\033[38;2;255;0;0m"
    reset_color = "\033[0m"
    print(f"{red_color}{warning1}{reset_color}")
    print(f"{red_color}{warning2}{reset_color}")
    print("\033[0m")

if __name__ == "__main__":
    Symbol()
    try:
        App().run(sys.argv[1:])
    except KeyboardInterrupt:
        print()
        warn("Interrupted by user.")