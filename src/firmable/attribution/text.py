"""Accent folding for organisation and ISP names (attribution v5).

Registrant names arrive with and without diacritics: "Telefónica", "Telefonica" and "Telefônica" are
one operator, and Turkish upper case "İ" lower-cases to "i" + U+0307. The curated tables in
`providers.py` and `accounts/eligibility.py` are ASCII, so every org / ISP name is folded before it is
normalised or matched.

`fold_name`:
1. maps letters that Unicode does not decompose (ı İ ø æ œ ß ł đ þ ð ħ, both cases) to ASCII;
2. NFKD (compatibility forms too: full-width letters, ligatures such as "ﬁ");
3. drops combining *diacritical* marks only (U+0300–U+036F and the extended / supplement /
   half-mark blocks), so Latin, Greek and Cyrillic lose accents while scripts whose vowel signs are
   combining marks (Thai, Devanagari, Arabic) keep them;
4. casefolds, then recomposes (NFC), so Hangul syllables and kana with (han)dakuten keep their
   precomposed form and Korean / Japanese names are unchanged apart from case and width.

The steps repeat until the string stops changing (at most `MAX_PASSES`), so the result is idempotent. DNS names are NOT folded here: internationalised domains are distinct
names and go through IDNA in `names.py`.
"""

from __future__ import annotations

import unicodedata

_NON_DECOMPOSING = str.maketrans({
    "ı": "i", "İ": "i", "ø": "o", "Ø": "o", "æ": "ae", "Æ": "ae", "œ": "oe", "Œ": "oe", "ß": "ss",
    "ẞ": "ss", "ł": "l", "Ł": "l", "đ": "d", "Đ": "d", "þ": "th", "Þ": "th", "ð": "d", "Ð": "d",
    "ħ": "h", "Ħ": "h",
})
# Combining Diacritical Marks, ... Extended, ... Supplement, ... for Symbols, Combining Half Marks.
_DIACRITIC_RANGES = ((0x0300, 0x036F), (0x1AB0, 0x1AFF), (0x1DC0, 0x1DFF), (0x20D0, 0x20FF), (0xFE20, 0xFE2F))


def _is_diacritic(ch: str) -> bool:
    cp = ord(ch)
    return any(lo <= cp <= hi for lo, hi in _DIACRITIC_RANGES)


MAX_PASSES = 5


def _fold_once(s: str) -> str:
    s = unicodedata.normalize("NFKD", s.translate(_NON_DECOMPOSING))
    s = "".join(ch for ch in s if not _is_diacritic(ch)).casefold()
    return unicodedata.normalize("NFC", s)


def fold_name(s: str | None) -> str:
    """Accent- and case-folded form of an organisation / ISP name ("" for None)."""
    if not s:
        return ""
    if s.isascii():
        return s.lower()
    # casefold can re-expose letters a pass must map or decompose (e.g. "ǅ", "ǿ"): repeat to a fixed point
    for _ in range(MAX_PASSES):
        folded = _fold_once(s)
        if folded == s:
            break
        s = folded
    return s
