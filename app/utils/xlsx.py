from __future__ import annotations


_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def xl_safe(value):
    """Неисполняемое значение ячейки Excel.

    Строки, которые начинаются с = + - @ (имена хостов, описания шар с чужих ПК),
    Excel воспринял бы как формулу. Префикс-апостроф делает их обычным текстом.
    """
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value
