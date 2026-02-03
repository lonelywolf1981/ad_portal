from __future__ import annotations

import base64


def dn_to_id(dn: str) -> str:
    """URL-safe identifier for a DN (used for HTML ids and query params)."""
    b = base64.urlsafe_b64encode((dn or "").encode("utf-8")).decode("ascii")
    return b.rstrip("=")


def id_to_dn(s: str) -> str:
    s = (s or "").strip()
    if not s:
        raise ValueError("empty")
    pad = "=" * (-len(s) % 4)
    raw = base64.urlsafe_b64decode((s + pad).encode("ascii"))
    return raw.decode("utf-8", errors="replace")


def dn_first_component_value(dn: str) -> str:
    """Return first RDN value from a DN (e.g. CN=USB-Deny,OU=... -> USB-Deny)."""
    s = (dn or "").strip()
    if not s:
        return ""

    # Extract first RDN (handle escaped commas)
    first: list[str] = []
    esc = False
    for ch in s:
        if esc:
            first.append(ch)
            esc = False
            continue
        if ch == "\\":
            esc = True
            continue
        if ch == ",":
            break
        first.append(ch)
    rdn = "".join(first).strip()

    if "=" in rdn:
        _, val = rdn.split("=", 1)
        val = val.strip()
    else:
        val = rdn

    # Unescape common DN escapes
    val = val.replace("\\,", ",").replace("\\+", "+").replace("\\=", "=").replace('\\"', '"')
    return val.strip()
