from __future__ import annotations


def guess_netbios(domain_suffix: str) -> str:
    d = (domain_suffix or "").strip()
    if not d:
        return ""
    return d.split(".")[0].upper()


def split_credential(username: str, domain_suffix: str) -> tuple[str, str, str]:
    """Return (winrm_user, smb_domain, smb_user)."""
    u = (username or "").strip()
    if not u:
        return "", "", ""

    if "\\" in u:
        dom, usr = u.split("\\", 1)
        dom = dom.strip()
        usr = usr.strip()
        if dom and usr:
            return f"{dom}\\{usr}", dom, usr
        return u, dom, usr

    if "@" in u:
        # UPN
        return u, "", u

    # Plain username: guess NETBIOS from domain
    netbios = guess_netbios(domain_suffix)
    if netbios:
        return f"{netbios}\\{u}", netbios, u
    return u, "", u
