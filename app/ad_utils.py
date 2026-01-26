from __future__ import annotations


def domain_to_base_dn(domain: str) -> str:
    domain = (domain or "").strip().strip(".")
    if not domain or "." not in domain:
        return ""
    parts = [p for p in domain.split(".") if p]
    return ",".join([f"DC={p}" for p in parts])


def build_dc_fqdn(dc_short: str, domain: str) -> str:
    dc_short = (dc_short or "").strip()
    domain = (domain or "").strip().strip(".")
    if not dc_short:
        return domain
    if "." in dc_short:
        return dc_short
    return f"{dc_short}.{domain}" if domain else dc_short


def split_group_dns(text: str) -> list[str]:
    if not text:
        return []
    return [x.strip() for x in text.split(";") if x.strip()]
