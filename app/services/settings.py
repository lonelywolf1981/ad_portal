from __future__ import annotations

from datetime import datetime

from sqlalchemy.orm import Session

from ..crypto import encrypt_str
from ..models import AppSettings
from ..utils.numbers import clamp_int


def save_settings(db: Session, st: AppSettings, form: dict) -> None:
    st.auth_mode = (form.get("auth_mode") or "local").strip()

    # AD connection
    st.ad_dc_short = (form.get("ad_dc_short") or "").strip()
    st.ad_domain = (form.get("ad_domain") or "").strip()

    mode = (form.get("ad_conn_mode") or "ldaps").strip()
    if mode == "ldaps":
        st.ad_port = 636
        st.ad_use_ssl = True
        st.ad_starttls = False
    else:
        st.ad_port = 389
        st.ad_use_ssl = False
        st.ad_starttls = True

    st.ad_bind_username = (form.get("ad_bind_username") or "").strip()
    pw = form.get("ad_bind_password") or ""
    if pw:
        st.ad_bind_password_enc = encrypt_str(pw)

    # Host logon query settings
    st.host_query_username = (form.get("host_query_username") or "").strip()
    qpw = form.get("host_query_password") or ""
    if qpw:
        st.host_query_password_enc = encrypt_str(qpw)

    st.host_query_timeout_s = clamp_int(
        form.get("host_query_timeout_s"),
        default=60,
        min_v=5,
        max_v=300,
    )

    # Background network scan settings
    st.net_scan_enabled = bool(form.get("net_scan_enabled"))
    st.net_scan_cidrs = (form.get("net_scan_cidrs") or "").strip()

    st.net_scan_interval_min = clamp_int(
        form.get("net_scan_interval_min"),
        default=120,
        min_v=30,
        max_v=24 * 60,
    )

    # Optional advanced knobs
    st.net_scan_concurrency = clamp_int(
        form.get("net_scan_concurrency"),
        default=64,
        min_v=4,
        max_v=256,
    )

    st.net_scan_method_timeout_s = clamp_int(
        form.get("net_scan_method_timeout_s"),
        default=20,
        min_v=5,
        max_v=60,
    )

    st.net_scan_probe_timeout_ms = clamp_int(
        form.get("net_scan_probe_timeout_ms"),
        default=350,
        min_v=100,
        max_v=1500,
    )

    # Access groups
    st.allowed_app_group_dns = ";".join(form.get("allowed_app_group_dns", []))
    st.allowed_settings_group_dns = ";".join(form.get("allowed_settings_group_dns", []))

    st.updated_at = datetime.utcnow()
    db.commit()
