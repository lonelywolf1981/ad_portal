from __future__ import annotations

from ..utils.dn import dn_first_component_value
from ..utils.datetime_fmt import fmt_dt_human


# Оставляем только поля, которые нужны в «Подробнее»
DETAIL_LABELS: dict[str, str] = {
    "department": "Отдел",
    "memberOf": "Группы",
    "whenCreated": "Создан",
    "whenChanged": "Изменён",
    "lastLogonTimestamp": "Последний вход (timestamp)",
    "pwdLastSet": "Пароль обновлён",
    "distinguishedName": "Путь",
    "otherPager": "ПИН код",
}


def build_detail_items(details: dict) -> list[dict]:
    order = [
        "department",
        "memberOf",
        "whenCreated",
        "whenChanged",
        "lastLogonTimestamp",
        "pwdLastSet",
        "distinguishedName",
        "otherPager",
    ]

    items: list[dict] = []

    # Special rule: show PIN code even if empty
    has_other_pager = "otherPager" in details

    for k in order:
        label = DETAIL_LABELS.get(k, k)

        if k not in details:
            if k == "otherPager" and not has_other_pager:
                items.append({"key": k, "label": label, "value": "—", "is_list": False})
            continue

        v = details.get(k)

        # Groups: show short names only (CN/first RDN value) as badges
        if k == "memberOf":
            vals = v if isinstance(v, list) else [v]
            names = []
            for gdn in vals:
                n = dn_first_component_value(str(gdn))
                if n:
                    names.append(n)
            names = sorted(set(names), key=lambda x: x.lower())
            if not names:
                continue
            items.append({"key": k, "label": label, "value": names, "is_list": True, "is_badges": True})
            continue

        # Human-friendly date/time
        if k in {"whenCreated", "whenChanged", "lastLogonTimestamp", "pwdLastSet"}:
            s = str(v).strip()
            if not s:
                continue
            items.append({"key": k, "label": label, "value": fmt_dt_human(s), "is_list": False})
            continue

        if isinstance(v, list):
            vv = [str(x).strip() for x in v if str(x).strip()]
            if not vv:
                if k == "otherPager":
                    items.append({"key": k, "label": label, "value": "—", "is_list": False})
                continue
            items.append({"key": k, "label": label, "value": vv, "is_list": True})
        else:
            s = str(v).strip()
            if not s:
                if k == "otherPager":
                    items.append({"key": k, "label": label, "value": "—", "is_list": False})
                continue
            items.append({"key": k, "label": label, "value": s, "is_list": False})

    return items
