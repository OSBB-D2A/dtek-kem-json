import json
import os
import re
import sys
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

import requests
from bs4 import BeautifulSoup

PAGE_URL = os.getenv("DTEK_URL", "https://www.dtek-kem.com.ua/ua/shutdowns")
STREET = os.getenv("DTEK_STREET", "вул. Донця Михайла")
TARGET_BUILDING = os.getenv("DTEK_BUILDING", "2A")
OUT = Path("output")
OUT.mkdir(exist_ok=True)


def save_json(path, data):
    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def canonical_building(value):
    """Normalize Latin/Cyrillic A and whitespace for keys such as 2A / 2А."""
    value = unicodedata.normalize("NFKC", str(value)).strip().casefold()
    value = value.replace("а", "a")
    return re.sub(r"\s+", "", value)


def main():
    checked_at = datetime.now(timezone.utc).isoformat()
    summary = {
        "checked_at_utc": checked_at,
        "url": PAGE_URL,
        "street": STREET,
        "target_building": TARGET_BUILDING,
        "success": False,
    }
    session = requests.Session()
    session.headers["User-Agent"] = (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
    )
    challenge_markers = (
        "incapsula", "imperva", "captcha", "verify you are human",
        "request unsuccessful", "access denied",
    )

    try:
        page = session.get(PAGE_URL, timeout=25)
        summary["page_status_code"] = page.status_code
        summary["final_url"] = page.url
        page.raise_for_status()

        if any(marker in page.text.lower() for marker in challenge_markers):
            raise RuntimeError("Сайт повернув CAPTCHA/WAF challenge замість сторінки графіків.")

        soup = BeautifulSoup(page.text, "html.parser")

        # Prefer the page's CSRF meta/input values; cookie fallback is only
        # useful on sites that explicitly accept the cookie value as the token.
        csrf = None
        for selector, attr in (
            ('meta[name="csrf-token"]', "content"),
            ('meta[name="csrf-param"]', "content"),
            ('input[name="_csrf"]', "value"),
            ('input[name="_csrf-dtek-kem"]', "value"),
        ):
            node = soup.select_one(selector)
            if node and node.get(attr):
                csrf = node.get(attr)
                break
        if not csrf:
            csrf = page.cookies.get("_csrf") or page.cookies.get("csrf")

        ajax_node = soup.select_one('meta[name="ajaxUrl"]')
        ajax_url = requests.compat.urljoin(
            page.url, ajax_node.get("content") if ajax_node else "/ua/ajax"
        )
        payload = {
            "method": "getHomeNum",
            "data[0][name]": "street",
            "data[0][value]": STREET,
            "data[1][name]": "updateFact",
            "data[1][value]": datetime.now().strftime("%d.%m.%Y %H:%M"),
        }
        headers = {
            "Referer": page.url,
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "application/json, text/javascript, */*; q=0.01",
        }
        if csrf:
            headers["X-CSRF-Token"] = str(csrf)
        session.headers.update(headers)

        response = session.post(ajax_url, data=payload, timeout=25)
        summary["ajax_status_code"] = response.status_code
        summary["ajax_url"] = ajax_url
        summary["content_type"] = response.headers.get("Content-Type", "")
        summary["response_bytes"] = len(response.content)
        response.raise_for_status()

        try:
            body = response.json()
        except ValueError as exc:
            sample = re.sub(r"\s+", " ", response.text[:240])
            if any(marker in response.text.lower() for marker in challenge_markers):
                raise RuntimeError("AJAX-відповідь містить CAPTCHA/WAF challenge, а не JSON.") from exc
            raise RuntimeError(f"Відповідь не є JSON. Початок: {sample!r}") from exc

        if not isinstance(body, dict) or body.get("result") is not True:
            raise RuntimeError("DTEK повернув JSON без result: true.")

        street_data = body.get("data")
        if not isinstance(street_data, dict):
            raise RuntimeError("У відповіді DTEK немає об'єкта data з переліком будинків.")

        update_timestamp = body.get("updateTimestamp")
        common = {
            "checked_at_utc": checked_at,
            "street": STREET,
            "updateTimestamp": update_timestamp,
            "source_url": PAGE_URL,
        }

        # Keep the original complete response for diagnostics and compatibility.
        save_json(OUT / "dtek-response.json", body)

        # Store every building returned for the street in a convenient wrapper.
        save_json(OUT / "dtek-street.json", {
            **common,
            "building_count": len(street_data),
            "data": street_data,
        })

        target_key = canonical_building(TARGET_BUILDING)
        matched_key = next(
            (key for key in street_data if canonical_building(key) == target_key),
            None,
        )
        building_result = {
            **common,
            "requested_building": TARGET_BUILDING,
            "found": matched_key is not None,
            "matched_key": matched_key,
            "data": street_data.get(matched_key) if matched_key is not None else None,
        }
        save_json(OUT / "dtek-2a.json", building_result)

        summary.update({
            "success": True,
            "saved_files": [
                "output/dtek-response.json",
                "output/dtek-street.json",
                "output/dtek-2a.json",
            ],
            "building_count": len(street_data),
            "target_building_found": matched_key is not None,
            "target_building_key": matched_key,
            "updateTimestamp": update_timestamp,
            "top_level_keys": list(body.keys()),
        })
        print(f"OK: збережено {len(street_data)} записів по вулиці.")
        if matched_key is not None:
            print(f"OK: будинок {TARGET_BUILDING} знайдено під ключем {matched_key!r}.")
        else:
            print(f"WARNING: будинок {TARGET_BUILDING} не знайдено серед ключів відповіді.")
        code = 0

    except Exception as exc:
        summary["error"] = f"{type(exc).__name__}: {exc}"
        print(f"ERROR: {summary['error']}", file=sys.stderr)
        code = 1
    finally:
        save_json(OUT / "run-summary.json", summary)

    return code


if __name__ == "__main__":
    raise SystemExit(main())
