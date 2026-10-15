import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests
from bs4 import BeautifulSoup

PAGE_URL = os.getenv("DTEK_URL", "https://www.dtek-kem.com.ua/ua/shutdowns")
STREET = os.getenv("DTEK_STREET", "вул. Донця Михайла")
OUT = Path("output")
OUT.mkdir(exist_ok=True)


def save_json(path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main():
    summary = {
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "url": PAGE_URL,
        "street": STREET,
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
        csrf = page.cookies.get("_csrf") or page.cookies.get("csrf")
        if not csrf:
            node = soup.select_one('meta[name="csrf-token"]')
            if node:
                csrf = node.get("content")
        if not csrf:
            node = soup.select_one('input[name="_csrf"]')
            if node:
                csrf = node.get("value")
        if not csrf:
            raise RuntimeError("Не знайдено CSRF-токен; можливо, сайт змінився або вимагає додаткової перевірки.")

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
        session.headers.update({
            "Referer": page.url,
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "X-CSRF-Token": str(csrf),
        })

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

        if not isinstance(body, (dict, list)):
            raise RuntimeError("JSON має неочікувану структуру.")

        save_json(OUT / "dtek-response.json", body)
        summary["success"] = True
        summary["saved_file"] = "output/dtek-response.json"
        summary["top_level_keys"] = list(body.keys()) if isinstance(body, dict) else None
        print("OK: JSON збережено.")
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
