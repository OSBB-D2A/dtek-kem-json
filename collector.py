import json
import os
import re
import sys
import time
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

from playwright.sync_api import sync_playwright

PAGE_URL = os.getenv("DTEK_URL", "https://www.dtek-kem.com.ua/ua/shutdowns")
STREET = os.getenv("DTEK_STREET", "вул. Донця Михайла")
TARGET_BUILDING = os.getenv("DTEK_BUILDING", "2A")
MAX_ATTEMPTS = int(os.getenv("DTEK_MAX_ATTEMPTS", "3"))
OUT = Path("output")
OUT.mkdir(exist_ok=True)

CHALLENGE_MARKERS = (
    "verify you are human", "request unsuccessful", "access denied",
    "checking your browser", "incapsula incident id", "imperva incident id",
)


def save_json(path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def canonical_building(value):
    value = unicodedata.normalize("NFKC", str(value)).strip().casefold()
    value = value.replace("а", "a")
    return re.sub(r"\s+", "", value)


def get_csrf(page):
    for selector, attr in (
        ('meta[name="csrf-token"]', "content"),
        ('input[name="_csrf"]', "value"),
        ('input[name="_csrf-dtek-kem"]', "value"),
    ):
        try:
            value = page.locator(selector).first.get_attribute(attr, timeout=700)
            if value:
                return value
        except Exception:
            pass
    return None


def fetch_street_data(page):
    # Run AJAX inside the real browser page to reuse its session cookies.
    return page.evaluate(
        """async ({street, csrf}) => {
          const form = new URLSearchParams();
          form.set('method', 'getHomeNum');
          form.set('data[0][name]', 'street');
          form.set('data[0][value]', street);
          form.set('data[1][name]', 'updateFact');
          const parts = new Intl.DateTimeFormat('en-GB', {
            timeZone: 'Europe/Kyiv', day: '2-digit', month: '2-digit',
            year: 'numeric', hour: '2-digit', minute: '2-digit',
            hourCycle: 'h23'
          }).formatToParts(new Date()).reduce((a, p) => (a[p.type] = p.value, a), {});
          form.set('data[1][value]', parts.day + '.' + parts.month + '.' + parts.year + ' ' + parts.hour + ':' + parts.minute);
          const headers = {
            'X-Requested-With': 'XMLHttpRequest',
            'Accept': 'application/json, text/javascript, */*; q=0.01'
          };
          if (csrf) headers['X-CSRF-Token'] = csrf;
          const response = await fetch('/ua/ajax', {
            method: 'POST', credentials: 'same-origin', headers, body: form
          });
          return {
            status: response.status,
            url: response.url,
            contentType: response.headers.get('content-type') || '',
            text: await response.text()
          };
        }""",
        {"street": STREET, "csrf": get_csrf(page)},
    )


def main():
    checked_at = datetime.now(timezone.utc).isoformat()
    summary = {
        "checked_at_utc": checked_at, "url": PAGE_URL, "street": STREET,
        "target_building": TARGET_BUILDING,
        "method": "Playwright Chromium + same-origin AJAX", "success": False,
    }
    try:
        last_error = None
        body = None
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            try:
                context = browser.new_context(
                    user_agent=("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                                "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"),
                    locale="uk-UA", timezone_id="Europe/Kyiv",
                )
                for attempt in range(1, MAX_ATTEMPTS + 1):
                    page = context.new_page()
                    try:
                        print(f"INFO: завантаження сторінки, спроба {attempt}/{MAX_ATTEMPTS}")
                        response = page.goto(PAGE_URL, wait_until="networkidle", timeout=120000)
                        summary["page_status_code"] = response.status if response else None
                        summary["final_url"] = page.url
                        page.wait_for_timeout(500)
                        html = page.content()
                        summary["page_bytes"] = len(html.encode("utf-8"))
                        summary["page_title"] = page.title()
                        # Avoid scanning all HTML for generic words such as "captcha":
                        # they can occur in scripts or unrelated page assets.
                        if response and response.status >= 400:
                            raise RuntimeError(f"Сторінка ДТЕК повернула HTTP {response.status}.")
                        if any(marker in page.title().lower() for marker in CHALLENGE_MARKERS):
                            raise RuntimeError("Заголовок сторінки вказує на CAPTCHA/WAF challenge.")

                        ajax = fetch_street_data(page)
                        summary["ajax_status_code"] = ajax["status"]
                        summary["ajax_url"] = ajax["url"]
                        summary["content_type"] = ajax["contentType"]
                        summary["response_bytes"] = len(ajax["text"].encode("utf-8"))
                        summary["ajax_response_excerpt"] = re.sub(r"\s+", " ", ajax["text"][:500])
                        if ajax["status"] < 200 or ajax["status"] >= 300:
                            raise RuntimeError(f"AJAX повернув HTTP {ajax['status']}.")
                        try:
                            parsed = json.loads(ajax["text"])
                        except ValueError as exc:
                            sample = re.sub(r"\s+", " ", ajax["text"][:500])
                            if any(marker in ajax["text"].lower() for marker in CHALLENGE_MARKERS):
                                raise RuntimeError("AJAX-відповідь містить явні ознаки CAPTCHA/WAF challenge, а не JSON.") from exc
                            raise RuntimeError(f"AJAX-відповідь не є JSON. Початок: {sample!r}") from exc
                        if not isinstance(parsed, dict) or parsed.get("result") is not True:
                            raise RuntimeError("DTEK повернув JSON без result: true.")
                        if not isinstance(parsed.get("data"), dict):
                            raise RuntimeError("У відповіді DTEK немає об'єкта data з переліком будинків.")
                        body = parsed
                        summary["attempt"] = attempt
                        break
                    except Exception as exc:
                        last_error = f"{type(exc).__name__}: {exc}"
                        print(f"WARNING: спроба {attempt} не вдалася: {last_error}", file=sys.stderr)
                        if attempt == MAX_ATTEMPTS:
                            try:
                                save_json(OUT / "diagnostics.json", {
                                    "checked_at_utc": checked_at, "error": last_error,
                                    "summary": summary, "page_title": page.title(),
                                    "page_url": page.url, "html_excerpt": page.content()[:12000],
                                    "ajax_response_excerpt": summary.get("ajax_response_excerpt"),
                                    "ajax_status_code": summary.get("ajax_status_code"),
                                    "ajax_content_type": summary.get("content_type"),
                                })
                            except Exception:
                                pass
                        else:
                            time.sleep(2 * attempt)
                    finally:
                        page.close()
                context.close()
            finally:
                browser.close()

        if body is None:
            raise RuntimeError(last_error or "Не вдалося отримати дані DTEK.")

        street_data = body["data"]
        update_timestamp = body.get("updateTimestamp")
        common = {
            "checked_at_utc": checked_at, "street": STREET,
            "updateTimestamp": update_timestamp, "source_url": PAGE_URL,
        }
        target_key = canonical_building(TARGET_BUILDING)
        matched_key = next(
            (key for key in street_data if canonical_building(key) == target_key), None,
        )
        if matched_key is None:
            summary.update({
                "target_building_found": False,
                "building_count": len(street_data),
                "updateTimestamp": update_timestamp,
            })
            raise RuntimeError(
                f"Будинок {TARGET_BUILDING} відсутній у відповіді DTEK; попередні файли не перезаписано."
            )

        target_data = street_data[matched_key]
        if not isinstance(target_data, dict):
            raise RuntimeError(
                f"Запис будинку {matched_key!r} має неочікуваний формат; попередні файли не перезаписано."
            )
        outage_fields = ("sub_type", "start_date", "end_date", "type")
        target_record_state = (
            "source_fields_empty"
            if all(not str(target_data.get(field) or "").strip() for field in outage_fields)
            else "source_fields_present"
        )

        # Replace published data only after the response and target record are validated.
        # Empty DTEK fields are preserved as-is and are not treated as a collector error.
        save_json(OUT / "dtek-response.json", body)
        save_json(OUT / "dtek-street.json", {
            **common, "building_count": len(street_data), "data": street_data,
        })
        save_json(OUT / "dtek-2a.json", {
            **common, "requested_building": TARGET_BUILDING,
            "found": True, "matched_key": matched_key, "record_state": target_record_state,
            "data": target_data,
        })
        summary.update({
            "success": True,
            "saved_files": ["output/dtek-response.json", "output/dtek-street.json", "output/dtek-2a.json"],
            "building_count": len(street_data), "target_building_found": True,
            "target_building_key": matched_key, "target_record_state": target_record_state,
            "updateTimestamp": update_timestamp,
            "top_level_keys": list(body.keys()),
        })
        print(f"OK: збережено {len(street_data)} записів по вулиці.")
        print(f"OK: будинок {TARGET_BUILDING} знайдено під ключем {matched_key!r}.")
        if target_record_state == "source_fields_empty":
            print("INFO: основні поля відключення порожні у відповіді DTEK; збережено без змін.")
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
