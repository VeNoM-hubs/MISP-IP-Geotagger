from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Optional, Set, Tuple

import requests
import urllib3
from pymisp import ExpandedPyMISP, PyMISPError

# ─────────────── Configuration ───────────────
CONFIG_FILE = Path(__file__).parent / "config" / "settings.json"
print(f"[DEBUG] Looking for config at: {CONFIG_FILE.resolve()}")

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

with CONFIG_FILE.open() as fh:
    cfg = json.load(fh)

print(f"[DEBUG] MISP URL loaded: {cfg['misp_url']}")

misp = ExpandedPyMISP(
    url=cfg["misp_url"],
    key=cfg["misp_key"],
    ssl=cfg["misp_verifycert"],
)

session = requests.Session()
session.headers.update({"User-Agent": "misp-geotagger/1.2"})
HTTP_TIMEOUT = 5  # seconds


# ─────────────── IP Location Lookup ───────────────
@lru_cache(maxsize=1024)
def ip_location(ip: str) -> Tuple[Optional[str], Optional[str]]:
    """Return ('country:XX', 'city:Name') or (None, None) for *ip*."""
    try:
        r = session.get(f"https://api.iplocation.net/?ip={ip}", timeout=HTTP_TIMEOUT)
        r.raise_for_status()
        data = r.json()
        country = data.get("country_code2") or None
        city = data.get("city") or None
        return (
            f"country:{country}" if country else None,
            f"city:{city}" if city else None,
        )
    except Exception as exc:
        print(f"[!] Error getting location for {ip}: {exc}")
        return None, None


def _ensure_tag_exists(tag: str) -> None:
    """Create *tag* on the server if it doesn’t already exist."""
    try:
        misp.get_tag(tag)
    except PyMISPError:
        try:
            misp.add_tag({"name": tag})
            print(f"[+] Created missing tag '{tag}'")
        except Exception as exc:
            print(f"[!] Could not create tag '{tag}': {exc}")


def _location_subset(tags: Set[str]) -> Set[str]:
    """Return only tags that start with country: or city: ."""
    return {t for t in tags if t.startswith(("country:", "city:"))}


# ─────────────── Main Logic ───────────────
def tag_ip_locations() -> None:
    print("[*] Fetching recent events…")
    try:
        events = misp.search_index(timestamp="5d", limit=cfg["event_limit"])
    except Exception as exc:
        print(f"[!] Failed to fetch events: {exc}")
        return

    if not isinstance(events, list):
        print("[!] Unexpected response from MISP")
        return

    for ev in events:
        event_uuid = ev["uuid"]
        event_info = ev.get("info", "")
        print(f"\n[+] Event UUID: {event_uuid} | Info: {event_info}")

        try:
            full_event = misp.get_event(event_uuid)  # no include_tags param
            attributes = full_event["Event"].get("Attribute", [])
        except Exception as exc:
            print(f"[!] Couldn’t fetch full event {event_uuid}: {exc}")
            continue

        for attr in attributes:
            if attr["type"] not in ("ip-src", "ip-dst"):
                continue

            ip_value  = attr["value"]
            attr_uuid = attr["uuid"]

            # ── Pull the attribute’s current tags (one extra API call) ──
            try:
                attr_full = misp.get_attribute(attr_uuid)
                current_tags = {
                    t["name"] for t in attr_full["Attribute"].get("Tag", [])
                }
            except Exception as exc:
                print(f"[!] Couldn’t fetch tags for {ip_value}: {exc}")
                current_tags = set()

            current_loc = _location_subset(current_tags)
            new_tags    = set(filter(None, ip_location(ip_value)))

            if new_tags == current_loc:
                print(f"[=] IP {ip_value} already correctly tagged -> {new_tags}")
                continue

            # ── Remove stale location tags ──
            for stale in current_loc - new_tags:
                try:
                    misp.untag(attr_uuid, stale)
                    print(f"[-] Removed outdated tag '{stale}' from {ip_value}")
                except Exception as exc:
                    print(f"[!] Couldn’t remove tag '{stale}' from {ip_value}: {exc}")

            # ── Add missing / updated tags ──
            for tag in new_tags - current_loc:
                try:
                    misp.tag(attr_uuid, tag)
                    print(f"[+] Added tag '{tag}' to {ip_value}")
                except PyMISPError as exc:
                    if "Tag does not exist" in str(exc):
                        _ensure_tag_exists(tag)
                        try:
                            misp.tag(attr_uuid, tag)
                            print(f"[+] Created and added '{tag}' to {ip_value}")
                        except Exception as exc2:
                            print(f"[!] Retry failed for '{tag}': {exc2}")
                    else:
                        print(f"[!] Failed to add '{tag}' to {ip_value}: {exc}")
                except Exception as exc:
                    print(f"[!] Unexpected error tagging {ip_value}: {exc}")

    print("\n[*] Done.")


# ─────────────── Entry Point ───────────────
if __name__ == "__main__":
    tag_ip_locations()