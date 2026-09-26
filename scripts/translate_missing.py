#!/usr/bin/env python3
"""
Translate missing MsgCode texts in the locales/*.json files.

Ported from eMuleQt's scripts/translate_missing.py (which works on Qt .ts files).
Here every language is one flat JSON file, code -> text, and en.json is the source.

Usage:
    scripts/translate_missing.py show              # list missing or stale codes
    scripts/translate_missing.py export            # export to scripts/missing.local.json
    scripts/translate_missing.py apply             # apply from scripts/missing.local.json
    scripts/translate_missing.py apply FILE.json   # apply from custom JSON file

Workflow after adding a code to locales/en.json:
    1. scripts/translate_missing.py export          # creates scripts/missing.local.json
    2. Fill in translations in the JSON             # manually or via LLM
    3. scripts/translate_missing.py apply           # writes into locales/<lang>.json
    4. go test ./locales                            # every language has every code
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LANG_DIR = ROOT / "locales"

SOURCE = "en"

# The languages eMuleQt ships (de_DE es_ES fr_FR it_IT ja_JP ko_KR pt_BR zh_CN).
# Files are named by base subtag only, because locales.Negotiate reduces an
# Accept-Language tag to it: pt holds Brazilian Portuguese, zh Simplified Chinese.
LANGUAGES = ["de", "es", "fr", "it", "ja", "ko", "pt", "zh"]

# Outside locales/: //go:embed *.json would pick it up there and the server would
# fail to load its nested objects. *.local.* is gitignored.
DEFAULT_EXPORT = ROOT / "scripts" / "missing.local.json"


def lang_path(lang: str) -> Path:
    return LANG_DIR / f"{lang}.json"


def load(lang: str) -> dict[str, str]:
    path = lang_path(lang)
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def get_missing(lang: str, source: dict[str, str]) -> list[str]:
    """Return the codes of @p source that @p lang lacks or leaves empty."""
    have = load(lang)
    return [code for code in source if not have.get(code, "").strip()]


def cmd_show():
    """Print missing and stale codes grouped by language."""
    source = load(SOURCE)
    any_issue = False
    for lang in LANGUAGES:
        missing = get_missing(lang, source)
        stale = [code for code in load(lang) if code not in source]
        if not missing and not stale:
            continue
        any_issue = True
        print(f"\n  {lang} ({len(missing)} missing, {len(stale)} stale):")
        for code in missing:
            print(f"    - {code}: {source[code]}")
        for code in stale:
            print(f"    ! {code} (not in {SOURCE}.json)")
    if not any_issue:
        print("  All languages are complete.")


def cmd_export():
    """Export missing codes to a JSON template for filling in translations.

    Format:
    {
        "code": {
            "_en": "English text",
            "de": "",
            "es": "",
            ...
        }
    }

    Only the languages that lack a code get a slot for it.
    """
    source = load(SOURCE)
    export: dict[str, dict[str, str]] = {}
    for lang in LANGUAGES:
        for code in get_missing(lang, source):
            export.setdefault(code, {"_en": source[code]})[lang] = ""

    if not export:
        print("  Nothing to export — all languages are complete.")
        return

    # Keep en.json's order so related codes stay together.
    ordered = {code: export[code] for code in source if code in export}
    DEFAULT_EXPORT.write_text(json.dumps(ordered, indent=2, ensure_ascii=False) + "\n",
                              encoding="utf-8")
    print(f"  Exported {len(ordered)} codes to {DEFAULT_EXPORT.relative_to(ROOT)}")
    print(f"  Fill in the empty values, then run: scripts/translate_missing.py apply")


def cmd_apply(json_path: Path = DEFAULT_EXPORT):
    """Read translations from JSON and write them into locales/<lang>.json."""
    if not json_path.exists():
        print(f"  Error: {json_path} not found. Run 'export' first.", file=sys.stderr)
        sys.exit(1)

    data: dict[str, dict[str, str]] = json.loads(json_path.read_text(encoding="utf-8"))
    source = load(SOURCE)

    for lang in LANGUAGES:
        current = load(lang)
        count = 0
        for code, entry in data.items():
            value = entry.get(lang, "")
            if not value.strip():
                continue
            if code not in source:
                print(f"  {lang}: skipping {code!r} — not in {SOURCE}.json", file=sys.stderr)
                continue
            # An existing translation is never overwritten.
            if current.get(code, "").strip():
                continue
            current[code] = value
            count += 1

        if count > 0:
            _write(lang, current, source)
        print(f"  {lang}: {count} codes applied")

    print(f"\n  Run 'go test ./locales' to check completeness.")


def _write(lang: str, texts: dict[str, str], source: dict[str, str]):
    """Write @p texts in en.json's code order; codes unknown to en.json go last so
    'show' can still report them."""
    ordered = {code: texts[code] for code in source if code in texts}
    ordered.update({code: text for code, text in texts.items() if code not in source})
    lang_path(lang).write_text(json.dumps(ordered, indent=2, ensure_ascii=False) + "\n",
                               encoding="utf-8")


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)

    cmd = sys.argv[1]
    if cmd == "show":
        cmd_show()
    elif cmd == "export":
        cmd_export()
    elif cmd == "apply":
        json_path = Path(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_EXPORT
        cmd_apply(json_path)
    else:
        print(f"  Unknown command: {cmd}", file=sys.stderr)
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
