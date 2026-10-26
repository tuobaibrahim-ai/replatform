"""أداة إصدار التراخيص (للمالك فقط — لا تُستخدم في مسار التشغيل).

المفتاح الخاص لا يُخزَّن في المستودع: المسار الافتراضي هو
%USERPROFILE%\\.replatform\\license_private.key
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
from datetime import date, timedelta
from pathlib import Path

from ..core import stdio
from . import licensing


def default_key_path() -> Path:
    home = Path(os.environ.get("USERPROFILE") or Path.home())
    return home / ".replatform" / "license_private.key"


def _read_seed(path: Path) -> bytes:
    if not path.is_file():
        raise SystemExit(f"المفتاح الخاص غير موجود: {path}")
    seed = path.read_bytes()
    if len(seed) != 32:
        raise SystemExit("المفتاح الخاص يجب أن يكون 32 بايت (بذرة Ed25519)")
    return seed


def cmd_keygen(args) -> int:
    target = Path(args.out) if args.out else default_key_path()
    if target.exists() and not args.force:
        raise SystemExit(f"موجود مسبقاً: {target} (استخدم --force)")
    target.parent.mkdir(parents=True, exist_ok=True)
    seed = secrets.token_bytes(32)
    target.write_bytes(seed)
    try:
        os.chmod(target, 0o600)
    except OSError:
        pass
    print(json.dumps({
        "private_key": str(target),
        "public_key": licensing.ed25519_public_key(seed).hex(),
        "note": "احتفظ بالخاص خارج المستودع ولا تشاركه.",
    }, ensure_ascii=False, indent=2))
    return 0


def cmd_issue(args) -> int:
    seed = _read_seed(Path(args.key) if args.key else default_key_path())
    today = date.today()
    expires = args.expires or (today + timedelta(days=args.days)).isoformat()
    payload = {
        "schema": licensing.LICENSE_SCHEMA,
        "license_id": args.id or f"RE-{secrets.token_hex(6).upper()}",
        "tier": args.tier,
        "customer": args.customer,
        "seats": args.seats,
        "issued": today.isoformat(),
        "expires": expires,
        "features": args.feature or [],
    }
    signed = licensing.sign_license(payload, seed)
    text = json.dumps(signed, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.out:
        target = Path(args.out)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        print(json.dumps({"written": str(target), "license_id": payload["license_id"]},
                         ensure_ascii=False))
    else:
        print(text, end="")
    return 0


def cmd_verify(args) -> int:
    data = json.loads(Path(args.license).read_text("utf-8"))
    state = licensing.verify_license(data)
    print(json.dumps(state, ensure_ascii=False, indent=2))
    return 0 if state["valid"] else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="license_admin", description="إدارة تراخيص REPLATFORM")
    sub = parser.add_subparsers(dest="command", required=True)

    p_key = sub.add_parser("keygen", help="توليد زوج مفاتيح Ed25519")
    p_key.add_argument("--out", help="مسار المفتاح الخاص")
    p_key.add_argument("--force", action="store_true")
    p_key.set_defaults(func=cmd_keygen)

    p_issue = sub.add_parser("issue", help="إصدار ترخيص موقّع")
    p_issue.add_argument("--tier", required=True, choices=licensing.KNOWN_TIERS)
    p_issue.add_argument("--customer", required=True)
    p_issue.add_argument("--seats", type=int, default=1)
    p_issue.add_argument("--days", type=int, default=365)
    p_issue.add_argument("--expires", help="YYYY-MM-DD (يتجاوز --days)")
    p_issue.add_argument("--id", help="معرّف ترخيص صريح")
    p_issue.add_argument("--feature", action="append", help="استحقاق إضافي (متكرر)")
    p_issue.add_argument("--key", help="مسار المفتاح الخاص")
    p_issue.add_argument("--out", help="ملف الإخراج")
    p_issue.set_defaults(func=cmd_issue)

    p_verify = sub.add_parser("verify", help="التحقق من ملف ترخيص")
    p_verify.add_argument("license")
    p_verify.set_defaults(func=cmd_verify)
    return parser


def main(argv: list[str] | None = None) -> int:
    stdio.configure()
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
