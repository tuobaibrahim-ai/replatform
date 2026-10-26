"""تراخيص تجارية موقّعة تعمل بلا اتصال شبكي (Ed25519، بلا اعتماديات).

المبدأ: النواة MIT وكل وظائفها متاحة بلا ترخيص. الترخيص يوثّق **استحقاقاً
تجارياً** (دعم، SLA، ميزات مؤسسية) ولا يعطّل التحليل ولا يتصل بخادم.

توقيع Ed25519 مطبّق وفق RFC 8032 لتفادي أي اعتمادية خارجية؛ يُتحقق منه
بمفتاح عام مثبّت في الكود، ويمكن تجاوزه عبر RE_LICENSE_PUBKEY للاختبار
أو للنشر المُدار ذاتياً.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import date, datetime
from pathlib import Path

from ..core import util
from ..core.config import ROOT

# --------------------------------------------------------------------------
# Ed25519 (RFC 8032) — تحقق وتوقيع بلا مكتبات خارجية.
# --------------------------------------------------------------------------

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)
_IDENTITY = (0, 1, 1, 0)


def _recover_x(y: int, sign: int) -> int | None:
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _I % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


def _decode_point(data: bytes) -> tuple[int, int, int, int] | None:
    if len(data) != 32:
        return None
    value = int.from_bytes(data, "little")
    sign = value >> 255
    y = value & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def _encode_point(point: tuple[int, int, int, int]) -> bytes:
    x, y, z, _ = point
    zinv = pow(z, _P - 2, _P)
    x = x * zinv % _P
    y = y * zinv % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _add(
    p1: tuple[int, int, int, int], p2: tuple[int, int, int, int]
) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = t1 * 2 * _D * t2 % _P
    d = z1 * 2 * z2 % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _double(p: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    x1, y1, z1, _ = p
    a = x1 * x1 % _P
    b = y1 * y1 % _P
    c = 2 * z1 * z1 % _P
    h = a + b
    e = h - (x1 + y1) * (x1 + y1)
    g = a - b
    f = c + g
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _scalar_mult(point: tuple[int, int, int, int], scalar: int):
    result = _IDENTITY
    addend = point
    while scalar:
        if scalar & 1:
            result = _add(result, addend)
        addend = _double(addend)
        scalar >>= 1
    return result


_BY = 4 * pow(5, _P - 2, _P) % _P
_BX_OPT = _recover_x(_BY, 0)
if _BX_OPT is None:  # pragma: no cover - ثابت رياضي، لا يفشل عملياً
    raise RuntimeError("نقطة قاعدة Ed25519 غير صالحة")
_BX: int = _BX_OPT
_BASE = (_BX, _BY, 1, _BX * _BY % _P)


def ed25519_public_key(seed: bytes) -> bytes:
    """المفتاح العام من بذرة خاصة 32 بايت."""
    if len(seed) != 32:
        raise ValueError("بذرة Ed25519 يجب أن تكون 32 بايت")
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    return _encode_point(_scalar_mult(_BASE, scalar))


def ed25519_sign(seed: bytes, message: bytes) -> bytes:
    """توقيع Ed25519 (يُستخدم في أداة الإصدار، لا في مسار التشغيل)."""
    if len(seed) != 32:
        raise ValueError("بذرة Ed25519 يجب أن تكون 32 بايت")
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    prefix = digest[32:]
    public = _encode_point(_scalar_mult(_BASE, scalar))
    nonce = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % _L
    r_point = _encode_point(_scalar_mult(_BASE, nonce))
    challenge = int.from_bytes(
        hashlib.sha512(r_point + public + message).digest(), "little"
    ) % _L
    s = (nonce + challenge * scalar) % _L
    return r_point + s.to_bytes(32, "little")


def ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """تحقق صارم: يرفض المفاتيح/التواقيع المشوّهة بلا استثناءات."""
    if len(public_key) != 32 or len(signature) != 64:
        return False
    public = _decode_point(public_key)
    r_bytes = signature[:32]
    r_point = _decode_point(r_bytes)
    if public is None or r_point is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    challenge = int.from_bytes(
        hashlib.sha512(r_bytes + public_key + message).digest(), "little"
    ) % _L
    left = _scalar_mult(_BASE, s)
    right = _add(r_point, _scalar_mult(public, challenge))
    return _encode_point(left) == _encode_point(right)


# --------------------------------------------------------------------------
# الترخيص
# --------------------------------------------------------------------------

LICENSE_SCHEMA = 1
LICENSE_PATH = ROOT / "license.json"
GRACE_DAYS = 14
COMMUNITY_FEATURES = ("core",)
KNOWN_TIERS = ("professional", "enterprise")

# مفتاح الإصدار العام (32 بايت hex). المفتاح الخاص لا يوجد في المستودع.
# يمكن تجاوزه عبر RE_LICENSE_PUBKEY للاختبار أو للنشر المُدار ذاتياً.
PINNED_PUBLIC_KEY = "a494da18a18a99d900724cfa9cb447d98295482b4d05adfafa4d69fd83bab6e7"

TIER_FEATURES = {
    "professional": ("core", "priority_support", "audit_export"),
    "enterprise": ("core", "priority_support", "audit_export", "fleet_report", "sso", "sla"),
}


class LicenseError(RuntimeError):
    """ترخيص غير صالح أو غير قابل للتطبيق."""


class EntitlementError(RuntimeError):
    """ميزة تتطلب استحقاقاً تجارياً سارياً."""


def _license_path(path: str | Path | None = None) -> Path:
    if path is not None:
        return Path(path)
    override = os.environ.get("RE_LICENSE_PATH", "").strip()
    return Path(override) if override else LICENSE_PATH


def _public_key() -> bytes | None:
    raw = os.environ.get("RE_LICENSE_PUBKEY", "").strip() or PINNED_PUBLIC_KEY
    if not raw:
        return None
    try:
        key = bytes.fromhex(raw)
    except ValueError:
        return None
    return key if len(key) == 32 else None


def canonical_payload(payload: dict) -> bytes:
    """التمثيل الموقّع: JSON مرتّب بلا مسافات، UTF-8."""
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def sign_license(payload: dict, seed: bytes) -> dict:
    """يضيف التوقيع إلى حمولة الترخيص (أداة الإصدار فقط)."""
    body = {key: value for key, value in payload.items() if key != "signature"}
    signature = ed25519_sign(seed, canonical_payload(body))
    return {**body, "signature": _b64encode(signature)}


def _community(reason: str = "") -> dict:
    return {
        "valid": False,
        "tier": "community",
        "license_id": "",
        "customer": "",
        "seats": 0,
        "issued": "",
        "expires": "",
        "days_left": None,
        "grace": False,
        "features": list(COMMUNITY_FEATURES),
        "reason": reason or "نسخة المجتمع (MIT)",
    }


def _parse_date(value: str) -> date | None:
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except (TypeError, ValueError):
        return None


def verify_license(data: dict, public_key: bytes | None = None) -> dict:
    """يتحقق من التوقيع والصلاحية ويعيد حالة موحّدة."""
    if not isinstance(data, dict):
        return _community("ملف ترخيص غير صالح")
    signature_text = data.get("signature")
    if not isinstance(signature_text, str) or not signature_text:
        return _community("توقيع مفقود")
    payload = {key: value for key, value in data.items() if key != "signature"}
    if int(payload.get("schema", 0) or 0) != LICENSE_SCHEMA:
        return _community(f"مخطط ترخيص غير مدعوم: {payload.get('schema')}")
    tier = str(payload.get("tier") or "").lower()
    if tier not in KNOWN_TIERS:
        return _community(f"فئة ترخيص غير معروفة: {tier or '(فارغة)'}")
    key = public_key or _public_key()
    if key is None:
        return _community("لا مفتاح عام مثبّت للتحقق من التراخيص")
    try:
        signature = _b64decode(signature_text)
    except (ValueError, TypeError):
        return _community("توقيع غير قابل للفك")
    if not ed25519_verify(key, canonical_payload(payload), signature):
        return _community("توقيع الترخيص غير صحيح")

    expires_text = str(payload.get("expires") or "")
    expires = _parse_date(expires_text)
    today = date.today()
    days_left = (expires - today).days if expires else None
    grace = bool(expires and days_left is not None and days_left < 0 and abs(days_left) <= GRACE_DAYS)
    if expires and days_left is not None and days_left < -GRACE_DAYS:
        return _community(f"انتهى الترخيص في {expires_text}")

    features = list(TIER_FEATURES.get(tier, COMMUNITY_FEATURES))
    for extra in payload.get("features") or []:
        if isinstance(extra, str) and extra not in features:
            features.append(extra)
    return {
        "valid": True,
        "tier": tier,
        "license_id": str(payload.get("license_id") or ""),
        "customer": str(payload.get("customer") or ""),
        "seats": int(payload.get("seats") or 0),
        "issued": str(payload.get("issued") or ""),
        "expires": expires_text,
        "days_left": days_left,
        "grace": grace,
        "features": features,
        "reason": "ترخيص سارٍ" + (" (فترة سماح)" if grace else ""),
    }


def status(path: str | Path | None = None) -> dict:
    """حالة الترخيص الحالي؛ لا يتصل بالشبكة ولا يقرأ أسراراً أخرى."""
    target = _license_path(path)
    if not target.exists():
        return _community()
    try:
        data = json.loads(target.read_text("utf-8"))
    except (json.JSONDecodeError, OSError):
        return _community("ملف الترخيص غير قابل للقراءة")
    return verify_license(data)


def activate(source: str | Path, destination: str | Path | None = None) -> dict:
    """يتحقق من ملف ترخيص ثم يثبّته. يرفض أي ترخيص غير صالح."""
    origin = Path(source)
    if not origin.is_file():
        raise LicenseError(f"ملف الترخيص غير موجود: {origin}")
    try:
        data = json.loads(origin.read_text("utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise LicenseError(f"ملف الترخيص غير قابل للقراءة: {exc}") from exc
    state = verify_license(data)
    if not state["valid"]:
        raise LicenseError(f"ترخيص مرفوض: {state['reason']}")
    target = _license_path(destination)
    util.atomic_write_text(
        target, json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    )
    return state


def deactivate(destination: str | Path | None = None) -> bool:
    """يحذف الترخيص المحلي ويعود لنسخة المجتمع."""
    target = _license_path(destination)
    if not target.exists():
        return False
    target.unlink()
    return True


def has_feature(name: str, path: str | Path | None = None) -> bool:
    return name in status(path)["features"]


def require_feature(name: str, path: str | Path | None = None) -> dict:
    """يرفع EntitlementError برسالة عربية واضحة عند غياب الاستحقاق."""
    state = status(path)
    if name in state["features"]:
        return state
    raise EntitlementError(
        f"الميزة '{name}' تتطلب ترخيصاً تجارياً سارياً (الحالي: {state['tier']}). "
        "النواة MIT تعمل كاملة بلا ترخيص. للترقية: docs/COMMERCIAL.md"
    )
