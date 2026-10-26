"""تشخيص جاهزية التثبيت: حزمة فحص واحدة + حزمة تشخيص قابلة للمشاركة.

لا يقرأ قيم الأسرار ولا يصدّرها: يُقنّع كل مفتاح قبل أي كتابة.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import sys
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from .. import __version__
from ..core import config as config_module
from ..core.config import CONFIG_PATH, ROOT, WORKSPACES_DIR, api_key, load_config

MIN_PYTHON = (3, 11)
SECRET_KEYS = {
    "api_key",
    "token",
    "password",
    "secret",
    "webhook",
    "client_secret",
    "apikey",
}
REDACTED = "(محجوب)"


def _status(ok: bool, warn: bool = False) -> str:
    if ok:
        return "ok"
    return "warn" if warn else "fail"


def _check_python() -> dict:
    current = sys.version_info[:3]
    ok = current[:2] >= MIN_PYTHON
    return {
        "id": "python",
        "title": "إصدار Python",
        "status": _status(ok),
        "detail": f"{current[0]}.{current[1]}.{current[2]} (الحد {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+)",
        "hint": "" if ok else "ثبّت Python 3.11 أو أحدث من python.org",
    }


def _check_platform() -> dict:
    is_windows = os.name == "nt"
    return {
        "id": "platform",
        "title": "نظام التشغيل",
        "status": _status(is_windows, warn=True),
        "detail": f"{platform.system()} {platform.release()} ({platform.machine()})",
        "hint": "" if is_windows else "المنصة مدعومة رسمياً على Windows 10/11 فقط",
    }


def _check_config() -> dict:
    raw = config_module.read_config_raw()
    exists = CONFIG_PATH.exists()
    if not exists:
        return {
            "id": "config",
            "title": "ملف الإعدادات",
            "status": "warn",
            "detail": "config.json غير موجود — ستُستخدم الافتراضات",
            "hint": "python repl.py config init",
        }
    if not raw:
        return {
            "id": "config",
            "title": "ملف الإعدادات",
            "status": "fail",
            "detail": "config.json غير صالح (JSON تالف أو ليس كائناً)",
            "hint": "أعد التسمية إلى config.json.bad ثم python repl.py config init",
        }
    version = config_module.config_version(raw)
    if version > config_module.CONFIG_VERSION:
        return {
            "id": "config",
            "title": "ملف الإعدادات",
            "status": "fail",
            "detail": f"نسخة المخطط {version} أحدث من المدعومة {config_module.CONFIG_VERSION}",
            "hint": "حدّث REPLATFORM بدل الرجوع لإصدار أقدم",
        }
    if version < config_module.CONFIG_VERSION:
        return {
            "id": "config",
            "title": "ملف الإعدادات",
            "status": "warn",
            "detail": f"نسخة المخطط {version} وتحتاج هجرة إلى {config_module.CONFIG_VERSION}",
            "hint": "python repl.py config migrate",
        }
    return {
        "id": "config",
        "title": "ملف الإعدادات",
        "status": "ok",
        "detail": f"صالح، نسخة المخطط {version}",
        "hint": "",
    }


def _check_provider() -> dict:
    cfg = load_config()
    key = api_key(cfg)
    enabled = bool((cfg.get("provider") or {}).get("base_url"))
    if key:
        return {
            "id": "provider",
            "title": "مزوّد النموذج",
            "status": "ok",
            "detail": f"مفتاح مضبوط ({config_module.mask_secret(key)})",
            "hint": "",
        }
    return {
        "id": "provider",
        "title": "مزوّد النموذج",
        "status": _status(False, warn=True) if enabled else "warn",
        "detail": "لا مفتاح API — وضع heuristic يعمل بلا شبكة",
        "hint": 'setx RE_API_KEY "..." ثم أعد فتح الطرفية',
    }


def _check_dependencies() -> dict:
    missing = []
    for module in ("pefile", "asn1crypto", "certifi"):
        try:
            __import__(module)
        except Exception:  # noqa: BLE001
            missing.append(module)
    return {
        "id": "dependencies",
        "title": "اعتماديات التشغيل",
        "status": _status(not missing),
        "detail": "كل الاعتماديات موجودة" if not missing else f"ناقص: {', '.join(missing)}",
        "hint": "" if not missing else "python -m pip install -r requirements.lock",
    }


def _check_tools() -> dict:
    from ..core.registry import detect_tools

    try:
        tools = detect_tools()
    except Exception as exc:  # noqa: BLE001
        return {
            "id": "tools",
            "title": "الأدوات الخارجية",
            "status": "warn",
            "detail": f"تعذّر الفحص: {type(exc).__name__}",
            "hint": "تحقق يدوياً من Java/apktool/jadx/Ghidra",
        }
    available = [item["name"] for item in tools if item.get("ok")]
    missing = [item["name"] for item in tools if not item.get("ok")]
    return {
        "id": "tools",
        "title": "الأدوات الخارجية",
        "status": _status(bool(available), warn=True),
        "detail": (
            f"متاح {len(available)}/{len(tools)}"
            + (f" — ناقص: {', '.join(missing[:6])}" if missing else "")
        ),
        "hint": "" if available else "راجع docs/DEPLOYMENT.md لتثبيت الأدوات الاختيارية",
    }


def _check_writable() -> dict:
    targets = [WORKSPACES_DIR, ROOT]
    failed = []
    for target in targets:
        try:
            target.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(dir=target, prefix=".doctor-", delete=True):
                pass
        except OSError:
            failed.append(str(target))
    return {
        "id": "writable",
        "title": "صلاحية الكتابة",
        "status": _status(not failed),
        "detail": "المجلدات قابلة للكتابة" if not failed else f"غير قابل للكتابة: {', '.join(failed)}",
        "hint": "" if not failed else "شغّل من مجلد يملك المستخدم صلاحية الكتابة عليه",
    }


def _check_disk() -> dict:
    try:
        usage = shutil.disk_usage(ROOT)
        free_gb = usage.free / (1024 ** 3)
    except OSError as exc:
        return {
            "id": "disk",
            "title": "مساحة القرص",
            "status": "warn",
            "detail": f"تعذّر القياس: {type(exc).__name__}",
            "hint": "",
        }
    ok = free_gb >= 2
    return {
        "id": "disk",
        "title": "مساحة القرص",
        "status": _status(ok, warn=True),
        "detail": f"متاح {free_gb:.1f} GB",
        "hint": "" if ok else "حرّر مساحة: التحليل يحتاج مساحات عمل مؤقتة",
    }


def _check_license() -> dict:
    from . import licensing

    try:
        state = licensing.status()
    except Exception as exc:  # noqa: BLE001
        return {
            "id": "license",
            "title": "الترخيص",
            "status": "warn",
            "detail": f"تعذّر القراءة: {type(exc).__name__}",
            "hint": "python repl.py license status",
        }
    if state["valid"]:
        return {
            "id": "license",
            "title": "الترخيص",
            "status": "ok",
            "detail": f"{state['tier']} — ينتهي {state['expires'] or 'بلا نهاية'}",
            "hint": "",
        }
    return {
        "id": "license",
        "title": "الترخيص",
        "status": "warn",
        "detail": "نسخة المجتمع (MIT) — كل الوظائف الأساسية متاحة",
        "hint": "للاشتراكات: python repl.py license activate <ملف>",
    }


CHECKS = (
    _check_python,
    _check_platform,
    _check_config,
    _check_provider,
    _check_dependencies,
    _check_tools,
    _check_writable,
    _check_disk,
    _check_license,
)


def run_checks(only: tuple[str, ...] = ()) -> dict:
    """ينفّذ كل الفحوص (أو المفردة بـ id) ويعيد تقريراً منظّماً."""
    checks = []
    for check in CHECKS:
        result = check()
        if only and result["id"] not in only:
            continue
        checks.append(result)
    counts = {"ok": 0, "warn": 0, "fail": 0}
    for item in checks:
        counts[item["status"]] = counts.get(item["status"], 0) + 1
    return {
        "ok": counts["fail"] == 0,
        "version": __version__,
        "generated": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "counts": counts,
        "checks": checks,
    }


def _redact(value):
    if isinstance(value, dict):
        return {
            key: REDACTED if key.lower() in SECRET_KEYS and item else _redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


def redacted_config() -> dict:
    """نسخة آمنة للمشاركة: تُقنّع كل حقل سرّي مهما كان موقعه."""
    return _redact(config_module.read_config_raw())


def _environment_text() -> str:
    lines = [
        f"REPLATFORM {__version__}",
        f"generated: {datetime.now(timezone.utc).replace(microsecond=0).isoformat()}",
        f"python: {platform.python_version()} ({sys.executable})",
        f"implementation: {platform.python_implementation()}",
        f"platform: {platform.platform()}",
        f"machine: {platform.machine()}",
        f"cwd: {Path.cwd()}",
        f"root: {ROOT}",
        f"frozen: {getattr(sys, 'frozen', False)}",
    ]
    return "\n".join(lines) + "\n"


def build_bundle(dest: str | Path, report: dict | None = None) -> Path:
    """ينشئ ZIP تشخيصياً آمناً (بلا أسرار) لإرفاقه بالدعم."""
    target = Path(dest)
    if target.suffix.lower() != ".zip":
        target = target.with_suffix(".zip")
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = report if report is not None else run_checks()
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "doctor.json", json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
        )
        archive.writestr("environment.txt", _environment_text())
        archive.writestr(
            "config.redacted.json",
            json.dumps(redacted_config(), ensure_ascii=False, indent=2) + "\n",
        )
        archive.writestr(
            "README.txt",
            "حزمة تشخيص REPLATFORM. الأسرار مقنّعة. راجع المحتوى قبل المشاركة.\n",
        )
    return target
