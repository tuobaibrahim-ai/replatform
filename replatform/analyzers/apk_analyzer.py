"""محلل APK: البيان، الأذونات، المكونات، المكتبات الأصلية، التوقيع."""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

from ..core.config import TOOLS_DIR, load_config
from . import Analyzer, Target

SIGNING_KEYS = ("v1", "v2", "v3", "v3_1", "v4")
SIGNING_LABELS = {"v1": "v1", "v2": "v2", "v3": "v3", "v3_1": "v3.1", "v4": "v4"}
MAX_IDSIG_BYTES = 16 * 1024 * 1024


def signing_schemes(info: dict) -> list[str]:
    return [SIGNING_LABELS[key] for key in SIGNING_KEYS if info.get(key)]


DANGEROUS = {
    "android.permission.READ_SMS", "android.permission.SEND_SMS",
    "android.permission.RECORD_AUDIO", "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION", "android.permission.READ_CONTACTS",
    "android.permission.CALL_PHONE", "android.permission.READ_PHONE_STATE",
    "android.permission.MANAGE_EXTERNAL_STORAGE", "android.permission.READ_CALL_LOG",
    "android.permission.PROCESS_OUTGOING_CALLS", "android.permission.SYSTEM_ALERT_WINDOW",
}


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _attr(element, name: str) -> str | None:
    for key, value in element.attrib.items():
        if _local(key) == name:
            return value
    return None


def _cfg_int(key: str, default: int) -> int:
    try:
        return int(load_config().get("analysis", {}).get(key, default))
    except (TypeError, ValueError):
        return default


def validate_apk(apk_path: str | Path) -> dict:
    """حدود أمان لملف APK قبل تمريره إلى apktool أو ZIP.

    يمنع الملفات الضخمة، والزيب بوم (عدد مدخلات/حجم غير مضغوط/نسبة ضغط
    شاذة)، ويُستخدم في المحلل وأدوات APK معاً.
    """
    path = Path(apk_path).resolve()
    if not path.is_file() or path.suffix.lower() != ".apk":
        raise ValueError(f"مطلوب ملف APK: {path}")
    size = path.stat().st_size
    max_mb = max(1, _cfg_int("apk_max_mb", 512))
    if size > max_mb * 1024 * 1024:
        raise ValueError(
            f"حجم APK ({size / (1024 * 1024):.1f} MB) يتجاوز حد التحليل "
            f"({max_mb} MB) — عدّل analysis.apk_max_mb عند الحاجة."
        )
    max_entries = max(1000, _cfg_int("apk_max_entries", 50000))
    max_uncompressed = max(1, _cfg_int("apk_uncompressed_max_mb", 2048)) * 1024 * 1024
    max_ratio = max(10, _cfg_int("apk_max_ratio", 200))
    try:
        with zipfile.ZipFile(path) as zf:
            infos = zf.infolist()
            if len(infos) > max_entries:
                raise ValueError(
                    f"عدد مدخلات APK ({len(infos)}) يتجاوز الحد ({max_entries})."
                )
            total = sum(max(0, int(info.file_size)) for info in infos)
    except zipfile.BadZipFile as exc:
        raise ValueError(f"ملف APK ليس ZIP صالحاً: {exc}") from exc
    if total > max_uncompressed:
        raise ValueError(
            f"المحتوى غير المضغوط في APK ({total / (1024 * 1024):.1f} MB) "
            f"يتجاوز الحد ({max_uncompressed // (1024 * 1024)} MB)."
        )
    if size and total > max(1024 * 1024, size * max_ratio):
        raise ValueError(
            "نسبة ضغط APK شاذة (احتمال زيب بوم) — رُفض الملف."
        )
    return {"size": size, "entries": len(infos), "uncompressed": total}


def decode_apk(apk_path: str, timeout: int = 300) -> dict:
    """يفك AndroidManifest.xml إلى نص XML + بيانات apktool.yml (الإصدار/الـ SDK)."""
    validate_apk(apk_path)
    apktool = TOOLS_DIR / "apktool.jar"
    if not apktool.exists():
        raise RuntimeError("apktool.jar غير موجود في tools/")
    tmp = tempfile.mkdtemp(prefix="re_apk_")
    try:
        proc = subprocess.run(
            ["java", "-jar", str(apktool), "d", str(apk_path),
             "-s", "-f", "-o", tmp],
            capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace",
        )
        manifest = Path(tmp) / "AndroidManifest.xml"
        if not manifest.exists():
            raise RuntimeError(f"تعذر فك البيان (رمز الخروج {proc.returncode})")
        manifest_limit = max(64, _cfg_int("apk_manifest_max_kb", 8192)) * 1024
        if manifest.stat().st_size > manifest_limit:
            raise RuntimeError("AndroidManifest.xml أكبر من الحد الآمن بعد الفك.")
        meta = {"min_sdk": "", "target_sdk": "", "version_code": "", "version_name": ""}
        yml = Path(tmp) / "apktool.yml"
        if yml.exists() and yml.stat().st_size <= 1024 * 1024:
            text = yml.read_text("utf-8", errors="replace")
            for key, pattern in (
                ("min_sdk", r"minSdkVersion:\s*['\"]?([^'\"\s]+)"),
                ("target_sdk", r"targetSdkVersion:\s*['\"]?([^'\"\s]+)"),
                ("version_code", r"versionCode:\s*['\"]?([^'\"\s]+)"),
                ("version_name", r"versionName:\s*['\"]?([^'\"\s]+)"),
            ):
                match = re.search(pattern, text)
                if match:
                    meta[key] = match.group(1)
        return {"xml": manifest.read_text("utf-8", errors="replace"), "meta": meta}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def decode_manifest(apk_path: str, timeout: int = 300) -> str:
    """واجهة مختصرة: نص XML فقط."""
    return decode_apk(apk_path, timeout)["xml"]


def _sdk_int(value: str | None) -> int | None:
    try:
        return int(str(value or "").strip().split(".", 1)[0])
    except (TypeError, ValueError):
        return None


def _intent_filter_info(element) -> tuple[bool, bool]:
    """يعيد (يوجد intent-filter، يوجد MAIN + LAUNCHER)."""
    has_filter = False
    launcher = False
    for child in element:
        if _local(child.tag) != "intent-filter":
            continue
        has_filter = True
        actions: set[str] = set()
        categories: set[str] = set()
        for item in child:
            name = _attr(item, "name") or ""
            if _local(item.tag) == "action":
                actions.add(name)
            elif _local(item.tag) == "category":
                categories.add(name)
        if (
            "android.intent.action.MAIN" in actions
            and "android.intent.category.LAUNCHER" in categories
        ):
            launcher = True
    return has_filter, launcher


def _parse_manifest_xml(xml_text: str):
    """يحلّل بيان APK بعد رفض DOCTYPE/ENTITY — حماية من تضخّم الكيانات (billion laughs)."""
    upper = xml_text.upper()
    if "<!DOCTYPE" in upper or "<!ENTITY" in upper:
        raise ValueError("بيان APK يحتوي DOCTYPE/ENTITY غير مسموح — رُفض حمايةً للتحليل.")
    return ET.fromstring(xml_text)  # noqa: S314 — محصَّن أعلاه، والحجم محدود في decode_apk


def parse_manifest(xml_text: str, meta: dict | None = None) -> dict:
    root = _parse_manifest_xml(xml_text)
    info: dict = {
        "package": _attr(root, "package") or "",
        "version_name": "",
        "version_code": "",
        "permissions": [],
        "features": [],
        "components": {"activities": 0, "services": 0, "receivers": 0, "providers": 0},
        "exported": 0,
        "exported_components": [],
        "exported_inferred": 0,
        "exported_without_permission": 0,
        "exported_missing_explicit": 0,
        "application": {},
        "main_activity": "",
    }
    component_elements: list[tuple[str, object]] = []
    application_permission = ""
    for element in root.iter():
        tag = _local(element.tag)
        if tag in ("uses-permission", "uses-permission-sdk-23"):
            name = _attr(element, "name")
            if name:
                info["permissions"].append(name)
        elif tag == "uses-feature":
            name = _attr(element, "name")
            if name:
                info["features"].append(name)
        elif tag == "uses-sdk":
            info["min_sdk"] = _attr(element, "minSdkVersion") or ""
            info["target_sdk"] = _attr(element, "targetSdkVersion") or ""
        elif tag == "application":
            application_permission = _attr(element, "permission") or ""
            info["application"] = {
                "debuggable": (_attr(element, "debuggable") or "false").lower() == "true",
                "allow_backup": (_attr(element, "allowBackup") or "true").lower() != "false",
                "cleartext": (_attr(element, "usesCleartextTraffic") or "false").lower() == "true",
                "permission": application_permission,
            }
        elif tag in ("activity", "activity-alias", "service", "receiver", "provider"):
            key = {"activity": "activities", "activity-alias": "activities",
                   "service": "services", "receiver": "receivers",
                   "provider": "providers"}[tag]
            info["components"][key] += 1
            component_elements.append((tag, element))
            if tag == "activity":
                _has_filter, launcher = _intent_filter_info(element)
                if launcher:
                    info["main_activity"] = _attr(element, "name") or ""
    if meta:
        info["min_sdk"] = info.get("min_sdk") or meta.get("min_sdk", "")
        info["target_sdk"] = info.get("target_sdk") or meta.get("target_sdk", "")
        info["version_code"] = info.get("version_code") or meta.get("version_code", "")
        info["version_name"] = info.get("version_name") or meta.get("version_name", "")
    info.setdefault("min_sdk", "")
    info.setdefault("target_sdk", "")

    # دلالات android:exported منذ Android 12 (targetSdk 31+):
    # - قيمة صريحة تحكم دائماً.
    # - عند غيابها: وجود intent-filter يعني exported=true افتراضياً،
    #   وإلا فالمكوّن خاص (false). غياب القيمة الصريحة مع intent-filter
    #   مخالف لمتطلبات targetSdk 31+ ويُنبَّه عليه.
    target_sdk = _sdk_int(info.get("target_sdk"))
    effective_target = target_sdk
    if effective_target is None:
        effective_target = _sdk_int(info.get("min_sdk"))
    if effective_target is None:
        effective_target = 1
    exported_components: list[dict] = []
    exported_total = 0
    inferred = 0
    without_permission = 0
    missing_explicit = 0
    for tag, element in component_elements:
        name = _attr(element, "name") or ""
        component_permission = _attr(element, "permission") or ""
        # android:permission على <application> يُورَّث لكل مكوّن بلا صلاحية خاصة.
        permission = component_permission or application_permission
        has_filter, _launcher = _intent_filter_info(element)
        explicit = _attr(element, "exported")
        if explicit is not None:
            exported = explicit.strip().lower() == "true"
            reason = "explicit"
        elif has_filter:
            exported = True
            reason = "intent-filter-default"
            inferred += 1
            if effective_target >= 31:
                missing_explicit += 1
        elif tag == "provider" and effective_target <= 16:
            # مزوّد المحتوى كان مُصدَّراً افتراضياً قبل Android 4.2 (API 17).
            exported = True
            reason = "provider-legacy-default"
            inferred += 1
        else:
            exported = False
            reason = "default-private"
        if not exported:
            continue
        exported_total += 1
        if not permission:
            without_permission += 1
        if len(exported_components) < 200:
            exported_components.append({
                "type": tag,
                "name": name,
                "permission": permission,
                "has_intent_filter": has_filter,
                "reason": reason,
            })
    info["exported"] = exported_total
    info["exported_components"] = exported_components
    info["exported_truncated"] = exported_total > len(exported_components)
    info["exported_inferred"] = inferred
    info["exported_without_permission"] = without_permission
    info["exported_missing_explicit"] = missing_explicit
    return info


def _cert_from_der(der: bytes) -> dict:
    """يحاول استخراج اسم الشهادة وتجزئتها (asn1crypto اختياري)."""
    result = {"sha256": hashlib.sha256(der).hexdigest()}
    try:
        from asn1crypto import x509

        cert = x509.Certificate.load(der)
        subject = cert.subject.native
        result["subject"] = subject.get("common_name") or subject.get("organization_name") or ""
        result["issuer"] = cert.issuer.native.get("common_name", "")
        result["not_after"] = str(cert["tbs_certificate"]["validity"]["not_after"].native)
    except Exception:  # noqa: BLE001
        pass
    return result


def signing_info(apk_path: str) -> dict:
    """يكتشف مخططات v1/v2/v3/v3.1/v4 ويستخرج أول شهادة إن أمكن."""
    info: dict = {
        "v1": False, "v2": False, "v3": False, "v3_1": False, "v4": False,
        "certs": [], "v1_files": [],
    }
    try:
        with zipfile.ZipFile(apk_path) as zf:
            names = zf.namelist()
            if len(names) > max(1000, _cfg_int("apk_max_entries", 50000)):
                info["error"] = "عدد مدخلات APK يتجاوز الحد الآمن."
                return info
            v1 = [n for n in names if re.match(r"META-INF/.*\.(RSA|DSA|EC)$", n, re.I)]
            info["v1_files"] = v1
            info["v1"] = bool(v1)
            if v1:
                if zf.getinfo(v1[0]).file_size > MAX_IDSIG_BYTES:
                    raise ValueError("شهادة v1 أكبر من الحد الآمن.")
                der = zf.read(v1[0])
                try:
                    from asn1crypto import cms

                    content = cms.ContentInfo.load(der)
                    cert_choices = content["content"]["certificates"]
                    if cert_choices:
                        info["certs"].append(_cert_from_der(cert_choices[0].chosen.dump()))
                except Exception:  # noqa: BLE001
                    info["certs"].append({"sha256": hashlib.sha256(der).hexdigest()})

        block = _apk_sig_block(apk_path)
        if block:
            pairs = block[8:-24]
            offset = 0
            while offset + 12 <= len(pairs):
                pair_len = int.from_bytes(pairs[offset:offset + 8], "little")
                if pair_len < 4 or offset + 8 + pair_len > len(pairs):
                    break
                pair_id = int.from_bytes(pairs[offset + 8:offset + 12], "little")
                value = pairs[offset + 12:offset + 8 + pair_len]
                if pair_id == 0x7109871A:
                    info["v2"] = True
                    info["certs"].extend(_v2_certs(value))
                elif pair_id == 0xF05368C0:
                    info["v3"] = True
                elif pair_id == 0x1B93AD61:
                    info["v3_1"] = True
                    try:
                        info["certs"].extend(_v2_certs(value))
                    except Exception:  # noqa: BLE001
                        pass
                offset += 8 + pair_len
    except Exception as exc:  # noqa: BLE001
        info["error"] = f"{type(exc).__name__}: {exc}"

    # توقيع v4 اختياري في ملف جانبي: <apk>.idsig
    idsig = Path(str(apk_path) + ".idsig")
    if idsig.is_file():
        info["v4"] = True
        info["v4_file"] = str(idsig)
        info["v4_size"] = idsig.stat().st_size
        if info["v4_size"] <= MAX_IDSIG_BYTES:
            try:
                digest = hashlib.sha256()
                with open(idsig, "rb") as handle:
                    for block in iter(lambda: handle.read(1024 * 1024), b""):
                        digest.update(block)
                info["v4_sha256"] = digest.hexdigest()
            except OSError:
                pass
        else:
            info["v4_error"] = "ملف .idsig أكبر من الحد الآمن؛ لم تُحسب التجزئة."

    # إزالة التكرار
    seen, unique = set(), []
    for cert in info["certs"]:
        key = cert.get("sha256")
        if key and key not in seen:
            seen.add(key)
            unique.append(cert)
    info["certs"] = unique
    info["schemes"] = signing_schemes(info)
    return info


def _apk_sig_block(apk_path: str) -> bytes | None:
    """يقرأ كتلة توقيع APK وحدها (بدون تحميل الملف كاملاً في الذاكرة).

    البنية: [حجم 8][أزواج][حجم 8][APK Sig Block 42] ثم الدليل المركزي.
    """
    path = Path(apk_path)
    size = path.stat().st_size
    if size < 32:
        return None
    magic = b"APK Sig Block 42"

    # نحتاج EOCD لمعرفة بداية الدليل المركزي بدقة.
    tail_len = min(size, 65557)
    with open(path, "rb") as handle:
        handle.seek(size - tail_len)
        tail = handle.read(tail_len)
    eocd = tail.rfind(b"PK\x05\x06")
    if eocd != -1 and eocd + 20 <= len(tail):
        cd_offset = int.from_bytes(tail[eocd + 16:eocd + 20], "little")
        if cd_offset != 0xFFFFFFFF and 32 <= cd_offset <= size:
            with open(path, "rb") as handle:
                handle.seek(cd_offset - 24)
                footer = handle.read(24)
            if len(footer) == 24 and footer[8:] == magic:
                block_size = int.from_bytes(footer[:8], "little")
                total = block_size + 8
                start = cd_offset - total
                if 24 <= total <= cd_offset and start >= 0:
                    with open(path, "rb") as handle:
                        handle.seek(start)
                        block = handle.read(total)
                    if (
                        len(block) == total
                        and int.from_bytes(block[:8], "little") == block_size
                        and block[-16:] == magic
                    ):
                        return block

    # مسار احتياطي لـ ZIP64 أو ملفات غير نمطية صغيرة.
    if size > 64 * 1024 * 1024:
        return None
    raw = path.read_bytes()
    footer = raw.rfind(magic)
    if footer == -1:
        return None
    trailing = int.from_bytes(raw[footer - 8:footer], "little")
    start = footer - trailing + 8
    if start < 8:
        return None
    block = raw[start:footer + 16]
    if (
        len(block) > 24
        and int.from_bytes(block[:8], "little") == trailing
        and block[-16:] == magic
    ):
        return block
    return None


def _v2_certs(value: bytes) -> list[dict]:
    """يستخرج الشهادات من قيمة كتلة التوقيع v2."""
    out: list[dict] = []

    def lp(data: bytes, offset: int) -> tuple[bytes, int]:
        length = int.from_bytes(data[offset:offset + 4], "little")
        start = offset + 4
        return data[start:start + length], start + length

    try:
        signers, _ = lp(value, 0)
        signer, _ = lp(signers, 0)
        signed_data, _ = lp(signer, 0)
        _digests, pos = lp(signed_data, 0)
        certs_blob, _ = lp(signed_data, pos)
        pos = 0
        while pos < len(certs_blob):
            cert_der, pos = lp(certs_blob, pos)
            out.append(_cert_from_der(cert_der))
    except Exception:  # noqa: BLE001
        pass
    return out


def _native_libs(apk_path: str) -> dict:
    abis: dict[str, int] = {}
    try:
        with zipfile.ZipFile(apk_path) as zf:
            names = zf.namelist()
            if len(names) > max(1000, _cfg_int("apk_max_entries", 50000)):
                return abis
            for name in names:
                if name.startswith("lib/") and name.endswith(".so"):
                    parts = name.split("/")
                    if len(parts) > 2:
                        abis[parts[1]] = abis.get(parts[1], 0) + 1
    except Exception:  # noqa: BLE001
        pass
    return abis


def quick_summary(path: str) -> dict:
    decoded = decode_apk(path, timeout=load_config()["analysis"]["apk_decode_timeout"])
    manifest = parse_manifest(decoded["xml"], decoded["meta"])
    signing = signing_info(path)
    return {
        "package": manifest.get("package", ""),
        "version": manifest.get("version_name", ""),
        "min_sdk": manifest.get("min_sdk", ""),
        "target_sdk": manifest.get("target_sdk", ""),
        "permissions": manifest.get("permissions", []),
        "debuggable": manifest.get("application", {}).get("debuggable", False),
        "exported": manifest.get("exported", 0),
        "exported_without_permission": manifest.get("exported_without_permission", 0),
        "exported_missing_explicit": manifest.get("exported_missing_explicit", 0),
        "main_activity": manifest.get("main_activity", ""),
        "signing": {k: signing.get(k, False) for k in SIGNING_KEYS},
        "schemes": signing.get("schemes", []),
        "certs": [c.get("subject") or c.get("sha256", "")[:16] for c in signing.get("certs", [])],
        "abis": _native_libs(path),
    }


class APKAnalyzer(Analyzer):
    name = "apk"
    description = "تحليل APK: البيان، الأذونات، المكونات، المكتبات، التوقيع"

    def can_handle(self, target: Target) -> bool:
        return target.kind == "APK"

    def run(self, target: Target, ws) -> dict:  # noqa: ARG002
        timeout = load_config()["analysis"]["apk_decode_timeout"]
        decoded = decode_apk(str(target.path), timeout=timeout)
        manifest = parse_manifest(decoded["xml"], decoded["meta"])
        signing = signing_info(str(target.path))
        abis = _native_libs(str(target.path))

        permissions = manifest.get("permissions", [])
        dangerous = sorted(set(permissions) & DANGEROUS)
        app = manifest.get("application", {})
        score = 0
        findings: list[str] = []
        if app.get("debuggable"):
            score += 2
            findings.append("قابل للتنقيح (debuggable=true) — خطر أمني")
        if not signing_schemes(signing):
            score += 2
            findings.append("غير موقّع")
        if app.get("cleartext"):
            score += 1
            findings.append("يسمح بحركة HTTP غير مشفرة (usesCleartextTraffic)")
        exported = int(manifest.get("exported", 0))
        if exported > 0:
            score += 1
            unprotected = int(manifest.get("exported_without_permission", 0))
            findings.append(f"{exported} مكوّن مُصدّر (exported)")
            if unprotected:
                score += 1
                examples = [
                    item.get("name", "") for item in manifest.get("exported_components", [])
                    if not item.get("permission")
                ][:5]
                findings.append(
                    f"{unprotected} مكوّن مُصدّر بلا permission"
                    + (": " + ", ".join(examples) if examples else "")
                )
        missing_explicit = int(manifest.get("exported_missing_explicit", 0))
        if missing_explicit:
            score += 1
            findings.append(
                f"{missing_explicit} مكوّن ذو intent-filter بلا android:exported صريح "
                "مع targetSdk 31+ (مخالف لمتطلبات Android 12+)"
            )
        if dangerous:
            score += min(3, len(dangerous))
            findings.append("أذونات حساسة: " + ", ".join(p.split(".")[-1] for p in dangerous))

        verdict = "critical" if score >= 5 else ("warn" if score >= 2 else "info")
        return {
            "kind": "APK",
            "manifest": manifest,
            "signing": signing,
            "abis": abis,
            "dangerous_permissions": dangerous,
            "score": score,
            "verdict": verdict,
            "findings": findings,
        }
