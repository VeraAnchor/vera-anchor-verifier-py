"""Pinned HCS-26 Draft v1.1 offline registry and SKILL.json checks."""

import hashlib
import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal, Never, cast

from .hcs1_v1 import parse_hcs1_reference_v1
from .json_canonical_v1 import (
    HcsJsonV1Error,
    canonical_hcs_json_v1,
    clone_hcs_json_v1,
    parse_strict_hcs_json_v1,
)

MAX_HCS26_V1_MANIFEST_BYTES = 256 * 1024
_RAW_MANIFEST_BYTES = MAX_HCS26_V1_MANIFEST_BYTES + 64 * 1024
_MAX_SAFE_INTEGER = (1 << 53) - 1

_TOPIC_RE = re.compile(r"^0\.0\.[0-9]+$", re.ASCII)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$", re.ASCII)
_SEMVER_RE = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$",
    re.ASCII,
)
_UID_RE = re.compile(r"^[1-9]\d*$", re.ASCII)
_DRIVE_PATH_RE = re.compile(r"^[A-Za-z]:", re.ASCII)
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")

_KEYS_DISCOVERY = frozenset({"p", "op", "t_id", "account_id", "metadata", "m"})
_KEYS_UPDATE = frozenset({"p", "op", "uid", "account_id", "metadata", "m"})
_KEYS_VERSION = frozenset(
    {"p", "op", "skill_uid", "version", "t_id", "checksum", "status", "m"}
)
_KEYS_METADATA = frozenset(
    {
        "name",
        "description",
        "author",
        "license",
        "tags",
        "languages",
        "capabilities",
        "homepage",
        "icon",
        "repo",
        "commit",
    }
)
_KEYS_MANIFEST = frozenset(
    {
        "name",
        "description",
        "version",
        "license",
        "author",
        "tags",
        "languages",
        "homepage",
        "repo",
        "commit",
        "entrypoints",
        "files",
    }
)
_KEYS_FILE = frozenset({"path", "hrl", "sha256", "mime"})


@dataclass(frozen=True, slots=True)
class Hcs26MemoV1:
    memo: str
    indexed: bool
    ttl: int
    type: Literal["discovery", "version"]
    type_code: Literal[0, 1]


@dataclass(frozen=True, slots=True)
class Hcs26VersionRegisterV1:
    p: Literal["hcs-26"]
    op: Literal["register"]
    skill_uid: int
    version: str
    t_id: str
    checksum: str
    status: Literal["active", "deprecated", "yanked"]
    m: str | None = None


@dataclass(frozen=True, slots=True)
class Hcs26SkillManifestV1:
    manifest: dict[str, object]
    canonical_payload: str
    sha256: str
    byte_length: int


@dataclass(frozen=True, slots=True)
class Hcs26VersionVerificationInput:
    version_register: str | bytes | bytearray | memoryview
    manifest: str | bytes | bytearray | memoryview
    expected_skill_uid: int | None = None
    expected_version: str | None = None
    expected_manifest_topic_id: str | None = None
    expected_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class Hcs26VersionVerificationV1:
    status: Literal["pass", "fail"]
    reason_code: str | None
    skill_uid: int | None
    version: str | None
    manifest_topic_id: str | None
    checksum_match: Literal["match", "mismatch", "not_checked"]
    version_status: Literal["active", "deprecated", "yanked"] | None
    sha256: str | None


class Hcs26V1Error(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _fail(code: str) -> Never:
    raise Hcs26V1Error(code)


def _js_length(value: str) -> int:
    return len(value.encode("utf-16-le", "surrogatepass")) // 2


def _trim(value: str) -> str:
    return value.strip().strip("\ufeff")


def _object(
    value: object,
    code: str = "HCS26_FIELD_INVALID",
) -> dict[str, object]:
    if type(value) is not dict:
        _fail(code)
    return cast(dict[str, object], value)


def _keys(value: Mapping[str, object], allowed: frozenset[str]) -> None:
    if any(key not in allowed for key in value):
        _fail("HCS26_FIELD_UNSUPPORTED")


def _text(value: object, maximum: int) -> str:
    if not isinstance(value, str):
        _fail("HCS26_FIELD_INVALID")

    text = _trim(value)
    if (
        not text
        or _js_length(text) > maximum
        or _CONTROL_RE.search(text) is not None
    ):
        _fail("HCS26_FIELD_INVALID")

    return text


def _optional(value: object, maximum: int) -> str | None:
    if value is None or value == "":
        return None

    if isinstance(value, str) and not _trim(value):
        return None

    return _text(value, maximum)


def _topic(value: object) -> str:
    topic = _text(value, 64)
    if _TOPIC_RE.fullmatch(topic) is None:
        _fail("HCS26_TOPIC_INVALID")
    return topic


def _version(value: object) -> str:
    version = _text(value, 64)
    if _SEMVER_RE.fullmatch(version) is None:
        _fail("HCS26_VERSION_INVALID")
    return version


def _sha(value: object) -> str:
    if not isinstance(value, str):
        _fail("HCS26_CHECKSUM_INVALID")

    raw = value[7:] if value.startswith("sha256:") else value
    if _SHA256_RE.fullmatch(raw) is None:
        _fail("HCS26_CHECKSUM_INVALID")

    return raw


def _js_number(value: object) -> float:
    if value is None:
        return 0.0

    if isinstance(value, bool):
        return 1.0 if value else 0.0

    if isinstance(value, (int, float)):
        try:
            return float(value)
        except OverflowError:
            return math.nan

    if isinstance(value, str):
        text = _trim(value)
        if not text:
            return 0.0

        lowered = text.lower()
        sign = -1 if lowered.startswith("-") else 1
        unsigned = lowered[1:] if lowered[:1] in {"+", "-"} else lowered

        try:
            if unsigned.startswith("0x"):
                return float(sign * int(unsigned[2:], 16))
            if unsigned.startswith("0b"):
                return float(sign * int(unsigned[2:], 2))
            if unsigned.startswith("0o"):
                return float(sign * int(unsigned[2:], 8))
            return float(text)
        except (ValueError, OverflowError):
            return math.nan

    return math.nan


def _positive(value: object) -> int:
    if value is None or value == "":
        _fail("HCS26_SKILL_UID_INVALID")

    number = _js_number(value)
    if (
        not math.isfinite(number)
        or not number.is_integer()
        or number < 1
        or number > _MAX_SAFE_INTEGER
    ):
        _fail("HCS26_SKILL_UID_INVALID")

    return int(number)


def _uid(value: object) -> str:
    uid = _text(value, 256)
    if _UID_RE.fullmatch(uid) is None:
        _fail("HCS26_SKILL_UID_INVALID")

    number = _js_number(uid)
    if (
        not math.isfinite(number)
        or not number.is_integer()
        or number > _MAX_SAFE_INTEGER
    ):
        _fail("HCS26_SKILL_UID_INVALID")

    return uid


def _hcs1_ref(value: object) -> str:
    text = _text(value, 256)
    try:
        return parse_hcs1_reference_v1(text).reference
    except TypeError:
        _fail("HCS1_REF_INVALID")


def _author(value: object) -> object:
    if isinstance(value, str):
        return _text(value, 512)

    author = _object(value)
    _keys(author, frozenset({"name", "contact", "url"}))
    result: dict[str, object] = {"name": _text(author.get("name"), 256)}
    contact = _optional(author.get("contact"), 512)
    url = _optional(author.get("url"), 2048)

    if contact is not None:
        result["contact"] = contact
    if url is not None:
        result["url"] = url

    return result


def _ints(value: object) -> list[int]:
    if type(value) is not list:
        _fail("HCS26_FIELD_INVALID")

    output: list[int] = []
    for item in cast(list[object], value):
        number = _js_number(item)
        if (
            not math.isfinite(number)
            or not number.is_integer()
            or number < 0
            or number > _MAX_SAFE_INTEGER
        ):
            _fail("HCS26_FIELD_INVALID")
        output.append(int(number))

    return sorted(set(output))


def _strings(value: object) -> list[str]:
    if type(value) is not list:
        _fail("HCS26_FIELD_INVALID")
    return [_text(item, 256) for item in cast(list[object], value)]


def _metadata(value: object, *, update: bool = False) -> object:
    if isinstance(value, str):
        return _hcs1_ref(value)

    obj = _object(value)
    _keys(obj, _KEYS_METADATA)

    if update and not obj:
        _fail("HCS26_FIELD_INVALID")

    result: dict[str, object] = {}

    for key, limit in (
        ("name", 256),
        ("description", 4096),
        ("license", 128),
    ):
        if not update or key in obj:
            result[key] = _text(obj.get(key), limit)

    if not update or "author" in obj:
        result["author"] = _author(obj.get("author"))

    for key in ("tags", "languages", "capabilities"):
        if key not in obj:
            continue

        item = obj.get(key)
        if item is None and not update:
            continue

        if item is None:
            result[key] = []
        elif key == "tags":
            result[key] = _ints(item)
        else:
            result[key] = _strings(item)

    for key, limit in (
        ("homepage", 2048),
        ("icon", 4096),
        ("repo", 4096),
    ):
        if key not in obj:
            continue

        item = _text(obj.get(key), limit) if update else _optional(obj.get(key), limit)
        if item is not None:
            result[key] = item

    if "commit" in obj:
        commit = _text(obj.get("commit"), 40)
        if _COMMIT_RE.fullmatch(commit) is None:
            _fail("HCS26_COMMIT_INVALID")
        result["commit"] = commit

    return result


def _parse_wire(
    value: str | bytes | bytearray | memoryview,
) -> dict[str, object]:
    try:
        parsed = parse_strict_hcs_json_v1(value, 1024)
    except HcsJsonV1Error as exc:
        _fail(
            "HCS26_MESSAGE_TOO_LARGE"
            if exc.code == "JSON_TOO_LARGE"
            else "HCS26_MESSAGE_INVALID"
        )

    return _object(parsed, "HCS26_MESSAGE_INVALID")


def _wire_size(value: object) -> None:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError):
        _fail("HCS26_MESSAGE_INVALID")

    if len(encoded) > 1024:
        _fail("HCS26_MESSAGE_TOO_LARGE")


def _memo_text(value: object) -> dict[str, object]:
    memo = _optional(value, 500)
    return {} if memo is None else {"m": memo}


def parse_hcs26_memo_v1(value: object) -> Hcs26MemoV1:
    """Parse one pinned HCS-26 discovery/version topic memo."""
    if not isinstance(value, str):
        _fail("HCS26_MEMO_INVALID")

    memo = _trim(value)
    match = re.fullmatch(r"hcs-26:(0|1):(\d+):(0|1)", memo, re.ASCII)
    if match is None:
        _fail("HCS26_MEMO_INVALID")

    ttl = int(match.group(2))
    if ttl > 31_536_000:
        _fail("HCS26_TTL_INVALID")

    type_code: Literal[0, 1] = 0 if match.group(3) == "0" else 1
    return Hcs26MemoV1(
        memo=memo,
        indexed=match.group(1) == "0",
        ttl=ttl,
        type="discovery" if type_code == 0 else "version",
        type_code=type_code,
    )


def parse_hcs26_discovery_register_v1(
    raw: str | bytes | bytearray | memoryview,
) -> Mapping[str, object]:
    """Parse one historical HCS-26 discovery registration."""
    obj = _parse_wire(raw)

    if (
        obj.get("p") != "hcs-26"
        or obj.get("op") != "register"
        or obj.get("skill_uid") is not None
        or obj.get("version") is not None
    ):
        _fail("HCS26_OPERATION_INVALID")

    _keys(obj, _KEYS_DISCOVERY)
    record: dict[str, object] = {
        "p": "hcs-26",
        "op": "register",
        "t_id": _topic(obj.get("t_id")),
        "account_id": _topic(obj.get("account_id")),
        "metadata": _metadata(obj.get("metadata")),
        **_memo_text(obj.get("m")),
    }
    _wire_size(record)
    return MappingProxyType(record)


def parse_hcs26_discovery_update_v1(
    raw: str | bytes | bytearray | memoryview,
) -> Mapping[str, object]:
    """Parse one supported historical HCS-26 discovery update."""
    obj = _parse_wire(raw)

    if (
        obj.get("p") != "hcs-26"
        or obj.get("op") != "update"
        or obj.get("uid") is None
    ):
        _fail("HCS26_OPERATION_INVALID")

    _keys(obj, _KEYS_UPDATE)
    if obj.get("account_id") is None and obj.get("metadata") is None:
        _fail("HCS26_UPDATE_EMPTY")

    record: dict[str, object] = {
        "p": "hcs-26",
        "op": "update",
        "uid": _uid(obj.get("uid")),
    }

    if obj.get("account_id") is not None:
        record["account_id"] = _topic(obj.get("account_id"))
    if obj.get("metadata") is not None:
        record["metadata"] = _metadata(obj.get("metadata"), update=True)

    record.update(_memo_text(obj.get("m")))
    _wire_size(record)
    return MappingProxyType(record)


def parse_hcs26_version_register_v1(
    raw: str | bytes | bytearray | memoryview,
) -> Hcs26VersionRegisterV1:
    """Parse one exact historical HCS-26 version registration."""
    obj = _parse_wire(raw)

    if (
        obj.get("p") != "hcs-26"
        or obj.get("op") != "register"
        or obj.get("skill_uid") is None
        or obj.get("version") is None
    ):
        _fail("HCS26_OPERATION_INVALID")

    _keys(obj, _KEYS_VERSION)
    status_raw = (
        "active"
        if obj.get("status") is None
        else _text(obj.get("status"), 40).lower()
    )
    if status_raw not in {"active", "deprecated", "yanked"}:
        _fail("HCS26_STATUS_INVALID")

    status = cast(Literal["active", "deprecated", "yanked"], status_raw)
    memo = _optional(obj.get("m"), 500)
    record = Hcs26VersionRegisterV1(
        p="hcs-26",
        op="register",
        skill_uid=_positive(obj.get("skill_uid")),
        version=_version(obj.get("version")),
        t_id=_topic(obj.get("t_id")),
        checksum=f"sha256:{_sha(obj.get('checksum'))}",
        status=status,
        m=memo,
    )
    wire: dict[str, object] = {
        "p": record.p,
        "op": record.op,
        "skill_uid": record.skill_uid,
        "version": record.version,
        "t_id": record.t_id,
        "checksum": record.checksum,
        "status": record.status,
    }

    if memo is not None:
        wire["m"] = memo

    _wire_size(wire)
    return record


def _file_path(value: object) -> str:
    path = _text(value, 512).replace("\\", "/")
    parts = path.split("/")

    if (
        path.startswith("/")
        or _DRIVE_PATH_RE.match(path) is not None
        or any(part in {"", ".", ".."} for part in parts)
    ):
        _fail("HCS26_PATH_INVALID")

    return path


def _manifest_file(value: object) -> dict[str, object]:
    obj = _object(value)
    _keys(obj, _KEYS_FILE)

    digest = _text(obj.get("sha256"), 64).lower()
    if _SHA256_RE.fullmatch(digest) is None:
        _fail("HCS26_FILE_HASH_INVALID")

    return {
        "path": _file_path(obj.get("path")),
        "hrl": _hcs1_ref(obj.get("hrl")),
        "sha256": digest,
        "mime": _text(obj.get("mime"), 256),
    }


def finalize_hcs26_skill_manifest_v1(value: object) -> Hcs26SkillManifestV1:
    """Normalize and hash one supplied HCS-26 SKILL.json manifest."""
    obj = _object(value)
    _keys(obj, _KEYS_MANIFEST)

    raw_files = obj.get("files")
    if type(raw_files) is not list or not 1 <= len(raw_files) <= 256:
        _fail("HCS26_FILES_INVALID")

    files = [_manifest_file(item) for item in cast(list[object], raw_files)]
    paths: set[str] = set()

    for file in files:
        path = cast(str, file["path"])
        if path in paths:
            _fail("HCS26_PATH_DUPLICATE")
        paths.add(path)

    if "SKILL.md" not in paths:
        _fail("HCS26_SKILL_MD_REQUIRED")

    files.sort(key=lambda item: cast(str, item["path"]).encode("utf-8"))
    normalized: dict[str, object] = {
        "name": _text(obj.get("name"), 256),
        "description": _text(obj.get("description"), 4096),
        "version": _version(obj.get("version")),
        "license": _text(obj.get("license"), 128),
        "author": _author(obj.get("author")),
    }

    if obj.get("tags") is not None:
        normalized["tags"] = _ints(obj.get("tags"))
    if obj.get("languages") is not None:
        normalized["languages"] = _strings(obj.get("languages"))

    for key, limit in (("homepage", 2048), ("repo", 4096)):
        item = _optional(obj.get(key), limit)
        if item is not None:
            normalized[key] = item

    if obj.get("commit") is not None:
        commit = _text(obj.get("commit"), 40)
        if _COMMIT_RE.fullmatch(commit) is None:
            _fail("HCS26_COMMIT_INVALID")
        normalized["commit"] = commit

    if obj.get("entrypoints") is not None:
        entrypoints = obj.get("entrypoints")
        if type(entrypoints) is not list:
            _fail("HCS26_FIELD_INVALID")
        normalized["entrypoints"] = entrypoints

    normalized["files"] = files

    try:
        canonical = canonical_hcs_json_v1(
            normalized,
            MAX_HCS26_V1_MANIFEST_BYTES,
        )
    except HcsJsonV1Error as exc:
        _fail(
            "HCS26_MANIFEST_TOO_LARGE"
            if exc.code == "JSON_TOO_LARGE"
            else "HCS26_CANONICALIZATION_FAILED"
        )

    payload = canonical.encode("utf-8")
    cloned = clone_hcs_json_v1(normalized)
    if type(cloned) is not dict:
        _fail("HCS26_CANONICALIZATION_FAILED")

    return Hcs26SkillManifestV1(
        manifest=cast(dict[str, object], cloned),
        canonical_payload=canonical,
        sha256=hashlib.sha256(payload).hexdigest(),
        byte_length=len(payload),
    )


def parse_hcs26_skill_manifest_v1(
    raw: str | bytes | bytearray | memoryview,
) -> Hcs26SkillManifestV1:
    """Parse strict JSON before normalizing and hashing SKILL.json."""
    try:
        parsed = parse_strict_hcs_json_v1(raw, _RAW_MANIFEST_BYTES)
    except HcsJsonV1Error as exc:
        _fail(
            "HCS26_MANIFEST_TOO_LARGE"
            if exc.code == "JSON_TOO_LARGE"
            else "HCS26_MANIFEST_JSON_INVALID"
        )

    return finalize_hcs26_skill_manifest_v1(parsed)


def verify_hcs26_skill_version_v1(
    input: Hcs26VersionVerificationInput,
) -> Hcs26VersionVerificationV1:
    """Cross-check one supplied historical version register against SKILL.json.

    This does not authenticate the source of the register or interpret its
    historical status as current policy.
    """
    register: Hcs26VersionRegisterV1 | None = None
    sha256: str | None = None
    checksum_match: Literal["match", "mismatch", "not_checked"] = "not_checked"

    def result(
        status: Literal["pass", "fail"],
        reason_code: str | None,
    ) -> Hcs26VersionVerificationV1:
        return Hcs26VersionVerificationV1(
            status=status,
            reason_code=reason_code,
            skill_uid=register.skill_uid if register is not None else None,
            version=register.version if register is not None else None,
            manifest_topic_id=register.t_id if register is not None else None,
            checksum_match=checksum_match,
            version_status=register.status if register is not None else None,
            sha256=sha256,
        )

    try:
        if not isinstance(input, Hcs26VersionVerificationInput):
            _fail("HCS26_INPUT_INVALID")

        register = parse_hcs26_version_register_v1(input.version_register)

        if (
            input.expected_skill_uid is not None
            and _positive(input.expected_skill_uid) != register.skill_uid
        ):
            _fail("HCS26_SKILL_UID_MISMATCH")

        if (
            input.expected_version is not None
            and _version(input.expected_version) != register.version
        ):
            _fail("HCS26_VERSION_MISMATCH")

        if (
            input.expected_manifest_topic_id is not None
            and _topic(input.expected_manifest_topic_id) != register.t_id
        ):
            _fail("HCS26_TOPIC_MISMATCH")

        manifest = parse_hcs26_skill_manifest_v1(input.manifest)
        sha256 = manifest.sha256
        checksum_match = "match" if sha256 == register.checksum[7:] else "mismatch"

        if checksum_match == "mismatch":
            _fail("HCS26_CHECKSUM_MISMATCH")

        if manifest.manifest.get("version") != register.version:
            _fail("HCS26_VERSION_MISMATCH")

        if input.expected_sha256 is not None and _sha(input.expected_sha256) != sha256:
            _fail("HCS26_EXPECTED_CHECKSUM_MISMATCH")

        return result("pass", None)
    except Hcs26V1Error as exc:
        return result("fail", exc.code)