import asyncio
import base64
import hashlib
import json
from collections.abc import Mapping

import pytest

from vera_anchor_verifier.resolvers.hcs1_mirror_v1 import Hcs1MirrorV1Config
from vera_anchor_verifier.resolvers.hcs26_mirror_v1 import (
    Hcs26MirrorV1Request,
    resolve_hcs26_skill_version_v1,
)
from vera_anchor_verifier.resolvers.hedera_mirror_v1 import (
    HederaMirrorFetchResponseV1,
)
from vera_anchor_verifier.standards.hcs.hcs1_v1 import Hcs1V1ContentOptions
from vera_anchor_verifier.standards.hcs.hcs26_v1 import (
    finalize_hcs26_skill_manifest_v1,
)

BASE = "https://testnet.mirrornode.hedera.com/api/v1"

DISCOVERY_TOPIC = "0.0.6001"
VERSION_TOPIC = "0.0.6002"
MANIFEST_TOPIC = "0.0.6003"
SKILL_MD_TOPIC = "0.0.6004"
RUN_TOPIC = "0.0.6005"
PUBLISHER = "0.0.6999"

SKILL_UID = 42
VERSION_SEQUENCE = 3

SKILL_MD = b"# Independent capability\n"
RUN_JS = b"export default function run() { return 1; }\n"

SKILL_MD_SHA = hashlib.sha256(SKILL_MD).hexdigest()
RUN_SHA = hashlib.sha256(RUN_JS).hexdigest()

MANIFEST = finalize_hcs26_skill_manifest_v1(
    {
        "name": "Independent agent capability",
        "description": "Pinned HCS-26 skill",
        "version": "1.2.3",
        "license": "MIT",
        "author": "Independent Author",
        "files": [
            {
                "path": "scripts/run.js",
                "hrl": f"hcs://1/{RUN_TOPIC}",
                "sha256": RUN_SHA,
                "mime": "application/javascript",
            },
            {
                "path": "SKILL.md",
                "hrl": f"hcs://1/{SKILL_MD_TOPIC}",
                "sha256": SKILL_MD_SHA,
                "mime": "text/markdown",
            },
        ],
    }
)


def run(coro):
    return asyncio.run(coro)


def b64(value: bytes | str) -> str:
    raw = value.encode("utf-8") if isinstance(value, str) else value
    return base64.b64encode(raw).decode("ascii")


def response(
    value: object,
    *,
    status: int = 200,
) -> HederaMirrorFetchResponseV1:
    return HederaMirrorFetchResponseV1(
        status=status,
        headers={},
        body=json.dumps(value, separators=(",", ":")).encode("utf-8"),
    )


def decode_options() -> Hcs1V1ContentOptions:
    def decompress(compressed: bytes, limit: int) -> bytes:
        assert len(compressed) <= limit
        return compressed

    return Hcs1V1ContentOptions(decompress_zstd=decompress)


def content_routes(
    topic: str,
    content: bytes,
) -> dict[str, object]:
    chunk = json.dumps(
        {
            "o": 0,
            "c": f"data:application/octet-stream;base64,{b64(content)}",
        },
        separators=(",", ":"),
    ).encode("utf-8")

    digest = hashlib.sha256(content).hexdigest()

    return {
        f"{BASE}/topics/{topic}": {
            "topic_id": topic,
            "memo": f"{digest}:zstd:base64",
            "submit_key": {"key": "present"},
            "admin_key": None,
        },
        (
            f"{BASE}/topics/{topic}"
            "/messages?limit=100&order=asc"
        ): {
            "messages": [
                {
                    "topic_id": topic,
                    "sequence_number": 1,
                    "message": b64(chunk),
                }
            ],
            "links": {"next": None},
        },
    }


def fixture(
    *,
    account: str | None = None,
    version_topic: str | None = None,
    skill_uid: int | None = None,
    version: str | None = None,
    status: str | None = None,
    checksum: str | None = None,
    manifest_bytes: bytes | None = None,
    skill_md: bytes | None = None,
    run_js: bytes | None = None,
    missing: str | None = None,
):
    urls: list[str] = []

    manifest_content = (
        manifest_bytes
        if manifest_bytes is not None
        else MANIFEST.canonical_payload.encode("utf-8")
    )
    skill_content = SKILL_MD if skill_md is None else skill_md
    run_content = RUN_JS if run_js is None else run_js

    discovery_message = json.dumps(
        {
            "p": "hcs-26",
            "op": "register",
            "t_id": (
                version_topic
                if version_topic is not None
                else VERSION_TOPIC
            ),
            "account_id": (
                account
                if account is not None
                else PUBLISHER
            ),
            "metadata": "hcs://1/0.0.6900",
        },
        separators=(",", ":"),
    )

    version_message = json.dumps(
        {
            "p": "hcs-26",
            "op": "register",
            "skill_uid": (
                skill_uid
                if skill_uid is not None
                else SKILL_UID
            ),
            "version": (
                version
                if version is not None
                else "1.2.3"
            ),
            "t_id": MANIFEST_TOPIC,
            "checksum": (
                "sha256:"
                + (
                    checksum
                    if checksum is not None
                    else MANIFEST.sha256
                )
            ),
            "status": (
                status
                if status is not None
                else "deprecated"
            ),
        },
        separators=(",", ":"),
    )

    paths: dict[str, object] = {
        f"{BASE}/topics/{DISCOVERY_TOPIC}": {
            "topic_id": DISCOVERY_TOPIC,
            "memo": "hcs-26:0:86400:0",
        },
        (
            f"{BASE}/topics/{DISCOVERY_TOPIC}"
            f"/messages/{SKILL_UID}"
        ): {
            "topic_id": DISCOVERY_TOPIC,
            "sequence_number": SKILL_UID,
            "consensus_timestamp": "1792039124.000000001",
            "message": b64(discovery_message),
        },
        f"{BASE}/topics/{VERSION_TOPIC}": {
            "topic_id": VERSION_TOPIC,
            "memo": "hcs-26:0:86400:1",
        },
        (
            f"{BASE}/topics/{VERSION_TOPIC}"
            f"/messages/{VERSION_SEQUENCE}"
        ): {
            "topic_id": VERSION_TOPIC,
            "sequence_number": VERSION_SEQUENCE,
            "consensus_timestamp": "1792039130.000000010",
            "message": b64(version_message),
        },
        **content_routes(
            MANIFEST_TOPIC,
            manifest_content,
        ),
        **content_routes(
            SKILL_MD_TOPIC,
            skill_content,
        ),
        **content_routes(
            RUN_TOPIC,
            run_content,
        ),
    }

    async def fetch(
        url: str,
        headers: Mapping[str, str],
        timeout_ms: int,
        max_response_bytes: int,
    ) -> HederaMirrorFetchResponseV1:
        del headers
        del timeout_ms
        del max_response_bytes

        urls.append(url)

        if url == missing:
            return HederaMirrorFetchResponseV1(
                status=404,
                headers={},
                body=b"",
            )

        if url not in paths:
            raise AssertionError(f"Unexpected Mirror URL: {url}")

        return response(paths[url])

    return fetch, urls


def request(
    **overrides: object,
) -> Hcs26MirrorV1Request:
    values: dict[str, object] = {
        "hedera_network": "testnet",
        "discovery_topic_id": DISCOVERY_TOPIC,
        "discovery_sequence_number": SKILL_UID,
        "version_sequence_number": VERSION_SEQUENCE,
    }
    values.update(overrides)

    return Hcs26MirrorV1Request(
        **values  # type: ignore[arg-type]
    )


def test_resolves_discovery_version_manifest_and_declared_files() -> None:
    fetch, urls = fixture()

    result = run(
        resolve_hcs26_skill_version_v1(
            Hcs1MirrorV1Config(fetch_impl=fetch),
            request(
                expected_skill_uid=SKILL_UID,
                expected_account_id=PUBLISHER,
                expected_version_topic_id=VERSION_TOPIC,
                expected_version="1.2.3",
                expected_manifest_reference=f"hcs://1/{MANIFEST_TOPIC}",
                expected_manifest_sha256=MANIFEST.sha256,
            ),
            decode_options(),
        )
    )

    assert result.status == "resolved"
    assert result.reason_code is None
    assert result.resolver_id == "hedera.mirror-rest.hcs26.v1"
    assert result.assurance == "mirror_corroborated"
    assert result.registry_memo_temporal_scope == "current_observation"

    assert result.discovery_consensus_timestamp_exact == "1792039124.000000001"
    assert result.version_consensus_timestamp_exact == "1792039130.000000010"
    assert result.publisher_account_id == PUBLISHER
    assert result.version_topic_id == VERSION_TOPIC
    assert result.skill_uid == SKILL_UID
    assert result.version == "1.2.3"
    assert result.historical_version_status == "deprecated"

    assert result.manifest_reference == f"hcs://1/{MANIFEST_TOPIC}"
    assert result.content_sha256 == MANIFEST.sha256
    assert result.manifest_sha256 == MANIFEST.sha256
    assert result.manifest is not None

    files = result.manifest_files
    assert files is not None
    assert files.status == "resolved"
    assert files.reason_code is None
    assert files.declared_file_count == 2
    assert files.resolved_file_count == 2
    assert files.total_bytes == len(SKILL_MD) + len(RUN_JS)

    assert [file.path for file in files.files] == [
        "SKILL.md",
        "scripts/run.js",
    ]
    assert [file.reference for file in files.files] == [
        f"hcs://1/{SKILL_MD_TOPIC}",
        f"hcs://1/{RUN_TOPIC}",
    ]
    assert all(file.status == "resolved" for file in files.files)

    assert urls == [
        f"{BASE}/topics/{DISCOVERY_TOPIC}",
        f"{BASE}/topics/{DISCOVERY_TOPIC}/messages/{SKILL_UID}",
        f"{BASE}/topics/{VERSION_TOPIC}",
        f"{BASE}/topics/{VERSION_TOPIC}/messages/{VERSION_SEQUENCE}",
        f"{BASE}/topics/{MANIFEST_TOPIC}",
        (
            f"{BASE}/topics/{MANIFEST_TOPIC}"
            "/messages?limit=100&order=asc"
        ),
        f"{BASE}/topics/{SKILL_MD_TOPIC}",
        (
            f"{BASE}/topics/{SKILL_MD_TOPIC}"
            "/messages?limit=100&order=asc"
        ),
        f"{BASE}/topics/{RUN_TOPIC}",
        (
            f"{BASE}/topics/{RUN_TOPIC}"
            "/messages?limit=100&order=asc"
        ),
    ]


def test_rejects_expected_skill_uid_before_io() -> None:
    fetch, urls = fixture()

    result = run(
        resolve_hcs26_skill_version_v1(
            Hcs1MirrorV1Config(fetch_impl=fetch),
            request(expected_skill_uid=41),
            decode_options(),
        )
    )

    assert result.status == "conflict"
    assert result.reason_code == "HCS26_SKILL_UID_MISMATCH"
    assert urls == []


def test_rejects_discovery_expectation_substitution_before_version_read() -> None:
    fetch, urls = fixture()

    result = run(
        resolve_hcs26_skill_version_v1(
            Hcs1MirrorV1Config(fetch_impl=fetch),
            request(expected_version_topic_id="0.0.9999"),
            decode_options(),
        )
    )

    assert result.status == "conflict"
    assert result.reason_code == "HCS26_VERSION_TOPIC_MISMATCH"
    assert len(urls) == 2

    fetch, urls = fixture()

    result = run(
        resolve_hcs26_skill_version_v1(
            Hcs1MirrorV1Config(fetch_impl=fetch),
            request(expected_account_id="0.0.9999"),
            decode_options(),
        )
    )

    assert result.status == "conflict"
    assert result.reason_code == "HCS26_PUBLISHER_ACCOUNT_MISMATCH"
    assert len(urls) == 2


def test_rejects_version_skill_uid_before_manifest_read() -> None:
    fetch, urls = fixture(skill_uid=41)

    result = run(
        resolve_hcs26_skill_version_v1(
            Hcs1MirrorV1Config(fetch_impl=fetch),
            request(),
            decode_options(),
        )
    )

    assert result.status == "conflict"
    assert result.reason_code == "HCS26_SKILL_UID_MISMATCH"
    assert len(urls) == 4


def test_rejects_different_requested_version_before_manifest_read() -> None:
    fetch, urls = fixture()

    result = run(
        resolve_hcs26_skill_version_v1(
            Hcs1MirrorV1Config(fetch_impl=fetch),
            request(expected_version="9.9.9"),
            decode_options(),
        )
    )

    assert result.status == "conflict"
    assert result.reason_code == "HCS26_VERSION_MISMATCH"
    assert len(urls) == 4


def test_rejects_version_register_checksum_inconsistent_with_manifest() -> None:
    fetch, _urls = fixture(checksum="f" * 64)

    result = run(
        resolve_hcs26_skill_version_v1(
            Hcs1MirrorV1Config(fetch_impl=fetch),
            request(),
            decode_options(),
        )
    )

    assert result.status == "conflict"
    assert result.reason_code == "HCS26_CHECKSUM_MISMATCH"
    assert result.manifest_files is None


def test_noncanonical_manifest_is_unsupported_before_file_reads() -> None:
    raw = json.dumps(
        {
            "files": [
                {
                    "path": "SKILL.md",
                    "hrl": f"hcs://1/{SKILL_MD_TOPIC}",
                    "sha256": SKILL_MD_SHA,
                    "mime": "text/markdown",
                }
            ],
            "author": "Independent Author",
            "license": "MIT",
            "version": "1.2.3",
            "description": "Pinned HCS-26 skill",
            "name": "Independent agent capability",
        }
    ).encode("utf-8")

    computed = finalize_hcs26_skill_manifest_v1(json.loads(raw))
    fetch, urls = fixture(
        manifest_bytes=raw,
        checksum=computed.sha256,
    )

    result = run(
        resolve_hcs26_skill_version_v1(
            Hcs1MirrorV1Config(fetch_impl=fetch),
            request(),
            decode_options(),
        )
    )

    assert result.status == "unsupported"
    assert result.reason_code == "HCS26_MANIFEST_CONTENT_NOT_CANONICAL"
    assert result.manifest_files is None
    assert len(urls) == 6


def test_preserves_missing_historical_version_as_unavailable() -> None:
    missing = (
        f"{BASE}/topics/{VERSION_TOPIC}"
        f"/messages/{VERSION_SEQUENCE}"
    )
    fetch, urls = fixture(missing=missing)

    result = run(
        resolve_hcs26_skill_version_v1(
            Hcs1MirrorV1Config(fetch_impl=fetch),
            request(),
            decode_options(),
        )
    )

    assert result.status == "unavailable"
    assert result.reason_code == "HCS26_REGISTRY_ENTRY_NOT_FOUND"
    assert len(urls) == 4


def test_manifest_file_checksum_mismatch_is_conflict_and_fail_fast() -> None:
    altered = b"altered SKILL.md\n"
    fetch, urls = fixture(skill_md=altered)

    result = run(
        resolve_hcs26_skill_version_v1(
            Hcs1MirrorV1Config(fetch_impl=fetch),
            request(),
            decode_options(),
        )
    )

    assert result.status == "conflict"
    assert result.reason_code == "HCS26_MANIFEST_FILE_CHECKSUM_MISMATCH"

    files = result.manifest_files
    assert files is not None
    assert files.status == "conflict"
    assert files.declared_file_count == 2
    assert files.resolved_file_count == 0
    assert files.total_bytes == 0
    assert len(files.files) == 1

    failed = files.files[0]
    assert failed.path == "SKILL.md"
    assert failed.status == "conflict"
    assert failed.expected_sha256 == SKILL_MD_SHA
    assert failed.observed_sha256 == hashlib.sha256(altered).hexdigest()
    assert failed.byte_length == len(altered)

    assert f"{BASE}/topics/{RUN_TOPIC}" not in urls


def test_missing_manifest_file_is_unavailable_and_stops_prefix() -> None:
    missing = f"{BASE}/topics/{SKILL_MD_TOPIC}"
    fetch, urls = fixture(missing=missing)

    result = run(
        resolve_hcs26_skill_version_v1(
            Hcs1MirrorV1Config(fetch_impl=fetch),
            request(),
            decode_options(),
        )
    )

    assert result.status == "unavailable"
    assert result.reason_code == "HCS1_TOPIC_NOT_FOUND"

    files = result.manifest_files
    assert files is not None
    assert files.declared_file_count == 2
    assert files.resolved_file_count == 0
    assert len(files.files) == 1
    assert files.files[0].path == "SKILL.md"
    assert files.files[0].status == "unavailable"

    assert f"{BASE}/topics/{RUN_TOPIC}" not in urls


def test_validates_untrusted_request_material_before_io() -> None:
    fetch, urls = fixture()

    with pytest.raises(
        TypeError,
        match="HCS26_VERIFICATION_LOCATOR_INVALID",
    ):
        run(
            resolve_hcs26_skill_version_v1(
                Hcs1MirrorV1Config(fetch_impl=fetch),
                request(
                    discovery_topic_id="https://example.invalid/private",
                ),
                decode_options(),
            )
        )

    with pytest.raises(
        TypeError,
        match="HCS26_VERIFICATION_LOCATOR_INVALID",
    ):
        run(
            resolve_hcs26_skill_version_v1(
                Hcs1MirrorV1Config(fetch_impl=fetch),
                Hcs26MirrorV1Request(
                    hedera_network="wrong",  # type: ignore[arg-type]
                    discovery_topic_id=DISCOVERY_TOPIC,
                    discovery_sequence_number=SKILL_UID,
                    version_sequence_number=VERSION_SEQUENCE,
                ),
                decode_options(),
            )
        )

    with pytest.raises(
        TypeError,
        match="HCS26_VERIFICATION_LOCATOR_INVALID",
    ):
        run(
            resolve_hcs26_skill_version_v1(
                Hcs1MirrorV1Config(fetch_impl=fetch),
                request(expected_manifest_sha256="invalid"),
                decode_options(),
            )
        )

    with pytest.raises(
        TypeError,
        match="HCS1_REFERENCE_INVALID",
    ):
        run(
            resolve_hcs26_skill_version_v1(
                Hcs1MirrorV1Config(fetch_impl=fetch),
                request(
                    expected_manifest_reference="https://evil.example",
                ),
                decode_options(),
            )
        )

    with pytest.raises(
        TypeError,
        match="HCS26_EXPECTED_VERSION_INVALID",
    ):
        run(
            resolve_hcs26_skill_version_v1(
                Hcs1MirrorV1Config(fetch_impl=fetch),
                request(expected_version=""),
                decode_options(),
            )
        )

    assert urls == []