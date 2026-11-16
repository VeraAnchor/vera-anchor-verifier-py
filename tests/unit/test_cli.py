import asyncio
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path

import pytest

import vera_anchor_verifier.cli.command_v1 as cli


@dataclass(frozen=True, slots=True)
class Validation:
    status: str
    reason_code: str | None = None


def run(argv: list[str]) -> tuple[int, dict[str, object]]:
    output: list[str] = []
    code = asyncio.run(cli.run_verifier_cli_v1(argv, output.append))
    assert len(output) == 1
    return code, json.loads(output[0])


@pytest.mark.parametrize(
    ("argv", "command"),
    [
        (
            [
                "verify",
                "dataset",
                "--bundle",
                "b.json",
                "--sources",
                "s.json",
                "--source-root",
                "root",
                "--intent",
                "i.json",
                "--policy",
                "p.json",
            ],
            "verify dataset",
        ),
        (
            [
                "verify",
                "execution",
                "--evidence",
                "e.json",
                "--intent",
                "i.json",
                "--policy",
                "p.json",
            ],
            "verify execution",
        ),
        (
            [
                "verify",
                "ingest",
                "--bundle",
                "b.json",
                "--material",
                "m.json",
                "--intent",
                "i.json",
                "--policy",
                "p.json",
            ],
            "verify ingest",
        ),
        (
            [
                "verify",
                "standards",
                "--evidence",
                "e.json",
                "--intent",
                "i.json",
                "--policy",
                "p.json",
            ],
            "verify standards",
        ),
        (["report", "validate", "--report", "r.json"], "report validate"),
        (
            [
                "policy",
                "assess",
                "--report",
                "r.json",
                "--policy",
                "p.json",
            ],
            "policy assess",
        ),
    ],
)
def test_command_surface_matches_js_v02(argv: list[str], command: str) -> None:
    assert cli._parse_args(argv)[0] == command


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["verify", "unknown"],
        ["report", "validate"],
        ["report", "validate", "--report"],
        [
            "report",
            "validate",
            "--report",
            "a.json",
            "--report",
            "b.json",
        ],
        ["report", "validate", "--unknown", "a.json"],
    ],
)
def test_argument_parser_fails_closed(argv: list[str]) -> None:
    with pytest.raises(cli.CliInputError):
        cli._parse_args(argv)


@pytest.mark.parametrize(
    ("value", "kind"),
    [
        ("https://explorer.example.com", "explorer"),
        ("https://explorer.example.com/v1", "explorer"),
        ("http://127.0.0.1:8000", "explorer"),
        ("https://mainnet-public.mirrornode.hedera.com/api/v1", "mirror"),
    ],
)
def test_endpoint_accepts_supported_roots(value: str, kind: str) -> None:
    assert cli._endpoint(value, kind) == value  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("value", "kind"),
    [
        ("http://explorer.example.com", "explorer"),
        ("https://user:pass@explorer.example.com", "explorer"),
        ("https://explorer.example.com/v2", "explorer"),
        ("https://explorer.example.com?token=secret", "explorer"),
        ("https://mirror.example.com", "mirror"),
        ("https://mirror.example.com/api/v1/", "mirror"),
    ],
)
def test_endpoint_rejects_unsupported_or_credentialed_urls(
    value: str,
    kind: str,
) -> None:
    with pytest.raises(cli.CliInputError):
        cli._endpoint(value, kind)  # type: ignore[arg-type]


def test_source_paths_are_bounded_unique_and_streamed(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "a.txt").write_bytes(b"alpha")
    (root / "b.txt").write_bytes(b"beta")

    files = cli._source_paths(str(root), ["a.txt", "b.txt"])
    assert [item["path_rel"] for item in files] == ["a.txt", "b.txt"]

    async def consume() -> bytes:
        chunks = []
        async for chunk in files[0]["source"]:
            chunks.append(bytes(chunk))
        return b"".join(chunks)

    assert asyncio.run(consume()) == b"alpha"

    with pytest.raises(cli.CliInputError, match="Duplicate"):
        cli._source_paths(str(root), ["a.txt", "a.txt"])


@pytest.mark.parametrize("path", ["../a.txt", "/a.txt", r"a\b.txt", "a/./b.txt"])
def test_source_paths_reject_noncanonical_paths(tmp_path: Path, path: str) -> None:
    root = tmp_path / "root"
    root.mkdir()
    with pytest.raises((cli.CliInputError, TypeError)):
        cli._source_paths(str(root), [path])


def test_source_paths_reject_symlinks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    link = root / "link.txt"
    original_lstat = Path.lstat

    def lstat(path: Path) -> os.stat_result:
        if path == link:
            return os.stat_result(
                (stat.S_IFLNK | 0o777, 0, 0, 0, 0, 0, 0, 0, 0, 0)
            )
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", lstat)

    with pytest.raises(cli.CliInputError, match="regular file"):
        cli._source_paths(str(root), ["link.txt"])


def test_report_validate_emits_schema_and_exit_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = tmp_path / "report.json"
    report.write_text('{"x":1}', encoding="utf-8")
    monkeypatch.setattr(
        cli,
        "validate_portable_verification_report_v1",
        lambda value: Validation("valid"),
    )

    code, output = run(["report", "validate", "--report", str(report)])

    assert code == 0
    assert output["schema_version"] == cli.CLI_SCHEMA
    assert output["command"] == "report validate"
    assert output["result"] == {"status": "valid", "reason_code": None}


def test_input_and_operation_failures_are_sanitized(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    code, output = run(["report", "validate", "--report", "--bad"])
    assert code == 64
    assert output == {
        "schema_version": cli.CLI_SCHEMA,
        "error": {"code": "CLI_INPUT_INVALID"},
    }

    report = tmp_path / "report.json"
    report.write_text("{}", encoding="utf-8")

    def fail(value: object) -> object:
        del value
        raise RuntimeError("secret response body")

    monkeypatch.setattr(cli, "validate_portable_verification_report_v1", fail)
    code, output = run(["report", "validate", "--report", str(report)])

    assert code == 70
    assert "secret" not in json.dumps(output)
    assert output == {
        "schema_version": cli.CLI_SCHEMA,
        "error": {"code": "CLI_OPERATION_FAILED"},
    }


def test_policy_parser_preserves_exact_execution_scope() -> None:
    policy = cli._check_policy(
        {
            "schema_version": "va.verification-policy.v1",
            "subject": {
                "kind": "execution",
                "id": "11111111-1111-4111-8111-111111111111",
                "hedera_network": "testnet",
            },
            "report_kind": "execution",
            "required_checks": ["acceptance.digest_recomputed"],
            "required_assurance": [],
            "execution_scope": {
                "profile": "sage-standards-v1",
                "expected_program": "sage",
                "requested_result_id": None,
            },
        }
    )

    assert policy.execution_scope is not None
    assert policy.execution_scope.profile == "sage-standards-v1"
    assert policy.execution_scope.expected_program == "sage"
    assert policy.execution_scope.requested_result_id is None