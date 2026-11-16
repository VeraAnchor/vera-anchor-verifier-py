"""Vera Anchor verifier CLI command surface."""

import asyncio
import json
import os
import stat
import sys
import uuid
from collections.abc import AsyncIterator, Callable, Mapping, Sequence
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Literal, cast
from urllib.parse import urlsplit

from ..contracts import HederaNetwork, VerificationIntent, VerificationSubject
from ..policy import (
    VerificationPolicyAssuranceV1,
    VerificationPolicyDecisionV1,
    VerificationPolicyExecutionScopeV1,
    VerificationPolicyV1,
    VerificationPolicyWorkflowV1,
    assess_portable_verification_policy_v1,
    triangulate_dataset_with_policy_v1,
    triangulate_execution_with_policy_v1,
    triangulate_ingest_with_policy_v1,
    verify_dataset_with_policy_v1,
    verify_execution_standards_with_policy_v1,
    verify_execution_with_policy_v1,
    verify_ingest_with_policy_v1,
)
from ..profiles.execution import ExecutionV1Input, PublicExecutionVerificationMaterial
from ..profiles.source_v1_helpers import SourceV1File, source_v1_path
from ..reports import (
    PortableVerificationReportKindV1,
    PortableVerificationReportV1,
    PortableVerificationReportValidationV1,
    validate_portable_verification_report_v1,
)
from ..resolvers import ExplorerPublicTransportV1, HederaMirrorV1Config
from ..resolvers.hcs1_mirror_v1 import Hcs1MirrorV1Config
from ..standards.hcs.hcs1_v1 import Hcs1V1ContentOptions
from ..triangulation import PublicExecutionTriangulationV1Config
from ..triangulation.public_v1 import PublicTriangulationV1Config

CLI_SCHEMA = "va.verifier-cli-result.v1"
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_SOURCE_BYTES = 1024 * 1024 * 1024
MAX_FILES = 256

type Command = Literal[
    "verify dataset",
    "verify execution",
    "verify ingest",
    "verify standards",
    "report validate",
    "policy assess",
]
type Options = dict[str, str]
type Emitter = Callable[[str], None]
type Mode = Literal["offline", "public"]

_COMMANDS: dict[Command, tuple[str, ...]] = {
    "verify dataset": (
        "bundle",
        "sources",
        "source-root",
        "intent",
        "policy",
        "receipt",
        "mode",
        "explorer-url",
        "mirror-url",
        "report-out",
    ),
    "verify execution": (
        "evidence",
        "intent",
        "policy",
        "verification-material",
        "mode",
        "explorer-url",
        "mirror-url",
        "report-out",
    ),
    "verify ingest": (
        "bundle",
        "material",
        "source-root",
        "intent",
        "policy",
        "receipt",
        "anchor-request-id",
        "mode",
        "explorer-url",
        "mirror-url",
        "report-out",
    ),
    "verify standards": (
        "evidence",
        "intent",
        "policy",
        "verification-material",
        "mirror-url",
        "report-out",
    ),
    "report validate": ("report",),
    "policy assess": ("report", "policy"),
}

_REPORT_KINDS: tuple[PortableVerificationReportKindV1, ...] = (
    "verification",
    "execution",
    "independent_standards",
    "public_triangulation",
    "authorized_dataset_triangulation",
    "authorized_ingest_triangulation",
    "execution_triangulation",
)


class CliInputError(ValueError):
    """Invalid CLI input."""


def _parse_args(argv: Sequence[str]) -> tuple[Command, Options]:
    value = f"{argv[0] if argv else ''} {argv[1] if len(argv) > 1 else ''}"
    command = next((item for item in _COMMANDS if item == value), None)
    if command is None or (len(argv) - 2) % 2:
        raise CliInputError("Unsupported command or malformed options")

    options: Options = {}
    for index in range(2, len(argv), 2):
        flag, option_value = argv[index], argv[index + 1]
        key = flag[2:] if flag.startswith("--") else ""
        if (
            not key
            or not option_value
            or option_value.startswith("--")
            or key not in _COMMANDS[command]
            or key in options
        ):
            raise CliInputError("Unexpected, duplicate or missing option")
        options[key] = option_value

    required = (
        ("bundle", "sources", "source-root", "intent", "policy")
        if command == "verify dataset"
        else ("evidence", "intent", "policy")
        if command in {"verify execution", "verify standards"}
        else ("bundle", "material", "intent", "policy")
        if command == "verify ingest"
        else ("report",)
        if command == "report validate"
        else ("report", "policy")
    )
    if any(key not in options for key in required):
        raise CliInputError("Missing required option")
    return command, options


def _option(options: Options, name: str) -> str:
    value = options.get(name)
    if value is None:
        raise CliInputError("Missing required option")
    return value


def _open_readonly(path: Path) -> int:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    return os.open(path, flags)


def _read_json(path: str) -> object:
    filename = Path(path).absolute()
    before = filename.lstat()
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_size > MAX_JSON_BYTES
    ):
        raise CliInputError("Invalid JSON input file")

    fd = _open_readonly(filename)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or opened.st_size > MAX_JSON_BYTES:
            raise CliInputError("Invalid JSON input file")
        data = bytearray()
        while chunk := os.read(fd, min(65536, MAX_JSON_BYTES + 1 - len(data))):
            data.extend(chunk)
            if len(data) > MAX_JSON_BYTES:
                raise CliInputError("JSON input exceeds size limit")
    finally:
        os.close(fd)
    return json.loads(data.decode("utf-8", errors="strict"))


def _check_intent(
    value: object,
    kind: Literal["dataset", "execution", "ingest"],
) -> VerificationIntent:
    if not isinstance(value, Mapping):
        raise CliInputError("Invalid independent verification intent")
    subject = value.get("subject")
    if (
        not isinstance(subject, Mapping)
        or subject.get("kind") != kind
        or not isinstance(subject.get("id"), str)
        or not isinstance(value.get("expected"), list)
    ):
        raise CliInputError("Invalid independent verification intent")
    return cast(VerificationIntent, value)


def _check_policy(value: object) -> VerificationPolicyV1:
    if not isinstance(value, Mapping):
        raise CliInputError("Invalid independent verification policy")

    subject = value.get("subject")
    checks = value.get("required_checks")
    assurance = value.get("required_assurance", [])
    report_kind = value.get("report_kind")
    on_unresolved = value.get("on_unresolved", "review")

    if (
        value.get("schema_version") != "va.verification-policy.v1"
        or not isinstance(subject, Mapping)
        or not isinstance(checks, list)
        or not all(isinstance(item, str) for item in checks)
        or not isinstance(assurance, list)
        or not all(item == "mirror_corroboration" for item in assurance)
        or report_kind not in _REPORT_KINDS
        or on_unresolved not in {"review", "deny"}
    ):
        raise CliInputError("Invalid independent verification policy")

    scope_value = value.get("execution_scope")
    scope: VerificationPolicyExecutionScopeV1 | None = None
    if scope_value is not None:
        if not isinstance(scope_value, Mapping):
            raise CliInputError("Invalid independent verification policy")

        profile = scope_value.get("profile")
        program = scope_value.get("expected_program")
        result_id = scope_value.get("requested_result_id")
        if (
            profile not in {"execution-v1", "sage-standards-v1"}
            or (program is not None and not isinstance(program, str))
            or (result_id is not None and not isinstance(result_id, str))
        ):
            raise CliInputError("Invalid independent verification policy")

        scope = VerificationPolicyExecutionScopeV1(
            profile=profile,
            expected_program=program,
            requested_result_id=result_id,
        )

    return VerificationPolicyV1(
        schema_version="va.verification-policy.v1",
        subject=cast(VerificationSubject, subject),
        report_kind=cast(PortableVerificationReportKindV1, report_kind),
        required_checks=tuple(cast(list[str], checks)),
        required_assurance=cast(
            tuple[VerificationPolicyAssuranceV1, ...],
            tuple(cast(list[str], assurance)),
        ),
        execution_scope=scope,
        on_unresolved=cast(Literal["review", "deny"], on_unresolved),
    )


def _same_subject(intent: VerificationIntent, policy: VerificationPolicyV1) -> None:
    actual, expected = intent["subject"], policy.subject
    if (
        actual["kind"] != expected["kind"]
        or actual["id"] != expected["id"]
        or actual.get("hedera_network") != expected.get("hedera_network")
    ):
        raise CliInputError("Independent intent does not match policy subject")


def _source_root(value: str) -> Path:
    root = Path(value).absolute()
    info = root.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise CliInputError("Invalid source root")
    return root.resolve(strict=True)


def _source_file(root: Path, relative_path: str) -> Path:
    name = source_v1_path(relative_path, 1024)
    current = root
    segments = name.split("/")

    for index, segment in enumerate(segments):
        current /= segment
        info = current.lstat()
        expected = (
            stat.S_ISDIR(info.st_mode)
            if index < len(segments) - 1
            else stat.S_ISREG(info.st_mode)
        )
        if stat.S_ISLNK(info.st_mode) or not expected:
            raise CliInputError("Source must be a regular file under the specified root")

    actual = current.resolve(strict=True)
    if not actual.is_relative_to(root):
        raise CliInputError("Source escapes specified root")
    return actual


async def _source_stream(
    root: Path,
    relative_path: str,
    budget: dict[str, int],
) -> AsyncIterator[bytes]:
    fd = _open_readonly(_source_file(root, relative_path))
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or opened.st_size > MAX_SOURCE_BYTES:
            raise CliInputError("Source file exceeds limit")

        while chunk := await asyncio.to_thread(os.read, fd, 65536):
            if len(chunk) > budget["remaining"]:
                raise CliInputError("Total source bytes exceed limit")
            budget["remaining"] -= len(chunk)
            yield chunk
    finally:
        os.close(fd)


def _source_paths(source_root: str, paths: object) -> list[SourceV1File]:
    root = _source_root(source_root)
    if not isinstance(paths, list) or not 1 <= len(paths) <= MAX_FILES:
        raise CliInputError("Source paths must be a nonempty bounded array")

    files: list[SourceV1File] = []
    unique: set[str] = set()
    budget = {"remaining": MAX_SOURCE_BYTES}
    total = 0

    for candidate in paths:
        path_rel = source_v1_path(candidate, 1024)
        identity = os.path.normcase(path_rel)
        if identity in unique:
            raise CliInputError("Duplicate source path")
        unique.add(identity)

        size = _source_file(root, path_rel).stat().st_size
        if size > MAX_SOURCE_BYTES - total:
            raise CliInputError("Total source bytes exceed limit")
        total += size

        files.append(
            {
                "path_rel": path_rel,
                "source": _source_stream(root, path_rel, budget),
            }
        )
    return files


def _dataset_sources(options: Options) -> list[SourceV1File]:
    manifest = _read_json(_option(options, "sources"))
    if not isinstance(manifest, Mapping) or set(manifest) != {"paths"}:
        raise CliInputError("Sources manifest must contain a bounded paths array")
    return _source_paths(_option(options, "source-root"), manifest["paths"])


def _ingest_material(options: Options) -> object:
    value = _read_json(_option(options, "material"))
    if not isinstance(value, Mapping):
        raise CliInputError("Invalid Ingest material descriptor")

    kind = value.get("kind")
    if kind == "json":
        if set(value) != {"kind", "value"} or "source-root" in options:
            raise CliInputError("Invalid inline JSON material")
        return {"kind": "json", "value": value["value"]}

    if kind == "text":
        if not set(value) <= {"kind", "text", "media_type"} or "source-root" in options:
            raise CliInputError("Invalid inline text material")

        text = value.get("text")
        media = value.get("media_type")
        if (
            not isinstance(text, str)
            or (
                media is not None
                and (
                    not isinstance(media, str)
                    or not media.strip()
                    or len(media) > 256
                    or media.strip() != media
                )
            )
        ):
            raise CliInputError("Invalid inline text material")

        return {
            "kind": "text",
            "text": text,
            **({} if media is None else {"media_type": media}),
        }

    if kind == "file":
        if set(value) != {"kind", "path_rel"}:
            raise CliInputError("Unknown Ingest material field")

        path_rel = source_v1_path(value.get("path_rel"), 1024)
        if "/" in path_rel:
            raise CliInputError("Single-file Ingest requires a basename")

        return {
            "kind": "file",
            "file": _source_paths(_option(options, "source-root"), [path_rel])[0],
        }

    if kind == "file_set":
        if set(value) != {"kind", "paths"}:
            raise CliInputError("Unknown Ingest material field")
        return {
            "kind": "file_set",
            "files": _source_paths(_option(options, "source-root"), value.get("paths")),
        }

    raise CliInputError("Unsupported Ingest material kind")


def _ingest_anchor(options: Options, mode: Mode) -> str | None:
    value = options.get("anchor-request-id")
    if mode == "offline":
        if value is not None:
            raise CliInputError("Offline Ingest cannot select a public anchor")
        return None

    if value is None:
        raise CliInputError("Public Ingest requires a Core anchor request UUID")

    try:
        parsed = uuid.UUID(value)
    except ValueError as error:
        raise CliInputError("Public Ingest requires a Core anchor request UUID") from error

    if parsed.version not in {1, 2, 3, 4, 5} or str(parsed) != value.lower():
        raise CliInputError("Public Ingest requires a Core anchor request UUID")
    return str(parsed)


def _endpoint(value: str, kind: Literal["explorer", "mirror"]) -> str:
    parsed = urlsplit(value)
    loopback = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    path = parsed.path.rstrip("/") if kind == "explorer" else parsed.path

    if (
        (parsed.scheme != "https" and not (loopback and parsed.scheme == "http"))
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or (kind == "explorer" and path not in {"", "/v1"})
        or (kind == "mirror" and path != "/api/v1")
    ):
        raise CliInputError("Invalid resolver endpoint")
    return value


def _required_network(intent: VerificationIntent) -> HederaNetwork:
    network = intent["subject"].get("hedera_network")
    if network not in {"mainnet", "testnet"}:
        raise CliInputError("Public verification requires an explicit Hedera network")
    return network


def _mode(
    options: Options,
    intent: VerificationIntent,
    policy: VerificationPolicyV1,
    offline_kind: Literal["verification", "execution"],
    public_kind: Literal["public_triangulation", "execution_triangulation"],
) -> tuple[Mode, str | None, str | None]:
    mode = options.get("mode", "offline")
    if mode not in {"offline", "public"}:
        raise CliInputError("Unsupported verification mode")

    if mode == "offline":
        if (
            "explorer-url" in options
            or "mirror-url" in options
            or policy.report_kind != offline_kind
        ):
            raise CliInputError("Offline verification rejects public resolver settings")
        return "offline", None, None

    _required_network(intent)
    if policy.report_kind != public_kind or "explorer-url" not in options:
        raise CliInputError("Public verification requires network, policy and Explorer")

    return (
        "public",
        _endpoint(options["explorer-url"], "explorer"),
        _endpoint(options["mirror-url"], "mirror") if "mirror-url" in options else None,
    )


def _jsonable(value: object) -> object:
    if is_dataclass(value) and not isinstance(value, type):
        return _jsonable(asdict(cast(Any, value)))
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


def _status_code(value: str) -> int:
    return 0 if value in {"allow", "valid"} else 2 if value == "review" else 1


def _save_report(path: str, report: PortableVerificationReportV1) -> None:
    if validate_portable_verification_report_v1(report).status != "valid":
        raise RuntimeError("Verifier produced an invalid portable report")

    data = (
        json.dumps(_jsonable(report), ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode()
    if len(data) > MAX_JSON_BYTES:
        raise RuntimeError("Verifier report exceeds output size limit")

    destination = Path(path).absolute()
    staging = destination.parent / f".va-verifier-{uuid.uuid4()}.tmp"
    fd: int | None = None

    try:
        fd = os.open(staging, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.write(fd, data)
        os.fsync(fd)
        os.close(fd)
        fd = None

        try:
            os.link(staging, destination)
        except FileExistsError as error:
            raise CliInputError("Report output already exists") from error
    finally:
        if fd is not None:
            os.close(fd)
        staging.unlink(missing_ok=True)


def _public_config(
    network: HederaNetwork,
    explorer: str,
    mirror: str | None,
) -> PublicTriangulationV1Config:
    return PublicTriangulationV1Config(
        explorer=ExplorerPublicTransportV1(base_url=explorer),
        mirror=None if mirror is None else HederaMirrorV1Config(base_urls={network: mirror}),
    )


def _execution_config(
    network: HederaNetwork,
    explorer: str,
    mirror: str | None,
) -> PublicExecutionTriangulationV1Config:
    return PublicExecutionTriangulationV1Config(
        explorer=ExplorerPublicTransportV1(base_url=explorer),
        mirror=None if mirror is None else HederaMirrorV1Config(base_urls={network: mirror}),
    )


def _execution_input(
    options: Options,
    intent: VerificationIntent,
    policy: VerificationPolicyV1,
) -> ExecutionV1Input:
    scope = policy.execution_scope
    if scope is None:
        raise CliInputError("Execution policy scope required")

    value: ExecutionV1Input = {
        "intent": intent,
        "evidence": _read_json(_option(options, "evidence")),
        "profile": scope.profile,
    }

    if scope.expected_program is not None:
        value["expected_program"] = scope.expected_program
    if scope.requested_result_id is not None:
        value["result_id"] = scope.requested_result_id
    if "verification-material" in options:
        value["verification_material"] = cast(
            PublicExecutionVerificationMaterial,
            _read_json(options["verification-material"]),
        )

    return value


def _run_report_validate(
    options: Options,
) -> tuple[PortableVerificationReportValidationV1, int]:
    result = validate_portable_verification_report_v1(
        _read_json(_option(options, "report"))
    )
    return result, _status_code(result.status)


def _run_policy_assess(
    options: Options,
) -> tuple[VerificationPolicyDecisionV1, int]:
    policy = _check_policy(_read_json(_option(options, "policy")))
    result = assess_portable_verification_policy_v1(
        _read_json(_option(options, "report")),
        policy,
    )
    return result, _status_code(result.decision)


async def _run_verify_standards(
    options: Options,
) -> tuple[VerificationPolicyWorkflowV1, int]:
    intent = _check_intent(_read_json(_option(options, "intent")), "execution")
    policy = _check_policy(_read_json(_option(options, "policy")))
    _same_subject(intent, policy)

    scope = policy.execution_scope
    network = _required_network(intent)
    if (
        policy.report_kind != "independent_standards"
        or scope is None
        or scope.profile != "sage-standards-v1"
        or scope.expected_program != "sage"
    ):
        raise CliInputError("Independent SAGE standards policy required")

    config = (
        Hcs1MirrorV1Config(
            base_urls={network: _endpoint(options["mirror-url"], "mirror")}
        )
        if "mirror-url" in options
        else Hcs1MirrorV1Config()
    )
    decode_options = cast(Hcs1V1ContentOptions, {})

    result = await verify_execution_standards_with_policy_v1(
        config,
        _execution_input(options, intent, policy),
        decode_options,
        policy,
    )
    return result, _status_code(result.policy.decision)


async def _run_verify_execution(
    options: Options,
) -> tuple[VerificationPolicyWorkflowV1, int]:
    intent = _check_intent(_read_json(_option(options, "intent")), "execution")
    policy = _check_policy(_read_json(_option(options, "policy")))
    _same_subject(intent, policy)

    mode, explorer, mirror = _mode(
        options,
        intent,
        policy,
        "execution",
        "execution_triangulation",
    )
    input_value = _execution_input(options, intent, policy)

    if mode == "public":
        if explorer is None:
            raise CliInputError("Public verification requires Explorer")

        result = await triangulate_execution_with_policy_v1(
            _execution_config(_required_network(intent), explorer, mirror),
            input_value,
            policy,
        )
    else:
        result = verify_execution_with_policy_v1(input_value, policy)

    return result, _status_code(result.policy.decision)


async def _run_verify_ingest(
    options: Options,
) -> tuple[VerificationPolicyWorkflowV1, int]:
    intent = _check_intent(_read_json(_option(options, "intent")), "ingest")
    policy = _check_policy(_read_json(_option(options, "policy")))
    _same_subject(intent, policy)

    mode, explorer, mirror = _mode(
        options,
        intent,
        policy,
        "verification",
        "public_triangulation",
    )
    anchor = _ingest_anchor(options, mode)
    bundle = _read_json(_option(options, "bundle"))
    material = _ingest_material(options)
    receipt = _read_json(options["receipt"]) if "receipt" in options else None

    if mode == "public":
        if explorer is None or anchor is None:
            raise CliInputError("Public Ingest requires Explorer and anchor request ID")

        config = _public_config(_required_network(intent), explorer, mirror)
        if receipt is None:
            result = await triangulate_ingest_with_policy_v1(
                config,
                bundle=bundle,
                material=material,
                intent=intent,
                anchor_request_id=anchor,
                policy=policy,
            )
        else:
            result = await triangulate_ingest_with_policy_v1(
                config,
                bundle=bundle,
                material=material,
                intent=intent,
                anchor_request_id=anchor,
                policy=policy,
                receipt=receipt,
            )
    elif receipt is None:
        result = await verify_ingest_with_policy_v1(
            bundle=bundle,
            material=material,
            intent=intent,
            policy=policy,
        )
    else:
        result = await verify_ingest_with_policy_v1(
            bundle=bundle,
            material=material,
            intent=intent,
            policy=policy,
            receipt=receipt,
        )

    return result, _status_code(result.policy.decision)


async def _run_verify_dataset(
    options: Options,
) -> tuple[VerificationPolicyWorkflowV1, int]:
    intent = _check_intent(_read_json(_option(options, "intent")), "dataset")
    policy = _check_policy(_read_json(_option(options, "policy")))
    _same_subject(intent, policy)

    mode, explorer, mirror = _mode(
        options,
        intent,
        policy,
        "verification",
        "public_triangulation",
    )
    bundle = _read_json(_option(options, "bundle"))
    files = _dataset_sources(options)
    receipt = _read_json(options["receipt"]) if "receipt" in options else None

    if mode == "public":
        if explorer is None:
            raise CliInputError("Public Dataset verification requires Explorer")

        config = _public_config(_required_network(intent), explorer, mirror)
        if receipt is None:
            result = await triangulate_dataset_with_policy_v1(
                config,
                bundle=bundle,
                files=files,
                intent=intent,
                policy=policy,
            )
        else:
            result = await triangulate_dataset_with_policy_v1(
                config,
                bundle=bundle,
                files=files,
                intent=intent,
                policy=policy,
                receipt=receipt,
            )
    elif receipt is None:
        result = await verify_dataset_with_policy_v1(
            bundle=bundle,
            files=files,
            intent=intent,
            policy=policy,
        )
    else:
        result = await verify_dataset_with_policy_v1(
            bundle=bundle,
            files=files,
            intent=intent,
            policy=policy,
            receipt=receipt,
        )

    return result, _status_code(result.policy.decision)


async def run_verifier_cli_v1(argv: Sequence[str], emit: Emitter) -> int:
    try:
        command, options = _parse_args(argv)
        report: PortableVerificationReportV1 | None = None
        output: object

        if command == "report validate":
            validation, code = _run_report_validate(options)
            output = validation
        elif command == "policy assess":
            decision, code = _run_policy_assess(options)
            output = decision
        elif command == "verify standards":
            workflow, code = await _run_verify_standards(options)
            report = workflow.report
            output = workflow
        elif command == "verify execution":
            workflow, code = await _run_verify_execution(options)
            report = workflow.report
            output = workflow
        elif command == "verify ingest":
            workflow, code = await _run_verify_ingest(options)
            report = workflow.report
            output = workflow
        else:
            workflow, code = await _run_verify_dataset(options)
            report = workflow.report
            output = workflow

        report_out = options.get("report-out")
        if report_out is not None:
            if report is None:
                raise CliInputError(
                    "Report export is only available for verification commands"
                )
            _save_report(report_out, report)

        emit(
            json.dumps(
                {
                    "schema_version": CLI_SCHEMA,
                    "command": command,
                    "result": _jsonable(output),
                },
                ensure_ascii=False,
                separators=(",", ":"),
            )
        )
        return code
    except (CliInputError, TypeError, SyntaxError, ValueError):
        emit(
            json.dumps(
                {
                    "schema_version": CLI_SCHEMA,
                    "error": {"code": "CLI_INPUT_INVALID"},
                },
                separators=(",", ":"),
            )
        )
        return 64
    except Exception:
        emit(
            json.dumps(
                {
                    "schema_version": CLI_SCHEMA,
                    "error": {"code": "CLI_OPERATION_FAILED"},
                },
                separators=(",", ":"),
            )
        )
        return 70


def main() -> int:
    return asyncio.run(run_verifier_cli_v1(sys.argv[1:], print))