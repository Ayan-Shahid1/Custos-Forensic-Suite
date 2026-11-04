"""Acquire a raw Windows RAM image with the bundled WinPmem executable."""

from __future__ import annotations

import argparse
import ctypes
import datetime as dt
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
from collections import deque
from pathlib import Path
from typing import Any


ARTIFACT_DIRECTORY = Path(__file__).resolve().parent
WINPMEM_NAME = "go-winpmem_amd64_1.0-rc2_signed.exe"
DIAGNOSTIC_LINES = 80
STORAGE_RESERVE_BYTES = 1024**3
RAM_SIZE_MULTIPLIER = 2


class CollectionError(Exception):
    """A collection prerequisite or output operation failed."""


def now_pair() -> tuple[str, str]:
    instant = dt.datetime.now(dt.timezone.utc)
    return (
        instant.isoformat(timespec="seconds").replace("+00:00", "Z"),
        instant.astimezone().isoformat(timespec="seconds"),
    )


def local_timezone_identifier() -> str:
    if os.name == "nt":
        try:
            import winreg

            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\TimeZoneInformation",
            ) as key:
                name, _ = winreg.QueryValueEx(key, "TimeZoneKeyName")
                if isinstance(name, str) and name:
                    return name
        except (OSError, ImportError):
            pass
    return str(dt.datetime.now().astimezone().tzinfo)


def is_administrator() -> bool:
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError) as exc:
        raise CollectionError(f"Could not determine administrator status: {exc}") from exc


def prompt_for_output_directory() -> str:
    try:
        return input(
            "Enter a custom save folder, or press Enter to save in this artifact folder: "
        )
    except EOFError as exc:
        raise CollectionError(
            "Output folder was not supplied and interactive input is unavailable."
        ) from exc


def validate_output_directory(raw_path: str | None) -> tuple[Path, int]:
    if raw_path is None or not raw_path.strip():
        destination = ARTIFACT_DIRECTORY
    else:
        destination = Path(raw_path.strip().strip("\"'")).expanduser()
    try:
        resolved = destination.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise CollectionError(
            f"Output folder does not exist or cannot be resolved: {destination}"
        ) from exc
    if not resolved.is_dir():
        raise CollectionError(f"Output destination is not a folder: {resolved}")
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", prefix=".a01-write-check-", dir=resolved, delete=True
        ):
            pass
        free_bytes = shutil.disk_usage(resolved).free
    except OSError as exc:
        raise CollectionError(
            f"Output folder is not writable or its free space cannot be checked: "
            f"{resolved}: {exc}"
        ) from exc
    return resolved, free_bytes


def installed_memory_bytes() -> int:
    if os.name != "nt":
        raise CollectionError("RAM acquisition and storage preflight require Windows.")
    installed_kib = ctypes.c_ulonglong()
    get_installed = ctypes.windll.kernel32.GetPhysicallyInstalledSystemMemory
    get_installed.argtypes = [ctypes.POINTER(ctypes.c_ulonglong)]
    get_installed.restype = ctypes.c_bool
    if get_installed(ctypes.byref(installed_kib)) and installed_kib.value:
        return installed_kib.value * 1024

    class MemoryStatusEx(ctypes.Structure):
        _fields_ = [
            ("dwLength", ctypes.c_ulong),
            ("dwMemoryLoad", ctypes.c_ulong),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]

    status = MemoryStatusEx()
    status.dwLength = ctypes.sizeof(status)
    if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
        if status.ullTotalPhys:
            return int(status.ullTotalPhys)
    raise CollectionError(
        "Windows did not provide installed/total physical memory; refusing "
        "acquisition without a storage preflight."
    )


def storage_preflight(free_bytes: int, installed_bytes: int) -> dict[str, Any]:
    estimated_required = installed_bytes * RAM_SIZE_MULTIPLIER
    required_with_reserve = estimated_required + STORAGE_RESERVE_BYTES
    passes = free_bytes >= required_with_reserve
    return {
        "available_bytes_before_capture": free_bytes,
        "installed_physical_memory_bytes": installed_bytes,
        "estimated_image_bytes": estimated_required,
        "additional_free_space_reserve_bytes": STORAGE_RESERVE_BYTES,
        "required_free_bytes_for_preflight": required_with_reserve,
        "passed": passes,
        "basis": (
            "Conservative preflight threshold of twice installed physical RAM plus "
            "1 GiB reserve. The actual raw image can be larger than installed RAM "
            "because physical address space contains gaps and device memory; this "
            "estimate is not a guaranteed upper bound."
        ),
    }


def _version_label(tool_path: Path) -> str | None:
    match = re.search(
        r"(\d+\.\d+(?:\.\d+)?(?:[-.]?(?:alpha|beta|rc)\d*)?)",
        tool_path.name,
        re.I,
    )
    return match.group(1) if match else None


def inspect_tool(tool_path: Path) -> dict[str, Any]:
    if not tool_path.is_file():
        raise CollectionError(f"WinPmem executable not found: {tool_path}")
    help_result = subprocess.run(
        [str(tool_path), "help", "acquire"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
        shell=False,
    )
    help_text = "\n".join((help_result.stdout, help_result.stderr)).strip()
    if help_result.returncode != 0:
        raise CollectionError(
            f"WinPmem acquisition help failed with exit code "
            f"{help_result.returncode}: {help_text[-2000:]}"
        )
    required_help_tokens = (
        "Acquire a memory image",
        "--progress",
        "--compression",
        "Output path to write image to",
    )
    missing = [token for token in required_help_tokens if token not in help_text]
    if missing:
        raise CollectionError(
            "The bundled WinPmem executable does not expose the verified acquire "
            f"interface; missing help items: {', '.join(missing)}."
        )
    try:
        size_bytes = tool_path.stat().st_size
    except OSError as exc:
        raise CollectionError(f"Could not inspect WinPmem executable: {exc}") from exc
    return {
        "path": str(tool_path.resolve()),
        "filename": tool_path.name,
        "version_label_from_filename": _version_label(tool_path),
        "version_reported_by_binary": None,
        "binary_version_metadata": None,
        "version_note": (
            "The executable has no PE product/file version metadata and does not "
            "support a version command. The filename identifies it as 1.0-rc2."
        ),
        "size_bytes": size_bytes,
        "authenticode_status": "not_signed",
        "help_exit_code": help_result.returncode,
        "acquire_help": help_text,
        "supported_acquire_options": [
            "--service_name",
            "--driver_path",
            "--nosparse",
            "--progress",
            "--compression=snappy|gzip",
            "[filename]",
        ],
        "raw_output_basis": (
            "This exact executable's acquire help offers optional snappy/gzip "
            "compression. Upstream acquire source sets the compression default "
            "to none; A01 omits --compression to request uncompressed raw output. "
            "Sparse output is the tool default."
        ),
        "authenticity_warning": (
            "Despite 'signed' in its filename, Windows Authenticode inspection "
            "reported this downloaded executable as NotSigned. Windows may block "
            "its driver; A01 will report the tool's actual failure and will not "
            "change security policy."
        ),
    }


def choose_output_paths(directory: Path, started_utc: str) -> tuple[Path, Path]:
    stamp = dt.datetime.fromisoformat(started_utc.replace("Z", "+00:00")).strftime(
        "%Y%m%dT%H%M%S.%fZ"
    )
    index = 0
    while True:
        suffix = "" if index == 0 else f"_{index}"
        image_path = directory / f"A01_memory_{stamp}{suffix}.raw"
        result_path = directory / f"A01_collection_{stamp}{suffix}.json"
        if not image_path.exists() and not result_path.exists():
            return image_path, result_path
        index += 1


def build_acquisition_arguments(tool_path: Path, output_path: Path) -> list[str]:
    return [
        str(tool_path),
        "--verbose",
        "acquire",
        "--progress",
        str(output_path),
    ]


def reserve_output_paths(image_path: Path, result_path: Path) -> tuple[Path, Path]:
    index = 0
    while True:
        suffix = "" if index == 0 else f"_{index}"
        candidate_image = image_path.with_name(
            f"{image_path.stem}{suffix}{image_path.suffix}"
        )
        candidate_result = result_path.with_name(
            f"{result_path.stem}{suffix}{result_path.suffix}"
        )
        try:
            with candidate_image.open("xb"):
                pass
        except FileExistsError:
            index += 1
            continue
        if candidate_result.exists():
            candidate_image.unlink()
            index += 1
            continue
        return candidate_image, candidate_result


def run_acquisition(
    arguments: list[str],
) -> tuple[int | None, list[str], bool, str | None, int]:
    diagnostics: deque[str] = deque(maxlen=DIAGNOSTIC_LINES)
    diagnostic_count = [0]
    cancelled = False
    process: subprocess.Popen[str] | None = None
    read_thread: threading.Thread | None = None
    try:
        creation_flags = (
            subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
        )
        process = subprocess.Popen(
            arguments,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
            creationflags=creation_flags,
        )

        def read_output() -> None:
            assert process is not None and process.stdout is not None
            for line in process.stdout:
                rendered = line.rstrip("\r\n")
                diagnostics.append(rendered)
                diagnostic_count[0] += 1
                print(rendered, flush=True)

        read_thread = threading.Thread(target=read_output, daemon=True)
        read_thread.start()
        try:
            return_code = process.wait()
        except KeyboardInterrupt:
            cancelled = True
            if os.name == "nt":
                try:
                    process.send_signal(signal.CTRL_BREAK_EVENT)
                    process.wait(timeout=15)
                except (OSError, ValueError, subprocess.TimeoutExpired):
                    process.terminate()
            else:
                process.terminate()
            try:
                return_code = process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                return_code = process.wait()
        if read_thread is not None:
            read_thread.join()
        return return_code, list(diagnostics), cancelled, None, diagnostic_count[0]
    except OSError as exc:
        if process is not None and process.poll() is None:
            process.terminate()
            process.wait()
        return None, list(diagnostics), cancelled, f"Could not start WinPmem: {exc}", diagnostic_count[0]


def parse_tool_duration(diagnostics: list[str]) -> str | None:
    for line in diagnostics:
        match = re.search(r"Completed imaging in\s+(.+)$", line, re.I)
        if match:
            return match.group(1).strip()
    return None


def write_result_json(result: dict[str, Any], destination: Path) -> Path:
    index = 0
    while True:
        candidate = destination if index == 0 else destination.with_name(
            f"{destination.stem}_{index}{destination.suffix}"
        )
        try:
            result["output"]["result_json_path"] = str(candidate)
            with candidate.open("x", encoding="utf-8", newline="\n") as output:
                json.dump(result, output, ensure_ascii=False, indent=2)
                output.write("\n")
            return candidate
        except FileExistsError:
            index += 1


def collect(output_directory: str | None) -> int:
    started_utc, started_local = now_pair()
    errors: list[str] = []
    validation: dict[str, Any] = {
        "checks": [],
        "storage": None,
    }
    tool_info: dict[str, Any] | None = None
    invocation_arguments: list[str] = []
    output_image: Path | None = None
    result_path: Path | None = None
    output_size: int | None = None
    tool_exit_code: int | None = None
    diagnostics: list[str] = []
    diagnostic_total: int | None = None
    cancelled = False
    tool_error: str | None = None
    acquisition_started = False
    image_reserved = False
    result_status = "failed"
    status_basis = "Prerequisites did not permit acquisition."

    try:
        if sys.platform != "win32":
            raise CollectionError("A01 WinPmem acquisition is supported only on Windows.")
        if sys.version_info[:2] != (3, 12):
            raise CollectionError(
                f"Python 3.12 is required; running {sys.version_info.major}.{sys.version_info.minor}."
            )
        validation["checks"].append({"check": "Windows Python 3.12", "passed": True})

        directory, free_bytes = validate_output_directory(output_directory)
        validation["checks"].append(
            {"check": "Destination exists and is writable", "passed": True}
        )
        output_image, result_path = choose_output_paths(directory, started_utc)
        tool_path = ARTIFACT_DIRECTORY / WINPMEM_NAME
        tool_info = inspect_tool(tool_path)
        validation["checks"].append(
            {"check": "WinPmem acquire CLI matches expected interface", "passed": True}
        )

        installed_bytes = installed_memory_bytes()
        storage = storage_preflight(free_bytes, installed_bytes)
        validation["storage"] = storage
        validation["checks"].append(
            {"check": "Destination free-space preflight", "passed": storage["passed"]}
        )
        if not storage["passed"]:
            raise CollectionError(
                "Insufficient destination storage. "
                f"Available: {free_bytes:,} bytes; conservative preflight requires "
                f"{storage['required_free_bytes_for_preflight']:,} bytes "
                "(twice installed RAM plus 1 GiB)."
            )

        if not is_administrator():
            raise CollectionError(
                "Administrator access is required by this A01 launcher policy. "
                "No acquisition was started."
            )
        validation["checks"].append(
            {"check": "Administrator token", "passed": True}
        )

        output_image, result_path = reserve_output_paths(output_image, result_path)
        image_reserved = True
        invocation_arguments = build_acquisition_arguments(tool_path, output_image)
        print(f"A01 output image: {output_image}", flush=True)
        print("Starting WinPmem acquisition. Do not shut down or suspend Windows.", flush=True)
        (
            tool_exit_code,
            diagnostics,
            cancelled,
            tool_error,
            diagnostic_total,
        ) = run_acquisition(invocation_arguments)
        acquisition_started = tool_exit_code is not None or tool_error is None
        if tool_error:
            errors.append(tool_error)
        if image_reserved and not acquisition_started:
            try:
                if output_image.exists() and output_image.stat().st_size == 0:
                    output_image.unlink()
            except OSError as exc:
                errors.append(
                    f"Could not remove the unused empty output reservation: {exc}"
                )
        try:
            output_size = output_image.stat().st_size if output_image.exists() else None
        except OSError as exc:
            errors.append(f"Could not inspect the capture output: {exc}")
        output_exists = output_image.exists()
        if cancelled:
            result_status = "partial" if output_exists else "failed"
            status_basis = (
                "User cancellation interrupted WinPmem. Any created output is retained "
                "and is incomplete; it must not be treated as a complete image."
            )
            errors.append("Acquisition was cancelled; any partial output was retained.")
        elif tool_exit_code == 0 and output_size is not None and output_size > 0:
            result_status = "success"
            status_basis = (
                "WinPmem returned exit code 0 and produced a nonempty output. These "
                "checks do not prove the image is complete or correct."
            )
        elif output_exists:
            result_status = "partial"
            status_basis = (
                "WinPmem did not complete successfully or produced an empty output. "
                "The created output was retained as an incomplete capture."
            )
            errors.append(
                "WinPmem failed or returned no usable image; any created output was retained."
            )
        else:
            result_status = "failed"
            status_basis = "WinPmem produced no output image."
            errors.append("WinPmem produced no output image.")

    except (CollectionError, OSError, subprocess.SubprocessError) as exc:
        errors.append(str(exc))
    except KeyboardInterrupt:
        cancelled = True
        errors.append("Acquisition setup was cancelled before WinPmem completed.")

    if image_reserved and output_image is not None and not acquisition_started:
        try:
            if output_image.exists() and output_image.stat().st_size == 0:
                output_image.unlink()
        except OSError as exc:
            errors.append(f"Could not remove the unused empty output reservation: {exc}")

    ended_utc, ended_local = now_pair()
    if output_image is not None:
        try:
            output_size = output_image.stat().st_size if output_image.exists() else None
        except OSError as exc:
            errors.append(f"Could not inspect the capture output: {exc}")
    if result_status == "failed" and cancelled and output_image is not None and output_image.exists():
        result_status = "partial"
        status_basis = (
            "User cancellation interrupted acquisition. A created output was retained "
            "as an incomplete capture."
        )

    result: dict[str, Any] = {
        "artifact_id": "A01",
        "status": result_status,
        "status_basis": status_basis,
        "tool": tool_info,
        "invocation_arguments": invocation_arguments,
        "output": {
            "image_path": str(output_image) if output_image else None,
            "format": "raw",
            "compression": "none",
            "sparse_output": True,
            "observed_size_bytes": output_size,
            "result_json_path": str(result_path) if result_path else None,
        },
        "timestamps": {
            "wrapper_start_utc": started_utc,
            "wrapper_start_local": started_local,
            "wrapper_end_utc": ended_utc,
            "wrapper_end_local": ended_local,
            "local_timezone_identifier": local_timezone_identifier(),
            "tool_reported_acquisition_duration": parse_tool_duration(diagnostics),
            "meaning": (
                "Wrapper timestamps measure this collector's operation. A duration "
                "is reported only if WinPmem exposed its own acquisition timing."
            ),
        },
        "tool_exit_code": tool_exit_code,
        "diagnostics": {
            "line_count_retained": len(diagnostics),
            "line_limit": DIAGNOSTIC_LINES,
            "total_line_count": diagnostic_total,
            "truncated": (
                diagnostic_total is not None
                and diagnostic_total > len(diagnostics)
            ),
            "lines": diagnostics,
            "start_error": tool_error,
        },
        "validation": validation,
        "errors": errors,
        "limitations": [
            "A01 uses this exact bundled WinPmem executable and its documented acquire command.",
            "The output is an uncompressed raw image; WinPmem's default sparse-file behavior is retained.",
            "Physical memory layout and gaps can make the logical image larger than installed RAM.",
            "The storage preflight is conservative but cannot guarantee the exact image size.",
            "Exit code zero and a nonempty file do not prove that all physical memory was acquired correctly.",
            "Windows protections may block this executable's unsigned driver; A01 will not disable protections or bypass a block.",
            "The WinPmem filename labels it 1.0-rc2, but the binary reports no version and contains no PE version metadata.",
        ],
    }
    result_write_error: OSError | None = None
    if result_path is not None:
        try:
            result_path = write_result_json(result, result_path)
        except OSError as exc:
            result_write_error = exc
            errors.append(
                f"Could not write collection result JSON at {result_path}: {exc}"
            )

    if result_write_error is not None:
        print("A01 status: failed (collection result JSON could not be saved)", flush=True)
    else:
        print(f"A01 status: {result_status}", flush=True)
    if output_image is not None:
        print(f"RAM image: {output_image}", flush=True)
    if output_size is not None:
        print(f"Observed image size: {output_size:,} bytes", flush=True)
    if result_path is not None and result_write_error is None:
        print(f"Collection result: {result_path}", flush=True)
    if errors:
        for error in errors:
            print(f"A01: {error}", file=sys.stderr, flush=True)

    if result_write_error is not None:
        return 2
    return {"success": 0, "partial": 1, "failed": 2}[result_status]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Acquire a raw Windows RAM image using the bundled WinPmem executable."
    )
    parser.add_argument(
        "--output-dir",
        help="Existing writable destination folder. Defaults to the A01 artifact folder.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    output_directory = args.output_dir
    if output_directory is None:
        try:
            output_directory = prompt_for_output_directory()
        except CollectionError as exc:
            print(f"A01: {exc}", file=sys.stderr, flush=True)
            return 2
    return collect(output_directory)


if __name__ == "__main__":
    raise SystemExit(main())
