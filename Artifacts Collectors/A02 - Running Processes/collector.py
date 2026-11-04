"""Collect a read-only snapshot of Windows process metadata with psutil."""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from ctypes import wintypes

try:
    import psutil
except ImportError as exc:
    raise SystemExit(
        "The A02 collector requires psutil. Install it in the project environment with: "
        '"E:\\FYP Custos Forensic Suite\\.venv\\Scripts\\python.exe" -m pip install psutil'
    ) from exc

PROCESS_FIELDS: tuple[tuple[str, Callable[[psutil.Process], Any]], ...] = (
    ("parent_pid", lambda process: process.ppid()),
    ("name", lambda process: process.name()),
    ("executable_path", lambda process: process.exe()),
    ("command_line", lambda process: process.cmdline()),
    ("username", lambda process: process.username()),
    ("status", lambda process: process.status()),
    ("thread_count", lambda process: process.num_threads()),
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _collection_time_metadata(started_at_utc: str, ended_at_utc: str) -> dict[str, Any]:
    started = datetime.fromisoformat(started_at_utc.replace("Z", "+00:00")).astimezone(
        timezone.utc
    )
    observed_end = datetime.fromisoformat(ended_at_utc.replace("Z", "+00:00")).astimezone(
        timezone.utc
    )
    clock_adjusted = observed_end < started
    ended = max(started, observed_end)
    timezone_id = None
    timezone_id_error = None
    timezone_id_source = (
        r"HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation\TimeZoneKeyName"
    )
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\TimeZoneInformation",
        ) as key:
            timezone_id = winreg.QueryValueEx(key, "TimeZoneKeyName")[0]
        if not isinstance(timezone_id, str) or not timezone_id.strip():
            timezone_id = None
            timezone_id_error = "The Windows TimeZoneKeyName value was empty or malformed."
    except (ImportError, OSError) as exc:
        timezone_id_error = f"{type(exc).__name__}: {exc}"
    return {
        "collection_started_at_utc": started.isoformat(),
        "collection_ended_at_utc": ended.isoformat(),
        "collection_started_at_local": started.astimezone().isoformat(),
        "collection_ended_at_local": ended.astimezone().isoformat(),
        "collection_time_zone_id": timezone_id,
        "collection_time_zone_id_source": timezone_id_source,
        "collection_time_zone_id_error": timezone_id_error,
        "collection_clock_adjusted": clock_adjusted,
    }


def _append_error(
    errors: list[dict[str, Any]],
    pid: int | None,
    field: str | None,
    error_type: str,
    message: str,
) -> None:
    errors.append(
        {
            "pid": pid,
            "field": field,
            "error_type": error_type,
            "message": message,
        }
    )


def _read_process_field(
    process: psutil.Process,
    pid: int,
    field: str,
    getter: Callable[[psutil.Process], Any],
    unavailable: dict[str, str],
    errors: list[dict[str, Any]],
) -> Any:
    try:
        value = getter(process)
    except psutil.ZombieProcess as exc:
        reason = "The process became a zombie while its metadata was being read."
        unavailable[field] = reason
        _append_error(errors, pid, field, "ZombieProcess", str(exc) or reason)
        return None
    except psutil.NoSuchProcess as exc:
        reason = "The process exited or its PID was reused during collection."
        unavailable[field] = reason
        _append_error(errors, pid, field, "NoSuchProcess", str(exc) or reason)
        return None
    except psutil.AccessDenied as exc:
        reason = "Windows denied access to this process field for the current token."
        unavailable[field] = reason
        _append_error(errors, pid, field, "AccessDenied", str(exc) or reason)
        return None
    except psutil.Error as exc:
        reason = f"psutil could not retrieve this field: {exc}"
        unavailable[field] = reason
        _append_error(errors, pid, field, type(exc).__name__, str(exc) or reason)
        return None

    if value is None:
        unavailable[field] = "psutil returned no value for this field."
    return value


def _collect_one_process(
    process: psutil.Process,
    errors: list[dict[str, Any]],
) -> dict[str, Any]:
    try:
        pid = int(process.pid)
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.Error) as exc:
        _append_error(
            errors,
            None,
            "pid",
            type(exc).__name__,
            str(exc) or "Could not read the process ID.",
        )
        reason = "The process exited or access was denied before its PID could be read."
        return {
            "pid": None,
            "parent_pid": None,
            "name": None,
            "executable_path": None,
            "command_line": None,
            "username": None,
            "creation_time_utc": None,
            "status": None,
            "thread_count": None,
        }

    unavailable: dict[str, str] = {}
    record: dict[str, Any] = {"pid": pid}
    creation_time = _read_process_field(
        process,
        pid,
        "creation_time_utc",
        lambda item: item.create_time(),
        unavailable,
        errors,
    )
    if creation_time is None:
        record["creation_time_utc"] = None
    else:
        record["creation_time_utc"] = datetime.fromtimestamp(
            creation_time, timezone.utc
        ).isoformat()

    for field, getter in PROCESS_FIELDS:
        record[field] = _read_process_field(
            process,
            pid,
            field,
            getter,
            unavailable,
            errors,
        )

    return record


def _write_json(
    output_path: Path,
    document: dict[str, Any],
    overwrite: bool,
) -> None:
    if not output_path.parent.is_dir():
        raise FileNotFoundError(f"Output directory does not exist: {output_path.parent}")
    if not overwrite and os.path.lexists(output_path):
        raise FileExistsError(f"Refusing to overwrite existing output: {output_path}")

    temporary_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            prefix=f".{output_path.name}.",
            suffix=".tmp",
            dir=output_path.parent,
            delete=False,
        ) as temporary_file:
            temporary_path = temporary_file.name
            json.dump(document, temporary_file, ensure_ascii=True, indent=2)
            temporary_file.write("\n")
            temporary_file.flush()
            os.fsync(temporary_file.fileno())

        if overwrite:
            os.replace(temporary_path, output_path)
        else:
            # On Windows, rename fails rather than replacing a destination created
            # concurrently after the preflight existence check.
            os.rename(temporary_path, output_path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass


def collect_processes(
    output_path: str | os.PathLike[str],
    overwrite: bool = False,
) -> dict[str, Any]:
    """Collect process metadata and atomically save a UTF-8 JSON snapshot."""
    started_at = _utc_now()
    destination = Path(os.path.abspath(Path(output_path).expanduser()))
    if not overwrite and os.path.lexists(destination):
        raise FileExistsError(f"Refusing to overwrite existing output: {destination}")
    if not destination.parent.is_dir():
        raise FileNotFoundError(f"Output directory does not exist: {destination.parent}")

    processes: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    enumeration_failed = False
    iterator = iter(psutil.process_iter())
    while True:
        try:
            process = next(iterator)
        except StopIteration:
            break
        except psutil.Error as exc:
            _append_error(
                errors,
                None,
                "process_enumeration",
                type(exc).__name__,
                str(exc) or "psutil could not continue process enumeration.",
            )
            enumeration_failed = True
            break

        try:
            processes.append(_collect_one_process(process, errors))
        except psutil.Error as exc:
            try:
                pid = int(process.pid)
            except psutil.Error:
                pid = None
            _append_error(
                errors,
                pid,
                None,
                type(exc).__name__,
                str(exc) or "psutil could not collect this process record.",
            )

    finished_at = _utc_now()
    if enumeration_failed and not processes:
        outcome = "failed"
    elif errors:
        outcome = "partial"
    else:
        outcome = "completed"

    document: dict[str, Any] = {
        "schema_version": 1,
        "artifact": "A02 - Running Processes",
        "source": "Current Windows process table",
        "method": "Read-only psutil process enumeration",
        **_collection_time_metadata(started_at, finished_at),
        "outcome": outcome,
        "process_count": len(processes),
        "process_identity_note": (
            "Use PID together with creation_time_utc to distinguish a process "
            "from a later process that reuses the same PID."
        ),
        "limitations": [
            "This is a live snapshot; processes may start, exit, or change during enumeration.",
            "Unavailable process fields are null; reasons remain in collection_errors.",
            "Visibility depends on the current Windows token and security policy.",
            "Administrator elevation can improve visibility but does not bypass protected-process restrictions or guarantee access to every field.",
            "Collection does not terminate, suspend, or modify processes.",
        ],
        "collection_errors": errors,
        "processes": processes,
    }
    _write_json(destination, document, overwrite)
    return document


def _collect_thread_snapshot(
    output_path: str | os.PathLike[str],
    overwrite: bool = False,
    process_names: dict[int, str | None] | None = None,
) -> dict[str, Any]:
    started_at = _utc_now()
    destination = Path(os.path.abspath(Path(output_path).expanduser()))
    if not overwrite and os.path.lexists(destination):
        raise FileExistsError(f"Refusing to overwrite existing output: {destination}")
    if not destination.parent.is_dir():
        raise FileNotFoundError(f"Output directory does not exist: {destination.parent}")

    threads: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    field_error_counts: dict[tuple[str, str], int] = {}
    enumeration_failed = False

    if os.name != "nt":
        _append_error(
            errors,
            None,
            "thread_enumeration",
            "UnsupportedPlatform",
            "The Windows Toolhelp thread snapshot API is available only on Windows.",
        )
        enumeration_failed = True
    else:
        class FileTime(ctypes.Structure):
            _fields_ = [
                ("dwLowDateTime", wintypes.DWORD),
                ("dwHighDateTime", wintypes.DWORD),
            ]

        class ThreadEntry32(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ThreadID", wintypes.DWORD),
                ("th32OwnerProcessID", wintypes.DWORD),
                ("tpBasePri", wintypes.LONG),
                ("tpDeltaPri", wintypes.LONG),
                ("dwFlags", wintypes.DWORD),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        create_snapshot = kernel32.CreateToolhelp32Snapshot
        create_snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        create_snapshot.restype = wintypes.HANDLE
        thread_first = kernel32.Thread32First
        thread_first.argtypes = [wintypes.HANDLE, ctypes.POINTER(ThreadEntry32)]
        thread_first.restype = wintypes.BOOL
        thread_next = kernel32.Thread32Next
        thread_next.argtypes = [wintypes.HANDLE, ctypes.POINTER(ThreadEntry32)]
        thread_next.restype = wintypes.BOOL
        open_thread = kernel32.OpenThread
        open_thread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        open_thread.restype = wintypes.HANDLE
        get_thread_priority = kernel32.GetThreadPriority
        get_thread_priority.argtypes = [wintypes.HANDLE]
        get_thread_priority.restype = wintypes.INT
        get_thread_times = kernel32.GetThreadTimes
        get_thread_times.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(FileTime),
            ctypes.POINTER(FileTime),
            ctypes.POINTER(FileTime),
            ctypes.POINTER(FileTime),
        ]
        get_thread_times.restype = wintypes.BOOL
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = [wintypes.HANDLE]
        close_handle.restype = wintypes.BOOL
        set_last_error = kernel32.SetLastError
        set_last_error.argtypes = [wintypes.DWORD]
        set_last_error.restype = None

        invalid_handle = ctypes.c_void_p(-1).value
        snapshot = create_snapshot(0x00000004, 0)
        if snapshot == invalid_handle:
            error_code = ctypes.get_last_error()
            _append_error(
                errors,
                None,
                "thread_snapshot",
                "WindowsAPIError",
                f"CreateToolhelp32Snapshot failed with Windows error {error_code}.",
            )
            enumeration_failed = True
        else:
            def collect_thread_details(
                thread_id: int,
                owner_pid: int,
            ) -> dict[str, Any]:
                unavailable: dict[str, str] = {}
                owner_name = (
                    process_names.get(owner_pid)
                    if process_names is not None
                    else None
                )
                if owner_name is None:
                    unavailable["owning_process_name"] = (
                        "The process snapshot did not provide a name for this owner PID."
                    )

                priority: int | None = None
                creation_time_utc: str | None = None
                user_cpu_seconds: float | None = None
                kernel_cpu_seconds: float | None = None

                def record_error(field: str, error_code: int) -> None:
                    reason = (
                        f"Windows error {error_code} while querying the thread."
                    )
                    unavailable[field] = reason
                    key = (field, reason)
                    field_error_counts[key] = field_error_counts.get(key, 0) + 1

                thread_handle = open_thread(0x0040 | 0x0800, False, thread_id)
                if not thread_handle:
                    error_code = ctypes.get_last_error()
                    for field in (
                        "current_priority",
                        "creation_time_utc",
                        "user_cpu_time_seconds",
                        "kernel_cpu_time_seconds",
                    ):
                        record_error(field, error_code)
                else:
                    try:
                        set_last_error(0)
                        priority_value = int(get_thread_priority(thread_handle))
                        priority_error = ctypes.get_last_error()
                        if priority_value == 0x7FFFFFFF:
                            record_error("current_priority", priority_error)
                        else:
                            priority = priority_value

                        creation = FileTime()
                        exit_time = FileTime()
                        kernel_time = FileTime()
                        user_time = FileTime()
                        if get_thread_times(
                            thread_handle,
                            ctypes.byref(creation),
                            ctypes.byref(exit_time),
                            ctypes.byref(kernel_time),
                            ctypes.byref(user_time),
                        ):
                            creation_ticks = (
                                (creation.dwHighDateTime << 32)
                                | creation.dwLowDateTime
                            )
                            kernel_ticks = (
                                (kernel_time.dwHighDateTime << 32)
                                | kernel_time.dwLowDateTime
                            )
                            user_ticks = (
                                (user_time.dwHighDateTime << 32)
                                | user_time.dwLowDateTime
                            )
                            windows_epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
                            creation_time_utc = (
                                windows_epoch
                                + timedelta(microseconds=creation_ticks / 10)
                            ).isoformat()
                            kernel_cpu_seconds = kernel_ticks / 10_000_000
                            user_cpu_seconds = user_ticks / 10_000_000
                        else:
                            error_code = ctypes.get_last_error()
                            for field in (
                                "creation_time_utc",
                                "user_cpu_time_seconds",
                                "kernel_cpu_time_seconds",
                            ):
                                record_error(field, error_code)
                    finally:
                        if not close_handle(thread_handle):
                            error_code = ctypes.get_last_error()
                            key = (
                                "thread_handle",
                                f"CloseHandle failed with Windows error {error_code}.",
                            )
                            field_error_counts[key] = field_error_counts.get(key, 0) + 1

                return {
                    "owning_process_name": owner_name,
                    "current_priority": priority,
                    "creation_time_utc": creation_time_utc,
                    "user_cpu_time_seconds": user_cpu_seconds,
                    "kernel_cpu_time_seconds": kernel_cpu_seconds,
                    "collection_status": (
                        "partial" if unavailable else "completed"
                    ),
                }

            try:
                entry = ThreadEntry32()
                entry.dwSize = ctypes.sizeof(ThreadEntry32)
                has_entry = bool(thread_first(snapshot, ctypes.byref(entry)))
                error_code = 0 if has_entry else ctypes.get_last_error()

                while has_entry:
                    thread_id = int(entry.th32ThreadID)
                    owner_pid = int(entry.th32OwnerProcessID)
                    thread_record: dict[str, Any] = {
                        "thread_id": thread_id,
                        "owner_process_id": owner_pid,
                        "base_priority": int(entry.tpBasePri),
                    }
                    thread_record.update(
                        collect_thread_details(thread_id, owner_pid)
                    )
                    threads.append(thread_record)
                    entry.dwSize = ctypes.sizeof(ThreadEntry32)
                    has_entry = bool(thread_next(snapshot, ctypes.byref(entry)))
                    error_code = 0 if has_entry else ctypes.get_last_error()

                if error_code not in (0, 18):
                    _append_error(
                        errors,
                        None,
                        "thread_enumeration",
                        "WindowsAPIError",
                        f"Thread32First/Thread32Next stopped with Windows error {error_code}.",
                    )
                    enumeration_failed = True
            finally:
                if not close_handle(snapshot):
                    _append_error(
                        errors,
                        None,
                        "snapshot_handle",
                        "WindowsAPIError",
                        "CloseHandle failed for the Toolhelp thread snapshot.",
                    )

    for (field, reason), count in sorted(field_error_counts.items()):
        _append_error(
            errors,
            None,
            field,
            "ThreadQueryError",
            f"{reason} Affected thread count: {count}.",
        )

    finished_at = _utc_now()
    if enumeration_failed and not threads:
        outcome = "failed"
    elif errors:
        outcome = "partial"
    else:
        outcome = "completed"

    document: dict[str, Any] = {
        "schema_version": 1,
        "artifact": "A02 - System-wide Thread Snapshot",
        "source": "Windows Toolhelp thread snapshot",
        "method": "Read-only CreateToolhelp32Snapshot with TH32CS_SNAPTHREAD",
        **_collection_time_metadata(started_at, finished_at),
        "outcome": outcome,
        "thread_count": len(threads),
        "thread_field_definitions": {
            "base_priority": "Base priority reported by THREADENTRY32, in Windows priority levels.",
            "current_priority": (
                "Relative thread priority returned by GetThreadPriority; this is "
                "not a guaranteed instantaneous scheduler priority."
            ),
            "creation_time_utc": "Thread creation timestamp converted from Windows FILETIME to UTC.",
            "user_cpu_time_seconds": "Cumulative thread CPU time in user mode, in seconds.",
            "kernel_cpu_time_seconds": "Cumulative thread CPU time in kernel mode, in seconds.",
            "owning_process_name": "Process name joined by owner_process_id from the separate process snapshot.",
        },
        "not_collected_fields": {
            "thread_state": (
                "Not collected: the selected documented Toolhelp and thread timing "
                "APIs do not provide a supported thread-state inventory."
            ),
            "wait_reason": (
                "Not collected: determining wait reason requires a system-information "
                "interface outside the documented APIs used by this collector."
            ),
            "start_address": (
                "Not collected: this collector does not use undocumented thread "
                "information classes to query a start address."
            ),
            "context_switch_count": (
                "Not collected: per-thread context-switch counters are not provided "
                "by the documented APIs used by this collector."
            ),
        },
        "limitations": [
            "This is a point-in-time system-wide thread inventory; threads can start or exit during collection.",
            "Current-priority, creation-time, and CPU-time fields are best-effort queries and can be denied or fail if a thread exits during collection.",
            "Unavailable thread values are null; reasons and affected counts are summarized in collection_errors rather than repeated in each thread record.",
            "CPU time is cumulative and is not an instantaneous utilization measurement.",
            "The Toolhelp snapshot does not identify whether a thread is executing in user mode or kernel mode.",
            "This output is not a separate inventory of kernel-only processes or kernel-mode threads.",
        ],
        "collection_errors": errors,
        "threads": threads,
    }
    _write_json(destination, document, overwrite)
    return document


def collect_thread_snapshot(
    output_path: str | os.PathLike[str],
    overwrite: bool = False,
    process_names: dict[int, str | None] | None = None,
) -> dict[str, Any]:
    """Collect and save a separate read-only Windows system-wide thread snapshot."""
    return _collect_thread_snapshot(output_path, overwrite, process_names)


def _default_threads_path(processes_path: Path) -> Path:
    return processes_path.with_name(
        f"{processes_path.stem}_threads{processes_path.suffix or '.json'}"
    )


def collect_process_and_thread_snapshots(
    output_path: str | os.PathLike[str],
    threads_output_path: str | os.PathLike[str] | None = None,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Save process and system-wide thread inventories to separate JSON files."""
    processes_destination = Path(os.path.abspath(Path(output_path).expanduser()))
    if processes_destination.is_dir():
        output_stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        processes_destination = (
            processes_destination / f"processes_{output_stamp}.json"
        )
    threads_destination = (
        Path(os.path.abspath(Path(threads_output_path).expanduser()))
        if threads_output_path is not None
        else _default_threads_path(processes_destination)
    )
    if os.path.normcase(str(processes_destination)) == os.path.normcase(
        str(threads_destination)
    ):
        raise ValueError("Process and thread outputs must be different files.")
    if not overwrite:
        for destination in (processes_destination, threads_destination):
            if os.path.lexists(destination):
                raise FileExistsError(
                    f"Refusing to overwrite existing output: {destination}"
                )

    processes_document = collect_processes(processes_destination, overwrite)
    process_names = {
        int(record["pid"]): record.get("name")
        for record in processes_document["processes"]
        if record.get("pid") is not None
    }
    threads_document = collect_thread_snapshot(
        threads_destination,
        overwrite,
        process_names,
    )
    return {
        "processes": processes_document,
        "threads": threads_document,
        "processes_output": str(processes_destination),
        "threads_output": str(threads_destination),
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Collect separate read-only Windows process and system-wide thread "
            "snapshots as JSON. The thread snapshot does not identify kernel-mode "
            "execution."
        )
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Destination path for the process UTF-8 JSON output",
    )
    parser.add_argument(
        "--threads-output",
        help=(
            "Destination for the separate thread JSON; by default, the process "
            "filename gets a _threads suffix"
        ),
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Explicitly allow replacing an existing output file",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        documents = collect_process_and_thread_snapshots(
            args.output,
            args.threads_output,
            overwrite=args.overwrite,
        )
    except (OSError, ValueError) as exc:
        print(json.dumps({"outcome": "failed", "error": str(exc)}), file=sys.stderr)
        return 2

    processes_document = documents["processes"]
    threads_document = documents["threads"]
    outcomes = (processes_document["outcome"], threads_document["outcome"])
    overall_outcome = (
        "completed" if all(outcome == "completed" for outcome in outcomes) else "partial"
    )
    print(
        json.dumps(
            {
                "outcome": overall_outcome,
                "processes_outcome": processes_document["outcome"],
                "process_count": processes_document["process_count"],
                "processes_output": documents["processes_output"],
                "threads_outcome": threads_document["outcome"],
                "thread_count": threads_document["thread_count"],
                "threads_output": documents["threads_output"],
                "collection_errors": (
                    len(processes_document["collection_errors"])
                    + len(threads_document["collection_errors"])
                ),
            },
            ensure_ascii=True,
        )
    )
    return 0 if overall_outcome == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
