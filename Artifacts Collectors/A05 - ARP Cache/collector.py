"""Read the local Windows IPv4 neighbor table through IP Helper."""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import socket
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

AF_INET = 2
NO_ERROR = 0
ERROR_NOT_FOUND = 1168
IF_MAX_STRING_SIZE = 256
IF_MAX_PHYS_ADDRESS_LENGTH = 32

NEIGHBOR_STATES: dict[int, tuple[str, str]] = {
    0: ("Unreachable", "Windows reports the neighbor as unreachable."),
    1: (
        "Incomplete",
        "Address resolution is incomplete; the link-layer address may not yet be known.",
    ),
    2: (
        "Probe",
        "Windows is probing a neighbor whose reachability is not currently confirmed.",
    ),
    3: (
        "Delay",
        "Windows is delaying probes while awaiting reachability confirmation.",
    ),
    4: (
        "Stale",
        "The cached mapping is not currently confirmed as reachable.",
    ),
    5: ("Reachable", "Windows considers the neighbor recently reachable."),
    6: ("Permanent", "Windows reports a permanent neighbor entry."),
    7: (
        "Maximum",
        "Documented enum sentinel; Microsoft specifies this is not a legal row state.",
    ),
}


class _SockaddrIn(ctypes.Structure):
    _fields_ = [
        ("sin_family", ctypes.c_ushort),
        ("sin_port", ctypes.c_ushort),
        ("sin_addr", ctypes.c_ubyte * 4),
        ("sin_zero", ctypes.c_ubyte * 8),
    ]


class _SockaddrIn6(ctypes.Structure):
    _fields_ = [
        ("sin6_family", ctypes.c_ushort),
        ("sin6_port", ctypes.c_ushort),
        ("sin6_flowinfo", ctypes.c_uint32),
        ("sin6_addr", ctypes.c_ubyte * 16),
        ("sin6_scope_id", ctypes.c_uint32),
    ]


class SOCKADDR_INET(ctypes.Union):
    _fields_ = [
        ("Ipv4", _SockaddrIn),
        ("Ipv6", _SockaddrIn6),
        ("si_family", ctypes.c_ushort),
    ]


class _NetLuidInfo(ctypes.Structure):
    _fields_ = [
        ("Reserved", ctypes.c_uint64, 24),
        ("NetLuidIndex", ctypes.c_uint64, 24),
        ("IfType", ctypes.c_uint64, 16),
    ]


class NET_LUID(ctypes.Union):
    _fields_ = [("Value", ctypes.c_uint64), ("Info", _NetLuidInfo)]


class _NeighborFlagBits(ctypes.Structure):
    _fields_ = [
        ("IsRouter", ctypes.c_ubyte, 1),
        ("IsUnreachable", ctypes.c_ubyte, 1),
        ("Reserved", ctypes.c_ubyte, 6),
    ]


class _NeighborFlags(ctypes.Union):
    _fields_ = [("Flags", ctypes.c_ubyte), ("Bits", _NeighborFlagBits)]


class _ReachabilityTime(ctypes.Union):
    _fields_ = [
        ("LastReachable", ctypes.c_uint32),
        ("LastUnreachable", ctypes.c_uint32),
    ]


class MIB_IPNET_ROW2(ctypes.Structure):
    _anonymous_ = ("NeighborFlags", "ReachabilityTime")
    _fields_ = [
        ("Address", SOCKADDR_INET),
        ("InterfaceIndex", ctypes.c_uint32),
        ("InterfaceLuid", NET_LUID),
        ("PhysicalAddress", ctypes.c_ubyte * IF_MAX_PHYS_ADDRESS_LENGTH),
        ("PhysicalAddressLength", ctypes.c_uint32),
        ("State", ctypes.c_uint32),
        ("NeighborFlags", _NeighborFlags),
        ("ReachabilityTime", _ReachabilityTime),
    ]


class MIB_IPNET_TABLE2(ctypes.Structure):
    _fields_ = [
        ("NumEntries", ctypes.c_uint32),
        ("Table", MIB_IPNET_ROW2 * 1),
    ]


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_uint32),
        ("Data2", ctypes.c_uint16),
        ("Data3", ctypes.c_uint16),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class _InterfaceFlags(ctypes.Structure):
    _fields_ = [
        ("HardwareInterface", ctypes.c_ubyte, 1),
        ("FilterInterface", ctypes.c_ubyte, 1),
        ("ConnectorPresent", ctypes.c_ubyte, 1),
        ("NotAuthenticated", ctypes.c_ubyte, 1),
        ("NotMediaConnected", ctypes.c_ubyte, 1),
        ("Paused", ctypes.c_ubyte, 1),
        ("LowPower", ctypes.c_ubyte, 1),
        ("EndPointInterface", ctypes.c_ubyte, 1),
    ]


class MIB_IF_ROW2(ctypes.Structure):
    _anonymous_ = ("InterfaceAndOperStatusFlags",)
    _fields_ = [
        ("InterfaceLuid", NET_LUID),
        ("InterfaceIndex", ctypes.c_uint32),
        ("InterfaceGuid", GUID),
        ("Alias", ctypes.c_wchar * (IF_MAX_STRING_SIZE + 1)),
        ("Description", ctypes.c_wchar * (IF_MAX_STRING_SIZE + 1)),
        ("PhysicalAddressLength", ctypes.c_uint32),
        ("PhysicalAddress", ctypes.c_ubyte * IF_MAX_PHYS_ADDRESS_LENGTH),
        ("PermanentPhysicalAddress", ctypes.c_ubyte * IF_MAX_PHYS_ADDRESS_LENGTH),
        ("Mtu", ctypes.c_uint32),
        ("Type", ctypes.c_uint32),
        ("TunnelType", ctypes.c_uint32),
        ("MediaType", ctypes.c_uint32),
        ("PhysicalMediumType", ctypes.c_uint32),
        ("AccessType", ctypes.c_uint32),
        ("DirectionType", ctypes.c_uint32),
        ("InterfaceAndOperStatusFlags", _InterfaceFlags),
        ("OperStatus", ctypes.c_uint32),
        ("AdminStatus", ctypes.c_uint32),
        ("MediaConnectState", ctypes.c_uint32),
        ("NetworkGuid", GUID),
        ("ConnectionType", ctypes.c_uint32),
        ("TransmitLinkSpeed", ctypes.c_uint64),
        ("ReceiveLinkSpeed", ctypes.c_uint64),
        ("InOctets", ctypes.c_uint64),
        ("InUcastPkts", ctypes.c_uint64),
        ("InNUcastPkts", ctypes.c_uint64),
        ("InDiscards", ctypes.c_uint64),
        ("InErrors", ctypes.c_uint64),
        ("InUnknownProtos", ctypes.c_uint64),
        ("InUcastOctets", ctypes.c_uint64),
        ("InMulticastOctets", ctypes.c_uint64),
        ("InBroadcastOctets", ctypes.c_uint64),
        ("OutOctets", ctypes.c_uint64),
        ("OutUcastPkts", ctypes.c_uint64),
        ("OutNUcastPkts", ctypes.c_uint64),
        ("OutDiscards", ctypes.c_uint64),
        ("OutErrors", ctypes.c_uint64),
        ("OutUcastOctets", ctypes.c_uint64),
        ("OutMulticastOctets", ctypes.c_uint64),
        ("OutBroadcastOctets", ctypes.c_uint64),
        ("OutQLen", ctypes.c_uint64),
    ]


class NativeApiProtocol(Protocol):
    def get_ip_net_table2(self, family: int, table_out: Any) -> int: ...

    def free_mib_table(self, table: Any) -> None: ...

    def get_if_entry2(self, row: Any) -> int: ...


class NativeApi:
    """Thin bindings to documented Iphlpapi.dll functions."""

    def __init__(self) -> None:
        if os.name != "nt":
            raise OSError("The Windows IP Helper APIs are available only on Windows.")
        iphlpapi = ctypes.WinDLL("Iphlpapi.dll", use_last_error=True)
        self._get_ip_net_table2 = iphlpapi.GetIpNetTable2
        self._get_ip_net_table2.argtypes = [
            ctypes.c_ushort,
            ctypes.POINTER(ctypes.POINTER(MIB_IPNET_TABLE2)),
        ]
        self._get_ip_net_table2.restype = ctypes.c_uint32
        self._free_mib_table = iphlpapi.FreeMibTable
        self._free_mib_table.argtypes = [ctypes.c_void_p]
        self._free_mib_table.restype = None
        self._get_if_entry2 = iphlpapi.GetIfEntry2
        self._get_if_entry2.argtypes = [ctypes.POINTER(MIB_IF_ROW2)]
        self._get_if_entry2.restype = ctypes.c_uint32

    def get_ip_net_table2(self, family: int, table_out: Any) -> int:
        return int(self._get_ip_net_table2(family, table_out))

    def free_mib_table(self, table: Any) -> None:
        self._free_mib_table(ctypes.cast(table, ctypes.c_void_p))

    def get_if_entry2(self, row: Any) -> int:
        return int(self._get_if_entry2(row))


def utc_now() -> str:
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


def _windows_error_message(code: int) -> str:
    try:
        message = ctypes.FormatError(code).strip()
    except (AttributeError, OSError, ValueError):
        message = ""
    return message or f"Windows API returned error code {code}."


def verify_native_layout() -> dict[str, int]:
    """Check ctypes layout against the documented SDK field sequence."""
    expected = {
        "sockaddr_inet_size": 28,
        "neighbor_row_size": 88,
        "neighbor_row_interface_index_offset": 28,
        "neighbor_row_interface_luid_offset": 32,
        "neighbor_row_physical_address_offset": 40,
        "neighbor_row_physical_address_length_offset": 72,
        "neighbor_row_state_offset": 76,
        "neighbor_row_flags_offset": 80,
        "neighbor_row_reachability_offset": 84,
        "neighbor_table_rows_offset": 8,
        "net_luid_size": 8,
        "interface_row_size": 1352,
        "interface_alias_offset": 28,
        "interface_description_offset": 542,
        "interface_physical_address_length_offset": 1056,
        "interface_physical_address_offset": 1060,
        "interface_status_flags_offset": 1152,
    }
    actual = {
        "sockaddr_inet_size": ctypes.sizeof(SOCKADDR_INET),
        "neighbor_row_size": ctypes.sizeof(MIB_IPNET_ROW2),
        "neighbor_row_interface_index_offset": MIB_IPNET_ROW2.InterfaceIndex.offset,
        "neighbor_row_interface_luid_offset": MIB_IPNET_ROW2.InterfaceLuid.offset,
        "neighbor_row_physical_address_offset": MIB_IPNET_ROW2.PhysicalAddress.offset,
        "neighbor_row_physical_address_length_offset": (
            MIB_IPNET_ROW2.PhysicalAddressLength.offset
        ),
        "neighbor_row_state_offset": MIB_IPNET_ROW2.State.offset,
        "neighbor_row_flags_offset": MIB_IPNET_ROW2.NeighborFlags.offset,
        "neighbor_row_reachability_offset": MIB_IPNET_ROW2.ReachabilityTime.offset,
        "neighbor_table_rows_offset": MIB_IPNET_TABLE2.Table.offset,
        "net_luid_size": ctypes.sizeof(NET_LUID),
        "interface_row_size": ctypes.sizeof(MIB_IF_ROW2),
        "interface_alias_offset": MIB_IF_ROW2.Alias.offset,
        "interface_description_offset": MIB_IF_ROW2.Description.offset,
        "interface_physical_address_length_offset": (
            MIB_IF_ROW2.PhysicalAddressLength.offset
        ),
        "interface_physical_address_offset": MIB_IF_ROW2.PhysicalAddress.offset,
        "interface_status_flags_offset": (
            MIB_IF_ROW2.InterfaceAndOperStatusFlags.offset
        ),
    }
    if actual != expected:
        raise RuntimeError(
            f"Unexpected native structure layout: expected {expected}, got {actual}"
        )
    return actual


def normalize_neighbor_row(
    row: MIB_IPNET_ROW2,
    record_index: int,
    observed_at_utc: str,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Copy a native IPv4 neighbor row into JSON-safe values."""
    errors: list[dict[str, Any]] = []
    family = int(row.Address.si_family)
    ip_address: str | None = None
    address_raw_hex: str
    if family == AF_INET:
        address_bytes = bytes(row.Address.Ipv4.sin_addr)
        address_raw_hex = address_bytes.hex().upper()
        try:
            ip_address = socket.inet_ntop(socket.AF_INET, address_bytes)
        except OSError as exc:
            errors.append(
                {
                    "record_index": record_index,
                    "field": "neighbor_address_ipv4",
                    "error_type": "AddressDecodeError",
                    "message": str(exc),
                }
            )
    else:
        address_bytes = ctypes.string_at(
            ctypes.addressof(row.Address), ctypes.sizeof(SOCKADDR_INET)
        )
        address_raw_hex = address_bytes.hex().upper()
        errors.append(
            {
                "record_index": record_index,
                "field": "address_family",
                "error_type": "UnexpectedAddressFamily",
                "message": (
                    f"GetIpNetTable2(AF_INET) returned address family {family}; "
                    "row retained with raw address bytes."
                ),
            }
        )

    reported_length = int(row.PhysicalAddressLength)
    physical_bytes_available = min(reported_length, IF_MAX_PHYS_ADDRESS_LENGTH)
    physical_bytes = bytes(row.PhysicalAddress[:physical_bytes_available])
    field_availability: dict[str, dict[str, str]] = {}
    if reported_length > IF_MAX_PHYS_ADDRESS_LENGTH:
        errors.append(
            {
                "record_index": record_index,
                "field": "physical_address_bytes_hex",
                "error_type": "InvalidPhysicalAddressLength",
                "message": (
                    f"Provider reported {reported_length} bytes; the documented "
                    f"structure buffer holds at most {IF_MAX_PHYS_ADDRESS_LENGTH}. "
                    "All bytes available in the native structure are preserved."
                ),
            }
        )
        field_availability["physical_address_bytes_hex"] = {
            "status": "partial",
            "reason": "Reported length exceeds the native structure's fixed buffer.",
        }
    elif reported_length == 0:
        field_availability["mac_address"] = {
            "status": "unavailable",
            "reason": "The provider reported no physical-address bytes for this row.",
        }
    elif reported_length != 6:
        field_availability["mac_address"] = {
            "status": "unsupported",
            "reason": (
                "A colon-separated MAC address is formatted only for a six-byte "
                "physical address; the original bytes and length are retained."
            ),
        }

    state_value = int(row.State)
    state = NEIGHBOR_STATES.get(state_value)
    if state is None:
        field_availability["state_label"] = {
            "status": "unsupported",
            "reason": "Windows returned a state value not defined in the documented enum mapping.",
        }
    elif state_value == 7:
        field_availability["state_label"] = {
            "status": "unsupported",
            "reason": (
                "Maximum is a documented enum sentinel, but Microsoft specifies "
                "that it is not a legal neighbor-row state."
            ),
        }
        errors.append(
            {
                "record_index": record_index,
                "field": "neighbor_state_value",
                "error_type": "IllegalNeighborStateSentinel",
                "message": (
                    "Windows returned the documented NlnsMaximum sentinel, "
                    "which Microsoft specifies is not a legal row state."
                ),
            }
        )

    raw_flags = int(row.NeighborFlags.Flags)
    last_reachable = int(row.ReachabilityTime.LastReachable)
    reachability_member = None
    reachability_meaning = (
        "Raw value from the documented reachability-time union in milliseconds. "
        "The native row does not provide a discriminator identifying whether "
        "LastReachable or LastUnreachable is the applicable union member."
    )

    record = {
        "record_index": record_index,
        "observed_at_utc": observed_at_utc,
        "source_api": "GetIpNetTable2(AF_INET)",
        "address_family": "IPv4" if family == AF_INET else None,
        "address_family_value": family,
        "neighbor_address_ipv4": ip_address,
        "address_bytes_hex": address_raw_hex,
        "interface_index": int(row.InterfaceIndex),
        "interface_luid_decimal": str(int(row.InterfaceLuid.Value)),
        "interface_luid_hex": f"0x{int(row.InterfaceLuid.Value):016X}",
        "physical_address_length_reported": reported_length,
        "physical_address_bytes_hex": physical_bytes.hex().upper(),
        "mac_address": (
            ":".join(f"{byte:02X}" for byte in physical_bytes)
            if reported_length == 6 and len(physical_bytes) == 6
            else None
        ),
        "neighbor_state_value": state_value,
        "neighbor_state_label": state[0] if state else None,
        "neighbor_state_meaning": state[1] if state else None,
        "router_flag": bool(raw_flags & 0x01),
        "unreachable_flag": bool(raw_flags & 0x02),
        "flags_raw_hex": f"0x{raw_flags:02X}",
        "reachability_time_value_ms": last_reachable,
        "reachability_time_union_member": reachability_member,
        "reachability_time_meaning": reachability_meaning,
        "interface": None,
        "field_availability": field_availability,
        "field_errors": [],
        "collection_status": "partial" if errors or field_availability else "success",
    }
    if ip_address is None:
        record["field_availability"]["neighbor_address_ipv4"] = {
            "status": "unavailable",
            "reason": "No IPv4 address could be decoded from the returned address union.",
        }
    return record, errors


def acquire_ipv4_neighbor_rows(
    api: NativeApiProtocol,
    observed_at_utc: str,
) -> tuple[list[dict[str, Any]], dict[str, Any], list[dict[str, Any]]]:
    """Acquire and copy table rows, releasing the native buffer on every path."""
    table_pointer = ctypes.POINTER(MIB_IPNET_TABLE2)()
    status_code: int | None = None
    rows: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    status = "failed"
    try:
        status_code = int(api.get_ip_net_table2(AF_INET, ctypes.byref(table_pointer)))
        if status_code == ERROR_NOT_FOUND:
            status = "success"
        elif status_code != NO_ERROR:
            errors.append(
                {
                    "error_type": "GetIpNetTable2Failed",
                    "return_code": status_code,
                    "message": _windows_error_message(status_code),
                }
            )
        elif not table_pointer:
            errors.append(
                {
                    "error_type": "MalformedNativeResult",
                    "message": "GetIpNetTable2 returned NO_ERROR with a null table pointer.",
                }
            )
        else:
            table = table_pointer.contents
            count = int(table.NumEntries)
            if count > 1_000_000:
                errors.append(
                    {
                        "error_type": "MalformedNativeResult",
                        "message": f"Neighbor table reported an implausible row count: {count}.",
                    }
                )
            else:
                rows_address = ctypes.addressof(table) + MIB_IPNET_TABLE2.Table.offset
                row_size = ctypes.sizeof(MIB_IPNET_ROW2)
                for index in range(count):
                    try:
                        native_row = MIB_IPNET_ROW2.from_address(
                            rows_address + index * row_size
                        )
                        record, row_errors = normalize_neighbor_row(
                            native_row, index, observed_at_utc
                        )
                        rows.append(record)
                        errors.extend(row_errors)
                    except (ValueError, OSError, ctypes.ArgumentError) as exc:
                        errors.append(
                            {
                                "record_index": index,
                                "error_type": "NeighborRowReadError",
                                "message": str(exc),
                            }
                        )
                status = "partial" if errors else "success"
    except Exception as exc:
        errors.append(
            {
                "error_type": "NativeProviderException",
                "message": f"{type(exc).__name__}: {exc}",
            }
        )
        status = (
            "partial"
            if status in ("success", "partial") or rows
            else "failed"
        )
    finally:
        if table_pointer:
            try:
                api.free_mib_table(table_pointer)
            except Exception as exc:
                errors.append(
                    {
                        "error_type": "FreeMibTableFailed",
                        "message": f"{type(exc).__name__}: {exc}",
                    }
                )
                status = "partial" if rows else "failed"

    if status == "success" and errors:
        status = "partial"
    provider = {
        "provider": "Windows IP Helper",
        "api": "GetIpNetTable2(AF_INET)",
        "status": status,
        "return_code": status_code,
        "rows_returned": len(rows),
        "scope": (
            "IPv4 neighbor entries returned by the local IP Helper provider for "
            "interfaces visible to this process."
        ),
        "errors": errors.copy(),
    }
    return rows, provider, errors


def _guid_string(value: GUID) -> str:
    raw = ctypes.string_at(ctypes.addressof(value), ctypes.sizeof(GUID))
    return str(uuid.UUID(bytes_le=raw))


def enrich_interfaces(
    records: list[dict[str, Any]],
    api: NativeApiProtocol,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Look up each distinct LUID/index once and attach cached interface details."""
    cache: dict[tuple[str, int], dict[str, Any]] = {}
    errors: list[dict[str, Any]] = []
    for record in records:
        luid = int(record["interface_luid_decimal"])
        index = int(record["interface_index"])
        cache_key = ("luid", luid) if luid else ("index", index)
        interface = cache.get(cache_key)
        if interface is None:
            row = MIB_IF_ROW2()
            if luid:
                row.InterfaceLuid.Value = luid
            else:
                row.InterfaceIndex = index
            try:
                return_code = int(api.get_if_entry2(ctypes.byref(row)))
            except Exception as exc:
                return_code = -1
                message = f"{type(exc).__name__}: {exc}"
            else:
                message = _windows_error_message(return_code) if return_code else ""

            if return_code == NO_ERROR:
                interface = {
                    "interface_index": int(row.InterfaceIndex),
                    "interface_luid_decimal": str(int(row.InterfaceLuid.Value)),
                    "interface_luid_hex": f"0x{int(row.InterfaceLuid.Value):016X}",
                    "interface_guid": _guid_string(row.InterfaceGuid),
                    "interface_alias": row.Alias,
                    "interface_description": row.Description,
                    "lookup_status": "success",
                    "field_errors": {},
                }
            else:
                interface = {
                    "interface_index": index,
                    "interface_luid_decimal": str(luid),
                    "interface_luid_hex": f"0x{luid:016X}",
                    "interface_guid": None,
                    "interface_alias": None,
                    "interface_description": None,
                    "lookup_status": "failed",
                    "field_errors": {
                        "interface_alias": message,
                        "interface_description": message,
                        "interface_guid": message,
                    },
                }
                errors.append(
                    {
                        "interface_index": index,
                        "interface_luid_decimal": str(luid),
                        "error_type": "GetIfEntry2Failed",
                        "return_code": return_code,
                        "message": message,
                    }
                )
            cache[cache_key] = interface

        record["interface"] = interface.copy()
        if interface["lookup_status"] != "success":
            record["field_errors"].append(
                {
                    "field": "interface",
                    "error_type": "InterfaceEnrichmentFailed",
                    "message": (
                        "Neighbor row retained; interface alias, description, "
                        "and GUID could not be resolved."
                    ),
                }
            )
            record["collection_status"] = "partial"

    return list(cache.values()), errors


def _write_json(destination: Path, document: dict[str, Any], overwrite: bool) -> None:
    if not destination.parent.is_dir():
        raise FileNotFoundError(
            f"Output directory does not exist: {destination.parent}"
        )
    if not overwrite and os.path.lexists(destination):
        raise FileExistsError(f"Refusing to overwrite existing output: {destination}")

    temporary_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            prefix=f".{destination.name}.",
            suffix=".tmp",
            dir=destination.parent,
            delete=False,
        ) as handle:
            temporary_path = handle.name
            handle.write("{\n")
            items = list(document.items())
            for item_index, (key, value) in enumerate(items):
                if item_index:
                    handle.write(",\n")
                handle.write(f"  {json.dumps(key, ensure_ascii=False)}: ")
                if key in ("neighbors", "interfaces", "errors") and isinstance(
                    value, list
                ):
                    handle.write("[\n")
                    for index, item in enumerate(value):
                        if index:
                            handle.write(",\n\n\n")
                        encoded = json.dumps(
                            item, ensure_ascii=False, indent=2
                        )
                        handle.write(
                            "\n".join(f"    {line}" for line in encoded.splitlines())
                        )
                    if value:
                        handle.write("\n")
                    handle.write("  ]")
                else:
                    encoded = json.dumps(value, ensure_ascii=False, indent=2)
                    handle.write(
                        "\n".join(f"  {line}" for line in encoded.splitlines())
                    )
            handle.write("\n}\n")
            handle.flush()
            os.fsync(handle.fileno())
        if overwrite:
            os.replace(temporary_path, destination)
        else:
            os.rename(temporary_path, destination)
        temporary_path = None
    finally:
        if temporary_path is not None:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass


def _resolve_output_path(output_path: str | os.PathLike[str]) -> Path:
    raw = os.fspath(output_path)
    requested = Path(os.path.abspath(Path(raw).expanduser()))
    if requested.is_dir():
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return requested / f"A05_arp_cache_{timestamp}.json"
    if raw.endswith((os.sep, os.altsep) if os.altsep else (os.sep,)):
        raise FileNotFoundError(f"Output directory does not exist: {requested}")
    return requested


def collect_arp_cache(
    output_path: str | os.PathLike[str],
    overwrite: bool = False,
    api: NativeApiProtocol | None = None,
) -> dict[str, Any]:
    """Collect and save an IPv4 neighbor-table snapshot."""
    started_at = utc_now()
    destination = _resolve_output_path(output_path)
    if not overwrite and os.path.lexists(destination):
        raise FileExistsError(f"Refusing to overwrite existing output: {destination}")
    if not destination.parent.is_dir():
        raise FileNotFoundError(
            f"Output directory does not exist: {destination.parent}"
        )

    errors: list[dict[str, Any]] = []
    providers: list[dict[str, Any]] = []
    records: list[dict[str, Any]] = []
    interface_records: list[dict[str, Any]] = []
    native_api = api
    if native_api is None:
        try:
            verify_native_layout()
            native_api = NativeApi()
        except Exception as exc:
            providers.append(
                {
                    "provider": "Windows IP Helper",
                    "api": "GetIpNetTable2(AF_INET)",
                    "status": "failed",
                    "return_code": None,
                    "rows_returned": 0,
                    "scope": "IPv4 neighbor table only.",
                    "errors": [
                        {
                            "error_type": "ProviderUnavailable",
                            "message": f"{type(exc).__name__}: {exc}",
                        }
                    ],
                }
            )
            errors.append(providers[-1]["errors"][0])

    if native_api is not None:
        observation_time = utc_now()
        records, provider_result, acquisition_errors = acquire_ipv4_neighbor_rows(
            native_api, observation_time
        )
        providers.append(provider_result)
        errors.extend(acquisition_errors)
        if provider_result["status"] != "failed":
            interface_records, interface_errors = enrich_interfaces(
                records, native_api
            )
            errors.extend(interface_errors)
            providers.append(
                {
                    "provider": "Windows IP Helper",
                    "api": "GetIfEntry2",
                    "status": "partial" if interface_errors else "success",
                    "lookups_attempted": len(interface_records),
                    "errors": interface_errors,
                    "scope": (
                        "Read-only interface alias, description, and GUID lookup "
                        "cached once per distinct interface LUID (or index when "
                        "LUID is zero)."
                    ),
                }
            )

    status = "failed"
    if any(provider.get("status") in ("success", "partial") for provider in providers):
        status = "partial" if errors or any(
            provider.get("status") == "partial" for provider in providers
        ) or any(record["collection_status"] == "partial" for record in records) else "success"

    timestamps = _collection_time_metadata(started_at, utc_now())
    document = {
        "schema_version": 1,
        "artifact": "A05",
        "artifact_name": "ARP Cache",
        "source": "Local Windows IPv4 neighbor table",
        **timestamps,
        "collection_status": status,
        "provider": "Windows IP Helper API",
        "collection_scope": (
            "GetIpNetTable2(AF_INET) returns IPv4 neighbor rows visible to the "
            "local collection process. IPv6 neighbor discovery is excluded."
        ),
        "deduplication": (
            "No records are deduplicated. The native table's rows are preserved "
            "individually; interface index and LUID remain part of each record's "
            "identity."
        ),
        "neighbor_count": len(records),
        "interface_count": len(interface_records),
        "providers_attempted": providers,
        "interfaces": interface_records,
        "limitations": [
            "This is a live snapshot of rows returned by Windows; entries can change during or immediately after collection.",
            "The provider does not promise expired entries, historical ARP traffic, or remote devices' neighbor caches.",
            "Collection visibility is limited to network compartments/interfaces visible to this API call and process; administrator access does not guarantee every compartment or field.",
            "A physical address can be missing or have a length other than six bytes. Raw bytes and reported length are retained; a formatted MAC is produced only for six bytes.",
            "Reachability-time values are Windows durations in milliseconds, not entry creation times, last packet times, or history.",
            "No hostnames, manufacturers, processes, users, traffic counters, or remote-device identities are collected.",
            "IPv6 neighbor discovery is intentionally outside A05's IPv4 ARP scope.",
            "The collector performs read-only table/interface queries; it does not flush or modify entries, request address resolution, ping, scan, or perform DNS lookups.",
        ],
        "errors": errors,
        "neighbors": records,
    }
    if status == "failed":
        document["errors"].append(
            {
                "error_type": "NeighborEnumerationFailed",
                "message": (
                    "IPv4 neighbor-table enumeration failed; an empty neighbor "
                    "array is not reported as a successful empty snapshot."
                ),
            }
        )
    _write_json(destination, document, overwrite)
    return document


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Collect a read-only snapshot of the local Windows IPv4 ARP cache."
    )
    parser.add_argument(
        "--output",
        required=True,
        help=(
            "Output JSON file path, or an existing folder to receive a "
            "timestamped JSON file"
        ),
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Explicitly permit replacing an existing output file",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        destination = _resolve_output_path(args.output)
        document = collect_arp_cache(destination, overwrite=args.overwrite)
    except (OSError, ValueError, RuntimeError) as exc:
        print(
            json.dumps(
                {"artifact": "A05", "collection_status": "failed", "error": str(exc)},
                ensure_ascii=False,
            ),
            file=sys.stderr,
        )
        return 2

    print(
        json.dumps(
            {
                "artifact": "A05",
                "collection_status": document["collection_status"],
                "neighbor_count": document["neighbor_count"],
                "interface_count": document["interface_count"],
                "error_count": len(document["errors"]),
                "output": str(destination),
            },
            ensure_ascii=False,
        )
    )
    return {"success": 0, "partial": 1, "failed": 2}[
        document["collection_status"]
    ]


if __name__ == "__main__":
    raise SystemExit(main())
