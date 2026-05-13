#!/usr/bin/env python3
import argparse
import json
import math
import os
import struct
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from elftools.dwarf.dwarf_expr import DWARFExprParser
from elftools.elf.elffile import ELFFile

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except AttributeError:
    pass


ENCODING_MAP = {
    0x01: "address",
    0x02: "boolean",
    0x03: "complex_float",
    0x04: "float",
    0x05: "signed",
    0x06: "signed_char",
    0x07: "unsigned",
    0x08: "unsigned_char",
}

SCALAR_ENCODINGS = {
    "float",
    "signed",
    "signed_char",
    "unsigned",
    "unsigned_char",
    "boolean",
    "address",
    "pointer",
}

SCALAR_KINDS = {"base", "typedef", "enum", "pointer"}


def decode_bytes(value):
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value


def attr(die, name: str):
    value = die.attributes.get(name)
    if value is None:
        return None
    return decode_bytes(value.value)


def source_path_from_parts(
    *,
    comp_dir: Optional[str],
    directory: Optional[str],
    file_name: Optional[str],
) -> Optional[str]:
    if not file_name:
        return None
    file_name = decode_bytes(file_name)
    directory = decode_bytes(directory) if directory else None
    comp_dir = decode_bytes(comp_dir) if comp_dir else None
    if os.path.isabs(str(file_name)):
        return str(file_name)
    if directory:
        directory_text = str(directory)
        if os.path.isabs(directory_text):
            return os.path.normpath(os.path.join(directory_text, str(file_name)))
        if comp_dir:
            return os.path.normpath(os.path.join(str(comp_dir), directory_text, str(file_name)))
        return os.path.normpath(os.path.join(directory_text, str(file_name)))
    if comp_dir:
        return os.path.normpath(os.path.join(str(comp_dir), str(file_name)))
    return str(file_name)


def compile_unit_source_path(cu) -> Optional[str]:
    top_die = cu.get_top_DIE()
    return source_path_from_parts(
        comp_dir=attr(top_die, "DW_AT_comp_dir"),
        directory=None,
        file_name=attr(top_die, "DW_AT_name"),
    )


def die_decl_source(dwarf_info, cu, die, fallback: Optional[str]) -> Optional[str]:
    file_index = attr(die, "DW_AT_decl_file")
    if not isinstance(file_index, int):
        return fallback
    try:
        line_program = dwarf_info.line_program_for_CU(cu)
    except Exception:
        return fallback
    if line_program is None:
        return fallback
    header = line_program.header
    file_entries = header.get("file_entry") or []
    if not file_entries:
        return fallback
    entry_index = file_index - 1 if file_index > 0 else file_index
    if entry_index < 0 or entry_index >= len(file_entries):
        return fallback
    entry = file_entries[entry_index]
    include_dirs = header.get("include_directory") or []
    comp_dir = attr(cu.get_top_DIE(), "DW_AT_comp_dir")
    directory = None
    dir_index = getattr(entry, "dir_index", None)
    if isinstance(dir_index, int) and dir_index > 0:
        include_index = dir_index - 1
        if 0 <= include_index < len(include_dirs):
            directory = include_dirs[include_index]
    return source_path_from_parts(
        comp_dir=comp_dir,
        directory=directory,
        file_name=getattr(entry, "name", None),
    ) or fallback


def die_decl_line(die) -> Optional[int]:
    line = attr(die, "DW_AT_decl_line")
    return line if isinstance(line, int) and line > 0 else None


def get_type_die(die):
    try:
        return die.get_DIE_from_attribute("DW_AT_type")
    except Exception:
        return None


def get_array_dims(array_die) -> List[int]:
    dims = []
    for child in array_die.iter_children():
        if child.tag != "DW_TAG_subrange_type":
            continue
        count = attr(child, "DW_AT_count")
        if isinstance(count, int):
            dims.append(count)
            continue
        lower = attr(child, "DW_AT_lower_bound")
        upper = attr(child, "DW_AT_upper_bound")
        if lower is None:
            lower = 0
        if isinstance(lower, int) and isinstance(upper, int):
            dims.append(upper - lower + 1)
    return dims


def unwrap_type_die(type_die, depth: int = 0):
    current = type_die
    while current is not None and depth <= 32:
        if current.tag not in (
            "DW_TAG_typedef",
            "DW_TAG_const_type",
            "DW_TAG_volatile_type",
            "DW_TAG_restrict_type",
        ):
            return current
        next_die = get_type_die(current)
        if next_die is None:
            return current
        current = next_die
        depth += 1
    return current


def resolve_type(type_die, depth: int = 0) -> Dict[str, Any]:
    if type_die is None or depth > 32:
        return {
            "type": "<unknown>",
            "size": None,
            "kind": "unknown",
            "encoding": None,
        }

    tag = type_die.tag
    name = attr(type_die, "DW_AT_name")
    size = attr(type_die, "DW_AT_byte_size")

    if tag == "DW_TAG_typedef":
        inner = resolve_type(get_type_die(type_die), depth + 1)
        if name:
            inner["type"] = name
        inner["kind"] = "typedef"
        return inner

    if tag in ("DW_TAG_const_type", "DW_TAG_volatile_type", "DW_TAG_restrict_type"):
        inner = resolve_type(get_type_die(type_die), depth + 1)
        prefix = {
            "DW_TAG_const_type": "const",
            "DW_TAG_volatile_type": "volatile",
            "DW_TAG_restrict_type": "restrict",
        }[tag]
        inner["type"] = f"{prefix} {inner['type']}"
        return inner

    if tag == "DW_TAG_base_type":
        encoding_raw = attr(type_die, "DW_AT_encoding")
        encoding = ENCODING_MAP.get(encoding_raw, str(encoding_raw))
        return {
            "type": name or f"<base:{encoding}>",
            "size": size,
            "kind": "base",
            "encoding": encoding,
        }

    if tag == "DW_TAG_pointer_type":
        target = resolve_type(get_type_die(type_die), depth + 1)
        pointer_size = size
        if pointer_size is None:
            try:
                pointer_size = type_die.cu["address_size"]
            except Exception:
                pointer_size = None
        return {
            "type": f"{target['type']} *",
            "size": pointer_size,
            "kind": "pointer",
            "encoding": "pointer",
        }

    if tag == "DW_TAG_array_type":
        elem = resolve_type(get_type_die(type_die), depth + 1)
        dims = get_array_dims(type_die)
        type_name = elem["type"]
        for dim in dims:
            type_name += f"[{dim}]"
        total_size = size
        if total_size is None and elem["size"] is not None and dims:
            total_size = elem["size"]
            for dim in dims:
                total_size *= dim
        return {
            "type": type_name,
            "size": total_size,
            "kind": "array",
            "encoding": "array",
        }

    if tag == "DW_TAG_structure_type":
        return {
            "type": f"struct {name}" if name else "anonymous struct",
            "size": size,
            "kind": "struct",
            "encoding": "struct",
        }

    if tag == "DW_TAG_union_type":
        return {
            "type": f"union {name}" if name else "anonymous union",
            "size": size,
            "kind": "union",
            "encoding": "union",
        }

    if tag == "DW_TAG_enumeration_type":
        return {
            "type": f"enum {name}" if name else "anonymous enum",
            "size": size,
            "kind": "enum",
            "encoding": "enum",
        }

    return {
        "type": name or tag,
        "size": size,
        "kind": tag,
        "encoding": None,
    }


def scalar_read_type_info(type_die, depth: int = 0) -> Optional[Dict[str, Any]]:
    if type_die is None or depth > 32:
        return None
    concrete_type = unwrap_type_die(type_die)
    if concrete_type is None:
        return None
    if concrete_type.tag == "DW_TAG_array_type":
        return scalar_read_type_info(get_type_die(concrete_type), depth + 1)
    type_info = resolve_type(type_die)
    kind = str(type_info.get("kind") or "").lower()
    encoding = str(type_info.get("encoding") or "").lower()
    size = type_info.get("size")
    if not isinstance(size, int) or size <= 0:
        return None
    if encoding in SCALAR_ENCODINGS or kind in SCALAR_KINDS:
        return type_info
    return None


def pointer_size_for_type(pointer_type_die) -> Optional[int]:
    concrete_type = unwrap_type_die(pointer_type_die)
    if concrete_type is None or concrete_type.tag != "DW_TAG_pointer_type":
        return None
    pointer_size = attr(concrete_type, "DW_AT_byte_size")
    if pointer_size is None:
        try:
            pointer_size = concrete_type.cu["address_size"]
        except Exception:
            pointer_size = None
    return pointer_size if isinstance(pointer_size, int) and pointer_size > 0 else None


def pointer_target_type_die(pointer_type_die):
    concrete_type = unwrap_type_die(pointer_type_die)
    if concrete_type is None or concrete_type.tag != "DW_TAG_pointer_type":
        return None
    return get_type_die(concrete_type)


def get_member_offset(dwarf_info, member_die) -> Optional[int]:
    location = member_die.attributes.get("DW_AT_data_member_location")
    if location is None:
        return 0
    value = decode_bytes(location.value)
    if isinstance(value, int):
        return value
    parser = DWARFExprParser(dwarf_info.structs)
    try:
        ops = parser.parse_expr(location.value)
    except Exception:
        return None
    if not ops:
        return 0
    if len(ops) == 1:
        op = ops[0]
        if op.op_name in ("DW_OP_plus_uconst", "DW_OP_constu", "DW_OP_consts"):
            return int(op.args[0])
        if op.op_name.startswith("DW_OP_lit"):
            try:
                return int(op.op_name.replace("DW_OP_lit", ""))
            except ValueError:
                return None
    return None


def make_variable_item(
    *,
    name: str,
    type_info: Dict[str, Any],
    address: int,
    scope: str,
    source: Optional[str],
    line: Optional[int] = None,
    is_static: Optional[bool] = None,
    read_info: Optional[Dict[str, Any]] = None,
    read_mode: Optional[str] = None,
    read_offset: Optional[int] = None,
    pointer_size: Optional[int] = None,
) -> Dict[str, Any]:
    item = {
        "name": name,
        "type": type_info["type"],
        "address": f"0x{address:08X}",
        "size": type_info["size"],
        "scope": scope,
        "kind": type_info["kind"],
        "encoding": type_info["encoding"],
        "source": source,
    }
    if line is not None:
        item["line"] = line
    if is_static is not None:
        item["isStatic"] = is_static
    if read_info is not None:
        item["readSize"] = read_info.get("size")
        item["readKind"] = read_info.get("kind")
        item["readEncoding"] = read_info.get("encoding")
    if read_mode:
        item["readMode"] = read_mode
    if read_offset is not None:
        item["readOffset"] = read_offset
    if pointer_size is not None:
        item["pointerSize"] = pointer_size
    return item


def read_info_for_variable(type_die, type_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    kind = str(type_info.get("kind") or "").lower()
    encoding = str(type_info.get("encoding") or "").lower()
    if kind == "array" or encoding == "array":
        return scalar_read_type_info(type_die)
    return None


def expand_struct_fields(
    dwarf_info,
    cu,
    type_die,
    *,
    base_name: str,
    base_address: int,
    source: Optional[str],
    line: Optional[int],
    is_static: bool,
    depth: int = 0,
    visited: Optional[Set[int]] = None,
) -> List[Dict[str, Any]]:
    if type_die is None or depth > 8:
        return []
    visited = visited or set()
    concrete_type = unwrap_type_die(type_die)
    if concrete_type is None or concrete_type.tag != "DW_TAG_structure_type":
        return []
    offset = concrete_type.offset
    if offset in visited:
        return []
    visited = {*visited, offset}

    fields: List[Dict[str, Any]] = []
    anonymous_index = 0
    for child in concrete_type.iter_children():
        if child.tag != "DW_TAG_member":
            continue
        member_name = attr(child, "DW_AT_name")
        if not member_name:
            anonymous_index += 1
            member_name = f"<anonymous_{anonymous_index}>"
        member_offset = get_member_offset(dwarf_info, child)
        member_type_die = get_type_die(child)
        member_type_info = resolve_type(member_type_die)
        member_read_info = read_info_for_variable(member_type_die, member_type_info)
        member_address = base_address + (member_offset or 0)
        field_name = f"{base_name}.{member_name}"
        member_source = die_decl_source(dwarf_info, cu, child, source)
        member_line = die_decl_line(child) or line

        if member_offset is None or child.attributes.get("DW_AT_bit_size") is not None:
            unsupported_type = {
                **member_type_info,
                "kind": "bitfield",
                "encoding": "bitfield",
            }
            fields.append(
                make_variable_item(
                    name=field_name,
                    type_info=unsupported_type,
                    address=member_address,
                    scope="struct_field",
                    source=member_source,
                    line=member_line,
                    is_static=is_static,
                )
            )
            continue

        fields.append(
            make_variable_item(
                name=field_name,
                type_info=member_type_info,
                address=member_address,
                scope="struct_field",
                source=member_source,
                line=member_line,
                is_static=is_static,
                read_info=member_read_info,
            )
        )

        concrete_member_type = unwrap_type_die(member_type_die)
        if (
            concrete_member_type is not None
            and concrete_member_type.tag == "DW_TAG_structure_type"
        ):
            fields.extend(
                expand_struct_fields(
                    dwarf_info,
                    cu,
                    concrete_member_type,
                    base_name=field_name,
                    base_address=member_address,
                    source=member_source,
                    line=member_line,
                    is_static=is_static,
                    depth=depth + 1,
                    visited=visited,
                )
            )
    return fields


def expand_pointer_struct_fields(
    dwarf_info,
    cu,
    pointer_type_die,
    *,
    base_name: str,
    pointer_address: int,
    source: Optional[str],
    line: Optional[int],
    is_static: bool,
) -> List[Dict[str, Any]]:
    pointer_size = pointer_size_for_type(pointer_type_die)
    target_type_die = pointer_target_type_die(pointer_type_die)
    if pointer_size is None or target_type_die is None:
        return []
    return _expand_indirect_struct_fields(
        dwarf_info,
        target_type_die,
        cu=cu,
        base_name=base_name,
        pointer_address=pointer_address,
        pointer_size=pointer_size,
        source=source,
        line=line,
        is_static=is_static,
    )


def expand_pointer_deref_value(
    pointer_type_die,
    *,
    base_name: str,
    pointer_address: int,
    source: Optional[str],
    line: Optional[int],
    is_static: bool,
) -> List[Dict[str, Any]]:
    pointer_size = pointer_size_for_type(pointer_type_die)
    target_type_die = pointer_target_type_die(pointer_type_die)
    if pointer_size is None or target_type_die is None:
        return []
    read_info = scalar_read_type_info(target_type_die)
    if read_info is None:
        return []
    return [
        make_variable_item(
            name=f"*{base_name}",
            type_info=read_info,
            address=pointer_address,
            scope="pointer_deref",
            source=source,
            line=line,
            is_static=is_static,
            read_mode="indirect",
            read_offset=0,
            pointer_size=pointer_size,
        )
    ]


def _expand_indirect_struct_fields(
    dwarf_info,
    type_die,
    *,
    cu,
    base_name: str,
    pointer_address: int,
    pointer_size: int,
    source: Optional[str],
    line: Optional[int],
    is_static: bool,
    base_offset: int = 0,
    depth: int = 0,
    visited: Optional[Set[int]] = None,
) -> List[Dict[str, Any]]:
    if type_die is None or depth > 8:
        return []
    visited = visited or set()
    concrete_type = unwrap_type_die(type_die)
    if concrete_type is None or concrete_type.tag != "DW_TAG_structure_type":
        return []
    offset = concrete_type.offset
    if offset in visited:
        return []
    visited = {*visited, offset}

    fields: List[Dict[str, Any]] = []
    anonymous_index = 0
    for child in concrete_type.iter_children():
        if child.tag != "DW_TAG_member":
            continue
        member_name = attr(child, "DW_AT_name")
        if not member_name:
            anonymous_index += 1
            member_name = f"<anonymous_{anonymous_index}>"
        member_offset = get_member_offset(dwarf_info, child)
        member_type_die = get_type_die(child)
        member_type_info = resolve_type(member_type_die)
        member_read_info = read_info_for_variable(member_type_die, member_type_info)
        read_offset = base_offset + (member_offset or 0)
        field_name = (
            f"{base_name}->{member_name}"
            if depth == 0
            else f"{base_name}.{member_name}"
        )
        member_source = die_decl_source(dwarf_info, cu, child, source)
        member_line = die_decl_line(child) or line

        if member_offset is None or child.attributes.get("DW_AT_bit_size") is not None:
            unsupported_type = {
                **member_type_info,
                "kind": "bitfield",
                "encoding": "bitfield",
            }
            fields.append(
                make_variable_item(
                    name=field_name,
                    type_info=unsupported_type,
                    address=pointer_address,
                    scope="pointer_field",
                    source=member_source,
                    line=member_line,
                    is_static=is_static,
                    read_mode="indirect",
                    read_offset=read_offset,
                    pointer_size=pointer_size,
                )
            )
            continue

        fields.append(
            make_variable_item(
                name=field_name,
                type_info=member_type_info,
                address=pointer_address,
                scope="pointer_field",
                source=member_source,
                line=member_line,
                is_static=is_static,
                read_info=member_read_info,
                read_mode="indirect",
                read_offset=read_offset,
                pointer_size=pointer_size,
            )
        )

        concrete_member_type = unwrap_type_die(member_type_die)
        if (
            concrete_member_type is not None
            and concrete_member_type.tag == "DW_TAG_structure_type"
        ):
            fields.extend(
                _expand_indirect_struct_fields(
                    dwarf_info,
                    concrete_member_type,
                    cu=cu,
                    base_name=field_name,
                    pointer_address=pointer_address,
                    pointer_size=pointer_size,
                    source=member_source,
                    line=member_line,
                    is_static=is_static,
                    base_offset=read_offset,
                    depth=depth + 1,
                    visited=visited,
                )
            )
    return fields


def get_variable_address(dwarf_info, die) -> Optional[int]:
    location = die.attributes.get("DW_AT_location")
    if location is None:
        return None
    parser = DWARFExprParser(dwarf_info.structs)
    try:
        ops = parser.parse_expr(location.value)
    except Exception:
        return None
    stack: List[int] = []
    for op in ops:
        if op.op_name == "DW_OP_addr":
            stack.append(int(op.args[0]))
        elif op.op_name in {"DW_OP_constu", "DW_OP_consts"}:
            stack.append(int(op.args[0]))
        elif op.op_name == "DW_OP_plus_uconst":
            if not stack:
                return None
            stack[-1] += int(op.args[0])
        elif op.op_name == "DW_OP_plus":
            if len(stack) < 2:
                return None
            right = stack.pop()
            left = stack.pop()
            stack.append(left + right)
        elif op.op_name == "DW_OP_minus":
            if len(stack) < 2:
                return None
            right = stack.pop()
            left = stack.pop()
            stack.append(left - right)
        else:
            return None
    return stack[-1] if len(stack) == 1 else None


def parse_axf_globals(axf_path: str, only_external: bool = False) -> List[Dict[str, Any]]:
    result = []
    with open(axf_path, "rb") as handle:
        elf = ELFFile(handle)
        if not elf.has_dwarf_info():
            raise RuntimeError("这个 AXF 没有 DWARF 调试信息，无法可靠获取变量类型。")
        dwarf_info = elf.get_dwarf_info()
        for cu in dwarf_info.iter_CUs():
            source_file = compile_unit_source_path(cu)
            for die in cu.iter_DIEs():
                if die.tag != "DW_TAG_variable":
                    continue
                name = attr(die, "DW_AT_name")
                if not name:
                    continue
                address = get_variable_address(dwarf_info, die)
                if address is None:
                    continue
                is_external = bool(attr(die, "DW_AT_external"))
                if only_external and not is_external:
                    continue
                is_static = not is_external
                variable_source = die_decl_source(dwarf_info, cu, die, source_file)
                variable_line = die_decl_line(die)
                type_die = get_type_die(die)
                type_info = resolve_type(type_die)
                read_info = read_info_for_variable(type_die, type_info)
                scope = "global" if is_external else "static_global"
                result.append(
                    make_variable_item(
                        name=name,
                        type_info=type_info,
                        address=address,
                        scope=scope,
                        source=variable_source,
                        line=variable_line,
                        is_static=is_static,
                        read_info=read_info,
                    )
                )
                result.extend(
                    expand_struct_fields(
                        dwarf_info,
                        cu,
                        type_die,
                        base_name=name,
                        base_address=address,
                        source=variable_source,
                        line=variable_line,
                        is_static=is_static,
                    )
                )
                result.extend(
                    expand_pointer_deref_value(
                        type_die,
                        base_name=name,
                        pointer_address=address,
                        source=variable_source,
                        line=variable_line,
                        is_static=is_static,
                    )
                )
                result.extend(
                    expand_pointer_struct_fields(
                        dwarf_info,
                        cu,
                        type_die,
                        base_name=name,
                        pointer_address=address,
                        source=variable_source,
                        line=variable_line,
                        is_static=is_static,
                    )
                )
    result.sort(key=lambda item: (int(item["address"], 16), item["name"]))
    return result


def emit(payload: Dict[str, Any]) -> None:
    print(json.dumps(payload, ensure_ascii=True), flush=True)


def debug(message: str) -> None:
    emit({"type": "debug", "message": message})


def read_config(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def connect_session(config: Dict[str, Any]):
    from pyocd.core.helpers import ConnectHelper

    target = str(config.get("target") or "").strip()
    probe = str(config.get("probe") or "").strip() or None
    packs = [
        str(item).strip()
        for item in config.get("packs", [])
        if str(item).strip()
    ]
    options: Dict[str, Any] = {
        "connect_mode": "attach",
        "cache.enable_memory": False,
        "cache.enable_register": False,
    }
    if packs:
        options["pack"] = packs
    debug(
        "connect_session "
        f"target={target or ''} probe={probe or ''} packs={len(packs)} "
        f"options={options}"
    )
    return ConnectHelper.session_with_chosen_probe(
        unique_id=probe,
        target_override=target or None,
        options=options,
    )


def _unsigned_from_bytes(data: bytes) -> int:
    return int.from_bytes(data, byteorder="little", signed=False)


def _signed_from_bytes(data: bytes) -> int:
    return int.from_bytes(data, byteorder="little", signed=True)


def _read_int(value, default: int = 0) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return default
        try:
            return int(text, 0)
        except ValueError:
            return default
    return default


def decode_value(variable: Dict[str, Any], data: bytes) -> float:
    encoding = str(variable.get("readEncoding") or variable.get("encoding") or "").lower()
    kind = str(variable.get("readKind") or variable.get("kind") or "").lower()
    size = _read_int(variable.get("readSize") or variable.get("size"), len(data))
    if not data or size <= 0:
        return math.nan
    data = data[:size]
    if encoding == "float":
        if size == 4:
            return float(struct.unpack("<f", data[:4])[0])
        if size == 8:
            return float(struct.unpack("<d", data[:8])[0])
        return math.nan
    if encoding in {"signed", "signed_char"}:
        return float(_signed_from_bytes(data))
    if encoding in {"unsigned", "unsigned_char", "address", "pointer"} or kind in {
        "pointer",
        "enum",
    }:
        return float(_unsigned_from_bytes(data))
    if encoding == "boolean":
        return 1.0 if _unsigned_from_bytes(data) != 0 else 0.0
    return math.nan


def _read_variable_data(target, variable: Dict[str, Any]) -> Optional[bytes]:
    mode = str(variable.get("readMode") or "direct").lower()
    name = variable.get("name") or ""
    if mode == "indirect":
        pointer_address = _read_int(variable.get("address"))
        pointer_size = max(1, _read_int(variable.get("pointerSize"), 4))
        try:
            pointer_data = bytes(target.read_memory_block8(pointer_address, pointer_size))
        except Exception as exc:
            debug(
                "read pointer failed "
                f"name={name} address=0x{pointer_address:X} "
                f"size={pointer_size} error={exc}"
            )
            raise
        target_address = _unsigned_from_bytes(pointer_data)
        if target_address == 0:
            return None
        address = target_address + _read_int(variable.get("readOffset"))
    else:
        address = _read_int(variable.get("address"))
    size = max(1, _read_int(variable.get("readSize") or variable.get("size"), 1))
    try:
        return bytes(target.read_memory_block8(address, size))
    except Exception as exc:
        debug(
            "read failed "
            f"name={name} address=0x{address:X} size={size} error={exc}"
        )
        raise


def read_once(target, variables: List[Dict[str, Any]]) -> List[float]:
    values: List[float] = []
    for variable in variables:
        data = _read_variable_data(target, variable)
        values.append(math.nan if data is None else decode_value(variable, data))
    return values


def run_reader(config_path: str) -> int:
    config = read_config(config_path)
    variables = list(config.get("variables") or [])
    period_ms = max(1, int(config.get("periodMs") or 100))
    if not variables:
        emit({"type": "error", "message": "没有可读取变量"})
        return 2

    session = None
    sample_count = 0
    try:
        debug(
            "reader config "
            f"target={config.get('target') or ''} probe={config.get('probe') or ''} "
            f"periodMs={period_ms} variables={len(variables)}"
        )
        for variable in variables:
            debug(
                "reader variable "
                f"name={variable.get('name') or ''} "
                f"address=0x{int(variable.get('address') or 0):X} "
                f"size={variable.get('size') or ''} "
                f"type={variable.get('type') or ''} "
                f"kind={variable.get('kind') or ''} "
                f"encoding={variable.get('encoding') or ''}"
            )
        session = connect_session(config)
        debug("session created")
        debug("session open start")
        session.open()
        debug("session open done")
        target = session.target
        emit({"type": "status", "message": "变量读取已连接"})
        interval = period_ms / 1000.0
        next_time = time.monotonic()
        while True:
            now = time.monotonic()
            if now < next_time:
                time.sleep(min(0.02, next_time - now))
                continue
            scheduled_time = next_time
            next_time = max(next_time + interval, now)
            sample_count += 1
            read_start = time.monotonic()
            values = read_once(target, variables)
            read_elapsed_ms = (time.monotonic() - read_start) * 1000.0
            lag_ms = max(0.0, (read_start - scheduled_time) * 1000.0)
            if sample_count <= 5 or sample_count % 100 == 0:
                debug(
                    f"sample count={sample_count} values={values[:8]} "
                    f"readMs={read_elapsed_ms:.3f} lagMs={lag_ms:.3f}"
                )
            emit(
                {
                    "type": "sample",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "values": values,
                    "readMs": read_elapsed_ms,
                    "lagMs": lag_ms,
                }
            )
    except KeyboardInterrupt:
        debug("keyboard interrupt")
        return 0
    except Exception as exc:
        debug(f"reader exception type={type(exc).__name__} message={exc}")
        emit({"type": "error", "message": str(exc)})
        return 1
    finally:
        try:
            if session is not None:
                debug("session close start")
                session.close()
                debug("session close done")
        except Exception:
            pass
    return 0


def run_list(axf_path: str, *, output: Optional[str], only_external: bool) -> int:
    variables = parse_axf_globals(axf_path, only_external=only_external)
    text = json.dumps(variables, ensure_ascii=False, indent=2)
    if output:
        with open(output, "w", encoding="utf-8") as handle:
            handle.write(text)
        print(f"saved: {output}")
    else:
        print(text)
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "read":
        parser = argparse.ArgumentParser(
            prog="axf_json.py read",
            description="Attach with pyOCD and stream selected variable samples.",
        )
        parser.add_argument("--config", required=True)
        args = parser.parse_args(argv[1:])
        return run_reader(args.config)

    if argv and argv[0] == "list":
        parser = argparse.ArgumentParser(
            prog="axf_json.py list",
            description="List AXF/ELF variables from DWARF debug information.",
        )
        parser.add_argument("axf", help="Keil .axf/.elf file path")
        parser.add_argument("-o", "--output")
        parser.add_argument("--only-external", action="store_true")
        args = parser.parse_args(argv[1:])
        return run_list(
            args.axf,
            output=args.output,
            only_external=args.only_external,
        )

    # Keep the original one-shot CLI working: `python axf_json.py app.axf`.
    parser = argparse.ArgumentParser()
    parser.add_argument("axf", help="Keil .axf/.elf file path")
    parser.add_argument("-o", "--output")
    parser.add_argument("--only-external", action="store_true")
    args = parser.parse_args(argv)
    return run_list(args.axf, output=args.output, only_external=args.only_external)


if __name__ == "__main__":
    raise SystemExit(main())
