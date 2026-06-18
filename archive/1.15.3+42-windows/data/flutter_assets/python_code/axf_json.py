#!/usr/bin/env python3
import argparse
import json
import math
import os
import struct
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, NamedTuple, Optional, Set, Tuple

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

AXF_BINARY_MAGIC = b"BAXFVAR1"
AXF_BINARY_VERSION = 1
AXF_BINARY_NULL_STRING_ID = 0xFFFFFFFF
AXF_BINARY_NULL_READ_OFFSET = -0x80000000
AXF_BINARY_FLAG_HAS_STATIC = 0x0001
AXF_BINARY_FLAG_STATIC_TRUE = 0x0002
AXF_BINARY_RECORD_STRUCT = struct.Struct("<IIIIIIIIIQIIiIHH")

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

_CACHE_MISS = object()
_TYPE_INFO_CACHE: Dict[int, Dict[str, Any]] = {}
_UNWRAP_TYPE_CACHE: Dict[int, Any] = {}
_LINE_PROGRAM_CACHE: Dict[int, Any] = {}
_EXPR_PARSER_CACHE: Dict[int, DWARFExprParser] = {}
_STRUCT_FIELD_TEMPLATE_CACHE: Dict[int, Tuple["StructFieldTemplate", ...]] = {}
_STRUCT_FIELD_TEMPLATE_CACHE_HITS = 0
_STRUCT_FIELD_TEMPLATE_CACHE_MISSES = 0


class StructFieldTemplate(NamedTuple):
    suffix: str
    offset: int
    type_info: Dict[str, Any]
    read_info: Optional[Dict[str, Any]]
    source: Optional[str]
    line: Optional[int]


def trace_timing(enabled: bool, message: str) -> None:
    if not enabled:
        return
    print(
        f"[axf-json-timing {datetime.now(timezone.utc).isoformat()}] {message}",
        file=sys.stderr,
        flush=True,
    )


def elapsed_ms(start: float) -> float:
    return (time.perf_counter() - start) * 1000.0


def add_elapsed(stats: Dict[str, float], key: str, start: float) -> None:
    stats[key] = stats.get(key, 0.0) + elapsed_ms(start)


def die_cache_key(die) -> Optional[int]:
    offset = getattr(die, "offset", None)
    return offset if isinstance(offset, int) else None


def decode_bytes(value):
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value


def attr(die, name: str):
    value = die.attributes.get(name)
    if value is None:
        return None
    return decode_bytes(value.value)


def line_program_for_cu_cached(dwarf_info, cu):
    key = getattr(cu, "cu_offset", None)
    if not isinstance(key, int):
        return dwarf_info.line_program_for_CU(cu)
    if key not in _LINE_PROGRAM_CACHE:
        _LINE_PROGRAM_CACHE[key] = dwarf_info.line_program_for_CU(cu)
    return _LINE_PROGRAM_CACHE[key]


def expr_parser_for_dwarf(dwarf_info) -> DWARFExprParser:
    key = id(dwarf_info.structs)
    parser = _EXPR_PARSER_CACHE.get(key)
    if parser is None:
        parser = DWARFExprParser(dwarf_info.structs)
        _EXPR_PARSER_CACHE[key] = parser
    return parser


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
        line_program = line_program_for_cu_cached(dwarf_info, cu)
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
    cache_key = die_cache_key(type_die) if depth == 0 else None
    if cache_key is not None:
        cached = _UNWRAP_TYPE_CACHE.get(cache_key, _CACHE_MISS)
        if cached is not _CACHE_MISS:
            return cached
    current = type_die
    while current is not None and depth <= 32:
        if current.tag not in (
            "DW_TAG_typedef",
            "DW_TAG_const_type",
            "DW_TAG_volatile_type",
            "DW_TAG_restrict_type",
        ):
            if cache_key is not None:
                _UNWRAP_TYPE_CACHE[cache_key] = current
            return current
        next_die = get_type_die(current)
        if next_die is None:
            if cache_key is not None:
                _UNWRAP_TYPE_CACHE[cache_key] = current
            return current
        current = next_die
        depth += 1
    if cache_key is not None:
        _UNWRAP_TYPE_CACHE[cache_key] = current
    return current


def resolve_type(type_die, depth: int = 0) -> Dict[str, Any]:
    cache_key = die_cache_key(type_die) if depth <= 32 else None
    if cache_key is not None:
        cached = _TYPE_INFO_CACHE.get(cache_key)
        if cached is not None:
            return dict(cached)
    result = _resolve_type_uncached(type_die, depth)
    if cache_key is not None:
        _TYPE_INFO_CACHE[cache_key] = dict(result)
    return result


def _resolve_type_uncached(type_die, depth: int = 0) -> Dict[str, Any]:
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
    parser = expr_parser_for_dwarf(dwarf_info)
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


def encode_variables_binary(variables: List[Dict[str, Any]]) -> Tuple[bytes, int]:
    string_ids: Dict[str, int] = {}
    strings: List[str] = []

    def intern(value: Any) -> int:
        if value is None:
            return AXF_BINARY_NULL_STRING_ID
        text = str(value).strip()
        if not text:
            return AXF_BINARY_NULL_STRING_ID
        existing = string_ids.get(text)
        if existing is not None:
            return existing
        string_id = len(strings)
        string_ids[text] = string_id
        strings.append(text)
        return string_id

    records = []
    for item in variables:
        address = _address_int(item.get("address"))
        read_offset = item.get("readOffset")
        if read_offset is None:
            normalized_read_offset = AXF_BINARY_NULL_READ_OFFSET
        else:
            try:
                normalized_read_offset = int(read_offset)
            except (TypeError, ValueError):
                normalized_read_offset = AXF_BINARY_NULL_READ_OFFSET
        pointer_size = item.get("pointerSize")
        if pointer_size is None:
            normalized_pointer_size = 0
        else:
            try:
                normalized_pointer_size = max(0, min(0xFFFF, int(pointer_size)))
            except (TypeError, ValueError):
                normalized_pointer_size = 0
        flags = 0
        is_static = item.get("isStatic")
        if is_static is not None:
            flags |= AXF_BINARY_FLAG_HAS_STATIC
            if bool(is_static):
                flags |= AXF_BINARY_FLAG_STATIC_TRUE
        records.append(
            AXF_BINARY_RECORD_STRUCT.pack(
                intern(item.get("name")),
                intern(item.get("type")),
                intern(item.get("scope")),
                intern(item.get("kind")),
                intern(item.get("encoding")),
                intern(item.get("source")),
                intern(item.get("readMode")),
                intern(item.get("readKind")),
                intern(item.get("readEncoding")),
                address,
                int(item.get("size") or 0),
                int(item.get("readSize") or 0),
                normalized_read_offset,
                int(item.get("line") or 0),
                normalized_pointer_size,
                flags,
            )
        )

    output = bytearray()
    output.extend(AXF_BINARY_MAGIC)
    output.extend(struct.pack("<HHI", AXF_BINARY_VERSION, 0, len(strings)))
    for text in strings:
        encoded = text.encode("utf-8")
        output.extend(struct.pack("<I", len(encoded)))
        output.extend(encoded)
    output.extend(struct.pack("<I", len(records)))
    output.extend(b"".join(records))
    return bytes(output), len(strings)


def read_info_for_variable(type_die, type_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    kind = str(type_info.get("kind") or "").lower()
    encoding = str(type_info.get("encoding") or "").lower()
    if kind == "array" or encoding == "array":
        return scalar_read_type_info(type_die)
    return None


def _struct_field_templates(
    dwarf_info,
    cu,
    type_die,
    *,
    depth: int = 0,
    visited: Optional[Set[int]] = None,
) -> Tuple[StructFieldTemplate, ...]:
    global _STRUCT_FIELD_TEMPLATE_CACHE_HITS
    global _STRUCT_FIELD_TEMPLATE_CACHE_MISSES
    if type_die is None or depth > 8:
        return ()
    visited = visited or set()
    concrete_type = unwrap_type_die(type_die)
    if concrete_type is None or concrete_type.tag != "DW_TAG_structure_type":
        return ()
    offset = die_cache_key(concrete_type)
    if offset is None:
        return ()
    if offset in visited:
        return ()
    cached = _STRUCT_FIELD_TEMPLATE_CACHE.get(offset)
    if cached is not None:
        _STRUCT_FIELD_TEMPLATE_CACHE_HITS += 1
        return cached
    _STRUCT_FIELD_TEMPLATE_CACHE_MISSES += 1
    visited = {*visited, offset}

    templates: List[StructFieldTemplate] = []
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
        member_relative_offset = member_offset or 0
        child_cu = getattr(child, "cu", cu)
        member_source = die_decl_source(dwarf_info, child_cu, child, None)
        member_line = die_decl_line(child)

        if member_offset is None or child.attributes.get("DW_AT_bit_size") is not None:
            unsupported_type = {
                **member_type_info,
                "kind": "bitfield",
                "encoding": "bitfield",
            }
            templates.append(
                StructFieldTemplate(
                    suffix=f".{member_name}",
                    offset=member_relative_offset,
                    type_info=unsupported_type,
                    read_info=None,
                    source=member_source,
                    line=member_line,
                )
            )
            continue

        templates.append(
            StructFieldTemplate(
                suffix=f".{member_name}",
                offset=member_relative_offset,
                type_info=member_type_info,
                read_info=member_read_info,
                source=member_source,
                line=member_line,
            )
        )

        concrete_member_type = unwrap_type_die(member_type_die)
        if (
            concrete_member_type is not None
            and concrete_member_type.tag == "DW_TAG_structure_type"
        ):
            nested_templates = _struct_field_templates(
                dwarf_info,
                child_cu,
                concrete_member_type,
                depth=depth + 1,
                visited=visited,
            )
            for nested in nested_templates:
                templates.append(
                    nested._replace(
                        suffix=f".{member_name}{nested.suffix}",
                        offset=member_relative_offset + nested.offset,
                        source=nested.source or member_source,
                        line=nested.line or member_line,
                    )
                )
    result = tuple(templates)
    _STRUCT_FIELD_TEMPLATE_CACHE[offset] = result
    return result


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
) -> List[Dict[str, Any]]:
    templates = _struct_field_templates(dwarf_info, cu, type_die)
    if not templates:
        return []
    return [
        make_variable_item(
            name=f"{base_name}{template.suffix}",
            type_info=template.type_info,
            address=base_address + template.offset,
            scope="struct_field",
            source=template.source or source,
            line=template.line or line,
            is_static=is_static,
            read_info=template.read_info,
        )
        for template in templates
    ]


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
    templates = _struct_field_templates(dwarf_info, cu, target_type_die)
    if not templates:
        return []
    return [
        make_variable_item(
            name=f"{base_name}->{template.suffix[1:]}",
            type_info=template.type_info,
            address=pointer_address,
            scope="pointer_field",
            source=template.source or source,
            line=template.line or line,
            is_static=is_static,
            read_info=template.read_info,
            read_mode="indirect",
            read_offset=template.offset,
            pointer_size=pointer_size,
        )
        for template in templates
    ]


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


def get_variable_address(dwarf_info, die) -> Optional[int]:
    location = die.attributes.get("DW_AT_location")
    if location is None:
        return None
    parser = expr_parser_for_dwarf(dwarf_info)
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


def parse_axf_globals(
    axf_path: str,
    only_external: bool = False,
    trace: bool = False,
) -> List[Dict[str, Any]]:
    total_start = time.perf_counter()
    stats: Dict[str, float] = {
        "cuCount": 0.0,
        "dieCount": 0.0,
        "variableDieCount": 0.0,
        "acceptedVariableCount": 0.0,
        "expandedVariableCount": 0.0,
        "missingNameCount": 0.0,
        "missingAddressCount": 0.0,
        "externalFilteredCount": 0.0,
    }
    result = []
    open_start = time.perf_counter()
    with open(axf_path, "rb") as handle:
        add_elapsed(stats, "openMs", open_start)
        elf_start = time.perf_counter()
        elf = ELFFile(handle)
        add_elapsed(stats, "elfInitMs", elf_start)
        dwarf_check_start = time.perf_counter()
        if not elf.has_dwarf_info():
            raise RuntimeError("这个 AXF 没有 DWARF 调试信息，无法可靠获取变量类型。")
        add_elapsed(stats, "dwarfCheckMs", dwarf_check_start)
        dwarf_start = time.perf_counter()
        dwarf_info = elf.get_dwarf_info()
        add_elapsed(stats, "getDwarfInfoMs", dwarf_start)
        cu_scan_start = time.perf_counter()
        for cu in dwarf_info.iter_CUs():
            stats["cuCount"] += 1.0
            source_file: Optional[str] = None
            source_file_computed = False

            def cu_source_file() -> Optional[str]:
                nonlocal source_file
                nonlocal source_file_computed
                if source_file_computed:
                    return source_file
                source_start = time.perf_counter()
                source_file = compile_unit_source_path(cu)
                source_file_computed = True
                add_elapsed(stats, "cuSourceMs", source_start)
                return source_file

            die_iter_start = time.perf_counter()
            for die in cu.iter_DIEs():
                stats["dieCount"] += 1.0
                if die.tag != "DW_TAG_variable":
                    continue
                stats["variableDieCount"] += 1.0
                name = attr(die, "DW_AT_name")
                if not name:
                    stats["missingNameCount"] += 1.0
                    continue
                address_start = time.perf_counter()
                address = get_variable_address(dwarf_info, die)
                add_elapsed(stats, "addressMs", address_start)
                if address is None:
                    stats["missingAddressCount"] += 1.0
                    continue
                is_external = bool(attr(die, "DW_AT_external"))
                if only_external and not is_external:
                    stats["externalFilteredCount"] += 1.0
                    continue
                is_static = not is_external
                decl_source_start = time.perf_counter()
                variable_source = die_decl_source(dwarf_info, cu, die, cu_source_file())
                variable_line = die_decl_line(die)
                add_elapsed(stats, "declSourceMs", decl_source_start)
                type_die = get_type_die(die)
                type_start = time.perf_counter()
                type_info = resolve_type(type_die)
                read_info = read_info_for_variable(type_die, type_info)
                add_elapsed(stats, "typeMs", type_start)
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
                stats["acceptedVariableCount"] += 1.0
                expand_start = time.perf_counter()
                expanded_struct = expand_struct_fields(
                    dwarf_info,
                    cu,
                    type_die,
                    base_name=name,
                    base_address=address,
                    source=variable_source,
                    line=variable_line,
                    is_static=is_static,
                )
                add_elapsed(stats, "expandStructMs", expand_start)
                result.extend(expanded_struct)
                stats["expandedVariableCount"] += float(len(expanded_struct))
                expand_start = time.perf_counter()
                expanded_pointer_value = expand_pointer_deref_value(
                    type_die,
                    base_name=name,
                    pointer_address=address,
                    source=variable_source,
                    line=variable_line,
                    is_static=is_static,
                )
                add_elapsed(stats, "expandPointerValueMs", expand_start)
                result.extend(expanded_pointer_value)
                stats["expandedVariableCount"] += float(len(expanded_pointer_value))
                expand_start = time.perf_counter()
                expanded_pointer_struct = expand_pointer_struct_fields(
                    dwarf_info,
                    cu,
                    type_die,
                    base_name=name,
                    pointer_address=address,
                    source=variable_source,
                    line=variable_line,
                    is_static=is_static,
                )
                add_elapsed(stats, "expandPointerStructMs", expand_start)
                result.extend(expanded_pointer_struct)
                stats["expandedVariableCount"] += float(len(expanded_pointer_struct))
            add_elapsed(stats, "dieIterMs", die_iter_start)
        add_elapsed(stats, "cuScanMs", cu_scan_start)
    sort_start = time.perf_counter()
    result.sort(key=lambda item: (int(item["address"], 16), item["name"]))
    add_elapsed(stats, "sortMs", sort_start)
    trace_timing(
        trace,
        "parse "
        f"path={axf_path} "
        f"variables={len(result)} "
        f"cus={int(stats['cuCount'])} "
        f"dies={int(stats['dieCount'])} "
        f"variableDies={int(stats['variableDieCount'])} "
        f"accepted={int(stats['acceptedVariableCount'])} "
        f"expanded={int(stats['expandedVariableCount'])} "
        f"missingName={int(stats['missingNameCount'])} "
        f"missingAddress={int(stats['missingAddressCount'])} "
        f"externalFiltered={int(stats['externalFilteredCount'])} "
        f"structTemplateCacheHits={_STRUCT_FIELD_TEMPLATE_CACHE_HITS} "
        f"structTemplateCacheMisses={_STRUCT_FIELD_TEMPLATE_CACHE_MISSES} "
        f"structTemplateCacheSize={len(_STRUCT_FIELD_TEMPLATE_CACHE)} "
        f"open={stats.get('openMs', 0.0):.2f}ms "
        f"elfInit={stats.get('elfInitMs', 0.0):.2f}ms "
        f"dwarfCheck={stats.get('dwarfCheckMs', 0.0):.2f}ms "
        f"getDwarfInfo={stats.get('getDwarfInfoMs', 0.0):.2f}ms "
        f"cuSource={stats.get('cuSourceMs', 0.0):.2f}ms "
        f"dieIter={stats.get('dieIterMs', 0.0):.2f}ms "
        f"address={stats.get('addressMs', 0.0):.2f}ms "
        f"declSource={stats.get('declSourceMs', 0.0):.2f}ms "
        f"type={stats.get('typeMs', 0.0):.2f}ms "
        f"expandStruct={stats.get('expandStructMs', 0.0):.2f}ms "
        f"expandPointerValue={stats.get('expandPointerValueMs', 0.0):.2f}ms "
        f"expandPointerStruct={stats.get('expandPointerStructMs', 0.0):.2f}ms "
        f"sort={stats.get('sortMs', 0.0):.2f}ms "
        f"total={elapsed_ms(total_start):.2f}ms",
    )
    return result


def _address_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return 0
        try:
            return int(text, 0)
        except ValueError:
            return 0
    return 0


def _die_function_name(die) -> str:
    return (
        attr(die, "DW_AT_linkage_name")
        or attr(die, "DW_AT_MIPS_linkage_name")
        or attr(die, "DW_AT_name")
        or "<unknown>"
    )


def _die_high_pc(die, low_pc: int) -> Optional[int]:
    high_attr = die.attributes.get("DW_AT_high_pc")
    if high_attr is None:
        return None
    high_value = decode_bytes(high_attr.value)
    if not isinstance(high_value, int):
        return None
    if high_attr.form == "DW_FORM_addr":
        return high_value
    return low_pc + high_value


def collect_axf_symbols(
    axf_path: str,
) -> Tuple[List[Tuple[int, int]], List[Dict[str, Any]]]:
    code_ranges: List[Tuple[int, int]] = []
    functions: List[Dict[str, Any]] = []
    with open(axf_path, "rb") as handle:
        elf = ELFFile(handle)
        for section in elf.iter_sections():
            try:
                flags = int(section["sh_flags"])
                address = int(section["sh_addr"])
                size = int(section["sh_size"])
            except Exception:
                continue
            if address <= 0 or size <= 0:
                continue
            # SHF_EXECINSTR = 0x4. These ranges are enough to reject stack
            # words that are clearly not return addresses.
            if flags & 0x4:
                code_ranges.append((address, address + size))

        if elf.has_dwarf_info():
            dwarf_info = elf.get_dwarf_info()
            for cu in dwarf_info.iter_CUs():
                source_file = compile_unit_source_path(cu)
                for die in cu.iter_DIEs():
                    if die.tag != "DW_TAG_subprogram":
                        continue
                    low_pc = attr(die, "DW_AT_low_pc")
                    if not isinstance(low_pc, int) or low_pc <= 0:
                        continue
                    high_pc = _die_high_pc(die, low_pc)
                    if not isinstance(high_pc, int) or high_pc <= low_pc:
                        high_pc = low_pc + 1
                    functions.append(
                        {
                            "name": _die_function_name(die),
                            "start": low_pc,
                            "end": high_pc,
                            "source": die_decl_source(
                                dwarf_info,
                                cu,
                                die,
                                source_file,
                            ),
                            "line": die_decl_line(die),
                        }
                    )

        symtab = elf.get_section_by_name(".symtab")
        if symtab is not None:
            for symbol in symtab.iter_symbols():
                try:
                    if symbol["st_info"]["type"] != "STT_FUNC":
                        continue
                    address = int(symbol["st_value"])
                    size = int(symbol["st_size"])
                except Exception:
                    continue
                if address <= 0:
                    continue
                name = decode_bytes(symbol.name) or "<unknown>"
                functions.append(
                    {
                        "name": str(name),
                        "start": address,
                        "end": address + max(1, size),
                        "source": None,
                        "line": None,
                    }
                )

    code_ranges.sort()
    functions.sort(key=lambda item: (int(item["start"]), int(item["end"])))
    return code_ranges, functions


def _is_code_address(address: int, code_ranges: List[Tuple[int, int]]) -> bool:
    address &= ~1
    for start, end in code_ranges:
        if start <= address < end:
            return True
        if start > address:
            break
    return False


def _symbolize_address(
    address: int,
    functions: List[Dict[str, Any]],
) -> Dict[str, Any]:
    normalized = address & ~1
    best: Optional[Dict[str, Any]] = None
    for function in functions:
        start = int(function.get("start") or 0)
        end = int(function.get("end") or start + 1)
        if start <= normalized < end:
            best = function
            break
        if start > normalized:
            break
    if best is None:
        return {
            "function": "<unknown>",
            "offset": None,
            "source": None,
            "line": None,
        }
    start = int(best.get("start") or normalized)
    return {
        "function": best.get("name") or "<unknown>",
        "offset": max(0, normalized - start),
        "source": best.get("source"),
        "line": best.get("line"),
    }


def _read_core_register_int(target, name: str) -> int:
    try:
        return int(target.read_core_register(name))
    except Exception:
        return 0


def _target_is_running_state(state: Any) -> bool:
    name = getattr(state, "name", str(state)).upper()
    return name in {"RUNNING", "SLEEPING", "RESET"}


def _make_stack_frame(
    *,
    index: int,
    address: int,
    kind: str,
    functions: List[Dict[str, Any]],
) -> Dict[str, Any]:
    symbol = _symbolize_address(address, functions)
    return {
        "index": index,
        "address": f"0x{(address & ~1):08X}",
        "function": symbol["function"],
        "offset": symbol["offset"],
        "source": symbol["source"],
        "line": symbol["line"],
        "kind": kind,
    }


def read_stack_backtrace(config: Dict[str, Any]) -> Dict[str, Any]:
    axf_path = str(config.get("axfPath") or "").strip()
    if not axf_path:
        raise RuntimeError("No AXF selected")
    stack_words = max(16, min(512, int(config.get("stackWords") or 128)))
    max_frames = max(4, min(64, int(config.get("maxFrames") or 32)))

    session = None
    was_running = False
    registers: Dict[str, int] = {}
    stack_words_data: List[int] = []
    stack_base = 0
    read_error: Optional[str] = None
    try:
        session = connect_session(config)
        session.open()
        target = session.target
        try:
            state = target.get_state()
        except Exception:
            state = None
        was_running = _target_is_running_state(state)
        target.halt()
        pc = _read_core_register_int(target, "pc")
        lr = _read_core_register_int(target, "lr")
        sp = _read_core_register_int(target, "sp")
        msp = _read_core_register_int(target, "msp")
        psp = _read_core_register_int(target, "psp")
        xpsr = _read_core_register_int(target, "xpsr")
        registers = {
            "pc": pc,
            "lr": lr,
            "sp": sp,
            "msp": msp,
            "psp": psp,
            "xpsr": xpsr,
        }
        stack_base = sp & ~0x3
        if stack_base > 0:
            stack_words_data = list(target.read_memory_block32(stack_base, stack_words))
    except Exception as exc:
        read_error = str(exc)
        raise
    finally:
        try:
            if session is not None and was_running:
                session.target.resume()
        except Exception:
            pass

    # Symbolization is deliberately after resume so the MCU is not held halted
    # while local AXF/DWARF parsing runs.
    code_ranges, functions = collect_axf_symbols(axf_path)
    frames: List[Dict[str, Any]] = []
    seen: Set[int] = set()

    def add_candidate(raw_address: int, kind: str) -> None:
        if len(frames) >= max_frames:
            return
        normalized = raw_address & ~1
        if normalized <= 0 or normalized in seen:
            return
        if kind == "stack" and not _is_code_address(normalized, code_ranges):
            return
        if normalized >= 0xFFFFFF00:
            return
        seen.add(normalized)
        frames.append(
            _make_stack_frame(
                index=len(frames),
                address=normalized,
                kind=kind,
                functions=functions,
            )
        )

    add_candidate(registers.get("pc", 0), "pc")
    add_candidate(registers.get("lr", 0), "lr")
    for word in stack_words_data:
        add_candidate(int(word), "stack")

    return {
        "type": "stack",
        "wasRunning": was_running,
        "registers": {
            key: f"0x{value:08X}" for key, value in registers.items()
        },
        "stackBase": f"0x{stack_base:08X}",
        "stackWords": len(stack_words_data),
        "frames": frames,
        "error": read_error,
    }


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


def _read_variable_data(target, variable: Dict[str, Any]) -> Tuple[Optional[bytes], bool]:
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
            return None, True
        address = target_address + _read_int(variable.get("readOffset"))
    else:
        address = _read_int(variable.get("address"))
    size = max(1, _read_int(variable.get("readSize") or variable.get("size"), 1))
    try:
        return bytes(target.read_memory_block8(address, size)), False
    except Exception as exc:
        debug(
            "read failed "
            f"name={name} address=0x{address:X} size={size} error={exc}"
        )
        raise


def read_once(target, variables: List[Dict[str, Any]]) -> Tuple[List[float], List[int]]:
    values: List[float] = []
    null_pointer_indices: List[int] = []
    for index, variable in enumerate(variables):
        data, is_null_pointer = _read_variable_data(target, variable)
        if is_null_pointer:
            null_pointer_indices.append(index)
        values.append(math.nan if data is None else decode_value(variable, data))
    return values, null_pointer_indices


def _json_sample_values(values: List[float]) -> List[Optional[float]]:
    return [value if math.isfinite(value) else None for value in values]


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
            values, null_pointer_indices = read_once(target, variables)
            read_elapsed_ms = (time.monotonic() - read_start) * 1000.0
            lag_ms = max(0.0, (read_start - scheduled_time) * 1000.0)
            if sample_count <= 5 or sample_count % 100 == 0:
                debug(
                    f"sample count={sample_count} values={values[:8]} "
                    f"nullPointers={null_pointer_indices[:8]} "
                    f"readMs={read_elapsed_ms:.3f} lagMs={lag_ms:.3f}"
                )
            emit(
                {
                    "type": "sample",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "values": _json_sample_values(values),
                    "nullPointers": null_pointer_indices,
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


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "stack":
        parser = argparse.ArgumentParser(
            prog="axf_json.py stack",
            description="Attach with pyOCD, briefly halt, read stack, then symbolize locally.",
        )
        parser.add_argument("--config", required=True)
        args = parser.parse_args(argv[1:])
        try:
            print(
                json.dumps(read_stack_backtrace(read_config(args.config)), ensure_ascii=False),
                flush=True,
            )
            return 0
        except Exception as exc:
            emit({"type": "error", "message": str(exc)})
            return 1

    if argv and argv[0] == "read":
        parser = argparse.ArgumentParser(
            prog="axf_json.py read",
            description="Attach with pyOCD and stream selected variable samples.",
        )
        parser.add_argument("--config", required=True)
        args = parser.parse_args(argv[1:])
        return run_reader(args.config)

    if argv and argv[0] == "list":
        emit(
            {
                "type": "error",
                "message": "AXF variable parsing is provided by the Rust parser only.",
            }
        )
        return 1

    parser = argparse.ArgumentParser(
        description="RTT debugger helper. AXF variable parsing is Rust-only."
    )
    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
