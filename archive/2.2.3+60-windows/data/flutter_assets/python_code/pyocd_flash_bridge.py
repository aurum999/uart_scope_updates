"""Run a pyOCD flash operation with machine-readable progress output."""

import argparse
import io
import json
import sys
from pathlib import Path

EVENT_PREFIX = "UART_SCOPE_FLASH_EVENT:"
MEMORY_READ_CHUNK_SIZE = 1024


def emit(event_type, **payload):
    event = {"type": event_type, **payload}
    sys.stdout.write(EVENT_PREFIX + json.dumps(event, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--operation",
        choices=("program", "chip-erase", "sector-erase", "read-memory"),
        default="program",
    )
    parser.add_argument("--target", required=True)
    parser.add_argument("--probe", required=True)
    parser.add_argument("--frequency", required=True, type=int)
    parser.add_argument("--pack", action="append", default=[])
    parser.add_argument("--base-address", type=lambda value: int(value, 0))
    parser.add_argument("--no-reset", action="store_true")
    parser.add_argument("--under-reset", action="store_true")
    parser.add_argument("--start-address", type=lambda value: int(value, 0))
    parser.add_argument("--end-address", type=lambda value: int(value, 0))
    parser.add_argument("firmware", nargs="?")
    args = parser.parse_args()
    if args.operation == "program" and not args.firmware:
        parser.error("firmware is required for programming")
    if args.operation in ("read-memory", "sector-erase"):
        if args.start_address is None or args.end_address is None:
            parser.error("operation requires start and end addresses")
        if not 0 <= args.start_address <= args.end_address <= 0xFFFFFFFF:
            parser.error("invalid address range")
    return args


def resolve_erase_sectors(memory_map, start_address, end_address, pname):
    """Validate the entire inclusive range before any sector is erased."""
    if not 0 <= start_address <= end_address <= 0xFFFFFFFF:
        raise ValueError("invalid sector erase range")

    sectors = []
    address = start_address
    while address <= end_address:
        region = memory_map.get_region_for_address(address, pname)
        if region is None or not region.is_flash or region.flash is None:
            raise ValueError(f"address 0x{address:08X} is not erasable flash")

        info = region.flash.get_sector_info(address)
        if info is None or info.size <= 0 or not info.base_addr <= address < info.base_addr + info.size:
            raise ValueError(f"sector information unavailable at 0x{address:08X}")
        sector_end = info.base_addr + info.size
        if info.base_addr < region.start or sector_end > region.end + 1:
            raise ValueError(f"sector at 0x{address:08X} exceeds its flash region")
        sectors.append(info.base_addr)
        address = sector_end

    return sectors, sectors[0], address - 1


class FlashProgressMapper:
    def __init__(self):
        self.phase = "erase"
        self.last_raw = 0.0

    def update(self, raw_value):
        raw = max(0.0, min(1.0, float(raw_value)))
        if self.phase == "erase" and self.last_raw - raw > 0.5:
            self.phase = "program"
            self.last_raw = 0.0
        self.last_raw = max(self.last_raw, raw)
        overall = self.last_raw * 0.5
        if self.phase == "program":
            overall = min(0.5 + overall, 0.99)
        return overall, self.phase, raw


def load_programming_image(path, base_address, memory_map):
    """Snapshot the image once so programming and verification use identical bytes."""
    data = Path(path).read_bytes()
    if not data:
        raise ValueError("Firmware file is empty")
    file_format = Path(path).suffix.lower().lstrip(".")
    if file_format == "hex":
        from intelhex import IntelHex

        text = data.decode("utf-8-sig")
        image = IntelHex(io.StringIO(text))
        segments = [
            (start, bytes(image.tobinarray(start=start, size=end - start)))
            for start, end in image.segments()
        ]
        stream = io.StringIO(text)
    elif file_format == "bin":
        if base_address is None:
            boot_memory = memory_map.get_boot_memory()
            if boot_memory is None:
                raise ValueError("No boot memory is defined for this device")
            base_address = boot_memory.start
        segments = [(base_address, data)]
        stream = io.BytesIO(data)
    else:
        raise ValueError("Only HEX and BIN files are supported")
    if not segments:
        raise ValueError("Firmware contains no program data")
    for address, payload in segments:
        if address < 0 or address + len(payload) > 0x100000000:
            raise ValueError("Invalid address range")
    return stream, file_format, segments


def verify_programmed_image(target, segments):
    total = sum(len(data) for _, data in segments)
    completed = 0
    emit("progress", fraction=0.8, phase="verify", raw=0.0)
    for address, expected in segments:
        for offset in range(0, len(expected), MEMORY_READ_CHUNK_SIZE):
            chunk = expected[offset:offset + MEMORY_READ_CHUNK_SIZE]
            actual = bytes(target.read_memory_block8(address + offset, len(chunk)))
            if len(actual) != len(chunk):
                raise RuntimeError(f"Verification incomplete read at 0x{address + offset:08X}")
            if actual != chunk:
                mismatch = next(i for i, (a, b) in enumerate(zip(actual, chunk)) if a != b)
                raise RuntimeError(
                    f"Verification failed at 0x{address + offset + mismatch:08X}: "
                    f"expected 0x{chunk[mismatch]:02X}, got 0x{actual[mismatch]:02X}"
                )
            completed += len(chunk)
            raw = completed / total
            emit("progress", fraction=min(0.8 + 0.2 * raw, 0.99), phase="verify", raw=raw)
    emit("status", message="Verification complete")


def main():
    from pyocd.core.helpers import ConnectHelper
    from pyocd.flash.file_programmer import FileProgrammer
    from pyocd.flash.eraser import FlashEraser

    args = parse_args()
    progress_mapper = FlashProgressMapper()

    def progress(value):
        overall, phase, raw = progress_mapper.update(value)
        emit("progress", fraction=overall * 0.8, phase=phase, raw=raw)

    packs = args.pack or None
    options = {"hide_programming_progress": True}
    if args.operation == "program":
        options.update({
            "cache.enable_memory": False,
            "cache.read_code_from_elf": False,
            "resume_on_disconnect": False,
        })
    if args.under_reset:
        options["connect_mode"] = "under-reset"
    session = ConnectHelper.session_with_chosen_probe(
        blocking=False,
        return_first=True,
        unique_id=args.probe,
        target_override=args.target,
        frequency=args.frequency,
        pack=packs,
        options=options,
    )
    if session is None:
        raise RuntimeError("No matching debug probe was found")

    with session:
        emit("status", message="Connected to debugger")
        if args.operation == "read-memory":
            size = args.end_address - args.start_address + 1
            data = bytearray()
            offset = 0
            while offset < size:
                chunk_size = min(MEMORY_READ_CHUNK_SIZE, size - offset)
                data.extend(
                    session.target.read_memory_block8(
                        args.start_address + offset,
                        chunk_size,
                    )
                )
                offset += chunk_size
                emit("progress", fraction=offset / size, phase="read")
            emit("memory", start=args.start_address, data=data.hex())
            emit("progress", fraction=1.0, phase="complete")
            return
        if args.operation == "chip-erase":
            emit("progress", fraction=0.0, phase="erase")
            session.target.reset_and_halt()
            FlashEraser(session, FlashEraser.Mode.CHIP).erase()
            session.target.reset()
            emit("progress", fraction=1.0, phase="complete")
            emit("status", message="Chip erase complete")
            return
        if args.operation == "sector-erase":
            pname = session.target.selected_core.node_name
            sectors, actual_start, actual_end = resolve_erase_sectors(
                session.target.memory_map,
                args.start_address,
                args.end_address,
                pname,
            )
            emit("erase-range", start=actual_start, end=actual_end, count=len(sectors))
            session.target.reset_and_halt()
            FlashEraser(session, FlashEraser.Mode.SECTOR).erase(sectors)
            session.target.reset()
            emit("status", message="Sector erase complete")
            return
        session.target.reset_and_halt()
        image, file_format, segments = load_programming_image(
            args.firmware, args.base_address, session.target.memory_map
        )
        programmer = FileProgrammer(
            session,
            progress=progress,
            no_reset=True,
        )
        with image:
            programmer.program(image, file_format=file_format, base_address=args.base_address)
        verify_programmed_image(session.target, segments)
        if not args.no_reset:
            session.target.reset()
        emit("progress", fraction=1.0, phase="complete", raw=1.0)
        emit("status", message="Programming complete")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        emit("error", message=str(error))
        raise
