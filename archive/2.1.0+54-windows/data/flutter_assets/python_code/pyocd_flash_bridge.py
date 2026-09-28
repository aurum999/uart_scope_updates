"""Run a pyOCD flash operation with machine-readable progress output."""

import argparse
import json
import sys

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


def main():
    from pyocd.core.helpers import ConnectHelper
    from pyocd.flash.file_programmer import FileProgrammer
    from pyocd.flash.eraser import FlashEraser

    args = parse_args()
    progress_mapper = FlashProgressMapper()

    def progress(value):
        overall, phase, raw = progress_mapper.update(value)
        emit("progress", fraction=overall, phase=phase, raw=raw)

    packs = args.pack or None
    session = ConnectHelper.session_with_chosen_probe(
        blocking=False,
        return_first=True,
        unique_id=args.probe,
        target_override=args.target,
        frequency=args.frequency,
        pack=packs,
        options={"hide_programming_progress": True},
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
        programmer = FileProgrammer(
            session,
            progress=progress,
            no_reset=True,
        )
        programmer.program(args.firmware, base_address=args.base_address)
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
