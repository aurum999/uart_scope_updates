"""Classic CAN model and the version 1 batch wire format used by Flutter."""
from __future__ import annotations

from dataclasses import dataclass, replace
import struct
import time

PROTOCOL_VERSION = 1
FRAME_STRUCT = struct.Struct('<QqIBBBx8s')


class BridgeError(Exception):
    def __init__(self, code: str, detail: str = ''):
        self.code = code
        super().__init__(detail or code)


@dataclass(frozen=True)
class Frame:
    id: int
    data: bytes = b''
    extended: bool = False
    remote: bool = False
    error: bool = False
    dlc: int | None = None
    timestamp_us: int = 0
    hardware_timestamp_us: int | None = None
    tx: bool = False

    def __post_init__(self):
        if self.dlc is None:
            object.__setattr__(self, 'dlc', len(self.data))
        if not 0 <= self.id <= (0x1FFFFFFF if self.extended or self.error else 0x7FF):
            raise BridgeError('id')
        if not 0 <= self.dlc <= 8 or len(self.data) > 8 or (
            bool(self.data) if self.remote else self.dlc != len(self.data)
        ):
            raise BridgeError('payload')

    @classmethod
    def from_dict(cls, value: dict):
        if value.get('fd') or value.get('error'):
            raise BridgeError('fdUnsupported' if value.get('fd') else 'payload')
        try:
            return cls(id=int(value['id']), data=bytes(value.get('data', [])),
                       extended=bool(value.get('extended')), remote=bool(value.get('remote')),
                       dlc=int(value.get('dlc', len(value.get('data', [])))))
        except (ValueError, TypeError, KeyError) as error:
            raise BridgeError('payload', str(error)) from error

    def sent(self):
        # A TX record means accepted by the SDK, not an on-wire acknowledgement.
        return replace(self, tx=True, timestamp_us=time.time_ns() // 1000,
                       hardware_timestamp_us=None)

    def pack(self) -> bytes:
        flags = int(self.extended) | int(self.remote) << 1 | int(self.tx) << 2 | int(self.error) << 3
        return FRAME_STRUCT.pack(self.timestamp_us, self.hardware_timestamp_us
                                 if self.hardware_timestamp_us is not None else -1,
                                 self.id, flags, self.dlc, 0, self.data.ljust(8, b'\0'))
