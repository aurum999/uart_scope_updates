"""ZLGCAN Windows SDK adapter, using the classic-CAN ZCAN_* API.

SDK reference: https://manual.zlg.cn/web/#/146
The CAN dependency plugin supplies the complete vendor SDK runtime directory.
The application may also select a user-provided SDK directory.
"""
from __future__ import annotations

import ctypes as c
import os
from pathlib import Path
import time

from can_wire import BridgeError, Frame

U8, U16, U32, U64 = c.c_uint8, c.c_uint16, c.c_uint32, c.c_uint64
HANDLE = c.c_void_p
EFF, RTR, ERR = 0x80000000, 0x40000000, 0x20000000


class CanFrame(c.Structure):
    _fields_ = [('can_id', U32), ('dlc', U8), ('pad', U8), ('reserved0', U8),
                ('reserved1', U8), ('data', U8 * 8)]


class TransmitData(c.Structure):
    _fields_ = [('frame', CanFrame), ('transmit_type', U32)]


class ReceiveData(c.Structure):
    _fields_ = [('frame', CanFrame), ('timestamp', U64)]


class CanInit(c.Structure):
    _fields_ = [('acc_code', U32), ('acc_mask', U32), ('reserved', U32),
                ('filter', U8), ('timing0', U8), ('timing1', U8), ('mode', U8)]


class ConfigUnion(c.Union):
    # The CAN FD member defines the union size even when CAN FD is not used.
    _fields_ = [('can', CanInit), ('reserved_fd', U32 * 7)]


class ChannelConfig(c.Structure):
    _fields_ = [('can_type', U32), ('config', ConfigUnion)]


class DeviceInfo(c.Structure):
    _fields_ = [('hw', U16), ('fw', U16), ('driver', U16), ('interface', U16),
                ('irq', U16), ('can_count', U8), ('serial', c.c_char * 20),
                ('name', c.c_char * 40), ('reserved', U16 * 4)]


class ChannelErrors(c.Structure):
    _fields_ = [('error_code', U32), ('passive', U8 * 3), ('arbitration_lost', U8)]


class ChannelStatus(c.Structure):
    _fields_ = [('interrupt', U8), ('mode', U8), ('status', U8), ('arbitration', U8),
                ('error_capture', U8), ('warning_limit', U8), ('rx_errors', U8),
                ('tx_errors', U8), ('reserved', U32)]


class Property(c.Structure):
    _fields_ = [('set_value', HANDLE), ('get_value', HANDLE), ('get_properties', HANDLE)]


BIT_TIMINGS = {1000000: (0x00, 0x14), 800000: (0x00, 0x16),
               500000: (0x00, 0x1C), 250000: (0x01, 0x1C), 125000: (0x03, 0x1C),
               100000: (0x04, 0x1C), 50000: (0x09, 0x1C), 20000: (0x18, 0x1C),
               10000: (0x31, 0x1C), 5000: (0xBF, 0xFF)}


class ZlgLibrary:
    def __init__(self, path: str):
        if os.name != 'nt':
            raise BridgeError('zlgPlatform', 'ZLGCAN requires Windows')
        dll_path = Path(path).expanduser().resolve()
        if not dll_path.is_file() or dll_path.name.lower() != 'zlgcan.dll':
            raise BridgeError('zlgConfig', 'Select zlgcan.dll from the complete vendor SDK')
        self._directories = []
        self._working_directory = None
        try:
            # Vendor kernels/resources may be opened relative to the SDK root.
            # This process belongs exclusively to CAN; RTT's process is separate.
            self._working_directory = os.getcwd()
            os.chdir(dll_path.parent)
            for folder in (dll_path.parent, dll_path.parent / 'kerneldlls'):
                if folder.is_dir():
                    self._directories.append(os.add_dll_directory(str(folder)))
            self.dll = c.WinDLL(str(dll_path), winmode=0x1100)
            self._bind('ZCAN_OpenDevice', HANDLE, U32, U32, U32)
            self._bind('ZCAN_CloseDevice', U32, HANDLE)
            self._bind('ZCAN_GetDeviceInf', U32, HANDLE, c.POINTER(DeviceInfo))
            self._bind('ZCAN_InitCAN', HANDLE, HANDLE, U32, c.POINTER(ChannelConfig))
            self._bind('ZCAN_StartCAN', U32, HANDLE)
            self._bind('ZCAN_ResetCAN', U32, HANDLE)
            self._bind('ZCAN_Receive', U32, HANDLE, c.POINTER(ReceiveData), U32, c.c_int)
            self._bind('ZCAN_Transmit', U32, HANDLE, c.POINTER(TransmitData), U32)
            self._bind('ZCAN_ReadChannelErrInfo', U32, HANDLE, c.POINTER(ChannelErrors))
            self._bind('ZCAN_ReadChannelStatus', U32, HANDLE, c.POINTER(ChannelStatus))
            if hasattr(self.dll, 'ZCAN_IsDeviceOnLine'):
                self._bind('ZCAN_IsDeviceOnLine', U32, HANDLE)
            if hasattr(self.dll, 'ZCAN_SetValue'):
                self._bind('ZCAN_SetValue', U32, HANDLE, c.c_char_p, HANDLE)
            if hasattr(self.dll, 'ZCAN_GetProperty'):
                self._bind('ZCAN_GetProperty', c.POINTER(Property), HANDLE)
                self._bind('ZCAN_ReleaseProperty', U32, c.POINTER(Property))
        except (OSError, AttributeError) as error:
            self.close()
            raise BridgeError('driver', f'{error}. DLL and plugin architecture must match.') from error

    def _bind(self, name, result, *args):
        function = getattr(self.dll, name)
        function.restype = result
        function.argtypes = list(args)

    def set_bitrate(self, handle, channel, bitrate):
        path, value = f'{channel}/baud_rate'.encode('ascii'), str(bitrate).encode('ascii')
        if hasattr(self.dll, 'ZCAN_SetValue'):
            if self.dll.ZCAN_SetValue(handle, path, c.cast(c.c_char_p(value), HANDLE)) != 1:
                raise BridgeError('bitrate', 'ZCAN_SetValue baud_rate failed')
        elif hasattr(self.dll, 'ZCAN_GetProperty'):
            prop = self.dll.ZCAN_GetProperty(handle)
            if not prop or not prop.contents.set_value:
                raise BridgeError('driver', 'ZCAN_GetProperty failed')
            try:
                setter = c.CFUNCTYPE(U32, c.c_char_p, c.c_char_p)(prop.contents.set_value)
                if setter(path, value) != 1:
                    raise BridgeError('bitrate', 'SDK baud_rate property rejected the bitrate')
            finally:
                self.dll.ZCAN_ReleaseProperty(prop)
        else:
            raise BridgeError('driver', 'SDK does not expose bitrate configuration')

    def scan(self, config):
        result = []
        # SDK has no universal enumeration API. Probe only the selected model.
        for index in range(16):
            handle = self.dll.ZCAN_OpenDevice(int(config['deviceType']), index, 0)
            if not handle:
                continue
            try:
                info = DeviceInfo()
                if self.dll.ZCAN_GetDeviceInf(handle, c.byref(info)) == 1:
                    name = bytes(info.name).decode('mbcs', errors='replace')
                    serial = bytes(info.serial).decode('ascii', errors='replace')
                    for channel in range(min(info.can_count, 16)):
                        result.append({'name': f'{name} {serial} / CAN{channel}',
                                       'deviceIndex': index, 'channelIndex': channel,
                                       'channel': str(channel)})
            finally:
                self.dll.ZCAN_CloseDevice(handle)
        return result

    def close(self):
        for directory in self._directories:
            directory.close()
        self._directories.clear()
        if self._working_directory is not None:
            os.chdir(self._working_directory)
            self._working_directory = None


class ZlgAdapter:
    def __init__(self, config, library_factory=ZlgLibrary):
        self.config = config
        self.library = library_factory(config['libraryPath'])
        self.device = None
        self.channel = None
        self._anchor = None
        self._last_stamp = 0
        self._buffer = (ReceiveData * 512)()
        self._last_error = 0
        try:
            self.device = self.library.dll.ZCAN_OpenDevice(int(config['deviceType']),
                                                           int(config['deviceIndex']), 0)
            if not self.device:
                raise BridgeError('driver', 'ZCAN_OpenDevice failed; check model, index and driver')
            info = DeviceInfo()
            if self.library.dll.ZCAN_GetDeviceInf(self.device, c.byref(info)) != 1:
                raise BridgeError('driver', 'ZCAN_GetDeviceInf failed')
            if not 0 <= int(config['channelIndex']) < info.can_count:
                raise BridgeError('channel', 'CAN channel index is out of range')
            init = ChannelConfig()
            init.can_type = 0
            init.config.can.acc_mask = 0xFFFFFFFF
            init.config.can.filter = 1
            init.config.can.mode = 1 if config.get('listenOnly') else 0
            bitrate = int(config['bitrate'])
            if int(config['deviceType']) in (3, 4):
                if bitrate not in BIT_TIMINGS:
                    raise BridgeError('bitrate', 'This model requires a supported SJA1000 bitrate')
                init.config.can.timing0, init.config.can.timing1 = BIT_TIMINGS[bitrate]
            else:
                self.library.set_bitrate(self.device, int(config['channelIndex']), bitrate)
            self.channel = self.library.dll.ZCAN_InitCAN(self.device, int(config['channelIndex']), c.byref(init))
            if not self.channel or self.library.dll.ZCAN_StartCAN(self.channel) != 1:
                raise BridgeError('driver', 'ZCAN_InitCAN / ZCAN_StartCAN failed')
        except Exception:
            self.close()
            raise

    def receive(self, timeout):
        count = self.library.dll.ZCAN_Receive(self.channel, self._buffer, len(self._buffer), 0)
        if count == 0xFFFFFFFF or count > len(self._buffer):
            raise BridgeError('disconnected', 'ZCAN_Receive failed')
        if not count:
            time.sleep(min(timeout, 0.005))
            return []
        frames = []
        for item in self._buffer[:count]:
            native, stamp = item.frame, int(item.timestamp)
            if self._anchor is None or stamp < self._last_stamp:
                self._anchor = time.time_ns() // 1000 - stamp
            self._last_stamp = stamp
            remote = bool(native.can_id & RTR)
            frames.append(Frame(id=native.can_id & 0x1FFFFFFF,
                                extended=bool(native.can_id & EFF), remote=remote,
                                error=bool(native.can_id & ERR), dlc=int(native.dlc),
                                data=b'' if remote else bytes(native.data[:native.dlc]),
                                timestamp_us=self._anchor + stamp, hardware_timestamp_us=stamp))
        return frames

    def send(self, frame):
        if self.config.get('listenOnly'):
            raise BridgeError('listenOnly')
        native = TransmitData()
        native.frame.can_id = frame.id | (EFF if frame.extended else 0) | (RTR if frame.remote else 0)
        native.frame.dlc = frame.dlc
        native.frame.data[:len(frame.data)] = frame.data
        if self.library.dll.ZCAN_Transmit(self.channel, c.byref(native), 1) != 1:
            raise BridgeError('send', 'ZCAN_Transmit did not accept the frame')

    def status(self):
        dll = self.library.dll
        if hasattr(dll, 'ZCAN_IsDeviceOnLine') and dll.ZCAN_IsDeviceOnLine(self.device) in (0, 3):
            raise BridgeError('disconnected', 'ZLGCAN device is offline')
        status, errors = ChannelStatus(), ChannelErrors()
        if dll.ZCAN_ReadChannelErrInfo(self.channel, c.byref(errors)) != 1:
            raise BridgeError('driver', 'ZCAN_ReadChannelErrInfo failed')
        if dll.ZCAN_ReadChannelStatus(self.channel, c.byref(status)) != 1:
            raise BridgeError('driver', 'ZCAN_ReadChannelStatus failed')
        state = 'bus_off' if status.status & 0x80 else (
            'passive' if status.rx_errors >= 128 or status.tx_errors >= 128 else 'active')
        code = errors.error_code
        changed = code != self._last_error
        self._last_error = code
        return {'state': state, 'detail': f'ZLGCAN error=0x{code:X}; RX={status.rx_errors}; TX={status.tx_errors}'
                if code and changed else ''}

    def close(self):
        try:
            if self.channel:
                self.library.dll.ZCAN_ResetCAN(self.channel)
        finally:
            try:
                if self.device:
                    self.library.dll.ZCAN_CloseDevice(self.device)
            finally:
                self.channel = self.device = None
                self.library.close()
