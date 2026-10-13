#!/usr/bin/env python3
"""CAN helper process: JSON control messages and base64 binary frame batches.

stdin: {requestId, command, params}; stdout: responses and events.
Only the protocol writer writes stdout. SDK diagnostics are redirected to stderr.
"""
from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
import json
import logging
import os
import queue
import sys
import threading
import time

from can_wire import BridgeError, FRAME_STRUCT, Frame, PROTOCOL_VERSION
from can_zlg import ZlgAdapter, ZlgLibrary, CanFrame, ReceiveData, TransmitData, ChannelConfig

VERSION = '1.0.0'
INTERFACES = ('pcan', 'kvaser', 'vector', 'ixxat', 'slcan', 'socketcan', 'virtual')


def can_module():
    try:
        import can
        return can
    except ImportError as error:
        raise BridgeError('pluginInvalid', 'python-can is missing from the plugin runtime') from error


class PythonCanAdapter:
    def __init__(self, config):
        self.can = can_module()
        self.config = config
        interface = config['interface']
        channel = config['channel']
        if interface in ('kvaser', 'vector', 'ixxat'):
            try:
                channel = int(channel)
            except ValueError as error:
                raise BridgeError('channel', 'This interface expects a numeric channel index') from error
        args = {'interface': interface, 'channel': channel, 'ignore_config': True}
        if interface != 'virtual':
            args['bitrate'] = int(config['bitrate'])
            # Backend listen-only modes have different API names.
            if config.get('listenOnly'):
                if interface == 'pcan':
                    args['state'] = self.can.BusState.PASSIVE
                elif interface == 'kvaser':
                    args['driver_mode'] = 1  # canDRIVER_SILENT
                elif interface == 'slcan':
                    args['listen_only'] = True
                else:
                    raise BridgeError('listenUnsupported', interface)
        if interface == 'vector':
            args['app_name'] = config.get('applicationName') or 'Ballet'
        if interface == 'ixxat' and config.get('hardwareId'):
            args['unique_hardware_id'] = config['hardwareId']
        if interface == 'pcan':
            args['fd'] = False
        self.bus = self.can.Bus(**args)
        self._clock_anchor = None

    def receive(self, timeout):
        message = self.bus.recv(timeout)
        if message is None:
            return []
        if message.is_fd:
            raise BridgeError('fdUnsupported', 'Received a CAN FD frame on a classic CAN session')
        if not message.is_rx:
            return []  # TX is logged once, when the SDK accepts the send request.
        raw = round(message.timestamp * 1000000) if message.timestamp else None
        now = time.time_ns() // 1000
        if raw is None:
            timestamp = now
        elif raw >= 946684800000000:
            timestamp = raw
        else:
            if self._clock_anchor is None:
                self._clock_anchor = now - raw
            timestamp = self._clock_anchor + raw
        return [Frame(id=message.arbitration_id, data=b'' if message.is_remote_frame else bytes(message.data),
                      extended=message.is_extended_id, remote=message.is_remote_frame,
                      error=message.is_error_frame, dlc=message.dlc,
                      timestamp_us=timestamp, hardware_timestamp_us=raw)]

    def send(self, frame):
        if self.config.get('listenOnly'):
            raise BridgeError('listenOnly')
        message = self.can.Message(arbitration_id=frame.id, data=frame.data, dlc=frame.dlc,
                                   is_extended_id=frame.extended, is_remote_frame=frame.remote,
                                   is_fd=False, check=True)
        self.bus.send(message, timeout=0.1)

    def status(self):
        try:
            state = self.bus.state
        except (NotImplementedError, AttributeError):
            return {'state': 'unknown'}
        return {'state': {self.can.BusState.ACTIVE: 'active', self.can.BusState.PASSIVE: 'passive',
                          self.can.BusState.ERROR: 'bus_off'}.get(state, 'unknown')}

    def close(self):
        self.bus.shutdown()


@dataclass
class PeriodicTask:
    frame: Frame
    interval: float
    deadline: float


class Bridge:
    def __init__(self, writer, adapter_factory=None):
        self.writer = writer
        self._write_lock = threading.Lock()
        self._publish_lock = threading.Lock()
        self._adapter_lock = threading.RLock()
        self._tasks_lock = threading.Lock()
        self._tasks: dict[str, PeriodicTask] = {}
        self._queue = queue.Queue(maxsize=8192)
        self._dropped = 0
        self._stop = threading.Event()
        self._session_stop = threading.Event()
        self._receiver = None
        self._adapter = None
        self._config = {}
        self._channel = ''
        self._adapter_factory = adapter_factory
        self._publisher = threading.Thread(target=self._publish_loop, daemon=True)
        self._publisher.start()

    def emit(self, message):
        with self._write_lock:
            self.writer.write(json.dumps(message, separators=(',', ':'), ensure_ascii=False) + '\n')
            self.writer.flush()

    def _enqueue(self, frame):
        try:
            self._queue.put_nowait(frame)
        except queue.Full:
            self._dropped += 1

    def _publish_loop(self):
        while not self._stop.wait(0.05):
            self.flush_frames()

    def flush_frames(self):
        with self._publish_lock:
            self._flush_frames()

    def _flush_frames(self):
        while True:
            frames = []
            for _ in range(512):
                try:
                    frames.append(self._queue.get_nowait())
                except queue.Empty:
                    break
            if not frames:
                break
            self.emit({'event': 'frames', 'channel': self._channel,
                       'data': base64.b64encode(b''.join(frame.pack() for frame in frames)).decode('ascii')})

    def _connected_adapter(self):
        if self._adapter is None or self._session_stop.is_set():
            raise BridgeError('notConnected')
        return self._adapter

    def _send(self, frame):
        if self._config.get('listenOnly'):
            raise BridgeError('listenOnly')
        with self._adapter_lock:
            self._connected_adapter().send(frame)
        self._enqueue(frame.sent())

    def _receive_loop(self):
        next_status = time.monotonic()
        try:
            while not self._session_stop.is_set():
                with self._adapter_lock:
                    frames = self._adapter.receive(0.01)
                for frame in frames:
                    self._enqueue(frame)
                now = time.monotonic()
                with self._tasks_lock:
                    # Execute while holding the task lock so stopping a task cannot
                    # acknowledge before an already selected send has completed.
                    for key, task in list(self._tasks.items()):
                        if now < task.deadline:
                            continue
                        try:
                            self._send(task.frame)
                        except Exception as error:
                            self._tasks.pop(key, None)
                            self.emit({'event': 'error', 'code': getattr(error, 'code', 'send'), 'detail': str(error)})
                            self.emit({'event': 'periodic', 'keys': list(self._tasks)})
                        else:
                            task.deadline += task.interval
                            if task.deadline <= now:
                                task.deadline = now + task.interval  # Never burst to catch up.
                if now >= next_status:
                    with self._adapter_lock:
                        status = self._adapter.status()
                    if status.get('state') == 'bus_off':
                        with self._tasks_lock:
                            self._tasks.clear()
                        self.emit({'event': 'periodic', 'keys': []})
                    self.emit({'event': 'status', 'dropped': self._dropped, **status})
                    if status.get('detail'):
                        self.emit({'event': 'error', 'code': 'bus', 'detail': status['detail']})
                    next_status = now + 0.5
        except Exception as error:
            self._session_stop.set()
            with self._tasks_lock:
                self._tasks.clear()
            self.emit({'event': 'error', 'code': getattr(error, 'code', 'driver'), 'detail': str(error)})
            self.emit({'event': 'status', 'state': 'disconnected', 'dropped': self._dropped})

    def scan(self, config):
        if self._adapter is not None:
            raise BridgeError('busy')
        if config.get('backend') == 'zlgcan':
            library = ZlgLibrary(config['libraryPath'])
            try:
                return library.scan(config)
            finally:
                library.close()
        interface = config.get('interface', 'pcan')
        if interface == 'virtual':
            return [{'name': 'Virtual CAN', 'interface': 'virtual', 'channel': 'ballet-can'}]
        if interface == 'slcan':
            from serial.tools import list_ports
            return [{'name': f'{port.device} — {port.description}', 'interface': 'slcan',
                     'channel': port.device} for port in list_ports.comports()]
        try:
            configs = can_module().detect_available_configs(interfaces=[interface])
        except NotImplementedError:
            return []
        return [{'name': str(item.get('description') or item.get('unique_hardware_id') or item.get('channel')),
                 'interface': interface, 'channel': str(item['channel']),
                 'hardwareId': str(item.get('unique_hardware_id') or '')} for item in configs]

    def open(self, config):
        if self._adapter is not None:
            raise BridgeError('busy')
        bitrate = int(config.get('bitrate', 0))
        if not 0 < bitrate <= 1000000:
            raise BridgeError('bitrate')
        self._config = dict(config)
        if self._adapter_factory:
            adapter = self._adapter_factory(config)
        elif config.get('backend') == 'zlgcan':
            adapter = ZlgAdapter(config)
        else:
            adapter = PythonCanAdapter(config)
        self._adapter = adapter
        self._channel = str(config.get('channelIndex', 0) if config.get('backend') == 'zlgcan'
                            else config.get('channel', ''))
        self._dropped = 0
        self._session_stop.clear()
        self._receiver = threading.Thread(target=self._receive_loop, daemon=True)
        self._receiver.start()
        return {'connected': True, 'periodic': 'software', 'fd': False}

    def close_session(self):
        self._session_stop.set()
        with self._tasks_lock:
            self._tasks.clear()
        if self._receiver:
            self._receiver.join(timeout=2)
            if self._receiver.is_alive():
                # Do not free an SDK handle still in use by a blocked receive.
                raise BridgeError('bridgeTimeout', 'CAN receive thread did not stop')
        self._receiver = None
        with self._adapter_lock:
            if self._adapter:
                adapter, self._adapter = self._adapter, None
                adapter.close()
        self.flush_frames()
        self.emit({'event': 'periodic', 'keys': []})
        self.emit({'event': 'status', 'state': 'disconnected', 'dropped': self._dropped})

    def dispatch(self, command, params):
        if command == 'hello':
            return {'protocolVersion': PROTOCOL_VERSION, 'version': VERSION, 'interfaces': INTERFACES}
        if command == 'scan':
            return self.scan(params)
        if command == 'open':
            return self.open(params)
        if command == 'close':
            self.close_session()
            return {}
        if command == 'send':
            self._send(Frame.from_dict(params['frame']))
            return {}
        if command == 'start_periodic':
            self._connected_adapter()
            if self._config.get('listenOnly'):
                raise BridgeError('listenOnly')
            frame = Frame.from_dict(params['frame'])
            interval = int(params['intervalMs'])
            key = str(params['key'])
            if not key or not 10 <= interval <= 3600000:
                raise BridgeError('interval')
            with self._tasks_lock:
                if len(self._tasks) >= 200 and key not in self._tasks:
                    raise BridgeError('sendListFull')
                self._tasks[key] = PeriodicTask(frame, interval / 1000, time.monotonic())
                self.emit({'event': 'periodic', 'keys': list(self._tasks)})
            return {}
        if command == 'stop_periodic':
            with self._tasks_lock:
                if params.get('key'):
                    self._tasks.pop(str(params['key']), None)
                else:
                    self._tasks.clear()
                self.emit({'event': 'periodic', 'keys': list(self._tasks)})
            return {}
        if command == 'shutdown':
            self.close_session()
            return {}
        raise BridgeError('bridgeProtocol', f'Unknown command: {command}')

    def shutdown(self):
        try:
            self.close_session()
        finally:
            self._stop.set()
            self._publisher.join(timeout=2)


def self_test():
    can_module()
    assert FRAME_STRUCT.size == 32
    assert (ctypes_sizes := [__import__('ctypes').sizeof(t) for t in
                            (CanFrame, TransmitData, ReceiveData, ChannelConfig)]) == [16, 20, 24, 32], ctypes_sizes
    return {'ok': True, 'protocolVersion': PROTOCOL_VERSION, 'version': VERSION}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--stdio', action='store_true')
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    protocol_stdout = sys.stdout
    sys.stdout = sys.stderr
    if os.name == 'nt':
        sys.stdin.reconfigure(encoding='utf-8')
        protocol_stdout.reconfigure(encoding='utf-8', newline='\n')
        sys.stderr.reconfigure(encoding='utf-8')
    logging.basicConfig(stream=sys.stderr, level=logging.WARNING)
    if args.self_test:
        protocol_stdout.write(json.dumps(self_test()) + '\n')
        return 0
    bridge = Bridge(protocol_stdout)
    try:
        for line in sys.stdin:
            request_id = None
            command = ''
            try:
                if len(line) > 1024 * 1024:
                    raise BridgeError('bridgeProtocol', 'Command exceeds the size limit')
                request = json.loads(line)
                request_id = request['requestId']
                command = request['command']
                result = bridge.dispatch(command, request.get('params', {}))
                bridge.emit({'requestId': request_id, 'ok': True, 'result': result})
            except Exception as error:
                bridge.emit({'requestId': request_id, 'ok': False,
                             'code': getattr(error, 'code', 'backend'), 'error': str(error)})
            if command == 'shutdown':
                break
    finally:
        bridge.shutdown()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
