#!/usr/bin/python3

from __future__ import unicode_literals

import datetime
import enum
from typing import Dict, List, Tuple
import hexdump
import json
import socket
import struct
import sys
import pathlib

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import NestedCompleter
from prompt_toolkit.styles import Style

from rich.console import Console
from rich.table import Table
from rich.text import Text


def u8(x: bytes) -> int: return struct.unpack("<B", x)[0]
def u16(x: bytes) -> int: return struct.unpack("<H", x)[0]
def u32(x: bytes) -> int: return struct.unpack("<I", x)[0]
def u64(x: bytes) -> int: return struct.unpack("<Q", x)[0]


def p8(x: int) -> bytes: return struct.pack("<B", x)
def p16(x: int) -> bytes: return struct.pack("<H", x)
def p32(x: int) -> bytes: return struct.pack("<I", x)
def p64(x: int) -> bytes: return struct.pack("<Q", x)


def convert_GetSystemTime(t: int) -> datetime.datetime:
    """
    Convert NTFS timestamp returned by GetSystemTime() to a datetime object
    """
    unix_ts = (t / 10000000) - 11644473600
    return datetime.datetime.fromtimestamp(unix_ts)


cfb_completer = NestedCompleter.from_nested_dict({
    'connect': None,
    'disconnect': None,
    'reconnect': None,
    'hook': None,
    'unhook': None,
    'monitor': None,
    'unmonitor': None,
    'save': None,
    'exit': None,
    'list': None,
    'show': None,
    'replay': None,
    'dump': None
})


class RequestId(enum.IntEnum):
    HookDriver = 0x01
    UnhookDriver = 0x02
    GetNumberOfDrivers = 0x03
    GetNamesOfDrivers = 0x04
    GetDriverInfo = 0x05
    EnableMonitoring = 0x07
    DisableMonitoring = 0x08
    EnumerateDriverObject = 0x11
    EnumerateDeviceObject = 0x12
    GetPendingIrpNumber = 0x13
    GetPendingIrp = 0x14
    EnumerateMinifilterObject = 0x15


class Session:
    """
    Defines a session to the CFB broker
    """
    host: str
    port: int
    cli: PromptSession
    __prompt: str
    drivers: Dict[str, Tuple[bool, bool]]
    irps: List

    def __init__(self, host: str, port: int, cli: PromptSession) -> None:
        self.host = host
        self.port = port
        self.cli = cli
        self.console = Console()
        self.drivers = {}
        self.__prompt = "cfb►  "
        self.irps = []
        self.connect()
        return

    def __del__(self) -> None:
        if self.is_connected:
            self.disconnect()
        return

    def connect(self) -> bool:
        self.hSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.hSock.connect((self.host, self.port))
            return True
        except socket.error:
            return False

    def disconnect(self) -> bool:
        if not self.hSock:
            return False

        try:
            self.hSock.close()
            self.hSock = None
            return True
        except socket.error:
            return False

    def reconnect(self) -> bool:
        return self.disconnect() and self.connect()

    @property
    def is_connected(self) -> bool:
        return self.hSock is not None

    def is_connected_str(self) -> str:
        return "✔️ " if self.is_connected else "❌ "

    def prompt(self) -> str:
        cmd = self.cli.prompt(self.is_connected_str() + self.__prompt)
        return cmd

    def send(self, js: Dict) -> bool:
        if not self.hSock:
            print("Not connected")
            return False
        try:
            data: bytes = json.dumps(js).encode("utf-8")
            self.hSock.sendall(data)
            return True
        except Exception as e:
            print(f"send() caught exception {e}")
            return False

    def recv(self, n: int) -> Dict[str, Dict]:
        if not self.hSock:
            print("Not connected")
            return {}
        data: bytes = self.hSock.recv(n)
        if not data:
            print("Empty response")
            return {}
        return json.loads(data.decode("utf-8"))

    def sr(self, js_in: dict) -> dict:
        if not self.send(js_in):
            return {}

        js_out = self.recv(10000)
        if not js_out:
            return {}
        return js_out

    def list_drivers(self) -> bool:
        js = self.sr({"id": RequestId.EnumerateDriverObject})
        if not js:
            return False
        rc = int(js.get("error_code", "-1"))
        if rc != 0:
            print(f"request failed, rc={rc}")
            return False

        res = js["body"]
        status = int(res.get("status", "-1"))
        if not status:
            print(
                f"operation failed, status={status}, reason='{res.get('reason', '')}'")
            return False

        for driver in res["body"]:
            if driver not in self.drivers:
                self.drivers[driver] = (False, False)

        self.cli.completer = NestedCompleter.from_nested_dict({
            'connect': None,
            'disconnect': None,
            'reconnect': None,
            'hook': {x: None for x in self.drivers},
            'unhook': {x: None for x in self.drivers},
            'monitor': {x: None for x in self.drivers},
            'unmonitor': {x: None for x in self.drivers},
            'save': None,
            'exit': None,
            'list': None,
            'show': None,
            'replay': None,
            'dump': None
        })

        return True

    def hook_driver(self, driver_path: str, hook: bool) -> bool:
        _id = RequestId.HookDriver if hook else RequestId.UnhookDriver
        js = self.sr({"id": _id, "driver_name": driver_path})
        if not js:
            return False
        rc = int(js.get("error_code", "-1"))
        if rc != 0:
            print(f"request failed, rc={rc}")
            return False
        return True

    def monitor_driver(self, driver_path: str, monitor: bool) -> bool:
        _id = RequestId.EnableMonitoring if monitor else RequestId.DisableMonitoring
        js = self.sr({"id": _id, "driver_name": driver_path})
        if not js:
            return False
        rc = int(js.get("error_code", "-1"))
        if rc != 0:
            print(f"request failed, rc={rc}")
            return False
        return True

    def dump_irps(self) -> int:
        js = self.sr({"id": RequestId.GetPendingIrp, "number_of_irp": 10})
        if not js:
            return 0
        rc = int(js.get("error_code", "-1"))
        if rc != 0:
            print(f"request failed, rc={rc}")
            return 0

        res = js["body"]
        status = int(res.get("status", "-1"))
        if not status:
            print(
                f"operation failed, status={status}, reason='{res.get('reason', '')}'")
            return 0

        if res["number_of_irp"] == 0:
            return 0

        self.irps.extend(res["body"])
        return len(res["body"])

    def show_irps(self) -> None:
        cols = [
            "TimeStamp",
            "DriverName",
            "DeviceName",
            "Irql",
            "Type",
            "MajorFunction",
            "MinorFunction",
            "IoctlCode",
            "Pid",
            "Tid",
            "Status",
            "ProcessName",
            "InputBufferLength",
            "OutputBufferLength",
        ]

        table = Table(title="IRPs")
        # TODO: use Live tables (https://rich.readthedocs.io/en/stable/live.html)

        for col in cols:
            table.add_column(col)

        for irp in self.irps:
            values = []
            for col in cols:
                value = ""
                if col == "TimeStamp":
                    value = convert_GetSystemTime(
                        irp["Header"][col]).strftime("%Y/%m/%d %H:%M:%S")
                else:
                    value = str(irp["Header"][col])
                values.append(value)

            table.add_row(*values)

        self.console.print(table)
        return

    def save_to_file(self, fname: pathlib.Path) -> bool:
        try:
            with fname.open("w") as f:
                for irp in self.irps:
                    f.write(json.dumps(irp))
        except Exception as e:
            print(f"save_to_file() caught exception {e}")
            return False
        return True

    def show_irp(self, index: int) -> None:
        cols = [
            "TimeStamp",
            "DriverName",
            "DeviceName",
            "Irql",
            "Type",
            "MajorFunction",
            "MinorFunction",
            "IoctlCode",
            "Pid",
            "Tid",
            "Status",
            "ProcessName",
            "InputBufferLength",
            "OutputBufferLength",
        ]

        try:
            irp: Dict = self.irps[index]
            for col in cols:
                value = ""
                if col == "TimeStamp":
                    value = convert_GetSystemTime(
                        irp["Header"][col]).strftime("%Y/%m/%d %H:%M:%S")
                else:
                    value = str(irp["Header"][col])
                t = Text()
                t.append(f"{col:32s}", style="bold magenta")
                t.append(value)
                self.console.print(t)

            if irp["Header"]["InputBufferLength"] > 0:
                t = Text()
                t.append("Input")
                self.console.print(t)
                hexdump.hexdump(bytearray(irp["InputBuffer"]))

            if irp["Header"]["OutputBufferLength"] > 0:
                t = Text()
                t.append("Output")
                self.console.print(t)
                hexdump.hexdump(bytearray(irp["OutputBuffer"]))

        except IndexError as e:
            print(f"`index` must be in [0, {len(self.irps)}[")
        except Exception as e:
            print(f"show_irp() caught exception {e}")
        return


def main(host: str, port: int) -> None:
    cfb_style = Style.from_dict({
        'completion-menu.completion': 'bg:#008888 #ffffff',
        'completion-menu.completion.current': 'bg:#00aaaa #000000',
        'scrollbar.background': 'bg:#88aaaa',
        'scrollbar.button': 'bg:#222222',
    })

    cli = PromptSession(completer=cfb_completer, style=cfb_style)
    sess = Session(host, port, cli)

    while True:
        try:
            text = sess.prompt().strip().split()
            if text[0] == 'connect':
                sess.connect()
            if text[0] == 'disconnect':
                sess.disconnect()
            if text[0] == 'reconnect':
                sess.reconnect()
            if text[0] == 'hook':
                print(sess.hook_driver(text[1], True))
            if text[0] == 'unhook':
                print(sess.hook_driver(text[1], False))
            if text[0] == 'monitor':
                print(sess.monitor_driver(text[1], True))
            if text[0] == 'unmonitor':
                print(sess.monitor_driver(text[1], False))
            if text[0] == 'save':
                fname = pathlib.Path(text[1])
                print(sess.save_to_file(fname))
            if text[0] == 'exit':
                break
            if text[0] == 'list':
                sess.list_drivers()
                print(json.dumps(sess.drivers, indent=4))
            if text[0] == 'info':
                idx = int(text[1])
                sess.show_irp(idx)
            if text[0] == 'dump':
                print(sess.dump_irps())
            if text[0] == 'show':
                sess.show_irps()
        except KeyboardInterrupt:
            continue
        except EOFError:
            break

    print('GoodBye!')
    sys.exit(0)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        host, port = ("192.168.57.87", 1337)
    else:
        host, port = (sys.argv[1], int(sys.argv[2]))

    main(host, port)
