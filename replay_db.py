import os, sys, sqlite3, ctypes, struct, collections
from contextlib import contextmanager
from typing import List, Any

import rpyc, hexdump

"""

Replay and fuzz all the entries from the SQLite database.

Target host must have Python3+ + `rpyc` module installed.
Then simply start `rpyc_classic` on the target like this:

```
c:\> rpyc_classic.py --host 0.0.0.0
```

"""

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3

Irp = collections.namedtuple(
    "Irp",
    [
        "TimeStamp",
        "IrqLevel",
        "Type",
        "IoctlCode",
        "Status",
        "ProcessId",
        "ThreadId",
        "InputBufferLength",
        "OutputBufferLength",
        "DriverName",
        "DeviceName",
        "ProcessName",
        "InputBuffer",
        "OutputBuffer",
    ]
)

def log(x): print(x)
def dbg(x): log(f"[*] {x}") if DEBUG else None
def ok(x): log(f"[+] {x}")
def err(x): log(f"[-] {x}")
def warn(x): log(f"[!] {x}")

@contextmanager
def GetDeviceHandle(conn, DeviceName, *args, **kwargs):
    Access = kwargs.get('dwDesiredAccess', GENERIC_READ | GENERIC_WRITE)
    handle = kernel32.CreateFileW(DeviceName, Access, 0, None, OPEN_EXISTING, 0, None)
    if handle == -1:
        raise IOError('Cannot get handle to %s' % DeviceName)
    try:
        yield handle
    finally:
        kernel32.CloseHandle(handle)


def DeviceIoctlControl(conn, DeviceName, IoctlCode, _in='', _out='', *args, **kwargs):
    dwBytesReturned = c_uint32()
    InputBufferSize = kwargs.get('_inlen', len(_in))
    OutputBufferSize = kwargs.get('_outlen', len(_out))
    InputBuffer = create_string_buffer(InputBufferSize)
    OutputBuffer = create_string_buffer(OutputBufferSize)
    InputBuffer.value = _in
    OutputBuffer.value = _out
    res = -1
    with GetDeviceHandle(conn, DeviceName) as hDriver:
        #print('Sending inbuflen=%dB to %s with ioctl=%#x (outbuflen=%dB)' % (InputBufferSize, DeviceName, IoctlCode, OutputBufferSize))
        res = kernel32.DeviceIoControl(hDriver, IoctlCode, InputBuffer, InputBufferSize, OutputBuffer, OutputBufferSize, byref(dwBytesReturned), None)
        #print('Sent %dB to %s with IoctlCode %#x' % (InputBufferSize, DeviceName, IoctlCode ))
        if res:
            if dwBytesReturned:
                ok(hexdump.hexdump(OutputBuffer))
        else:
            #warn( GetLastError(), FormatError(GetLastError()) )
            pass
    return res


def MutateFuzzWord(data: bytearray) -> bytearray:
    if len(data) < 2:
        return data

    for offset in range(0, len(data), 2):
        fuzzed_data = data[::]
        #dbg("Fuzzing WORD at offset %d" % offset)
        struct.pack_into("<H", fuzzed_data, offset, 0x4141)
        yield fuzzed_data
        struct.pack_into("<H", fuzzed_data, offset, 0xffff)
        yield fuzzed_data


def MutateFuzzDword(data: bytearray) -> bytearray:
    if len(data) < 4:
        return data

    for offset in range(0, len(data), 4):
        fuzzed_data = data[::]
        #dbg("Fuzzing DWORD at offset %d" % offset)
        struct.pack_into("<I", fuzzed_data, offset, 0x41414141)
        yield fuzzed_data
        struct.pack_into("<I", fuzzed_data, offset, 0xffffffff)
        yield fuzzed_data


def MutateFuzzQword(data: bytearray) -> bytearray:
    if len(data) < 8:
        return data

    for offset in range(0, len(data), 8):
        fuzzed_data = data[::]
        #dbg("Fuzzing QWORD at offset %d" % offset)
        struct.pack_into("<Q", fuzzed_data, offset, 0x4141414141414141)
        yield fuzzed_data
        struct.pack_into("<Q", fuzzed_data, offset, 0xffffffffffffffff)
        yield fuzzed_data


def MutateFuzzFlipHiBit(data: bytearray):
    for offset in range(0, len(data)):
        fuzzed_data = data[::]
        fuzzed_data[offset] = fuzzed_data[offset] | 0b10000000 if not fuzzed_data[offset] & 0x80 else fuzzed_data[offset] & 0b01111111
        yield fuzzed_data


def Mutate(data: bytes):
    data = bytearray(data)
    for out in MutateFuzzQword(data): yield out
    for out in MutateFuzzDword(data): yield out
    for out in MutateFuzzWord(data): yield out
    for out in MutateFuzzFlipHiBit(data): yield out


def Fuzz(remote: rpyc.core.protocol.Connection, entry: Irp) -> int:
    DeviceName = entry.DeviceName.lower().replace(r"\device", r"\\.")
    IoctlCode = entry.IoctlCode
    lpIrpDataOut = b"\x00"*entry.OutputBufferLength
    for mutated_data in Mutate(entry.InputBuffer):
        lpIrpDataIn = bytes(mutated_data)
        #os.system("clear")
        #hexdump.hexdump(lpIrpDataIn)
        DeviceIoctlControl(remote, DeviceName, IoctlCode, lpIrpDataIn, lpIrpDataOut)


def AutoFuzz(conn: rpyc.core.protocol.Connection, db_path: str):
    sql = sqlite3.connect(db_path)
    c = sql.cursor()
    c.execute("SELECT * FROM Irps WHERE Type = 14 AND InputBufferLength > 0")
    for entry in c.fetchall():
        irp = Irp(*entry)
        try:
            Fuzz(conn, irp)
        except Exception as e:
            #err("Exception: %s" % str(e))
            #break
            pass
    sql.close()
    return


def Connect(host: str, port:int = 18812) -> rpyc.core.protocol.Connection:
    global ntdll, kernel32, c_uint32, GetLastError, FormatError, create_string_buffer, byref
    conn = rpyc.classic.connect(host, port)
    conn.execute("from ctypes import *")

    ntdll = conn.namespace["windll"].ntdll
    kernel32 = conn.namespace["windll"].kernel32
    c_uint32 = conn.namespace["c_uint32"]
    GetLastError = conn.namespace["GetLastError"]
    FormatError = conn.namespace["FormatError"]
    create_string_buffer = conn.namespace["create_string_buffer"]
    byref = conn.namespace["byref"]
    return conn


if __name__ == '__main__':
    sqlite_file = sys.argv[1]
    target_fuzz = sys.argv[2]
    conn = Connect(target_fuzz)
    AutoFuzz(conn, sqlite_file)