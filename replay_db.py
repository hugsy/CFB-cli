import sys, sqlite3, ctypes, struct
from contextlib import contextmanager
from typing import List, Any

import rpyc, hexdump

"""

Start rpyc_classic on the target like this:

```
c:\> rpyc_classic.py --host 0.0.0.0
```

"""

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3


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
                print(hexdump.hexdump(OutputBuffer))
        else:
            #print( GetLastError(), FormatError(GetLastError()) )
            pass
    return res


#def MutateFuzzQword(original_data):


def Mutate(data):
    for offset in range(0, len(data), 8):
        #print("- Fuzzing QWORD at offset %d" % offset)
        fuzzed_data = bytearray(data)
        struct.pack_into("<Q", fuzzed_data, offset, 0x4141414141414141)
        yield fuzzed_data




def Fuzz(remote: rpyc.core.protocol.Connection, entry: List[Any]) -> int:
    DeviceName = entry[10].lower().replace(r"\device", r"\\.") # DeviceName
    IoctlCode = entry[3] # IoctlCode
    lpIrpDataOut = b"\x00"*entry[8] # OutputBufferLength
    for mutated_data in Mutate(entry[12]): # InputBuffer
        lpIrpDataIn = bytes(mutated_data)
        #print(hexdump.hexdump(lpIrpDataIn))
        DeviceIoctlControl(remote, DeviceName, IoctlCode, lpIrpDataIn, lpIrpDataOut)


def AutoFuzz(conn: rpyc.core.protocol.Connection, db_path: str):
    sql = sqlite3.connect(db_path)
    c = sql.cursor()
    c.execute("SELECT * FROM Irps WHERE Type = 14 AND InputBufferLength > 0")
    for entry in c.fetchall():
        Fuzz(conn, entry)
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
    Test(conn)
    AutoFuzz(conn, sqlite_file)