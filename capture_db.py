#!/usr/bin/python3

"""

Simple command line client to test the broker exposed features.

This shouldn't be used in other cases than testing.

"""

from enum import Enum, unique

import base64, json, pprint, sys, time, socket, datetime, struct, sqlite3, os, hexdump

MAX_MESSAGE_SIZE = 65536
MAX_ACCEPTABLE_MESSAGE_SIZE = MAX_MESSAGE_SIZE-2


#
# some helpers
#
DEBUG = True

def u8 (x): return struct.unpack("<B", x)[0]
def u16(x): return struct.unpack("<H", x)[0]
def u32(x): return struct.unpack("<I", x)[0]
def u64(x): return struct.unpack("<Q", x)[0]

def p8 (x): return struct.pack("<B", x)
def p16(x): return struct.pack("<H", x)
def p32(x): return struct.pack("<I", x)
def p64(x): return struct.pack("<Q", x)

def log(x): print(x)
def dbg(x): log(f"[*] {x}") if DEBUG else None
def ok(x): log(f"[+] {x}")
def err(x): log(f"[-] {x}")
def warn(x): log(f"[!] {x}")


#
# some windows constants
#
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 0x3
INVALID_HANDLE_VALUE = -1
PIPE_READMODE_BYTE = 0x0
PIPE_READMODE_MESSAGE = 0x2
ERROR_SUCCESS = 0
ERROR_PIPE_BUSY = 231
ERROR_MORE_DATA = 234

FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x00000100
FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000
FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200

LCID_ENGLISH = (0x00 & 0xFF) | (0x01 & 0xFF) << 16


def convert_GetSystemTime(t):
    unix_ts = (t / 10000000) - 11644473600
    return datetime.datetime.fromtimestamp(unix_ts)




@unique
class TaskType(Enum):
    """
    See TaskType in ..\Broker\Task.h
    """
    IoctlResponse = 1
    HookDriver = 2
    UnhookDriver = 3
    GetDriverInfo = 4
    NumberOfDriver = 5
    NotifyEventHandle = 6
    EnableMonitoring = 7
    DisableMonitoring = 8
    GetInterceptedIrps = 9
    ReplayIrp = 10
    StoreTestCase = 11
    EnumerateDrivers = 12

def IrpMajorType(i):
    IrpMajorTypes = {
        0x00: "IRP_MJ_CREATE",
        0x01: "IRP_MJ_CREATE_NAMED_PIPE",
        0x02: "IRP_MJ_CLOSE",
        0x03: "IRP_MJ_READ",
        0x04: "IRP_MJ_WRITE",
        0x05: "IRP_MJ_QUERY_INFORMATION",
        0x06: "IRP_MJ_SET_INFORMATION",
        0x07: "IRP_MJ_QUERY_EA",
        0x08: "IRP_MJ_SET_EA",
        0x09: "IRP_MJ_FLUSH_BUFFERS",
        0x0a: "IRP_MJ_QUERY_VOLUME_INFORMATION",
        0x0b: "IRP_MJ_SET_VOLUME_INFORMATION",
        0x0c: "IRP_MJ_DIRECTORY_CONTROL",
        0x0d: "IRP_MJ_FILE_SYSTEM_CONTROL",
        0x0e: "IRP_MJ_DEVICE_CONTROL",
        0x0f: "IRP_MJ_INTERNAL_DEVICE_CONTROL",
        0x10: "IRP_MJ_SHUTDOWN",
        0x11: "IRP_MJ_LOCK_CONTROL",
        0x12: "IRP_MJ_CLEANUP",
        0x13: "IRP_MJ_CREATE_MAILSLOT",
        0x14: "IRP_MJ_QUERY_SECURITY",
        0x15: "IRP_MJ_SET_SECURITY",
        0x16: "IRP_MJ_POWER",
        0x17: "IRP_MJ_SYSTEM_CONTROL",
        0x18: "IRP_MJ_DEVICE_CHANGE",
        0x19: "IRP_MJ_QUERY_QUOTA",
        0x1a: "IRP_MJ_SET_QUOTA",
        0x1b: "IRP_MJ_PNP",
    }
    return IrpMajorTypes.get(i, "")



def PrepareRequest(dwType, *args):
    j = {
        "header": {},
        "body":{
            "type": dwType.value,
        }
    }
    data_length = 0
    data = b""
    for arg in args:
        data_length += len(arg)
        data += arg
    j["body"]["data_length"] = data_length
    j["body"]["data"] = base64.b64encode(data).decode("utf-8")
    return json.dumps(j).encode("ascii")



class BrokerSession:

    def OpenPipe(self):
        raise NotImplementedError("OpenPipe() must be redefined")

    def ClosePipe(self):
        raise NotImplementedError("ClosePipe() must be redefined")

    def sr(self, _type, *args):
        raise NotImplementedError("sr() must be redefined")

    def EnumerateDrivers(self):
        js = self.sr(TaskType.EnumerateDrivers)
        ok("EnumerateDrivers -> " + json.dumps(js, indent=4, sort_keys=True))

    def HookDriver(self, driver_name):
        lpszDriverName = driver_name.encode("utf-16")[2:]
        res = self.sr(TaskType.HookDriver, lpszDriverName)
        ok("hook -> " + json.dumps(res, indent=4, sort_keys=True))

    def UnhookDriver(self, driver_name):
        lpszDriverName = driver_name.encode("utf-16")[2:]
        res = self.sr(TaskType.UnhookDriver, lpszDriverName)
        ok("unhook -> " + json.dumps(res, indent=4, sort_keys=True))

    def EnableMonitoring(self):
        res = self.sr(TaskType.EnableMonitoring)
        ok("enable_monitoring -> " + json.dumps(res, indent=4, sort_keys=True))

    def DisableMonitoring(self):
        res = self.sr(TaskType.DisableMonitoring)
        ok("disable_monitoring -> " + json.dumps(res, indent=4, sort_keys=True))

    def GetInterceptedIrps(self):
        res = self.sr(TaskType.GetInterceptedIrps)
        # sanitize some fields
        for i in range(res["body"]["nb_entries"]):
            res["body"]["entries"][i]["header"]["DeviceName"] = "{}".format("".join(map(chr, res["body"]["entries"][i]["header"]["DeviceName"])))
            res["body"]["entries"][i]["header"]["DriverName"] = "{}".format("".join(map(chr, res["body"]["entries"][i]["header"]["DriverName"])))
            res["body"]["entries"][i]["header"]["ProcessName"] = "{}".format("".join(map(chr, res["body"]["entries"][i]["header"]["ProcessName"])))
        return res





class BrokerTcpSession(BrokerSession):
    def __init__(self, host, port):
        import signal
        self.hSock = None
        self.host = host
        self.port = port
        self.dwTimeout = 20
        signal.signal(signal.SIGALRM, self.throw_timeout_exception)
        return

    def throw_timeout_exception(self, signum, frame):
        import socket, errno, os
        raise socket.timeout(os.strerror(errno.ETIME))

    def sr(self, _type, *args):
        import signal
        ## send
        req = PrepareRequest(_type, *args)
        signal.alarm(self.dwTimeout)
        ret = self.hSock.sendall(req)
        signal.alarm(0)
        assert ret is None

        ## recv response
        signal.alarm(self.dwTimeout)
        res = b""
        while True:
            # fucking ip fragmentation
            res += self.hSock.recv(MAX_MESSAGE_SIZE)
            assert res is not None
            res = res[::]
            try:
                js = json.loads(res)
                return js
            except Exception as e:
                #err("Exception {:s} when parsing '''\n{:s}\n'''".format(str(e),res.decode("utf-8")))
                pass

    def OpenPipe(self):
        import signal
        self.hSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.hSock.connect( (self.host, self.port) )
        ok("tcp socket connected")
        return

    def ClosePipe(self):
        self.hSock.close()
        ok("tcp socket disconnect")
        return


def PopulateDb(irps):
    db_path = "/tmp/irps.sqlite"
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("""
CREATE TABLE IF NOT EXISTS Irps (
    TimeStamp integer,
    IrqLevel integer,
    Type integer,
    IoctlCode integer,
    Status integer,
    ProcessId integer NOT NULL,
    ThreadId integer NOT NULL,
    InputBufferLength integer,
    OutputBufferLength integer,
    DriverName text NOT NULL,
    DeviceName text NOT NULL,
    ProcessName text NOT NULL,

    InputBuffer blob,
    OutputBuffer blob
)
""")
    conn.commit()

    body = irps["body"]
    entries = body["entries"]
    for i in range(body["nb_entries"]):
        entry = entries[i]
        values = [
            convert_GetSystemTime(entry["header"]["TimeStamp"]).strftime("%s"),
            entry["header"]["Irql"],
            entry["header"]["Type"],
            entry["header"]["IoctlCode"],
            entry["header"]["Status"],
            entry["header"]["Pid"],
            entry["header"]["Tid"],
            entry["header"]["InputBufferLength"],
            entry["header"]["OutputBufferLength"],
            entry["header"]["DriverName"],
            entry["header"]["DeviceName"],
            entry["header"]["ProcessName"],
            bytearray(entry["body"]["InputBuffer"]),
            bytearray(entry["body"]["OutputBuffer"]),
        ]
        c.execute("INSERT INTO Irps VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", values)

    conn.commit()
    conn.close()
    return True


def run_forever(r):
    while True:
        try:
            irps = r.GetInterceptedIrps()
            if irps["body"]["nb_entries"]:
                ok("got %d irps" % irps["body"]["nb_entries"])
                PopulateDb(irps)
            time.sleep(0.5)
        except KeyboardInterrupt:
            break
    return


def capture(r, driver_list):
    r.OpenPipe()
    #r.EnumerateDrivers()
    #for driver_name in driver_list: r.HookDriver(driver_name)

    #r.EnableMonitoring()
    #ok("EnableMonitoring() success")

    #run_forever()

    #ok("GetInterceptedIrps() success")
    r.DisableMonitoring()
    #ok("DisableMonitoring() success")

    for driver_name in driver_list: r.UnhookDriver(driver_name)

    #ok("UnhookDriver() success")
    r.ClosePipe()
    #ok("ClosePipe() success")
    return




if __name__ == '__main__':

    if len(sys.argv) != 3:
        err(f"invalid syntax: {sys.argv[0]} ip port")
        sys.exit(1)

    ok("connecting to {:s}:{:d}".format(sys.argv[1], int(sys.argv[2]) ))
    r = BrokerTcpSession( sys.argv[1], int(sys.argv[2]) )

    capture(r, [
        ## windows
        #"\\driver\\lxss\0",
        #"\\driver\\condrv\0",
        #"\\driver\\win32k\0",
        #"\\driver\\kbdclass\0",
        #"\\driver\\tdx\0",
        #"\\filesystem\\netbios\0",
        #"\\filesystem\\luafv\0",

        ## hv
        #"\\driver\\vmbus\0",
        #"\\driver\\vmssnpxy\0",
        #"\\driver\\vmssp\0",
        #"\\driver\\vmsproxy\0",

        ## hmp
        # "\\driver\\hmpalert\0",
        # "\\driver\\hitmanpro37\0",

        ## iobit mf
        # "\\filesystem\\IMFDownProtect\0",
        # "\\filesystem\\IMFFilter\0",
        # "\\driver\\IMFObCallback\0",
        # "\\driver\\IMFForceDelete\0",

        ## sav
        "\\driver\\hitmanpro37\0",
        "\\driver\\hmpalert\0",
        "\\driver\\hmpnet\0",
        "\\filesystem\\SAVOnAccess\0",
        "\\filesystem\\Sophos Endpoint Defense\0",

    ] )

    sys.exit(0)
