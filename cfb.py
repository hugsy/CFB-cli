#!/usr/bin/env python3.8

from __future__ import unicode_literals

import sys
import socket
import struct
import datetime

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter, NestedCompleter
from prompt_toolkit.lexers import PygmentsLexer
from prompt_toolkit.styles import Style
from pygments.lexers.shell import BashSessionLexer

def u8 (x: bytearray) -> int: return struct.unpack("<B", x)[0]
def u16(x: bytearray) -> int: return struct.unpack("<H", x)[0]
def u32(x: bytearray) -> int: return struct.unpack("<I", x)[0]
def u64(x: bytearray) -> int: return struct.unpack("<Q", x)[0]

def p8 (x: int) -> bytearray: return struct.pack("<B", x)
def p16(x: int) -> bytearray: return struct.pack("<H", x)
def p32(x: int) -> bytearray: return struct.pack("<I", x)
def p64(x: int) -> bytearray: return struct.pack("<Q", x)



def convert_GetSystemTime(t: int) -> datetime.datetime:
    """
    Convert NTFS timestamp returned by GetSystemTime() to a datetime object
    """
    unix_ts = (t / 10000000) - 11644473600
    return datetime.datetime.fromtimestamp(unix_ts)



def hexdump(source:bytearray, length:int=0x10, separator:str=".", base:int=0x00, align:int=10) -> str:
    result = []
    for i in range(0, len(source), length):
        chunk = bytearray(source[i:i + length])
        hexa = " ".join(["%.02x" % b for b in chunk])
        text = "".join([chr(b) if 0x20 <= b < 0x7F else separator for b in chunk])
        msg = "{addr:#0{aw}x}     {data:<{dw}}    {text}".format(aw=align,addr=base+i,dw=3*length,data=hexa,text=text)
        result.append(msg)
    return "\n".join(result)



cfb_completer = NestedCompleter.from_nested_dict({
    'connect': None, 'disconnect': None, 'reconnect': None,
    'hook': None, 'unhook': None,
    'start-monitoring': None, 'stop-monitoring': None,
    'save': None, 'exit': None,
    # commands handled strictly by the broker
    'list-drivers': None, 'replay-irp': None, 'get-irps': None
})



class Session:
    """
    Defines a session to the CFB broker
    """
    is_connected : bool
    host : str
    port : int
    __prompt: str
    cli : PromptSession


    def __init__(self, host:str, port:int, cli:PromptSession) -> None:
        self.host = host
        self.port = port
        self.cli = cli
        self.__sock = None
        self.__prompt = "cfb► "
        self.connect()
        return


    def __del__(self) -> None:
        if self.is_connected:
            self.disconnect()
        return


    def connect(self) -> bool:
        self.hSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.hSock.connect(self.host, self.port)
            return True
        except socket.error:
            return False


    def disconnect(self) -> bool:
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
        return self.__sock is not None


    def is_connected_str(self) -> str:
        return "✔️" if self.is_connected else "❌"


    def prompt(self) -> str:
        cmd = self.cli.prompt(self.is_connected_str() + self.__prompt)
        return cmd



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
            text = sess.prompt()
            print(text)
        except KeyboardInterrupt:
            continue
        except EOFError:
            break

    print('GoodBye!')
    return


if __name__ == '__main__':
    if len(sys.argv) != 3:
        host, port = "10.0.0.63", 1337
    else:
        host, port = sys.argv[1], int(sys.argv[2])

    main(host, port)