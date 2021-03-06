#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
EXTERNAL FILTER for Communigate Pro Server.

The plugin is designed to integrate with DrWeb virus and spam detection services via Rspamd HTTP protocol
The plugin is launched in CommuniGate Pro as External Filters.

Tested with:
  drweb-mail-servers 11.1.0-1902252019
  Communigate Pro v.6.0.11
  Communigate Pro v.6.2.12


MIT License

Copyright (c) 2019 Alexander Morokov

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import os
import io
import re
import sys
import math
import fcntl
import select
import signal
import socket
import json
import http.client
from multiprocessing import Process
from traceback import format_exc
from typing import BinaryIO

__author__ = "Alexander Morokov"
__copyright__ = "Copyright 2019, https://github.com/delatars/CgpDrweb"

__license__ = "MIT"
__version__ = "1.9"
__email__ = "morocov.ap.muz@gmail.com"


# ################### SETTINGS ###########################

# Set socket on which drweb Rspamd HTTP listen (drweb-ctl cfshow maild.rspamdhttpsocket --value)
# Examples:
#   tcp socket: 127.0.0.1:8020
#   unix socket: /tmp/drweb.socket
RSPAMD_HTTP_SOCKET = "127.0.0.1:8020"
# Communigate pro working directory
CGP_PATH = "/var/CommuniGate"

# show debug info
DEBUG = False

# ########################################################

# stdin listener pid
_MAIN_PROCESS_PID = os.getpid()


def print(message, on_debug=False):
    """
    Override built-in print function, to add comments symbol, and flush.

    From Communigate Pro Docs:
    An information response starts with the asterisk (*) symbol.
     The Server ignores information responses, but they can be seen in the Server Log.
    """
    if on_debug and not DEBUG:
        return
    if not isinstance(message, str):
        message = str(message)
    sys.stdout.write("* " + repr(message) + "\r\n")
    sys.stdout.flush()


def ServerSendResponse(seqnum, command, arguments=[] or ""):
    """ Function Send response to Communigate Pro Server via Helper protocol """
    if isinstance(arguments, list):
        arguments = " ".join([argument.strip() for argument in arguments])
    response = f"{str(seqnum).strip()} {command.strip()} {arguments.strip()}\r\n"
    if len(response) > 4096:
        print("Error: response length greater then 4096 bytes")
    sys.stdout.write(response)
    sys.stdout.flush()


class RspamdHttpConnector:

    def __init__(self, connection_string):
        self._connection_string = connection_string
        self._connector = self._get_connector()
        self._headers = [
            ("Host", self._connection_string),
            ("Accept-Encoding", "identity"),
            ("User-Agent", "CGP-DrWeb-Rspamd-plugin"),
            ("Content-Type", "application/x-www-form-urlencoded")
        ]
        self.msg_id = None

    def _get_bytes_from_objects(self, _object, encoding="utf8"):
        """ Detect object and read bytes from it. """
        if os.path.isfile(_object):
            with open(_object, "rb") as eml:
                return eml.read()
        if isinstance(_object, io.BufferedReader):
            data = _object.read()
            if isinstance(data, str):
                data = data.encode(encoding)
            return data
        elif isinstance(_object, bytes):
            return _object
        elif isinstance(_object, str):
            return _object.encode(encoding)
        else:
            raise NotImplementedError(f"Unknown object: {type(_object)}")

    def _get_connector(self):
        """ Get connector based on RSPAMD_HTTP_SOCKET to communicate with Rspamd """
        tcp = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}")
        if re.match(tcp, self._connection_string):
            return self._tcp_connector
        else:
            return self._unix_connector

    def _tcp_connector(self, message):
        """ : param message: bytes """
        host, port = self._connection_string.split(":")
        self.add_header("Content-Length", len(message))
        con = http.client.HTTPConnection(host, int(port))
        con.connect()
        laddr, raddr = con.sock.getsockname(), con.sock.getpeername()
        print(f"{self.msg_id}: {laddr} -> {raddr}: Connected to maild.", on_debug=True)
        con.putrequest("POST", "/checkv2")
        for header in self._headers:
            con.putheader(header[0], header[1])
        con.endheaders()
        print(f"{self.msg_id}: {laddr} -> {raddr}: Send message to maild.", on_debug=True)
        con.send(message)
        print(f"{self.msg_id}: {laddr} <- {raddr}: Waiting for response from maild.", on_debug=True)
        response = con.getresponse()
        rspamd_result = response.read()
        con.close()
        if not rspamd_result:
            return {"error": "Error: Rspamd server is not responding"}
        return json.loads(rspamd_result)

    def _unix_connector(self, message):
        """ : param message: bytes """
        CRLF = "\r\n"
        init_line = ["POST /checkv2 HTTP/1.1"]
        self.add_header("Content-Length", len(message))
        headers = init_line + [f"{header[0]}: {header[1]}" for header in self._headers]
        headers = (CRLF.join(headers) + 2*CRLF).encode("utf8")

        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.connect(self._connection_string)
        raddr = client.getpeername()
        print(f"{self.msg_id}: localhost -> {raddr}: Connected to maild.", on_debug=True)
        print(f"{self.msg_id}: localhost -> {raddr}: Send message to maild.", on_debug=True)
        client.send(headers + message)
        print(f"{self.msg_id}: localhost <- {raddr}: Waiting for response from maild.", on_debug=True)
        rspamd_result = client.recv(1024)
        if not rspamd_result:
            return {"error": "Error: Rspamd server is not responding"}
        headers, body = rspamd_result.decode("utf8").split("\r\n\r\n")
        client.close()
        return json.loads(body)

    def add_header(self, name, value):
        """ Add header to HTTP headers list """
        if isinstance(value, (tuple, list)):
            for val in value:
                self._headers.append((str(name).strip(), str(val).strip()))
        else:
            self._headers.append((str(name).strip(), str(value).strip()))

    def check_message(self, message):
        """
        Check message via Rspamd HTTP protocol.

        : param message: str, fileobject, bytes, path
            Message to check via Rspamd.
        """
        data = self._get_bytes_from_objects(message)
        rspamd_check = self._connector
        result = rspamd_check(data)
        return result

    def test_connection(self):
        """ Testing connection via gotten connector """
        if self._connector.__name__ == "_tcp_connector":
            try:
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                ip, port = self._connection_string.split(":")
                client.connect((ip, int(port)))
                client.close()
                return True
            except Exception as err:
                print(f"Error: Cannot connect to Rspamd: {err} : {RSPAMD_HTTP_SOCKET}")
                return False
        else:
            try:
                client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                client.connect(self._connection_string)
                client.close()
                return True
            except Exception as err:
                print(f"Error: Cannot connect to Rspamd: {err} : {RSPAMD_HTTP_SOCKET}")
                return False


class CgpServerRequestExecute:
    """
    Callable class take a server request as argument, parse and execute corresponding callback.

    http://www.communigate.com/CommuniGatePro/Helpers.html#Protocol
    Communigate server helper protocol request format:
        <seqnum> <command> <arguments>

    New callback names must match server commands, and take to positional arguments (seqnum, arguments)

    def INTF(self, seqnum, arguments)
        ...
    """
    __PROTOCOL_VERSION = 4

    def __call__(self, data):
        try:
            seqnum, command, arguments = self._protocol_parser(data)
        except IndexError:
            print(f"Can't parse: {data}", on_debug=True)
            print("Bad Syntax: <seqnum> <command> <parameters> expected.")
        else:
            self._executor(seqnum, command, arguments)

    def _executor(self, seqnum, command, arguments):
        """ Get command and execute corresponding callback """
        print(f"{seqnum}: Received request: {command} {arguments}", on_debug=True)
        try:
            method = getattr(self, command)
        except AttributeError:
            print(f"Error: Unknown command: {command}")
            return
        try:
            method(seqnum, arguments)
        except Exception as err:
            if DEBUG:
                print(f"Callback Error: {method.__name__} : {format_exc()}")
            else:
                print(f"Callback Error: {method.__name__} : {err}")
            ServerSendResponse(seqnum, "OK")

    def _parse_envelope(self, envelope: list):
        """
        Parse Communigate Pro message envelope and return dict with:
            - from
            - rcpts
            - ip
        """
        result = {
            "from": "",
            "rcpts": [],
            "ip": ""
        }
        rcpts = []
        for line in envelope:
            # From line
            if line.startswith("P "):
                mail_from = re.findall(r"^P\s[^<]*<([^>]*)>.*$", line)
                if mail_from:
                    result["from"] = mail_from[0]
            # Rcpt line
            elif line.startswith("R "):
                rcpt = re.findall(r"^R\s[^<]*<([^>]*)>.*$", line)
                if rcpt:
                    rcpts += rcpt
            # Sender info line
            elif line.startswith("S "):
                ip = re.findall(r"^S .*\[([0-9a-f.:]+)\]", line)
                if ip:
                    result["ip"] = ip[0]
        result["rcpts"] = rcpts
        return result

    def _parse_cgp_message(self, message: BinaryIO):
        """
        Parse Communigate Pro message and return parsed envelope and message bytes.
        Parsed envelope is a dict with keys:
         - From
         - Rcpts
         - Ip

        Communigate Pro add envelope to messages:
        <envelope>
        S <user1@test.test> SMTP [10.4.0.159]
        A testlab1.test [10.21.2.87]
        O L
        P I 26-04-2019 15:57:14 0000 ____ ____ <user1@test.test>
        R W 26-04-2019 15:57:14 0000 ____ _FY_ <user3@test.test>
        ...
        <end envelope>

        <message>
        ...
        <end message>

        """
        def read_envelope():
            while 1:
                line = message.readline()
                if line == b"\n" or b"":
                    return None
                yield line

        envelope = []
        for lin in read_envelope():
            if lin is None:
                break
            envelope.append(lin.decode('utf8'))  # guess cgp save envelope in utf8
        parsed_envelope = self._parse_envelope(envelope)
        message = message.read()
        return parsed_envelope, message

    def _protocol_parser(self, data):
        """
        CGP Helper protocol conversation example:
                O: * My Helper program started
                I: 00001 INTF 1
                O: 00001 INTF 1
                I: 00002 COMMAND parameters
                O: 00002 OK
                I: 00003 COMMAND parameters
                I: 00004 COMMAND parameters
                O: * processing 00003 will take some time
                O: 00004 ERROR description
                O: 00003 OK
                I: 00005 QUIT
                O: * processed: 5 requests. Quitting.
                O: 00005 OK
                I: stdin closed
        """
        data = data.strip().split(" ")
        seqnum = data[0]
        command = data[1]
        arguments = data[2:]
        return seqnum, command, arguments

    def _return_headers_from_rspamd_symbols(self, symbols):
        """
        Get symbols json and return iterated headers list.

        : param symbols: json

        : return: list
            [X-Spam-Symbol-1: ..., X-Spam-Symbol-2: ..., X-Spam-Symbol-3: ...]
        """
        headers = []
        for value in enumerate(symbols.values()):
            header = f"X-Spam-Symbol-{value[0]+1}"
            value = f"{value[1]['name']} ({value[1]['score']}) {value[1].get('description', '')}"
            headers.append(f"{header}: {value}")
        return headers

    def _return_optional_headers(self, rspamd_result):
        result = []
        action = [f"X-Spam-Action: {rspamd_result.get('action')}"] if rspamd_result.get('action') else []
        symbols = self._return_headers_from_rspamd_symbols(rspamd_result.get('symbols', {}))
        result += action + symbols
        return result

    def INTF(self, seqnum, arguments):
        """ Communigate Pro INTF command.
        return a protocol version """
        ServerSendResponse(seqnum, "INTF", str(self.__PROTOCOL_VERSION))

    def QUIT(self, seqnum, arguments):
        """ Communigate Pro QUIT command.
        Stops the helper. """
        print(f"CGP DrWeb Rspamd plugin version {__version__} stopped")
        ServerSendResponse(seqnum, "OK")
        os.kill(_MAIN_PROCESS_PID, signal.SIGTERM)

    def FILE(self, seqnum, arguments):
        """ Communigate Pro FILE command.
        http://www.communigate.com/CommuniGatePro/Helpers.html#Filters
        Server sends:
                seqNum FILE fileName

        Responses Format:
                seqNum [ modifiers ] OK

        available modifiers:
            - seqNum ADDHEADER header-field-text OK
            - seqNum MIRRORTO address OK
            - seqNum ADDROUTE address OK

        available responses:
            - seqNum ERROR report
            - seqNum DISCARD
            - seqNum REJECTED report
            - seqNum FAILURE
        """

        if not arguments:
            print("Error: FILE command requires <parameter>.")
            return
        # arguments[0] = Queue/nnnnn.msg or Queue/01-09/nnnnn.msg

        Rspamd = RspamdHttpConnector(RSPAMD_HTTP_SOCKET)
        Rspamd.msg_id = seqnum
        # If CGP message parse it
        if re.match(r"^Queue/.*\.msg", arguments[0]):
            with open(os.path.join(CGP_PATH, arguments[0]), "rb") as msg:
                print(f"{seqnum}: Parse message: {msg.name}", on_debug=True)
                envelope, message = self._parse_cgp_message(msg)
                # add headers to HTTP request
                Rspamd.add_header("From", envelope['from'])
                Rspamd.add_header("Rcpt", envelope['rcpts'])
                Rspamd.add_header("Ip", envelope['ip'])
        # Condition for testing purposes
        else:
            with open(arguments[0], "rb") as msg:
                print(f"{seqnum}: Parse message: {msg.name}", on_debug=True)
                message = msg.read()

        # Check message and get a json result
        rspamd_result = Rspamd.check_message(message)
        # If rspamd can't check mail return OK response and print error to CGP log
        if rspamd_result.get('error', False):
            print(rspamd_result['error'])
            ServerSendResponse(seqnum, "OK")
            return
        # adding headers to message
        spam_score = rspamd_result.get('score', 'error')
        junk_score = lambda score: "X" * (math.frexp(score)[1]-4)
        mandatory_headers = [
            f"X-Spam-Score: {spam_score}",
            f"X-Spam-Threshold: {rspamd_result.get('required_score', 'error')}",
            f"X-Junk-Score: {junk_score(spam_score)}",
        ]
        optional_headers = self._return_optional_headers(rspamd_result)
        result_headers = mandatory_headers + optional_headers
        wrapped_headers = '\"' + "\e".join(result_headers) + '\"'
        ServerSendResponse(seqnum, "ADDHEADER", [wrapped_headers, "OK"])


class ProcessExecutor:

    def __init__(self):
        self.workers = {}

    def clean(self):
        """ Exit from all completed processes """
        for fd, process in dict(self.workers).items():
            if not process.is_alive():
                process.join()
                del self.workers[fd]

    def add_worker(self, process: Process):
        self.workers[process.sentinel] = process

    def submit(self, func, *args):
        scan_process = Process(target=func, args=args)
        scan_process.daemon = True
        scan_process.start()
        self.add_worker(scan_process)


class StdinListener:

    def __init__(self, on_stdin_callback, executor):
        if sys.platform.startswith('linux'):
            self.poll_impl = self._epoll
        elif sys.platform.startswith(('dragonfly', 'freebsd', 'netbsd', 'openbsd', 'bsd')):
            self.poll_impl = self._kqueue
        elif sys.platform.startswith('darwin'):
            self.poll_impl = self._kqueue
        else:
            print(f"Error: Unsupported platform: {sys.platform}")
        self.executor = executor
        self._futures = []
        self._fd = sys.stdin.fileno()
        self.on_stdin_callback = on_stdin_callback
        fl = fcntl.fcntl(self._fd, fcntl.F_GETFL)
        fcntl.fcntl(self._fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

    def _epoll(self):
        epoll = select.epoll()
        epoll.register(self._fd, select.EPOLLIN)
        try:
            while True:
                events = epoll.poll(10)
                for fileno, event in events:
                    data = sys.stdin.readline()
                    self.executor.submit(self.on_stdin_callback, data)
                self.executor.clean()
        finally:
            epoll.unregister(self._fd)
            epoll.close()

    def _kqueue(self):
        fd = sys.stdin.fileno()
        fl = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

        KQ_EV_FLAGS = select.KQ_EV_ADD | select.KQ_EV_ENABLE | select.KQ_EV_CLEAR
        kev = select.kevent(fd, filter=select.KQ_FILTER_READ, flags=KQ_EV_FLAGS)
        kq = select.kqueue()
        try:
            while 1:
                kevents = kq.control((kev,), 4096, 0.01)
                for kevent in kevents:
                    data = sys.stdin.readline()
                    self.executor.submit(self.on_stdin_callback, data)
                self.executor.clean()
        finally:
            kq.close()

    def start_polling(self):
        print(f"CGP DrWeb Rspamd plugin version {__version__} started")
        self.poll_impl()


if __name__ == "__main__":
    # Check connection before start
    if not RspamdHttpConnector(RSPAMD_HTTP_SOCKET).test_connection():
        exit(1)
    stdin_listener = StdinListener(CgpServerRequestExecute(), ProcessExecutor())
    try:
        stdin_listener.start_polling()
    except KeyboardInterrupt:
        exit(0)
