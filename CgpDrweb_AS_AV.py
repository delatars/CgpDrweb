#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
EXTERNAL FILTER for Communigate Pro Server.

The plugin is designed to integrate with DrWeb virus and spam detection services via Rspamd HTTP protocol
The plugin is launched in CommuniGate Pro as External Filters.

Tested with:
  drweb-mail-servers 11.1.0-1902252019
  Communigate Pro 6.2.12


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

__author__ = "Alexander Morokov"
__copyright__ = "Copyright 2019, https://github.com/delatars/CgpDrweb"

__license__ = "MIT"
__version__ = "1.0"
__email__ = "morocov.ap.muz@gmail.com"


# ################### SETTINGS ###########################

# Set socket on which drweb Rspamd HTTP listen (drweb-ctl cfshow maild.rspamdhttpsocket --value)
# Examples:
#   tcp socket: 127.0.0.1:8020
#   unix socket: /tmp/drweb.socket
RSPAMD_SOCKET = "127.0.0.1:8020"
# Communigate pro working directory
CGP_PATH = "/var/CommuniGate"

# ########################################################

# stdin listener pid
_MAIN_PROCESS_PID = os.getpid()


def print(message):
    """
    Override built-in print function, to add comments symbol, and flush.

    From Communigate Pro Docs:
    An information response starts with the asterisk (*) symbol.
     The Server ignores information responses, but they can be seen in the Server Log.
    """
    if not isinstance(message, str):
        message = str(message)
    sys.stdout.write("* " + repr(message) + "\r\n")
    sys.stdout.flush()


def ServerSendResponse(seqnum, command, arguments=[] or ""):
    """ Function Send response to Communigate Pro Server via Helper protocol """
    if isinstance(arguments, list):
        arguments = " ".join([argument.strip() for argument in arguments])
    response = "%s %s %s\r\n" % (str(seqnum).strip(), command.strip(), arguments.strip())
    if len(response) > 4096:
        print("Error: response length greater then 4096 bytes")
    sys.stdout.write(response)
    sys.stdout.flush()


class RspamdHttpConnector:

    def __init__(self, connection_string):
        self._connection_string = connection_string
        self._connector = self._get_connector()
        self._headers = [
            ("Host", "%s" % self._connection_string),
            ("Accept-Encoding", "identity"),
            ("User-Agent", "CGP-DrWeb-Rspamd-plugin"),
            ("Content-Type", "application/x-www-form-urlencoded")
        ]

    def _get_bytes_from_objects(self, _object):
        """ Detect object and read bytes from it. """
        if os.path.isfile(_object):
            with open(_object, "rb") as eml:
                return eml.read()
        if isinstance(_object, io.BufferedReader):
            data = _object.read()
            if isinstance(data, str):
                data = data.encode("utf8")
            return data
        elif isinstance(_object, bytes):
            return _object
        elif isinstance(_object, str):
            return _object.encode("utf8")
        else:
            raise NotImplementedError("Unknown object: %s" % type(_object))

    def _get_connector(self):
        """ Get connector based on RSPAMD_SOCKET to communicate with Rspamd """
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
        con.putrequest("POST", "/checkv2")
        for header in self._headers:
            con.putheader(header[0], header[1])
        con.endheaders()
        con.send(message)
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
        headers = init_line + ["%s: %s" % (header[0], header[1]) for header in self._headers]
        headers = (CRLF.join(headers) + 2*CRLF).encode("utf8")

        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.connect(self._connection_string)
        client.send(headers + message)
        rspamd_result = client.recv(1000)
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
                print("Error: Cannot connect to Rspamd: %s : %s" % (err, RSPAMD_SOCKET))
                return False
        else:
            try:
                client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                client.connect(self._connection_string)
                client.close()
                return True
            except Exception as err:
                print("Error: Cannot connect to Rspamd: %s : %s" % (err, RSPAMD_SOCKET))
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
        seqnum, command, arguments = self._protocol_parser(data)
        self._executor(seqnum, command, arguments)

    def _executor(self, seqnum, command, arguments):
        """ Get command and execute corresponding callback """
        try:
            method = getattr(self, command)
        except AttributeError:
            print("Error: Unknown command: %s" % command)
            method = getattr(self, "_NULL")
        try:
            method(seqnum, arguments)
        except Exception as err:
            print("Callback Error: %s : %s" % (method.__name__, err))
            ServerSendResponse(seqnum, "OK")

    def _parse_envelope(self, envelope):
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
        envelope = envelope.split("\n")
        for line in envelope:
            # From line
            if line.startswith("P "):
                mail_from = re.findall(r"^P\s[^<]*<([^>]*)>.*$", line)
                assert mail_from != []
                result["from"] = mail_from[0]
            # Rcpt line
            elif line.startswith("R "):
                rcpt = re.findall(r"^R\s[^<]*<([^>]*)>.*$", line)
                assert rcpt != []
                rcpts += rcpt
            # Sender info line
            elif line.startswith("S "):
                ip = re.findall(r"^S .*\[([0-9a-f.:]+)\]", line)
                assert ip != []
                result["ip"] = ip[0]
        result["rcpts"] = rcpts
        return result

    def _parse_cgp_message(self, message):
        """
        Split Communigate Pro message and return parsed envelope and message.
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

        :type message: str
        :return: envelope: dict : message: str
        """
        split_index = message.find("\n\n")
        envelope = message[:split_index]
        parsed_envelope = self._parse_envelope(envelope)
        message = message[split_index+2:]
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
        try:
            seqnum = data[0]
            command = data[1]
            arguments = data[2:]
        except IndexError:
            print("Bad Syntax: <seqnum> <command> <parameters> expected.")
            seqnum = ""
            command = "_NULL"
            arguments = ""
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
            header = "X-Spam-Symbol-%s" % (value[0]+1)
            value = "%s (%s) %s" % (value[1]["name"], value[1]["score"], value[1].get("description", ""))
            headers.append("%s: %s" % (header, value))
        return headers

    def _return_optional_headers(self, rspamd_result):
        result = []
        action = ["X-Spam-Action: %s" % rspamd_result.get("action")] if rspamd_result.get("action") else []
        symbols = self._return_headers_from_rspamd_symbols(rspamd_result.get("symbols", {}))
        result += action + symbols
        return result

    def _NULL(self, seqnum, arguments):
        """ void callback """
        pass

    def INTF(self, seqnum, arguments):
        """ Communigate Pro INTF command.
        return a protocol version """
        ServerSendResponse(seqnum, "INTF", str(self.__PROTOCOL_VERSION))

    def QUIT(self, seqnum, arguments):
        """ Communigate Pro QUIT command.
        Stops the helper. """
        print("CGP DrWeb Rspamd plugin version 1.0 stopped")
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

        if arguments == []:
            print("Error: FILE command requires <parameter>.")
            return
        # arguments[0] = Queue/nnnnn.msg or Queue/01-09/nnnnn.msg

        Rspamd = RspamdHttpConnector(RSPAMD_SOCKET)
        # If CGP message parse it
        if re.match(r"^Queue/.*\.msg", arguments[0]):
            with open(os.path.join(CGP_PATH, arguments[0]), "r") as msg:
                message = msg.read()
                envelope, message = self._parse_cgp_message(message)
                # add headers to HTTP request
                Rspamd.add_header("From", envelope["from"])
                Rspamd.add_header("Rcpt", envelope["rcpts"])
                Rspamd.add_header("Ip", envelope["ip"])
        # Condition for testing purposes
        else:
            with open(arguments[0], "r") as msg:
                message = msg.read()

        # Check message and get a json result
        rspamd_result = Rspamd.check_message(message)
        # If rspamd can't check mail return OK response and print error to CGP log
        if rspamd_result.get("error", False):
            print(rspamd_result["error"])
            ServerSendResponse(seqnum, "OK")
            return
        # adding headers to message
        spam_score = rspamd_result.get("score", "error")
        junk_score = lambda score: "X" * (math.frexp(score)[1]-4)
        mandatory_headers = [
            "X-Spam-Score: %s" % spam_score,
            "X-Spam-Threshold: %s" % rspamd_result.get("required_score", "error"),
            "X-Junk-Score: %s" % junk_score(spam_score),
        ]
        optional_headers = self._return_optional_headers(rspamd_result)
        result_headers = mandatory_headers + optional_headers
        wrapped_headers = '\"' + "\e".join(result_headers) + '\"'
        ServerSendResponse(seqnum, "ADDHEADER", [wrapped_headers, "OK"])


def start():
    """ Function start a non-blocking stdin listener """
    print("CGP DrWeb Rspamd plugin version %s started" % __version__)
    fd = sys.stdin.fileno()
    fl = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

    epoll = select.epoll()
    epoll.register(fd, select.EPOLLIN)
    try:
        while True:
            events = epoll.poll(1)
            for fileno, event in events:
                data = sys.stdin.readline()
                ServerExec = CgpServerRequestExecute()
                p = Process(target=ServerExec, args=(data,))
                p.daemon = True
                p.start()
    finally:
        epoll.unregister(fd)
        epoll.close()


if __name__ == "__main__":
    # Check connection before start
    if not RspamdHttpConnector(RSPAMD_SOCKET).test_connection():
        exit(1)
    try:
        start()
    except KeyboardInterrupt:
        exit(0)
