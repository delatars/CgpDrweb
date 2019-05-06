#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import io
import re
import sys
import fcntl
import select
import signal
import socket
import json
import urllib.request
from multiprocessing import Process


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
    """ Override built-in print function, to add comments symbol, and flush.

    From Communigate Pro Docs:
    An information response starts with the asterisk (*) symbol.
     The Server ignores information responses, but they can be seen in the Server Log.
    """
    sys.stdout.write("* " + message + "\r\n")
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
        rest_url = "http://%s/checkv2" % self._connection_string
        with urllib.request.urlopen(rest_url, message) as response:
            rspamd_result = response.read()
        return json.loads(rspamd_result)

    def _unix_connector(self, message):
        """ : param message: bytes """
        CRLF = "\r\n"
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.connect(self._connection_string)
        content_length = len(message)
        headers = [
            "POST /checkv2 HTTP/1.1",
            "User-Agent: CGP-DrWeb-Rspamd-plugin",
            "Content-Type: application/x-www-form-urlencoded",
            "Content-Length: %s" % content_length
        ]
        headers = (CRLF.join(headers) + 2*CRLF).encode("utf8")
        client.send(headers + message + (2*CRLF).encode("utf8"))
        rspamd_result = client.recv(600)
        client.close()
        return json.loads(rspamd_result)

    def check_message(self, message):
        """ Check message via Rspamd HTTP protocol.

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
    """ Callable class take a server request as argument, parse and execute corresponding callback.

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

    def _message_delete_service_info(self, message):
        """ Delete service info and return message.
        Communigate Pro added a self service info to messages:

        S <user1@test.test> SMTP [10.4.0.159]
        A testlab1.test [10.21.2.87]
        O L
        P I 26-04-2019 15:57:14 0000 ____ ____ <user1@test.test>
        R W 26-04-2019 15:57:14 0000 ____ _FY_ <user3@test.test>

        ...
        <envelope>
        <message>
        """
        split_index = message.find("\n\n")
        return message[split_index+2:]

    def _protocol_parser(self, data):
        """ CGP Helper protocol conversation example:
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
            print("Bad Syntax: <seqnum> <command> <arguments> expected.")
            seqnum = ""
            command = "_NULL"
            arguments = ""
        return seqnum, command, arguments

    def _return_headers_from_rspamd_symbols(self, symbols):
        """ Get symbols json and return iterated headers list.

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
        Rspamd = RspamdHttpConnector(RSPAMD_SOCKET)
        # arguments[0] - Queue/nnnnn.msg
        if os.path.exists(os.path.join(CGP_PATH, arguments[0])):
            with open(os.path.join(CGP_PATH, arguments[0]), "r") as msg:
                message = msg.read()
                # Remove CGP service info
                message = self._message_delete_service_info(message)
        else:
            with open(arguments[0], "r") as msg:
                message = msg.read()
        # Check message and get a json result
        rspamd_result = Rspamd.check_message(message)
        # If rspamd can't check mail return OK respone and print error to CGP log
        if rspamd_result.get("error", False):
            print(rspamd_result["error"])
            ServerSendResponse(seqnum, "OK")
            return
        # adding headers to message
        new_headers = [
            "X-Spam-Score: %s" % rspamd_result["score"],
            "X-Spam-Threshold: %s" % rspamd_result["required_score"],
            "X-Spam-Action: %s" % rspamd_result["action"]
        ]
        symbols_headers = self._return_headers_from_rspamd_symbols(rspamd_result["symbols"])
        result_headers = new_headers + symbols_headers
        wrapped_headers = '\"' + "\e".join(result_headers) + '\"'
        ServerSendResponse(seqnum, "ADDHEADER", [wrapped_headers, "OK"])


def start():
    """ Function start a non-blocking stdin listener """
    print("CGP DrWeb Rspamd plugin version 1.0 started")
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
