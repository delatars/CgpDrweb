#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import string
import os
import re
from subprocess import PIPE, Popen
import random

# ################################## SETTINGS #####################################
CGP_PATH = "/var/CommuniGate"
SPAMC_BIN = "spamc"
CGP_IPC_DIR = os.path.join(CGP_PATH, "Submitted")
SPAMD_SERVER = "<SPAMD_IP>"
SPAMD_PORT = "<SPAMD_PORT>"
SPAMD_CONNECTION_TIMEOUT = 20
# ##################################################################################


class SpamdResult:

    def __init__(self):
        self.connection = False
        self.score = None
        self.threshold = None
        self.report = ""


class CgpHelper:

    def __init__(self, stdin):
        """ Get fileobject as argument"""
        self.spamd_result = SpamdResult()
        self._added_headers = []
        self._message = stdin.read()
        self._spamd_check()
        self._construct_message()

    def _construct_message(self):
        """ Construct message with added headers """
        headers = self._get_headers()
        added_headers = "".join(self._added_headers)
        body = self._get_body()
        # delimiter between headers and body
        delimiter = "\n\n"
        self._modified_message = headers + added_headers + delimiter + body

    def _get_headers(self):
        """ Get headers from message """
        split_index = self._message.find("\n\n")
        return self._message[: split_index]

    def _get_body(self):
        """ Get body from message """
        split_index = self._message.find("\n\n")
        return self._message[split_index+2:]

    def _spamd_check(self):
        """ Do request to spamd server via spamc utility and fill 'spamd_result' object """
        if not os.path.exists(SPAMC_BIN):
            raise Exception("Can't find spamc utility for path (%s)" % SPAMC_BIN)
        spamc = Popen([SPAMC_BIN, "-d", SPAMD_SERVER, "-p", str(SPAMD_PORT), "-t", str(SPAMD_CONNECTION_TIMEOUT), "-R"],
                      stdin=PIPE, stderr=PIPE, stdout=PIPE)
        spamc.stdin.write(self._message.encode("utf-8"))
        result, err = spamc.communicate()
        if len(err) > 0:
            raise Exception(err.decode("utf-8"))
        else:
            result = result.decode("utf-8")
        score = re.findall(r"^([\d.]+)/[\d.]+", result)[0]
        threshold = re.findall(r"^[\d.]+/([\d.]+)", result)[0]
        report = "\n".join(re.findall(r"\n(.*)", result))
        if score != "0" and threshold != "0":
            self.spamd_result.connection = True
            self.spamd_result.score = float(score)
            self.spamd_result.threshold = float(threshold)
            self.spamd_result.report = report

    def add_header(self, header, value):
        """ Method add header and reconstruct message """
        header = str(header).strip()
        value = str(value).strip()
        self._added_headers.append("\n%s: %s" % (header, value))
        self._construct_message()

    def proceed(self):
        """ Method return modified message to cgp queue """
        message_id = ''.join((random.choice(string.ascii_lowercase + string.digits)) for i in range(20))
        modified_message = "filtered_message_%s" % message_id
        with open(os.path.join(CGP_IPC_DIR, modified_message), "w") as tmp:
            tmp.write(self._modified_message)
        os.rename(os.path.join(CGP_IPC_DIR, modified_message), os.path.join(CGP_IPC_DIR, modified_message + ".sub"))


if __name__ == "__main__":
    # Get message from stdin
    message = sys.stdin
    # Create CgpHelper object and check message for spam
    cgp = CgpHelper(message)
    # Modify message by adding headers
    cgp.add_header("X-Spamd-Connection", cgp.spamd_result.connection)
    cgp.add_header("X-Spam-Score", cgp.spamd_result.score)
    cgp.add_header("X-Spam-Threshold", cgp.spamd_result.threshold)
    cgp.add_header("X-Spam-Report", cgp.spamd_result.report)
    # Return message to cgp queue
    cgp.proceed()
