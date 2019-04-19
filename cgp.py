#!/usr/bin/python
# -*- coding: utf-8 -*-
import sys
import os
import re
from subprocess import PIPE, Popen
from random import randint

###################################MANDATORY VARS ##########################################
CGP_PATH = "/var/CommuniGate"
SPAMC_BIN = "spamc"
CGP_IPC_DIR = os.path.join(CGP_PATH, "Submitted")
SPAMD_SERVER = "<SPAMD_IP>"
SPAMD_PORT = "<SPAMD_PORT>"
####### SERVICE VARS ########
DEBUG = False
DEBUG_LOGDIR = CGP_PATH
SPAMD_CONNECTION_TIMEOUT = 20
###################################################################################

class Devnull:
    def write(self, msg): pass
    def flush(self): pass
    def __call__(self, a, b): pass

def logging(logfile, msg):
    f = open(os.path.join(DEBUG_LOGDIR, logfile), "a")
    f.write(msg)
    f.write("---------------------------------------------------------------")
    f.close()

if DEBUG:
    DEBUGSTREAM = logging
else:
    DEBUGSTREAM = Devnull()


def split_message(message):
    msg = message.read()
    split_index = msg.find("\n\n")
    headers = msg[: split_index]
    body = msg[split_index:]
    return headers, body


def SpamCheck(message):
    """ Function do request to spamd server via spamc utility and return
         - spamd_connection
         - score
         - threshold
         - report
    """
    spamc = Popen([SPAMC_BIN, "-d", SPAMD_SERVER, "-p", str(SPAMD_PORT), "-t", str(SPAMD_CONNECTION_TIMEOUT), "-R"],
                  stdin=PIPE, stderr=PIPE, stdout=PIPE)
    spamc.stdin.write(bytes(message))
    spamd_connection = "True"
    result = spamc.communicate()[0]
    score = re.findall(r"^([\d.]+)/[\d.]+", result)[0]
    threshold = re.findall(r"^[\d.]+/([\d.]+)", result)[0]
    report = "\n".join(re.findall(r"\n(.*)", result))
    if score == "0" and threshold == "0":
        spamd_connection = "False"
        score = "none"
        threshold = "none"
        report = "none"
    return spamd_connection, score, threshold, report


def creating_filtered_msg(headers, body, spamd_connection, score, threshold, report):
    filtered_message = "filtered_message_%s.tmp" % str(randint(1, 10000000))
    with open(os.path.join(CGP_IPC_DIR, filtered_message), "w") as tmp:
        tmp.write(headers)
        tmp.write("\n")
        tmp.write("X-Spamd-Connection: %s" % spamd_connection)
        tmp.write("\n")
        tmp.write("X-Spam-Score: %s" % score)
        tmp.write("\n")
        tmp.write("X-Spam-Threshold: %s" % threshold)
        tmp.write("\n")
        tmp.write("X-Spam-Report: %s" % report)
        tmp.write(body)
    return filtered_message


def proceed(message):
    if DEBUG:
        with open(os.path.join(CGP_IPC_DIR, message), "r") as filt:
            msg = filt.read()
        print >> DEBUGSTREAM("filtered_msg.log", msg)
    os.rename(os.path.join(CGP_IPC_DIR, message), os.path.join(CGP_IPC_DIR, message+".sub"))


if __name__ == "__main__":
    # Getting fileobject from stdin
    message = sys.stdin
    # Split message and removing unused info
    headers, body = split_message(message)
    # Send message for audit to Spamd
    spamd_connection, score, treshold, report = SpamCheck(message)
    # Adding additional headers to message
    filtered_msg = creating_filtered_msg(headers, body, spamd_connection, score, treshold, report)
    # Proceed to CGP Queue
    proceed(filtered_msg)