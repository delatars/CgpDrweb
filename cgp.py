#!/usr/bin/python
# -*- coding: utf-8 -*-
import sys
import os
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
SPAMD_CONNECTION_TIMEOUT = 5
###################################################################################

class Devnull:
    def write(self, msg): pass
    def flush(self): pass
    def __call__(self, a,b): pass

def logging(logfile, msg):
    f = open(os.path.join(DEBUG_LOGDIR, logfile), "a")
    f.write(msg)
    f.write("---------------------------------------------------------------")
    f.close()

if DEBUG:
    DEBUGSTREAM = logging
else:
    DEBUGSTREAM = Devnull()

def parse_message(message):
    msg = message.read()
    split_index = msg.find("\n\n")
    headers = msg[: split_index]
    body = msg[split_index+2:]
    msg_for_check = "\n"
    for header in headers:
        msg_for_check += header
    msg_for_check += "\n"
    for line in body:
        msg_for_check += line
    return msg_for_check, headers, body

def SpamCheck(message):
    spamc = Popen("%s -d %s -p %s -t %s -c" % (SPAMC_BIN, SPAMD_SERVER, SPAMD_PORT, SPAMD_CONNECTION_TIMEOUT),
                        shell=True, stdin=PIPE, stderr=PIPE, stdout=PIPE)
    spamc.stdin.write(bytes(message))
    result = spamc.communicate()[0].split("/")
    if result[0] == "0":
        spamd_connection = False
        spam_score = "None"
        spam_result = "None"
    else:
        spamd_connection = True
        spam_score = result[0].strip()
        if result[1].strip() == "0.0":
            spam_result = "SPAM"
        else:
            spam_result = "NOT_SPAM"
    return spamd_connection, spam_score, spam_result

def creating_filtered_msg(headers, body, spamd_connection, score, spam_status):
        filtered_message = "filtered_message_%s.tmp" % str(randint(1, 10000000))
        with open(os.path.join(CGP_IPC_DIR, filtered_message), "w") as tmp:
            # adding base headers
            for line in headers:
                tmp.write(line)
            # adding additional headers
            tmp.write("\n")
            tmp.write("X-Spamd-Connection: %s\n" % spamd_connection)
            tmp.write("X-Spam-Status: %s\n" % spam_status)
            tmp.write("X-Spam-Score: %s\n" % score)
            # adding headers delimiter
            tmp.write("\n")
            # adding body
            for line in body:
                tmp.write(line)
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
    msg_for_check, headers, body = parse_message(message)
    print >> DEBUGSTREAM("stdin.log", msg_for_check)
    # Send message for audit to Spamd
    spamd_connection, score, spam_status = SpamCheck(msg_for_check)
    # Adding additional headers to message
    filtered_msg = creating_filtered_msg(headers, body, spamd_connection, score, spam_status)
    # Proceed to CGP Queue
    proceed(filtered_msg)