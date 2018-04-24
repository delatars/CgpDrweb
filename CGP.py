#!/usr/local/bin/python
# -*- coding: utf-8 -*-
import sys
import os
from subprocess import PIPE, Popen
from random import randint

################################### VARS ##########################################
CGP_PATH = "/var/CommuniGate"
SPAMC_BIN = os.path.join(CGP_PATH, "Queue", "spamc")
CGP_IPC_DIR = os.path.join(CGP_PATH, "Submitted")
SPAMD_SERVER = "127.0.0.1"
SPAMD_PORT = "783"
###################################################################################


def parse_message(message):
    msg = message.readlines()
    for index, line in enumerate(msg):
        if line =="\n":
            headers_end_pnt = index
            body_start_pnt = index+1

    headers = msg[: headers_end_pnt]
    body = msg[body_start_pnt:]
    msg_for_check = "\n"
    for header in headers:
        msg_for_check += header
    msg_for_check += "\n"
    for line in body:
        msg_for_check += line
    return msg_for_check, headers, body

def SpamCheck(message):
    spamc = Popen("%s -d %s -p %s -c" % (SPAMC_BIN, SPAMD_SERVER, SPAMD_PORT), 
                        shell=True, stdin=PIPE, stderr=PIPE, stdout=PIPE)
    spamc.stdin.write(bytes(message))
    result = spamc.communicate()[0].split("/")
    spam_score = result[0].strip()
    if result[1].strip() == "0.0":
        spam_result = "SPAM"
    else:
        spam_result = "NOT_SPAM"
    return spam_score, spam_result

def creating_filtered_msg(headers, body, score, spam_status):
        filtered_message = "filtered_message_%s.tmp" % str(randint(1,10000000))
        with open(os.path.join(CGP_IPC_DIR, filtered_message), "w") as tmp:
            # adding base headers
            for line in headers:
                tmp.write(line)
            # adding additional headers
            tmp.write("X-Spam-Status: %s\n" % spam_status)
            tmp.write("X-Spam-Score: %s\n" % score)
            # adding headers delimiter
            tmp.write("\n")
            # adding body
            for line in body:
                tmp.write(line)
        return filtered_message

def proceed(message):
    os.rename(os.path.join(CGP_IPC_DIR, message), os.path.join(CGP_IPC_DIR, message+".sub"))


if __name__ == "__main__":
    # Getting fileobject from stdin
    message = sys.stdin
    # Split message and removing unused info
    msg_for_check, headers, body = parse_message(message)
    # Send message for audit to Spamd
    score, spam_status = SpamCheck(msg_for_check)
    # Adding additional headers to message
    filtered_msg = creating_filtered_msg(headers, body, score, spam_status)
    # Proceed to CGP Queue
    proceed(filtered_msg)
