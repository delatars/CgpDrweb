# drweb-maild spamd + spamc + CGP
Script to call Drweb SpamD from CommuniGate Pro Rules

Script use the "spamc" utility from the spamassassin package, to call drweb spamd. 


Script get message from stdin and return message with additional headers to
Communigate Pro PIPE directory (Submitted)
Additional headers:
- X-Spam-Connection:
- X-Spam-Score:
- X-Spam-Threshold:
- X-Spam-Report: 


# Installation
- Donwload script to your prefered directory
- Configure your drweb-maid:
    - drweb-ctl cfset MailD.SpamdSocket 127.0.0.1:783
- Configure script vars according your parameters
- Go to Communigate Pro web interface (http://localhost:8020)
- Switch to Setting -> Mail -> Rules
- Create rule to prevent mail loop such as example:
    - DATA
        - Header Field   is not     X-Spam-Connection*
    - ACTION 
        - Execute      /path to your script/cgp.py
        - Discard
 
http://www.communigate.com/CGPDrWeb/russian.html