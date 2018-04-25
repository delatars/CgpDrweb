# drweb-maild spamd + spamc + CGP
Script to call Drweb SpamD from CommuniGate Pro Rules


Script get message from stdin and return message with additional headers to
Communigate Pro PIPE directory (Submitted)
Additional headers:
- X-Spam-Status: SPAM/NOT_SPAM
- X-Spam-Score: 0.0


# Installation
- Donwload script to your prefered directory
- Configure your drweb-maid:
    - drweb-ctl cfset MailD.SpamdSocket 127.0.0.1:783
- Configure script vars according your parameters
- Go to Communigate Pro web interface (http://localhost:8020)
- Switch to Setting -> Mail -> Rules
- Create rule such as example:
    - DATA
        - Any Recipient in     *@domain.com 
        - Message Size  less than   32768 
        - Header Field   is not     X-Spam-Status*
    - ACTION 
        - Execute      /path to your script/CGP.py
        - Discard
 
