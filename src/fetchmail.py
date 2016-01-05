#!/usr/bin/python
from libsmk.rwconfig import read_config
import json
import sys
import subprocess
import os
import os.path

def main(): 
    cfg = json.loads(read_config(os.path.join(os.environ.get("HOME"), ".signmykey", "settings.cfg")))

    # Read the existing fetchmail file
    fh = open(os.path.join(os.environ.get("HOME"), ".fetchmailrc"))
    fetchmailrc = fh.read()
    fh.close()

    # Replace the email address
    fetchmailrc = fetchmailrc.replace("%ADDRESS%", cfg['mailaddress'])

    # Replace the password 
    fetchmailrc = fetchmailrc.replace("%PASSWORD%", cfg['mailpassword'])

    # Call fetchmail
    proc=subprocess.Popen(['/usr/bin/fetchmail', '-f', '-'], stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    proc.stdin.write(fetchmailrc)
    (sout, serr) = proc.communicate()
    print sout
    print serr


main()
