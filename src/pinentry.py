#!/usr/bin/python
from libsmk.rwconfig import read_config
import json
import sys
import os
import os.path

#
# Mimics GPG's keyentry
#
def main(): 
    cfg = json.loads(read_config(os.path.join(os.environ.get("HOME"), ".signmykey", "settings.cfg")))

    def safe_flush():
        try:
            sys.stdout.flush()
        except IOError, e:
            if "Broken pipe" in str(e):
                pass
            else:
                raise e


    sys.stdout.write("OK\n")
    safe_flush()
    l = sys.stdin.readline()
    while l is not None:
        l = l.strip()
        if l == "BYE":
            sys.stdout.write("OK\n")
    	    safe_flush()
            sys.exit(0)
        elif l == "GETPIN":
            sys.stdout.write("D " + cfg['gpgpin'] + "\n")
            sys.stdout.write("OK\n")
    	    safe_flush()
        else:
            sys.stdout.write("OK\n")
    	    safe_flush()
        l = sys.stdin.readline()

main()
