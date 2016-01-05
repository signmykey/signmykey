#!/usr/bin/python
import sys
import re

def is_email_address(addr):
    # From http://www.w3.org/TR/html5/forms.html#valid-e-mail-address
    # See: http://stackoverflow.com/a/8829363/1467532
    if (re.match(r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$", addr)):
        return True
    else:
        return False

###############################
if __name__ == "__main__":
    print "is_email_address('" + sys.argv[1] + "'): " + str(is_email_address(sys.argv[1]))


