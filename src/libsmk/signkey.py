#!/usr/bin/python
from cStringIO import StringIO
import subprocess
import os.path
import os
import re
import sys
import tempfile
import select
import time
import traceback

if __name__ == "__main__":
    from util import is_email_address
else:
    from .util import is_email_address


class SignKeyException(Exception):
    def __init__(self, message, trace, *args):
        self.message = message
        self.trace = trace         
        super(SignKeyException, self).__init__(message, trace, *args) 

    def __str__(self):
        return self.message

#
#
#
def signkey(pubkey, email_addr, signing_key_fp):
    session_logger = StringIO()
    encrypted_key  = None # The ultimate result

    signing_key_fp    = re.sub(r"\s+", "", signing_key_fp)
    signing_key_fp_16 = signing_key_fp[-16:]

    # Step 0: Sanity Check
    ####################################################
    if not is_email_address(email_addr):
        raise SignKeyException("'" + email_addr + "' does not appear to be a valid email address.", session_logger.getvalue())


    # Step 1: Sniff the pubkey to make sure it looks ok 
    ####################################################
    proc = subprocess.Popen(['/usr/bin/gpg2', '--with-fingerprint', '-'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc.stdin.write(pubkey)
    (sout,serr) = proc.communicate()
    session_logger.write("Peeking at the key:\n" + sout + "\n\n")

    # Make sure the email is in there
    if not re.match(r"^pub", sout):
        raise SignKeyException("Input does not appear to be a public key.", session_logger.getvalue())

    # Make sure the email is in there
    if not re.search(r"^(pub|uid).*?<(" + re.escape(email_addr) + r")>\s*$", sout, re.MULTILINE):
        raise SignKeyException("Could not find email address '" + email_addr + "' in the public key.", session_logger.getvalue())

    # Get the key fingerprint
    m = re.search(r"^\s*Key fingerprint\s*=\s*((\s+[a-fA-F0-9]{4}){10})\s*$", sout, re.MULTILINE)
    fingerprint = None
    if m:
        fingerprint = re.sub(r"\s+", "", m.group(1))
    
    if fingerprint is None:
        raise SignKeyException("Could not extract fingerprint from public key.", session_logger.getvalue())


    # Step 2: Create a new temprary keyring to work from
    #####################################################

    # Read the keyring
    fh = open(os.path.join(os.environ["HOME"], ".gnupg", "pubring.gpg"), "rb")
    pub_keyring = fh.read()
    fh.close()

    # Write the existing keyring to our temp keyring
    temp_keyring = tempfile.NamedTemporaryFile('rw+b')
    try:

        temp_keyring.write(pub_keyring)
        temp_keyring.flush()
        temp_keyring.seek(0)


    # Step 3: Import the supplied key
    #####################################################

        # Import they key
        proc = subprocess.Popen(['/usr/bin/gpg2', '--no-default-keyring', '--keyring', temp_keyring.name, '--import', '-'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        proc.stdin.write(pubkey)
        (sout,serr) = proc.communicate()
        session_logger.write("Importing the key:\n" + sout + "\n\n")

        if not re.search(r"^.*: public key \".*\" imported\s*$", sout, re.MULTILINE):
            raise SignKeyException("Could not import public key.", session_logger.getvalue())

    # Step 4: Sign the key
    #####################################################


        session_logger.write("Signing the key:\n")
        __do_sign_key(temp_keyring.name, fingerprint, email_addr, session_logger)
        session_logger.write("\n\n")
        

    # Step 5: Encrypt the signed key
    #####################################################

        # Check that the sig exists 
        proc = subprocess.Popen(['/usr/bin/gpg2', '--no-default-keyring', '--keyring', temp_keyring.name, '--list-sigs', fingerprint], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        (sout,serr) = proc.communicate()
        session_logger.write("Checking that the sig exists:\n" + sout + "\n\n")

        # Export the key into ASCII 
        proc = subprocess.Popen(['/usr/bin/gpg2', '--no-default-keyring', '--keyring', temp_keyring.name, '--armor', '--export', fingerprint], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (signed_key,serr) = proc.communicate()
        session_logger.write("Exporting the key (blank means OK):\n" + serr + "\n\n")

        # Sanity check that we've actually signed it
        proc = subprocess.Popen(['/usr/bin/gpg2', '--list-packets', '-'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        proc.stdin.write(signed_key)
        (sout,serr) = proc.communicate()
        session_logger.write("Listing the packets:\n" + sout + "\n\n")

        if "\n:signature packet: algo 1, keyid " + signing_key_fp_16 + "\n" not in sout:
            raise SignKeyException("Could not find the signature packet. Something went wrong.", session_logger.getvalue())

        # Encrypt the signed key, to be opened only by the correct owner
	proc = subprocess.Popen(['/usr/bin/gpg2', '--no-default-keyring', '--keyring', temp_keyring.name, '--armor', '--recipient', fingerprint, '--trust-model', 'always', '--encrypt', '-'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc.stdin.write(signed_key)
        (encrypted_key,serr) = proc.communicate()
        session_logger.write("Exporting the key (blank means OK):\n" + serr + "\n\n")


    except Exception, e:
        temp_keyring.close()
        if isinstance(e, SignKeyException):
            raise e
        else:
            session_logger.write("Uncaught Python error:\n" + traceback.format_exc() + "\n\n")
            raise SignKeyException(str(e), session_logger.getvalue())

    temp_keyring.close()
    return (encrypted_key, session_logger.getvalue())
        


###########################################################################################################

def __do_sign_key(keyring, fingerprint, email, session_logger):
    fingerprint = re.sub(r"\s+", "", fingerprint)

    cmd = '/usr/bin/gpg2 --no-default-keyring --keyring "' + keyring + '" --default-cert-expire 6m --default-cert-level 2 --cert-policy-url https://signmykey.com/policies/46f451003fad1557ca8e8cd795adc5703a8f8b075a0a1a44ac679a29429883fa/ --edit-key ' + fingerprint
    proc=subprocess.Popen(['/usr/bin/script', '--quiet', '--command', cmd, '/dev/null'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    # Read the key-signing menu and parse the ids
    menu = __read_from_gpg(proc.stdout, session_logger)
    ids  = __get_identities(menu)

    # Select the id that matches our email, and ask to sign
    option = ""
    for item in ids:
        if (item[1] == email):
            option = item[0]
            break

    if option == "":
        __gpg_quit(proc)
        print "Could not find email"
        return

    __write_to_gpg(option + '\n', proc.stdin, session_logger)
    __read_from_gpg(proc.stdout, session_logger)

    __write_to_gpg('sign\n', proc.stdin, session_logger)
    menu = __read_from_gpg(proc.stdout, session_logger)

    __write_to_gpg('y\n', proc.stdin, session_logger)
    __read_from_gpg(proc.stdout, session_logger, 30)

    __write_to_gpg('quit\n', proc.stdin, session_logger)
    __read_from_gpg(proc.stdout, session_logger)

    __write_to_gpg('y\n', proc.stdin, session_logger)
    __read_from_gpg(proc.stdout, session_logger)

 

def __gpg_quit(proc):
    # Quit if it's still running
    if proc.poll() is None:
        proc.stdin.write('quit\n')
        for l in proc.stdout:
            print l


def __get_identities(menu):
    ids = []
    lines = re.split(r"[\r\n]+", menu)
    for l in lines:
        l = l.strip()
        m = re.match(r"^\[.*?\]\s+\((\d+)\).*<(.*?)>$", l)
        if m:
            if (is_email_address(m.group(2))):
                ids.append( (m.group(1), m.group(2)) )
    return ids


def __write_to_gpg(data, fd, logger):
    fd.write(data)
    #logger.write(data)


def __read_from_gpg(fd, logger, timeout=0.3):
    data = ""
    bytes_read = 0
    
    while True:
       sleep_time = 0
    
       # Wait until there is data to read
       while not __has_data(fd):
           # Break if we see the prompt
           if len(data) > 5 and data[len(data)-6:len(data)] == "\ngpg> ":
               logger.write(data)
               return data

           if sleep_time > timeout:
               logger.write(data)
               return data
          
           time.sleep(0.1)
           sleep_time += 0.1

       char = fd.read(1)
      
       # End of file reached
       if char is None:
           return data

       # Read the character  
       data += char
       bytes_read += 1

       # Exit too many bytes (10Kb)
       if bytes_read >= 10240:
           return data


def __has_data(fd):
    if select.select([fd,],[],[],0.0)[0]:
        return True
    else:
        return False


###############################
if __name__ == "__main__":
    pubkey = sys.stdin.read()
    try:
        print signkey(pubkey, sys.argv[1], "F792 2C6C A38E 1972 C18E  09CF 479E E7E0 FDF8 8313")
    except SignKeyException, e:
        print e.message
        print "======="
        print e.trace
