#!/usr/bin/python

# GPG Key-Signing Robot
# Uses GMail's DKIM fields to validate the sender

import os.path
import os
import sys
import dkim
import re
import smtplib
import json
import email
import time
from libsmk.signkey import SignKeyException, signkey
from libsmk.rwconfig import read_config
from libsmk.validate_mail import validate_mail

class ProcessMailException(Exception):
    pass

# Lockfile
pidfile = "/tmp/process_mail_lock.pid"

# Audit file
audit_file = os.path.join(os.environ.get("HOME"), ".signmykey", "audit.json")

# Settings
settings = json.loads(read_config(os.path.join(os.environ.get("HOME"), ".signmykey", "settings.cfg")))

# Maildirs
maildir = os.path.join(os.environ.get("HOME"), "Maildir")

# Mail settings
smtp_host = 'smtp.gmail.com'
smtp_port = 587
smtp_user = settings['mailaddress']
smtp_pass = settings['mailpassword']
signing_key_fp = settings['gpgfingerprint']

audit_fp = settings['auditfingerprint']
audit_email = settings['auditemail']


def main():
    audit_fh = None

    try:  
        # Bail if already running
        if os.path.isfile(pidfile):
            sys.stderr.write("'%s' already exists, exiting.\n" % (pidfile,))
            sys.exit()
        else:
            fh = open(pidfile, 'w')
            fh.write(str(os.getpid()))
            fh.close()

        # Open the audit file for appending
        audit_fh = open(audit_file, "a") 
    
        # List and process all the new emails, moving them to cur
        newd = os.path.join(maildir, 'new')
        for fname in os.listdir(newd):
            fpath = os.path.join(newd, fname)
            if not os.path.isfile(fpath):
                continue

            sys.stderr.write("Processing new mail: '" + fpath + "'\n")
            fh = open(fpath, "r")
            message = fh.read()
            fh.close()

            flag = ":2,S"
            email_addr = None
            try:
                # Be sure that the email contains a pgp key
                pubkey = extract_public_key(message)
                if pubkey is None or pubkey.strip() == "":
                    raise ProcessMailException("No public key")

                # Validate the email message
                (email_addr, isvalid, error_message) = validate_mail(message)
                if not isvalid:
                    raise ProcessMailException(error_message)

                # Sign the email message
                trace = process_email(email_addr, message, pubkey)
                if trace is not None:
                    flag = ":2,R"
                    audit_fh.write(json.dumps({"success": 1, "input":message, "trace":trace, "file":fpath+flag}) + "\n")
            except Exception, e:
                flag = ":2,F"

                # Log the failure
                trace = ""
                try:
                    trace = e.trace
                except:
                    pass
                audit_fh.write(json.dumps({"success": 0, "input":message, "trace":trace, "file":fpath+flag, "error":str(e)}) + "\n")

		## Send the response
                if email_addr is not None:

                    ## Send a note to the auditor
                    audit_note = """
Success: 0

Input:
%s

Trace:
%s

Error:
%s
""" % (message, trace, str(e))
                    send_mail(audit_email, "signmykey.com audit: success: 0", encrypt_string(audit_note, audit_fp))

 
                    # Carefully limit the error message to prevent too many details from leaking
                    # (a last resport in case the error messages are unexpectedly detailed)
                    emsg = re.split(r"[\r\n]+", str(e).strip())
                    if len(emsg) > 0:
                        emsg = emsg[0]
                    else: 
                        emsg = "Unknown error"
                    if len(emsg) > 80:
                        emsg = emsg[0:77] + "..."

                    response = """Hello %s,

Unfortunately your OpenPGP key could not be signed due to the following error:


\t%s


An administrator has been automatically contacted to investigate the error.

Sincerely,

    The signmykey.com signing authority.
""" % (email_addr, emsg) 

                    send_mail(email_addr, "signmykey.com: there was an error signing your key", response)
            finally:
                os.rename(fpath, os.path.join(maildir, "cur", fname+flag))  

    # Release the lockfile
    finally:

        # Close the audit file
        if audit_fh is not None:
            try:
                audit_fh.close()
            except Exception, e:
                sys.stderr.write(traceback.format_exc() + "\n")

        os.unlink(pidfile)


#
# Extract the public key
#        
def extract_public_key(message):

    def extract_key_from_payload(strmsg):
        m = re.search(r"(" + re.escape("-----BEGIN PGP PUBLIC KEY BLOCK-----") + r".*?" + re.escape("-----END PGP PUBLIC KEY BLOCK-----") + ")", strmsg, re.DOTALL|re.MULTILINE) 
        if not m: 
            return None
        else:
            return m.group(1)

    def extract_key_recursive(m):
        if not m.is_multipart(): # Base case
            return extract_key_from_payload(m.get_payload(decode=True))
        else:
            for submsg in m.get_payload():
                k = extract_key_recursive(submsg)
                if k is not None:
                    return k
        return None

    return extract_key_recursive(email.message_from_string(message))


#
# Pass the email to the top-level email processor
#
def process_email(email_addr, message, pubkey):

    (enc_signed_key, trace) = signkey(pubkey, email_addr, signing_key_fp)

    ## Send a note to the auditor
    audit_note = """
Success: 1

Input:
%s

Trace:
%s
""" % (message, trace)
    send_mail(audit_email, "signmykey.com audit: success: 1", encrypt_string(audit_note, audit_fp))


    # Compose and send the response
    response = """Good news %s,

Your email and your public key were successfully validated. Your signed OpenPGP key is included below. Please note that it is encrypted against the public key you provided. This extra measure just makes sure that you possess the corresponding private key.

Sincerely,

    The signmykey.com signing authority.

%s
""" % (email_addr, enc_signed_key) 
    send_mail(email_addr, "Your signed OpenPGP key is enclosed.", response)

    # All done
    return trace 


def send_mail(to, subject, body):
   #print body
   #return
   message = """\From: %s\nTo: %s\nSubject: %s\n\n%s
   """ % (smtp_user, to, subject, body)
   server = smtplib.SMTP()
   server.connect(smtp_host,smtp_port)
   server.ehlo()
   server.starttls()
   server.login(smtp_user,smtp_pass)
   server.sendmail(smtp_user, to, message)
   server.close()
   time.sleep(5)
   print 'successfully sent the mail'

#
#
#
def get_required_header(headers, header):
    result = get_headers_by_name(headers, header)
    if len(result) == 0:
        raise Exception("Required header '" + header + "' is missing.")
    elif len(result) > 1:
        raise Exception("Required header '" + header + "' appears more than once.")
    else:
        return result[0]

#
#
#
def get_headers_by_name(headers, header):
    result = []
    for h in headers:
        if h[0].lower() == header.lower():
            result.append(h[1])
    return result

#
#
#
def parse_dkim_sig(sigheader):
    a = re.split(r"\s*;\s*", sigheader)
    sig = {}
    for x in a:
        if x:
            m = re.match(r"(\w+)\s*=\s*(.*)", x, re.DOTALL)
            if m is None:
                continue
            sig[m.group(1)] = m.group(2)
    return sig


#
#
#
def encrypt_string(message, recv_fingerprint):
    import subprocess
    recv_fingerprint = re.sub(r"\s+","", recv_fingerprint)
    proc = subprocess.Popen(['/usr/bin/gpg2', '--armor', '--recipient', recv_fingerprint, '--trust-model', 'always', '--encrypt', '-'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    proc.stdin.write(message)
    (encrypted_str,serr) = proc.communicate()
    return encrypted_str


#
#
#
main()
