#!/usr/bin/python
import sys
import dkim
import re
import email

if __name__ == "__main__":
    from util import is_email_address
else:
    from .util import is_email_address


class ValidateMailException(Exception):
    pass


#            
# Validate an email
# Returns a 3-tuple: (FromAddress, IsValid, ErrorMessage)
#
def validate_mail(message):

    # Step 1: Read the from address, so that we at least know where to 
    #         send the error message to
    from_addr = None
    try:
        # Get the one and only from address
        (headers, body) = dkim.rfc822_parse(message)
        from_addr  = __get_raw_email_addr(__get_required_header(headers, "From"))
        if not is_email_address(from_addr):
            return (None, False, "'" + str(from_addr) + "' is not valid From: address")
    except Exception, e:
            return (None, False, e.__str__())

    # Step 2: Validate the email via a helper method
    # 
    try:
        if "@gmail.com" not in from_addr:
            return (from_addr, False, "Not a Gmail address. At this time, signmykey.com only supports GMail.")

        valid_addr = __validate_mail(message)
        if from_addr == valid_addr and valid_addr is not None and valid_addr != "": 
            return (valid_addr, True, None)
        else:
            return (from_addr, False, "From address mismatch in last stage of processing.")
    except Exception, e:
            return (from_addr, False, e.__str__())

#
# The main helper method
#
def __validate_mail(message):

    # First things first (and this is critical), 
    # validate the DKIM signature
    if not dkim.verify(message):
        raise ValidateMailException("DKIM signature verification failed\n")

    # Parse the email
    (headers, body) = dkim.rfc822_parse(message)

    # Get the one and only DKIM-Signature header and from address
    from_addr = __get_raw_email_addr(__get_required_header(headers, "From"))
    dkim_sig  = __get_required_header(headers, "DKIM-Signature")

    # Check that the from address and the Return-Path address are consistent
    return_paths = __get_headers_by_name(headers, "Return-Path")
    if len(return_paths) == 0:
        raise ValidateMailException("No return paths specified\n")
    for rp in return_paths:
        if __get_raw_email_addr(rp) != from_addr:
            raise ValidateMailException("'Return-Path: " + str(rp) + "' does not match from address.\n")

    # Check a few things in the DKIM header
    dkim_fields = parse_dkim_sig(dkim_sig)

    if 'bh' not in dkim_fields:
        raise ValidateMailException("Missing the DKIM body hash.\n")

    if 'h' not in dkim_fields:
        raise ValidateMailException("Missing DKIM headers key (h=).\n")

    if 'd' not in dkim_fields:
        raise ValidateMailException("Missing DKIM domain field.\n")

    if dkim_fields['d'] != "gmail.com":
        raise ValidateMailException("Not from gmail.com\n")

    signed_headers = [fld.lower().strip() for fld in dkim_fields['h'].split(":")]
    if 'from' not in signed_headers:
        raise ValidateMailException("From address is not included in signed headers!\n")

    # Some other magic stuff
    # NOTE: It is legal for there to be numerous Authentication-Results headers, 
    #       but, we won't handle that yet. Instead, just fail if there is more than one.
    auth_results = __get_required_header(headers, "Authentication-Results").strip()
    if not re.match(r"^mx\.google\.com;", auth_results):
        raise ValidateMailException("Authentication-Results header not from mx.google.com\n")
 
    # check various features    
    auth_results = " " + re.sub(r"\s+", " ", auth_results).lower().strip() + " "

    if " dkim=pass " not in auth_results:
        raise ValidateMailException("Authentication-Results failure: No 'dkim=pass'\n")

    if " dmarc=pass " not in auth_results:
        raise ValidateMailException("Authentication-Results failure: No 'dmarc=pass'\n")

    if " spf=pass " not in auth_results:
        raise ValidateMailException("Authentication-Results failure: No 'spf=pass'\n")

    # Try to get the smtp.mailfrom header
    if not re.match(r"^.*spf=pass [^;]+? smtp.mailfrom=" + re.escape(from_addr) + "(;.*)?$", auth_results):
        raise ValidateMailException("Authentication-Results failure: invalid or missing smtp.mailfrom address\n")

    return from_addr

#
#
#
def __get_required_header(headers, header):
    result = __get_headers_by_name(headers, header)
    if len(result) == 0:
        raise Exception("Required header '" + header + "' is missing.")
    elif len(result) > 1:
        raise Exception("Required header '" + header + "' appears more than once.")
    else:
        return result[0]

#
#
#
def __get_headers_by_name(headers, header):
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
def __get_raw_email_addr(addr):
    addr = addr.strip()
    matches = re.search(r"<([^>]+)>", addr)
    if not matches:
        return addr
    result = matches.group(1).strip()
    if is_email_address(result):
        return result
    else:
        return addr

###############################
if __name__ == "__main__":
    message = sys.stdin.read()
    print validate_mail(message)
