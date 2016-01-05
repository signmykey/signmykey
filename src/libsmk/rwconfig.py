#!/usr/bin/python
import subprocess
import re
import os.path
import os
import hashlib
from Crypto.Cipher import AES
from Crypto import Random
import json

class ConfigException(Exception):
    pass

#
# Read a configuration from an obfuscated config file
#
def read_config(path):
    fh = open(path, "r")
    data = None
    for l in fh:
        if not re.match(r"^\s*#", l): 
            data = l.strip()
            break
    if data is not None:
        try:
            rec = json.loads(data)
            cfg = __deobfuscate_str(rec['data'].decode('hex'))
            h   = hashlib.sha256(cfg.strip() + __salt).hexdigest()
            if h == rec['hash']:
                return cfg
            else:
                raise ConfigException("Malformed config file: Hash mismatch")
        except ConfigException, e:
             raise e
        except Exception, e:
             raise ConfigException("Malformed config file: " + str(e))

    raise ConfigException("Malformed config file: No data")

#
# Write a configuration to an obfuscated config file
#
def write_config(data, path):

    # Truncate the file
    fh = open(path, "w")
    fh.close()
  
    # Change it's permissions
    os.chmod(path, 0o600)

    # Write to the file
    fh = open(path, "r+")
    fh.write("""# WARNING: 
# This file contains SENSITIVE data (i.e., PASSWORDS)
# Treat it as you would any secret file.
# Make sure that its permissions are 600 or similar.
#
# It _is_ obfuscated via hardware serial numbers, and it
# will be difficult to read if lifted and moved to another
# filesystem BY ACCIDENT. (e.g., backed up)
#
# But, it provides ZERO protection against a determined
# attacker. You have been warned.
#
""")
    h = hashlib.sha256(data.strip() + __salt).hexdigest()
    record = { "data": __obfuscate_str(data).encode('hex'), "hash": h }
    fh.write(json.dumps(record))
    fh.close()


#################### PRIVATE ####################
     
#
# Deobfuscate a string by decrypting it with the hardware token
# NOTE: Security through obscurity.
#
def __deobfuscate_str(s):
    iv  = s[0:16]
    enc = s[16:]
    obj = AES.new(__get_hw_token().decode('hex'), AES.MODE_CBC, iv)
    return obj.decrypt(enc)

#
# Obfuscate a string by encrypting it with the hardware token
# NOTE: Security through obscurity.
#
def __obfuscate_str(s):
   
    # Pad
    while len(s) % 16 != 0:
        s = s + " "

    iv = Random.new().read(AES.block_size)
    obj = AES.new(__get_hw_token().decode('hex'), AES.MODE_CBC, iv)
    return iv + obj.encrypt(s)

#
# Synthesize a (hopefully stable) hardware token
#
__hw_token = None
def __get_hw_token():
    global __hw_token
    if __hw_token is None:
        data = __get_cpu_serial() + \
               __get_drive_uuid() + \
               __get_mac_addr() + \
               __get_dbus_machine_id()
        __hw_token = hashlib.sha256(data + __salt).hexdigest()
    return __hw_token

#
# Read the dbud machine id
#
def __get_dbus_machine_id():

    fpath = None
    if os.path.isfile("/etc/machine-id"):
        fpath = "/etc/machine-id"
    elif os.path.isfile("/var/lib/dbus/machine-id"):
        fpath = "/var/lib/dbus/machine-id"
    else:
        raise ConfigException("Could read dbus machine id.")
    
    fh = open(fpath, "r")
    data = fh.read().strip()
    fh.close()
    return data
    
#
# If possible, read the CPU ID 
# (This works on a Raspberry Pi)
#
def __get_cpu_serial():

    # On a Raspberry Pi, we can just get the CPU Id
    fh = open("/proc/cpuinfo")
    data = fh.read()
    fh.close()

    # Parse the HWaddr
    lines = re.split(r"[\r\n]+", data)
    for l in lines:
        l = l.strip()
        m = re.match(r'.*Serial\s*:\s*([a-fA-F0-9]+)\s*$', l)
        if m:
            return m.group(1) 

    return "NO CPU SERIAL"


#
# Read the drive UUIDs
#
def __get_drive_uuid():
    base = r"/dev/disk/by-uuid"
    drives = []
    for fname in os.listdir(base):
        fpath = os.path.join(base, fname)
        if not os.path.islink(fpath):
            continue
        drives.append(fname)

    if len(drives) == 0:
        raise ConfigException("No disks to enumerate.")

    drives.sort()
    return ",".join(drives)

#
# Read the MAC address from Eth0
#
def __get_mac_addr():

    interfaces = []

    # Call ifconfig
    proc = subprocess.Popen(['ifconfig'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (sout,serr) = proc.communicate()
    code = proc.wait()

    # Parse the HWaddr
    lines = re.split(r"[\r\n]+", sout)
    for l in lines:
        l = l.strip()
        m = re.match(r'^eth\d+.*HWaddr\s+([a-fA-F0-9]{2}(:[a-fA-F0-9]{2}){5})\s*$', l)
        if m:
            interfaces.append(m.group(1))

    # Make sure we got something
    if len(interfaces) == 0:
        raise ConfigException("Could not prase HWaddr.")

    return ",".join(interfaces)


# Not secret
__salt = "zTPiUsC3gSYBKvIYgVeAnUZoORjEOllNcGEy4quvrC8D40Qv1VMWODYEnK5YOBx"



###############################
if __name__ == "__main__":
    import tempfile
    print "CPU:    '" + str(__get_cpu_serial()) + "'" 
    print "Drives: '" + str(__get_drive_uuid()) + "'" 
    print "Macs:   '" + str(__get_mac_addr()) + "'" 
    print "DBus Id:'" + str(__get_dbus_machine_id()) + "'"
    print "Token:  '" + str(__get_hw_token()) + "'"
    temp_cfg = tempfile.NamedTemporaryFile('rw+b')
    write_config("HELLO WORLD", temp_cfg.name)
    print read_config(temp_cfg.name)
    temp_cfg.close()
    
