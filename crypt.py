#!/usr/bin/env python3

import os
import sys
import hashlib

_magic = b"\xC0\xFF\xEE\xD0\x0D"
_magic_len = len(_magic)

def printerr(msg):
    sys.stderr.write("%s\n" % msg)

def write_crypt(data, output):
    if output is None:
        sys.stdout.write(data)
        sys.stdout.flush()
    else:
        output.write(data)

def _crypt(cryptkey, data, cryptkey_len):
    edata = []
    bi = 0
    for b in data:
        edata.append(b ^ cryptkey[bi % cryptkey_len])
        bi += 1
    return bytes(edata)

def do_encrypt(password, file, output):
    printerr("Calculating password hash...")
    m = hashlib.sha3_512()
    m.update(bytes(password, "utf-8"))
    cryptkey = m.digest()
    cryptkey_len = len(cryptkey)
    printerr("Preparing...")
    writefile = open(output, "wb") if output != '-' else None
    printerr("Writing magic...")
    write_crypt(_magic, writefile)
    printerr("Calculating checksum...")
    checksum_m = hashlib.sha384()
    checksum_m.update(cryptkey)
    checksum_m.update(b"\xD0")
    checksum_m.update(bytes([cryptkey[4], cryptkey[7]]))
    checksum = bytes(checksum_m.hexdigest(), "utf-8")
    checksum_len = len(checksum)
    printerr("Writing checksum to file...")
    write_crypt(bytes([checksum_len]), writefile)
    write_crypt(_crypt(cryptkey, checksum, cryptkey_len), writefile)
    if writefile is not None:
        printerr("Encrypted data starts at offset %i" % writefile.tell())
    printerr("Encrypting...")
    with open(file, "rb") as f:
        ddata = f.read(cryptkey_len)
        while ddata:
            write_crypt(_crypt(cryptkey, ddata, cryptkey_len), writefile)
            ddata = f.read(cryptkey_len)
    printerr("Done.")
    if writefile is not None:
        writefile.close()
    return 0

def do_decrypt(password, file, output):
    printerr("Calculating password hash...")
    m = hashlib.sha3_512()
    m.update(bytes(password, "utf-8"))
    cryptkey = m.digest()
    cryptkey_len = len(cryptkey)
    printerr("Preparing...")
    writefile = open(output, "wb") if output != '-' else None
    with open(file, "rb") as f:
        printerr("Checking magic...")
        magic = f.read(_magic_len)
        if magic != _magic:
            printerr("This is not a c0ffeedood encrypted file")
            return 2
        printerr("Validating checksum...")
        checksum_len = int.from_bytes(f.read(1), byteorder="little", signed=False)
        checksum_enc = f.read(checksum_len)
        checksum = _crypt(cryptkey, checksum_enc, cryptkey_len)
        checksum_m = hashlib.sha384()
        checksum_m.update(cryptkey)
        checksum_m.update(b"\xD0")
        checksum_m.update(bytes([cryptkey[4], cryptkey[7]]))
        checksum_claim = bytes(checksum_m.hexdigest(), "utf-8")
        if checksum_claim != checksum:
            printerr("Password incorrect")
            return 3
        printerr("Encrypted data starts at offset %i" % f.tell())
        printerr("Decrypting...")
        edata = f.read(cryptkey_len)
        while edata:
            write_crypt(_crypt(cryptkey, edata, cryptkey_len), writefile)
            edata = f.read(cryptkey_len)
    printerr("Done.")
    if writefile is not None:
        writefile.close()
    return 0

if __name__ == '__main__':
    if len(sys.argv) <= 4:
        printerr("Usage: %s <action> <password> <file> <destination>" % sys.argv[0])
        printerr("\nActions:")
        printerr("  encrypt, decrypt")
        printerr("\nDestination must be a file or - for stdout")
    elif sys.argv[1] == "encrypt": exit(do_encrypt(sys.argv[2], sys.argv[3], sys.argv[4]))
    elif sys.argv[1] == "decrypt": exit(do_decrypt(sys.argv[2], sys.argv[3], sys.argv[4]))
    else: printerr("Unknown action %s, valid actions: encrypt, decrypt" % sys.argv[1])
    exit(255)
