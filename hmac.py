"""HMAC (Keyed-Hashing for Message Authentication) Python module.

Implements the HMAC algorithm as described by RFC 2104.
"""

# import warnings as _warnings
#from _operator import _compare_digest as compare_digest
from uhashlib import sha256
import ubinascii
PendingDeprecationWarning = None
RuntimeWarning = None

trans_5C = bytes((x ^ 0x5C) for x in range(256))
trans_36 = bytes((x ^ 0x36) for x in range(256))

def translate(d, t):
    return bytes(t[x] for x in d)


def warn(msg, cat=None, stacklevel=1):
    print("%s: %s" % ("Warning" if cat is None else cat.__name__, msg))

def HMAC(key, msg):
    """Create a new HMAC object.

    key:       key for the keyed hash object.
    msg:       Initial input for the hash, if provided.

    Note: key and msg must be a bytes or bytearray objects.
    """

    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("key: expected bytes or bytearray, but got %r" % type(key).__name__)

    blocksize = 64

    if len(key) > blocksize:
        key = sha256(key).digest()

    inner = sha256()

    key = key + bytes(blocksize - len(key))
    inner.update(translate(key, trans_36))
    if msg is not None:
        inner.update(msg)

    innerDigest = inner.digest()
    outer = sha256()
    outer.update(translate(key, trans_5C))
    outer.update(innerDigest)
    return ubinascii.hexlify(outer.digest())
