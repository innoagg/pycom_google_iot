import ujson
import string
from ubinascii import b2a_base64
import crypto
import time

class MicroJWT:

    def __init__(self, project_id, private_key, algorithm, validity):
        self.token = {
            # The time that the token was issued at
            'iat': time.time(),
            # The time the token expires.
            'exp': time.time() + validity,
            # The audience field should always be set to the GCP project id.
            'aud': project_id
        }
        self.encoded = self.encode(self.token, private_key, algorithm)

    def isValid(self):
        return time.time() < self.token['exp']

    def encodedValue(self):
        return self.encoded

    def b42_urlsafe_encode(self, payload):
        return string.translate(b2a_base64(payload)[:-1].decode('utf-8'),{ ord('+'):'-', ord('/'):'_' })

    def encode(self, payload, private_key, algorithm):
        headerfields = { 'typ': 'JWT', 'alg': algorithm }
        content = self.b42_urlsafe_encode(ujson.dumps(headerfields).encode('utf-8'))
        content = content + '.' + self.b42_urlsafe_encode(ujson.dumps(payload).encode('utf-8'))
        signature = self.b42_urlsafe_encode(crypto.generate_rsa_signature(content, private_key))
        return content + '.' + signature

def new(project_id, private_key, algorithm, validity):
    return MicroJWT(project_id, private_key, algorithm, validity)
