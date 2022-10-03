import json
import base64
import hashlib
import uuid
import binascii
import urllib.parse as urlparse
from urllib.parse import urlencode, parse_qs

import redis
import rsa


#################################
# PRESIGNED URLs for API itself #
#################################

X_ADB_CREDENTIAL = "X-ADB-Credential"


class SignatureError(Exception): pass
class CredentialError(Exception): pass


class PresignURLManagerBase:
    """
    Implement generation of presigned URLs for the API itself,
    (different from s3 presigned-URLs), to give temporary access to
    a resource/endpoint, regardless of the token content or roles.
    """


class RedisPresignURLManager(PresignURLManagerBase):

    def __init__(self, presign_cfg):
        self.cfg = presign_cfg
        self.public_key = rsa.PublicKey.load_pkcs1(open(self.cfg["public_key"]).read().encode())
        self.private_key = rsa.PrivateKey.load_pkcs1(open(self.cfg["private_key"]).read().encode())
        self.redis_client = redis.Redis(**self.cfg["backend"]["params"])
        self.signature_version = "v1"  # just in case, future proof

    def _generate_id(self, signature):
        md5sum = hashlib.md5(str(signature).encode()).hexdigest()
        rand = uuid.uuid4().hex  # sprinkle some randomness to protect forging signature
        return "{}-{}".format(md5sum,rand)

    def sign(self, method, path, user=None, ttl=None):
        """
        Generate a temp credential to access `path` with `method`,
        given the authentication context `user`
        """

        jti = None
        if user and user.token:
            # associate the signature with a token ID "jti"
            claims = user.token.get("claims") or {}
            jti = claims.get("jti")
            if not jti:
                raise SignatureError(f"Can't find 'jti' fied in token claims: {claims}")

        # path can contain query string params, isolate them so it's easier to compare
        # request's later
        parsed = urlparse.urlparse(path)
        path = parsed.path
        params = parse_qs(parsed.query)

        # build the signature
        signature = {
            "jti": jti,
            "method": method,
            "path": path,
            "params": params,
            "version": self.signature_version
        }
        sign_id = self._generate_id(signature)
        signature["id"] = sign_id
        signature = json.dumps(signature)

        # register for a limited TTL
        self.redis_client.set(sign_id,signature,ex=int(ttl or self.cfg["ttl"]))
        # encrypt/encode
        encrypted = rsa.encrypt(sign_id.encode(),self.public_key)
        encoded = base64.b64encode(encrypted).decode()

        return encoded

    def verify(self, encoded):
        try:
            # signature expired? same as what we have generated?
            encrypted = base64.b64decode(encoded)
            sign_id = rsa.decrypt(encrypted,self.private_key).decode()
            raw_stored = self.redis_client.get(sign_id)
            if not raw_stored:
                raise CredentialError(f"Credential ({sign_id}) has expired")
            signature = json.loads(raw_stored)
            if signature.get("id") != sign_id:
                raise SignatureError("Signature IDs dont match")
        except binascii.Error as e:
            raise SignatureError(f"Unable to decode signature: {e}")
        except rsa.DecryptionError as e:
            raise SignatureError(f"Unable to decrypt signature: {e}")
        except json.JSONDecodeError as e:
            raise SignatureError(f"Unable to load signature as json: {e}")

        version = signature.get("version")
        if version != self.signature_version:
            raise SignatureError(f"Unknow (or not set) signature version: '{version}', can only handle '{self.signature_version}'")

        # if we get there, it's all good!
        return signature

    def generate(self, method, path, user=None, ttl=None):
        signature = self.sign(method,path,user,ttl)
        # add signature to the URL
        url_parts = list(urlparse.urlparse(path))
        query = dict(urlparse.parse_qsl(url_parts[4]))
        query.update({X_ADB_CREDENTIAL:signature})
        url_parts[4] = urlencode(query)
        cred_path = urlparse.urlunparse(url_parts)

        return cred_path

    def check(self, request, user=None):
        cred = request.query_params.get(X_ADB_CREDENTIAL,None)
        if not cred:
            return

        signature = self.verify(cred)

        if user and signature.get("jti") != user.token.claims.get("jti"):
            raise CredentialError("'jti' don't match, not allowed")
        if request.method.lower() != signature.get("method","").lower():
            raise CredentialError("'method' don't match, not allowed")
        if request.url.path != signature.get("path"):
            raise CredentialError("'path' don't match, not allowed ({} != {})".format(request.url.path,signature.get("path")))
        for param in request.query_params.keys():
            if param == X_ADB_CREDENTIAL:
                continue  # never part of signature (obviously, it's the signature...)
            req_param = request.query_params.get(param)
            sign_param = signature.get("params",{}).get(param)
            # parse_qs return params in single element list if only one param in query string. normalize.
            if len(sign_param) == 1:
                sign_param = sign_param.pop()
            if req_param != sign_param:
                raise CredentialError("'params' don't match, not allowed ({} != {})".format(req_param,sign_param))

        return signature

