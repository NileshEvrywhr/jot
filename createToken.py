import base64
import hmac
import rsa
import hashlib

(pubkey, privkey) = rsa.newkeys(2048)

with open('private.key','wb') as keyfile:
    keyfile.write(privkey._save_pkcs1_pem())
with open('public.key','wb') as keyfile:
    keyfile.write(pubkey._save_pkcs1_pem())

file = open('private.key')
key = file.read()

header = '{"typ": "JWT", "alg": "RS256", "jku": "http://localhost/.well-known/jwks.json", "kid": "35bd6664-7d9f-4098-aa48-7104494d593a"}'
payload = '{ "username": "admin", "iat": 1627204936, "exp": 1627226536}'

urlSafeEncodedBytes = base64.urlsafe_b64encode(header.encode("utf-8")) 
urlSafeEncodedHeader = str(urlSafeEncodedBytes,"utf-8").split('=')[0]

urlSafeEncodedBytes = base64.urlsafe_b64encode(payload.encode("utf-8")) 
urlSafeEncodedPayload = str(urlSafeEncodedBytes,"utf-8").split('=')[0]

token = urlSafeEncodedHeader + '.' + urlSafeEncodedPayload

# enable for HS256
# sign = base64.urlsafe_b64encode(rsa.sign(token.encode("utf-8"), rsa.PrivateKey._load_pkcs1_pem(bytes(key,'utf-8')), 'SHA-256')).decode('utf-8').rstrip('=')

# enable for RS256
sign = base64.urlsafe_b64encode(hmac.new(bytes(key,'utf-8'),token.encode("utf-8"),hashlib.sha256).digest()).decode('utf-8').rstrip('=')

token = token + '.' + sign

print(token)