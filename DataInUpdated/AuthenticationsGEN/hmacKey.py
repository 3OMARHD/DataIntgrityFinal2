
import secrets
import base64
key = secrets.token_bytes(32)
print(base64.b64encode(key).decode())