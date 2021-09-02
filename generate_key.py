from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

backend = default_backend()
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048, backend=backend)
private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.BestAvailableEncryption(b'42230'))
public_key = private_key.public_key()

public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.PKCS1
    )
with open('public_key.pem', 'wb') as f:
    f.write(public_key_pem)
with open('private_key.pem', 'wb') as f:
    f.write(private_key_pem)