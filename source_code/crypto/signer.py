from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

def sign_hash(hash_bytes, private_key):
    return private_key.sign(
        hash_bytes,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
