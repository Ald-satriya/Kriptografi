from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def verify_signature(public_key, signature, hash_bytes):
    try:
        public_key.verify(
            signature,
            hash_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except:
        return False