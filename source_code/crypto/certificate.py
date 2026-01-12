from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from datetime import datetime, timedelta

def generate_certificate(private_key):
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ID"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Universitas Pelita Bangsa"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Aldi Satriya"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .sign(private_key, hashes.SHA256())
    )

    return cert


def save_certificate(cert, path):
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))