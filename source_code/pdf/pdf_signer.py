from PyPDF2 import PdfReader, PdfWriter
import json
from datetime import datetime
import os

def save_execution_manifest(exec_dir, filename, file_hash, signature_hash):
    manifest = {
        "filename": filename,
        "file_hash": file_hash,
        "signature_hash": signature_hash,
        "executed_at": datetime.utcnow().isoformat()
    }

    with open(os.path.join(exec_dir, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)


def embed_signature(input_pdf, output_pdf, signature_hex):
    reader = PdfReader(input_pdf)
    writer = PdfWriter()

    for page in reader.pages:
        writer.add_page(page)

    writer.add_metadata({
        "/DigitalSignature": signature_hex
    })

    with open(output_pdf, "wb") as f:
        writer.write(f)

        
