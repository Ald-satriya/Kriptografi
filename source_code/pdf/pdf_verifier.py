from PyPDF2 import PdfReader

def extract_signature(pdf_file):
    reader = PdfReader(pdf_file)
    return reader.metadata.get("/DigitalSignature", None)
