"""
SISTEM TANDA TANGAN DIGITAL PDF
UAS KRIPTOGRAFI - RSA 2048-bit & SHA-256
"""

from flask import Flask, render_template, request, jsonify, send_file, session
from flask_cors import CORS
import os
import hashlib
import base64
import json
from datetime import datetime
import tempfile
from io import BytesIO
import traceback
import zipfile
from flask import send_file, jsonify
import os
from datetime import datetime
import pandas as pd
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4, letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
import qrcode
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')

# Import kriptografi
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

from crypto.key_manager import generate_keys
from crypto.signer import sign_hash
from crypto.verifier import verify_signature
from pdf.pdf_signer import embed_signature
from audit.audit_log import log_action


# Import PDF
import PyPDF2

app = Flask(__name__)
app.secret_key = 'digital-signature-secret-key-uas-project-2024'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['TEST_FOLDER'] = 'test_pdfs'
app.config['OUTPUT_FOLDER'] = 'outputs'
app.config['SIGNATURE_FOLDER'] = 'outputs/signatures'
app.config['REPORT_FOLDER'] = 'outputs/reports'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# Setup folders
for folder in [app.config['UPLOAD_FOLDER'], 
               app.config['TEST_FOLDER'],
               app.config['OUTPUT_FOLDER'],
               app.config['SIGNATURE_FOLDER'],
               app.config['REPORT_FOLDER']]:
    os.makedirs(folder, exist_ok=True)

CORS(app)

class DigitalSignaturePDF:
    def __init__(self):
        self.signature_log = []
        self.public_key = None
        self.generate_keys()
        self.private_key = None
    
    def generate_keys(self, key_size=2048):
        """Generate RSA key pair"""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        self.public_key = self.private_key.public_key()
        
        # Save keys to file
        self.save_keys_to_file()
        
        # Log generation
        self.log_activity("KEY_GENERATION", "RSA Key Pair generated", {
            "key_size": key_size,
            "timestamp": datetime.now().isoformat()
        })
    
    def save_keys_to_file(self):
        """Save keys to files"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Save private key
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        with open(os.path.join(app.config['OUTPUT_FOLDER'], f'private_key_{timestamp}.pem'), 'wb') as f:
            f.write(private_pem)
        
        # Save public key
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        with open(os.path.join(app.config['OUTPUT_FOLDER'], f'public_key_{timestamp}.pem'), 'wb') as f:
            f.write(public_pem)
    
    def get_keys_pem(self):
        """Get keys in PEM format"""
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem.decode('utf-8'), public_pem.decode('utf-8')
    
    def log_activity(self, activity_type, description, data=None):
        """Log system activity"""
        
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'activity': activity_type,
            'description': description,
            'data': data or {}
        }
        self.signature_log.append(log_entry)
        
        # Save log to file
        log_file = os.path.join(app.config['OUTPUT_FOLDER'], 'activity_log.json')
        with open(log_file, 'w') as f:
            json.dump(self.signature_log, f, indent=2)
        
        return log_entry
    
    def sign_pdf(self, pdf_path, output_path=None, document_info=None):
        """Sign PDF document with digital signature"""
        try:
            # Read PDF content
            with open(pdf_path, 'rb') as file:
                pdf_content = file.read()
            
            # Calculate file hash (SHA-256)
            pdf_hash = hashlib.sha256(pdf_content).digest()
            pdf_hash_hex = hashlib.sha256(pdf_content).hexdigest()
            
            # Sign hash dengan private key
            signature = self.private_key.sign(
                pdf_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            # Encode signature to base64
            signature_b64 = base64.b64encode(signature).decode('utf-8')
            
            # Create signature metadata
            timestamp = datetime.now().isoformat()
            metadata = {
                'signature': signature_b64,
                'timestamp': timestamp,
                'algorithm': 'RSA-SHA256-PSS',
                'hash': base64.b64encode(pdf_hash).decode('utf-8'),
                'hash_hex': pdf_hash_hex,
                'key_size': 2048,
                'document_info': document_info or {},
                'signature_length': len(signature),
                'hash_algorithm': 'SHA-256'
            }
            
            # Create signed PDF
            if output_path is None:
                timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = os.path.basename(pdf_path)
                name, ext = os.path.splitext(filename)
                output_path = os.path.join(
                    app.config['SIGNATURE_FOLDER'], 
                    f'{name}_signed_{timestamp_str}{ext}'
                )
            
            # Copy original PDF and add signature page
            reader = PyPDF2.PdfReader(pdf_path)
            writer = PyPDF2.PdfWriter()
            
            # Copy all pages
            for page in reader.pages:
                writer.add_page(page)
            
            # Add signature metadata as custom data
            writer.add_metadata({
                '/Signature': json.dumps(metadata),
                '/Title': f'Signed Document - {os.path.basename(pdf_path)}',
                '/Author': 'Digital Signature System',
                '/Creator': 'UAS Kriptografi Project',
                '/Producer': 'Python Flask Digital Signature',
                '/CreationDate': timestamp,
                '/ModDate': timestamp
            })
            
            # Add signature information page
            signature_page = self.create_signature_page(metadata, pdf_path)
            writer.add_page(signature_page)
            
            # Write output PDF
            with open(output_path, 'wb') as output_file:
                writer.write(output_file)
            
            # Save signature separately
            sig_file = output_path.replace('.pdf', '_signature.json')
            with open(sig_file, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            # Generate QR Code for signature
            qr_file = output_path.replace('.pdf', '_qrcode.png')
            self.generate_qr_code(signature_b64, qr_file)
            
            # Log activity
            self.log_activity("SIGN_CREATION", "PDF document signed", {
                'original_file': os.path.basename(pdf_path),
                'signed_file': os.path.basename(output_path),
                'signature_file': os.path.basename(sig_file),
                'hash': pdf_hash_hex[:16] + '...',
                'timestamp': timestamp
            })
            
            # Generate verification report
            report_file = self.generate_verification_report(pdf_path, output_path, metadata, True)
            
            return {
                'status': 'success',
                'signed_pdf': output_path,
                'signature_file': sig_file,
                'qr_code': qr_file,
                'report_file': report_file,
                'metadata': metadata,
                'hash': pdf_hash_hex,
                'message': 'PDF berhasil ditandatangani secara digital'
            }
            
        except Exception as e:
            error_msg = str(e)
            traceback.print_exc()
            
            # Log error
            self.log_activity("SIGN_ERROR", "Error signing PDF", {
                'error': error_msg,
                'file': os.path.basename(pdf_path)
            })
            
            return {'status': 'error', 'message': error_msg}
    
    def create_signature_page(self, metadata, original_filename):
        """Create a signature information page"""
        buffer = BytesIO()
        c = canvas.Canvas(buffer, pagesize=A4)
        
        # Title
        c.setFont("Helvetica-Bold", 16)
        c.drawString(100, 750, "DIGITAL SIGNATURE VERIFICATION PAGE")
        c.line(100, 745, 500, 745)
        
        # Document Info
        c.setFont("Helvetica-Bold", 12)
        c.drawString(100, 720, "Document Information:")
        c.setFont("Helvetica", 10)
        c.drawString(120, 700, f"Original File: {os.path.basename(original_filename)}")
        c.drawString(120, 680, f"Signing Time: {metadata['timestamp']}")
        c.drawString(120, 660, f"Algorithm: {metadata['algorithm']}")
        
        # Signature Info
        c.setFont("Helvetica-Bold", 12)
        c.drawString(100, 630, "Signature Information:")
        c.setFont("Helvetica", 10)
        c.drawString(120, 610, f"Key Size: {metadata['key_size']}-bit RSA")
        c.drawString(120, 590, f"Hash Algorithm: {metadata['hash_algorithm']}")
        c.drawString(120, 570, f"Signature Length: {metadata['signature_length']} bytes")
        
        # Hash Value
        c.setFont("Helvetica-Bold", 12)
        c.drawString(100, 540, "Document Hash (SHA-256):")
        c.setFont("Courier", 8)
        hash_display = metadata['hash_hex']
        for i, line in enumerate([hash_display[j:j+64] for j in range(0, len(hash_display), 64)]):
            c.drawString(120, 520 - (i * 15), line)
        
        # Verification Instructions
        c.setFont("Helvetica-Bold", 12)
        c.drawString(100, 400, "Verification Instructions:")
        c.setFont("Helvetica", 10)
        instructions = [
            "1. Hash dokumen asli menggunakan SHA-256",
            "2. Dekripsi tanda tangan menggunakan public key",
            "3. Bandingkan hash yang didekripsi dengan hash dokumen",
            "4. Jika sama, tanda tangan VALID",
            "5. Jika berbeda, tanda tangan INVALID atau dokumen berubah"
        ]
        
        for i, instruction in enumerate(instructions):
            c.drawString(120, 380 - (i * 20), instruction)
        
        # Footer
        c.setFont("Helvetica-Oblique", 8)
        c.drawString(100, 50, "Generated by UAS Kriptografi - Digital Signature System")
        c.drawString(100, 35, f"Verification Timestamp: {datetime.now().isoformat()}")
        
        c.save()
        buffer.seek(0)
        
        # Create PDF page from buffer
        from PyPDF2 import PdfReader
        return PdfReader(buffer).pages[0]
    
    def generate_qr_code(self, signature_data, output_path):
        """Generate QR Code for signature"""
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(signature_data[:500])
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        img.save(output_path)
    
    def verify_signature(self, pdf_path, signature_data=None):
        """Verify digital signature of PDF"""
        try:
            # Read PDF content
            with open(pdf_path, 'rb') as file:
                pdf_content = file.read()
            
            # Calculate hash
            pdf_hash = hashlib.sha256(pdf_content).digest()
            pdf_hash_hex = hashlib.sha256(pdf_content).hexdigest()
            
            # If signature_data is provided directly
            if signature_data:
                if isinstance(signature_data, str):
                    signature_data = json.loads(signature_data)
                signature = base64.b64decode(signature_data['signature'])
                original_hash_hex = signature_data.get('hash_hex', '')
            else:
                # Try to extract from PDF metadata
                reader = PyPDF2.PdfReader(pdf_path)
                metadata = reader.metadata
                
                if '/Signature' in metadata:
                    sig_meta = json.loads(metadata['/Signature'])
                    signature = base64.b64decode(sig_meta['signature'])
                    original_hash_hex = sig_meta.get('hash_hex', '')
                else:
                    return {
                        'status': 'error', 
                        'message': 'Tidak ditemukan tanda tangan digital dalam PDF',
                        'verified': False
                    }
            
            # Verify signature
            try:
                self.public_key.verify(
                    signature,
                    pdf_hash,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                
                # Compare hashes
                hash_match = (pdf_hash_hex == original_hash_hex) if original_hash_hex else True
                
                verification_data = {
                    'verified': True,
                    'hash_match': hash_match,
                    'document_integrity': 'INTACT' if hash_match else 'COMPROMISED',
                    'authentication': 'VALID',
                    'non_repudiation': 'PROVEN'
                }
                
                # Log success
                self.log_activity("VERIFICATION_SUCCESS", "Signature verified successfully", {
                    'file': os.path.basename(pdf_path),
                    'verification_data': verification_data
                })
                
                # Generate verification report
                report_file = self.generate_verification_report(pdf_path, pdf_path, 
                                                               signature_data or sig_meta, 
                                                               False, verification_data)
                
                return {
                    'status': 'success',
                    'verified': True,
                    'hash_match': hash_match,
                    'message': 'Tanda tangan digital VALID',
                    'details': verification_data,
                    'report_file': report_file,
                    'document_hash': pdf_hash_hex,
                    'original_hash': original_hash_hex,
                    'integrity': 'Dokumen asli dan utuh' if hash_match else 'Dokumen mungkin telah diubah'
                }
                
            except InvalidSignature:
                # Log failure
                self.log_activity("VERIFICATION_FAILED", "Signature verification failed", {
                    'file': os.path.basename(pdf_path),
                    'reason': 'Invalid signature'
                })
                
                return {
                    'status': 'success',
                    'verified': False,
                    'message': 'Tanda tangan digital INVALID atau tidak cocok',
                    'details': {
                        'verified': False,
                        'document_integrity': 'UNKNOWN',
                        'authentication': 'FAILED',
                        'non_repudiation': 'NOT PROVEN'
                    },
                    'document_hash': pdf_hash_hex,
                    'original_hash': original_hash_hex,
                    'integrity': 'Dokumen mungkin telah diubah atau tanda tangan tidak valid'
                }
            
        except Exception as e:
            error_msg = str(e)
            traceback.print_exc()
            
            # Log error
            self.log_activity("VERIFICATION_ERROR", "Error during verification", {
                'error': error_msg,
                'file': os.path.basename(pdf_path)
            })
            
            return {
                'status': 'error', 
                'message': f'Error verifikasi: {error_msg}',
                'verified': False
            }
    
    def generate_verification_report(self, original_pdf, signed_pdf, metadata, 
                                   is_signing=True, verification_data=None):
        """Generate detailed verification report"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = os.path.join(
            app.config['REPORT_FOLDER'], 
            f'report_{timestamp}.pdf'
        )
        
        doc = SimpleDocTemplate(report_file, pagesize=A4)
        story = []
        styles = getSampleStyleSheet()
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=16,
            spaceAfter=30,
            alignment=1
        )
        story.append(Paragraph("LAPORAN TANDA TANGAN DIGITAL", title_style))
        
        # Subtitle
        subtitle_style = ParagraphStyle(
            'CustomSubtitle',
            parent=styles['Normal'],
            fontSize=12,
            textColor=colors.grey,
            alignment=1
        )
        story.append(Paragraph("UAS Kriptografi - Implementasi RSA & SHA-256", subtitle_style))
        story.append(Spacer(1, 20))
        
        # Document Information
        story.append(Paragraph("<b>INFORMASI DOKUMEN</b>", styles['Heading2']))
        
        doc_info = [
            ["Asal Dokumen:", os.path.basename(original_pdf)],
            ["Waktu Proses:", datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
            ["Jenis Proses:", "Pembuatan Tanda Tangan" if is_signing else "Verifikasi Tanda Tangan"],
            ["Algoritma:", metadata.get('algorithm', 'RSA-SHA256')],
            ["Ukuran Kunci:", f"{metadata.get('key_size', 2048)}-bit"]
        ]
        
        table = Table(doc_info, colWidths=[150, 300])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(table)
        story.append(Spacer(1, 20))
        
        # Signature Details
        story.append(Paragraph("<b>DETAIL TANDA TANGAN</b>", styles['Heading2']))
        
        sig_data = [
            ["Timestamp:", metadata.get('timestamp', '')],
            ["Panjang Tanda Tangan:", f"{metadata.get('signature_length', 0)} bytes"],
            ["Hash Algorithm:", metadata.get('hash_algorithm', 'SHA-256')],
        ]
        
        if 'hash_hex' in metadata:
            sig_data.append(["Document Hash:", metadata['hash_hex'][:64]])
            if len(metadata['hash_hex']) > 64:
                sig_data.append(["", metadata['hash_hex'][64:]])
        
        table = Table(sig_data, colWidths=[150, 300])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(table)
        story.append(Spacer(1, 20))
        
        # Verification Results
        if verification_data:
            story.append(Paragraph("<b>HASIL VERIFIKASI</b>", styles['Heading2']))
            
            verification_table = [
                ["Aspek Keamanan", "Status", "Keterangan"],
                ["Autentikasi", verification_data.get('authentication', 'N/A'), 
                 "Verifikasi identitas penandatangan"],
                ["Integritas Data", verification_data.get('document_integrity', 'N/A'),
                 "Dokumen tidak berubah setelah ditandatangani"],
                ["Non-repudiasi", verification_data.get('non_repudiation', 'N/A'),
                 "Penandatangan tidak dapat menyangkal tandatangannya"],
                ["Hash Match", "MATCH" if verification_data.get('hash_match') else "MISMATCH",
                 "Kesesuaian hash dokumen"]
            ]
            
            table = Table(verification_table, colWidths=[150, 100, 200])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('BACKGROUND', (1, 1), (1, -1), 
                 colors.lightgreen if verification_data.get('verified') else colors.pink),
            ]))
            story.append(table)
        
        # Security Analysis
        story.append(Spacer(1, 20))
        story.append(Paragraph("<b>ANALISIS KEAMANAN</b>", styles['Heading2']))
        
        analysis = [
            "1. <b>RSA 2048-bit</b>: Tingkat keamanan tinggi, tahan terhadap serangan brute-force",
            "2. <b>SHA-256</b>: Fungsi hash kriptografi yang kuat, resisten collision",
            "3. <b>PSS Padding</b>: Meningkatkan keamanan terhadap serangan tertentu",
            "4. <b>Timestamp</b>: Mencegah replay attack dengan pencatatan waktu",
            "5. <b>Digital Signature</b>: Memberikan autentikasi, integritas, dan non-repudiasi",
            "6. <b>Hash Verification</b>: Memastikan dokumen tidak berubah setelah ditandatangani"
        ]
        
        for item in analysis:
            story.append(Paragraph(item, styles['Normal']))
            story.append(Spacer(1, 5))
        
        # Conclusion
        story.append(Spacer(1, 20))
        conclusion = "Kesimpulan: Sistem tanda tangan digital ini "
        if verification_data and verification_data.get('verified'):
            conclusion += "<b>BERHASIL</b> memverifikasi keaslian dan integritas dokumen."
        else:
            conclusion += "<b>TIDAK DAPAT</b> memverifikasi keaslian dokumen atau dokumen telah diubah."
        
        story.append(Paragraph(conclusion, styles['Normal']))
        
        # Footer
        story.append(Spacer(1, 30))
        footer_style = ParagraphStyle(
            'Footer',
            parent=styles['Normal'],
            fontSize=8,
            textColor=colors.grey,
            alignment=1
        )
        story.append(Paragraph("Generated by UAS Kriptografi Digital Signature System", footer_style))
        story.append(Paragraph(f"Report ID: {timestamp}", footer_style))
        
        # Build PDF
        doc.build(story)
        
        return report_file
    
    def create_test_pdfs(self):
        """Create test PDFs for demonstration"""
        test_files = []
        
        # Test 1: Simple Document
        test1_path = os.path.join(app.config['TEST_FOLDER'], 'test_document_1.pdf')
        self._create_test_pdf(
            test1_path,
            "Dokumen Test UAS Kriptografi",
            [
                "Ini adalah dokumen test untuk tanda tangan digital.",
                "Digunakan untuk keperluan UAS Kriptografi.",
                "Dokumen ini akan ditandatangani menggunakan RSA-SHA256.",
                "",
                "Informasi Penting:",
                "- Nama: Mahasiswa Kriptografi",
                "- NIM: 123456789",
                "- Mata Kuliah: Kriptografi",
                "- Dosen: Dr. Kriptografer, M.Kom.",
                "",
                "Timestamp: " + datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            ]
        )
        test_files.append(test1_path)
        
        # Test 2: Contract Document
        test2_path = os.path.join(app.config['TEST_FOLDER'], 'test_kontrak_2.pdf')
        self._create_test_pdf(
            test2_path,
            "KONTRAK DIGITAL UAS KRIPTOGRAFI",
            [
                "PERJANJIAN TANDA TANGAN DIGITAL",
                "",
                "Pihak Pertama: Mahasiswa",
                "Pihak Kedua: Sistem Tanda Tangan Digital",
                "",
                "PASAL 1 - KETENTUAN UMUM",
                "1. Dokumen ini digunakan untuk keperluan UAS Kriptografi",
                "2. Tanda tangan digital menggunakan algoritma RSA 2048-bit",
                "3. Hash dokumen menggunakan SHA-256",
                "",
                "PASAL 2 - VERIFIKASI",
                "1. Tanda tangan dapat diverifikasi kapan saja",
                "2. Integritas dokumen terjamin melalui hash",
                "3. Non-repudiasi tercapai melalui kriptografi asimetris",
                "",
                "Dibuat pada: " + datetime.now().strftime('%d %B %Y')
            ]
        )
        test_files.append(test2_path)
        
        # Test 3: Certificate
        test3_path = os.path.join(app.config['TEST_FOLDER'], 'test_sertifikat_3.pdf')
        self._create_test_pdf(
            test3_path,
            "SERTIFIKAT DIGITAL",
            [
                "SERTIFIKAT KEASLIAN DOKUMEN",
                "",
                "Diberikan kepada:",
                "MAHASISWA UAS KRIPTOGRAFI",
                "",
                "Atas partisipasi dalam:",
                "IMPLEMENTASI TANDA TANGAN DIGITAL",
                "Menggunakan Algoritma RSA dan SHA-256",
                "",
                "Dengan ini menyatakan bahwa:",
                "1. Dokumen ini asli dan utuh",
                "2. Tanda tangan digital valid",
                "3. Integritas terjamin secara kriptografis",
                "",
                "Nomor Sertifikat: CERT-" + datetime.now().strftime('%Y%m%d%H%M%S'),
                "Tanggal Terbit: " + datetime.now().strftime('%d/%m/%Y')
            ]
        )
        test_files.append(test3_path)
        
        self.log_activity("TEST_CREATION", "Test PDFs created", {
            'test_files': [os.path.basename(f) for f in test_files]
        })
        
        return test_files
    
    def _create_test_pdf(self, filepath, title, content_lines):
        """Helper function to create test PDF"""
        c = canvas.Canvas(filepath, pagesize=letter)
        
        # Title
        c.setFont("Helvetica-Bold", 16)
        c.drawCentredString(300, 750, title)
        c.line(100, 740, 500, 740)
        
        # Content
        c.setFont("Helvetica", 12)
        y_position = 700
        
        for line in content_lines:
            if y_position < 50:
                c.showPage()
                c.setFont("Helvetica", 12)
                y_position = 750
            
            c.drawString(100, y_position, line)
            y_position -= 20
        
        # Footer
        c.setFont("Helvetica-Oblique", 8)
        c.drawString(100, 30, "Dokumen Test - UAS Kriptografi - Digital Signature System")
        
        c.save()
    
    def export_all_results(self, include_tests=True):
        """Export all results for submission"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        zip_filename = f"uas_kriptografi_results_{timestamp}.zip"
        zip_path = os.path.join(app.config['OUTPUT_FOLDER'], zip_filename)
        
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # Add source code
            source_files = ['app.py', 'testing.py', 'report_generator.py']
            for file in source_files:
                if os.path.exists(file):
                    zipf.write(file, f'source_code/{file}')
            
            # Add test PDFs
            if include_tests and os.path.exists(app.config['TEST_FOLDER']):
                for test_file in os.listdir(app.config['TEST_FOLDER']):
                    test_path = os.path.join(app.config['TEST_FOLDER'], test_file)
                    if os.path.isfile(test_path):
                        zipf.write(test_path, f'test_pdfs/{test_file}')
            
            # Add signatures
            if os.path.exists(app.config['SIGNATURE_FOLDER']):
                for sig_file in os.listdir(app.config['SIGNATURE_FOLDER']):
                    sig_path = os.path.join(app.config['SIGNATURE_FOLDER'], sig_file)
                    if os.path.isfile(sig_path):
                        zipf.write(sig_path, f'signatures/{sig_file}')
            
            # Add reports
            if os.path.exists(app.config['REPORT_FOLDER']):
                for report_file in os.listdir(app.config['REPORT_FOLDER']):
                    report_path = os.path.join(app.config['REPORT_FOLDER'], report_file)
                    if os.path.isfile(report_path):
                        zipf.write(report_path, f'reports/{report_file}')
            
            # Add activity log
            log_file = os.path.join(app.config['OUTPUT_FOLDER'], 'activity_log.json')
            if os.path.exists(log_file):
                zipf.write(log_file, 'activity_log.json')
            
            # Add keys
            for key_file in os.listdir(app.config['OUTPUT_FOLDER']):
                if key_file.endswith('.pem'):
                    key_path = os.path.join(app.config['OUTPUT_FOLDER'], key_file)
                    zipf.write(key_path, f'keys/{key_file}')
        
        return zip_path

# Initialize digital signature system
ds_system = DigitalSignaturePDF()

# Create test PDFs on startup
ds_system.create_test_pdfs()

@app.route('/')
def index():
    """Home page"""
    return render_template('index.html')

@app.route('/execute')
def execute():
    """Execute page for signing/verifying"""
    return render_template('execute.html')

@app.route('/process')
def process():
    """Process flow page"""
    return render_template('process.html')

@app.route('/manual')
def manual():
    """Manual/book page"""
    return render_template('manual.html')

@app.route('/testing')
def testing():
    """Testing page"""
    return render_template('testing.html')

@app.route('/results')
def results():
    return render_template('result.html')


# API Routes
@app.route('/api/generate-keys', methods=['GET'])
def generate_keys():
    """Generate new RSA key pair"""
    ds_system.generate_keys()
    private_key, public_key = ds_system.get_keys_pem()
    
    return jsonify({
        'status': 'success',
        'private_key': private_key,
        'public_key': public_key,
        'message': 'RSA key pair generated successfully'
    })

@app.route('/api/upload-pdf', methods=['POST'])
def upload_pdf():
    """Upload PDF file"""
    if 'file' not in request.files:
        return jsonify({'status': 'error', 'message': 'No file uploaded'})
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'status': 'error', 'message': 'No file selected'})
    
    if file and file.filename.lower().endswith('.pdf'):
        filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{file.filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Calculate file hash
        with open(filepath, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        
        return jsonify({
            'status': 'success',
            'filename': filename,
            'filepath': filepath,
            'file_hash': file_hash,
            'message': 'File uploaded successfully'
        })
    
    return jsonify({'status': 'error', 'message': 'Invalid file type. Only PDF allowed'})

@app.route('/api/sign-pdf', methods=['POST'])
def sign_pdf():
    """Sign PDF document"""
    try:
        data = request.json
        filepath = data.get('filepath')
        document_info = data.get('document_info', {})
        
        if not filepath or not os.path.exists(filepath):
            return jsonify({'status': 'error', 'message': 'File not found'})
        
        # Sign the PDF
        result = ds_system.sign_pdf(filepath, document_info=document_info)
        
        if result['status'] == 'success':
            # Read the signed PDF for download
            with open(result['signed_pdf'], 'rb') as f:
                signed_pdf_data = base64.b64encode(f.read()).decode('utf-8')
            
            # Read signature file
            with open(result['signature_file'], 'r') as f:
                signature_data = json.load(f)
            
            # Read QR code
            with open(result['qr_code'], 'rb') as f:
                qr_data = base64.b64encode(f.read()).decode('utf-8')
            
            # Read report
            with open(result['report_file'], 'rb') as f:
                report_data = base64.b64encode(f.read()).decode('utf-8')
            
            return jsonify({
                'status': 'success',
                'signed_pdf': signed_pdf_data,
                'signature_data': signature_data,
                'qr_code': qr_data,
                'report': report_data,
                'filename': os.path.basename(result['signed_pdf']),
                'report_filename': os.path.basename(result['report_file']),
                'hash': result['hash'],
                'message': 'PDF berhasil ditandatangani secara digital'
            })
        else:
            return jsonify(result)
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/verify-pdf', methods=['POST'])
def verify_pdf():
    """Verify PDF signature"""
    try:
        data = request.json
        filepath = data.get('filepath')
        signature_data = data.get('signature_data')
        
        if not filepath or not os.path.exists(filepath):
            return jsonify({'status': 'error', 'message': 'File not found'})
        
        # Verify signature
        result = ds_system.verify_signature(filepath, signature_data)
        
        if result.get('status') == 'success' and result.get('report_file'):
            # Read report
            with open(result['report_file'], 'rb') as f:
                report_data = base64.b64encode(f.read()).decode('utf-8')
            
            result['report'] = report_data
            result['report_filename'] = os.path.basename(result['report_file'])
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/get-test-pdfs', methods=['GET'])
def get_test_pdfs():
    """Get list of test PDFs"""
    test_files = []
    if os.path.exists(app.config['TEST_FOLDER']):
        for file in os.listdir(app.config['TEST_FOLDER']):
            if file.lower().endswith('.pdf'):
                filepath = os.path.join(app.config['TEST_FOLDER'], file)
                file_size = os.path.getsize(filepath)
                
                # Calculate hash
                with open(filepath, 'rb') as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()
                
                test_files.append({
                    'filename': file,
                    'filepath': filepath,
                    'size': file_size,
                    'hash': file_hash,
                    'created': datetime.fromtimestamp(os.path.getctime(filepath)).isoformat()
                })
    
    return jsonify({
        'status': 'success',
        'test_files': test_files,
        'count': len(test_files)
    })

@app.route('/api/run-complete-test', methods=['POST'])
def run_complete_test():
    """Run complete test suite"""
    try:
        data = request.json
        test_file = data.get('test_file')
        
        if not test_file or not os.path.exists(test_file):
            return jsonify({'status': 'error', 'message': 'Test file not found'})
        
        test_results = []
        
        # 1. Sign the test PDF
        sign_result = ds_system.sign_pdf(test_file, document_info={
            'test_type': 'complete_test',
            'purpose': 'UAS Kriptografi Testing'
        })
        
        if sign_result['status'] != 'success':
            return jsonify({'status': 'error', 'message': 'Signing failed'})
        
        test_results.append({
            'test': 'Signing',
            'status': 'PASSED',
            'hash': sign_result.get('hash', ''),
            'signed_file': os.path.basename(sign_result['signed_pdf'])
        })
        
        # 2. Verify the signature
        verify_result = ds_system.verify_signature(sign_result['signed_pdf'])
        
        test_results.append({
            'test': 'Verification',
            'status': 'PASSED' if verify_result.get('verified') else 'FAILED',
            'verified': verify_result.get('verified', False),
            'message': verify_result.get('message', '')
        })
        
        # 3. Tamper test - modify the PDF and verify again
        tampered_file = test_file.replace('.pdf', '_tampered.pdf')
        with open(test_file, 'rb') as f:
            original_content = f.read()
        
        # Add a small modification
        tampered_content = original_content + b' '
        with open(tampered_file, 'wb') as f:
            f.write(tampered_content)
        
        tamper_verify = ds_system.verify_signature(tampered_file, sign_result['metadata'])
        
        test_results.append({
            'test': 'Tamper Detection',
            'status': 'PASSED' if not tamper_verify.get('verified') else 'FAILED',
            'verified': tamper_verify.get('verified', False),
            'expected': False,
            'message': 'Tanda tangan harus invalid setelah dokumen diubah'
        })
        
        # Clean up tampered file
        if os.path.exists(tampered_file):
            os.remove(tampered_file)
        
        # 4. Generate comprehensive report
        final_report = {
            'test_timestamp': datetime.now().isoformat(),
            'original_file': os.path.basename(test_file),
            'test_results': test_results,
            'success_rate': sum(1 for r in test_results if r['status'] == 'PASSED') / len(test_results) * 100,
            'signature_metadata': sign_result['metadata'],
            'verification_details': verify_result
        }
        
        # Save test report
        report_file = os.path.join(
            app.config['REPORT_FOLDER'],
            f'complete_test_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        )
        
        with open(report_file, 'w') as f:
            json.dump(final_report, f, indent=2)
        
        return jsonify({
            'status': 'success',
            'test_results': test_results,
            'success_rate': final_report['success_rate'],
            'report_file': report_file,
            'message': f'Complete test executed. Success rate: {final_report["success_rate"]:.1f}%'
        })
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/export-results', methods=['GET'])
def export_results():
    """Export all results as ZIP file"""
    try:
        zip_path = ds_system.export_all_results()
        
        if os.path.exists(zip_path):
            return send_file(
                zip_path,
                as_attachment=True,
                download_name=os.path.basename(zip_path),
                mimetype='application/zip'
            )
        else:
            return jsonify({'status': 'error', 'message': 'Export file not found'})
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/get-activity-log', methods=['GET'])
def get_activity_log():
    """Get system activity log"""
    log_file = os.path.join(app.config['OUTPUT_FOLDER'], 'activity_log.json')
    
    if os.path.exists(log_file):
        with open(log_file, 'r') as f:
            log_data = json.load(f)
        
        return jsonify({
            'status': 'success',
            'log_entries': log_data,
            'total_entries': len(log_data)
        })
    else:
        return jsonify({
            'status': 'success',
            'log_entries': [],
            'total_entries': 0
        })

@app.route('/api/download-file', methods=['POST'])
def download_file():
    """Download file"""
    try:
        data = request.json
        filename = data.get('filename')
        file_data = data.get('file_data')
        
        if not filename or not file_data:
            return jsonify({'status': 'error', 'message': 'Invalid request'})
        
        # Decode base64 data
        file_content = base64.b64decode(file_data)
        
        # Save to temporary file
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
        temp_file.write(file_content)
        temp_file.close()
        
        return send_file(
            temp_file.name,
            as_attachment=True,
            download_name=filename,
            mimetype='application/pdf'
        )
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/generate-final-report', methods=['POST'])
def generate_final_report():
    """Generate final UAS report"""
    try:
        data = request.json
        student_info = data.get('student_info', {})
        
        # Generate comprehensive final report
        report_content = generate_final_report_content(student_info, ds_system.signature_log)
        
        # Save report
        report_file = os.path.join(
            app.config['REPORT_FOLDER'],
            f'uas_final_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
        )
        
        # Create PDF report
        doc = SimpleDocTemplate(report_file, pagesize=A4)
        story = []
        styles = getSampleStyleSheet()
        
        # Title
        story.append(Paragraph("LAPORAN UAS KRIPTOGRAFI", styles['Title']))
        story.append(Paragraph("IMPLEMENTASI TANDA TANGAN DIGITAL", styles['Heading1']))
        story.append(Spacer(1, 20))
        
        # Student Information
        story.append(Paragraph("INFORMASI MAHASISWA", styles['Heading2']))
        student_data = [
            ["Nama:", student_info.get('name', 'Mahasiswa')],
            ["NIM:", student_info.get('nim', '123456789')],
            ["Mata Kuliah:", "Kriptografi"],
            ["Dosen:", student_info.get('lecturer', 'Dr. Kriptografer, M.Kom.')],
            ["Tanggal:", datetime.now().strftime('%d %B %Y')]
        ]
        
        table = Table(student_data, colWidths=[100, 300])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        story.append(table)
        story.append(Spacer(1, 20))
        
        # Add report sections
        for section in report_content.get('sections', []):
            story.append(Paragraph(section['title'], styles['Heading2']))
            for content in section['content']:
                story.append(Paragraph(content, styles['Normal']))
            story.append(Spacer(1, 10))
        
        # Build PDF
        doc.build(story)
        
        # Read report for response
        with open(report_file, 'rb') as f:
            report_data = base64.b64encode(f.read()).decode('utf-8')
        
        return jsonify({
            'status': 'success',
            'report': report_data,
            'filename': os.path.basename(report_file),
            'message': 'Laporan UAS berhasil digenerate'
        })
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

def generate_final_report_content(student_info, activity_log):
    """Generate content for final report"""
    sections = [
        {
            'title': '1. PENDAHULUAN',
            'content': [
                'Laporan ini merupakan hasil implementasi sistem tanda tangan digital untuk UAS Kriptografi.',
                'Sistem ini mengimplementasikan algoritma RSA dengan fungsi hash SHA-256 untuk memberikan',
                'jaminan keamanan terhadap dokumen digital dalam hal:',
                '- <b>Autentikasi</b>: Memverifikasi identitas penandatangan',
                '- <b>Integritas</b>: Memastikan dokumen tidak berubah',
                '- <b>Non-repudiasi</b>: Mencegah penyangkalan tanda tangan'
            ]
        },
        {
            'title': '2. IMPLEMENTASI ALGORITMA',
            'content': [
                '2.1 <b>RSA (Rivest-Shamir-Adleman)</b>',
                '   - Key Size: 2048-bit',
                '   - Public Exponent: 65537',
                '   - Padding Scheme: PSS dengan MGF1',
                '',
                '2.2 <b>SHA-256 (Secure Hash Algorithm)</b>',
                '   - Output: 256-bit hash value',
                '   - Collision resistant',
                '   - One-way function'
            ]
        },
        {
            'title': '3. HASIL IMPLEMENTASI',
            'content': [
                f'Total Aktivitas Sistem: {len(activity_log)}',
                'Fitur yang berhasil diimplementasikan:',
                '   - Pembuatan tanda tangan digital',
                '   - Verifikasi tanda tangan',
                '   - Pembuatan dokumen test',
                '   - Analisis keamanan',
                '   - Laporan otomatis',
                '   - Export hasil lengkap'
            ]
        },
        {
            'title': '4. ANALISIS KEAMANAN',
            'content': [
                '4.1 <b>Kekuatan Sistem</b>',
                '   - RSA 2048-bit memberikan keamanan yang memadai',
                '   - SHA-256 menjamin integritas data',
                '   - Timestamp mencegah replay attack',
                '',
                '4.2 <b>Kelemahan dan Perbaikan</b>',
                '   - Private key harus disimpan dengan aman',
                '   - Perlu implementasi sertifikat digital',
                '   - Dapat dikembangkan dengan blockchain'
            ]
        },
        {
            'title': '5. KESIMPULAN',
            'content': [
                'Sistem tanda tangan digital berhasil diimplementasikan dengan baik.',
                'Semua persyaratan UAS terpenuhi termasuk:',
                '   - File PDF asli dan bertanda tangan',
                '   - File tanda tangan digital',
                '   - Hasil verifikasi',
                '   - Source code program',
                '   - Laporan lengkap',
                '',
                'Sistem ini dapat digunakan untuk menjamin keaslian dokumen digital',
                'dalam berbagai aplikasi seperti kontrak, sertifikat, dan dokumen penting lainnya.'
            ]
        }
    ]
    
    return {'sections': sections}

if __name__ == '__main__':
    print("=" * 60)
    print("DIGITAL SIGNATURE SYSTEM - UAS KRIPTOGRAFI")
    print("=" * 60)
    print("Server running on http://localhost:5000")
    print("\nTest PDFs created in: test_pdfs/")
    print("Outputs saved in: outputs/")
    print("\nAccess the web interface at:")
    print("  • http://localhost:5000 - Home")
    print("  • http://localhost:5000/execute - Sign/Verify")
    print("  • http://localhost:5000/testing - Testing")
    print("  • http://localhost:5000/results - Export Results")
    print("=" * 60)
    app.run(debug=True, host='0.0.0.0', port=5000)