#!/usr/bin/env python3
"""
Report Generator for UAS Submission
Membuat laporan lengkap untuk pengumpulan UAS
"""

import os
import json
import hashlib
from datetime import datetime
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

class UASReportGenerator:
    def __init__(self, output_dir='outputs/reports'):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
    def generate_final_report(self, student_info, test_results, signature_log):
        """Generate final UAS report"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = os.path.join(self.output_dir, f'uas_final_report_{timestamp}.pdf')
        
        doc = SimpleDocTemplate(filename, pagesize=A4)
        story = []
        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=20,
            spaceAfter=30,
            alignment=1,
            textColor=colors.HexColor('#2c3e50')
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=14,
            spaceAfter=12,
            spaceBefore=20,
            textColor=colors.HexColor('#2980b9')
        )
        
        # Cover Page
        story.append(Spacer(1, 2*inch))
        story.append(Paragraph("LAPORAN UAS KRIPTOGRAFI", title_style))
        story.append(Spacer(1, 0.5*inch))
        story.append(Paragraph("IMPLEMENTASI TANDA TANGAN DIGITAL", styles['Heading2']))
        story.append(Spacer(1, 1*inch))
        
        story.append(Paragraph("<b>Diajukan untuk memenuhi tugas</b>", styles['Normal']))
        story.append(Paragraph("<b>Mata Kuliah Kriptografi</b>", styles['Normal']))
        story.append(Spacer(1, 1*inch))
        
        # Student Info Table
        student_data = [
            ["Nama Mahasiswa", student_info.get('name', 'Mahasiswa')],
            ["NIM", student_info.get('nim', '123456789')],
            ["Program Studi", student_info.get('program', 'Teknik Informatika')],
            ["Dosen Pengampu", student_info.get('lecturer', 'Dr. Kriptografer, M.Kom.')],
            ["Tanggal Penyelesaian", datetime.now().strftime('%d %B %Y')]
        ]
        
        table = Table(student_data, colWidths=[150, 300])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('PADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(table)
        
        story.append(Spacer(1, inch))
        doc.build(story)
        
        # Start new page for content
        story = []
        
        # Table of Contents
        story.append(Paragraph("DAFTAR ISI", heading_style))
        
        toc_items = [
            ("1. PENDAHULUAN", 1),
            ("2. TUJUAN DAN MANFAAT", 2),
            ("3. IMPLEMENTASI ALGORITMA", 3),
            ("  3.1 Algoritma RSA", 3),
            ("  3.2 Fungsi Hash SHA-256", 4),
            ("4. HASIL IMPLEMENTASI", 5),
            ("5. PENGUJIAN SISTEM", 6),
            ("6. ANALISIS KEAMANAN", 7),
            ("7. KESIMPULAN", 8),
            ("LAMPIRAN", 9)
        ]
        
        for item, page in toc_items:
            story.append(Paragraph(f"{item} ...... {page}", styles['Normal']))
        
        story.append(Spacer(1, 0.5*inch))
        
        # Chapter 1: Introduction
        story.append(Paragraph("1. PENDAHULUAN", heading_style))
        story.append(Paragraph(
            "Tanda tangan digital merupakan teknologi kriptografi yang memungkinkan "
            "pembuktian keaslian, integritas, dan non-repudiasi pada dokumen digital. "
            "Dalam era digital seperti saat ini, kebutuhan akan keamanan dokumen elektronik "
            "semakin meningkat, terutama untuk dokumen-dokumen penting seperti kontrak, "
            "sertifikat, dan dokumen resmi lainnya.",
            styles['Normal']
        ))
        
        story.append(Spacer(1, 0.2*inch))
        story.append(Paragraph(
            "Laporan ini menyajikan implementasi sistem tanda tangan digital menggunakan "
            "algoritma RSA dan fungsi hash SHA-256. Sistem ini dikembangkan sebagai "
            "bagian dari penugasan UAS Mata Kuliah Kriptografi.",
            styles['Normal']
        ))
        
        # Chapter 2: Objectives
        story.append(Paragraph("2. TUJUAN DAN MANFAAT", heading_style))
        
        objectives = [
            "1. Mengimplementasikan algoritma RSA untuk tanda tangan digital",
            "2. Menggunakan fungsi hash SHA-256 untuk integritas data",
            "3. Membuat sistem verifikasi tanda tangan yang handal",
            "4. Menganalisis keamanan sistem yang diimplementasikan",
            "5. Membuat laporan lengkap untuk penilaian UAS"
        ]
        
        for obj in objectives:
            story.append(Paragraph(obj, styles['Normal']))
        
        story.append(Spacer(1, 0.2*inch))
        story.append(Paragraph(
            "<b>Manfaat:</b> Sistem ini dapat digunakan untuk menjamin keaslian "
            "dokumen digital, mencegah pemalsuan, dan memberikan bukti hukum "
            "yang kuat dalam transaksi elektronik.",
            styles['Normal']
        ))
        
        # Chapter 3: Algorithm Implementation
        story.append(Paragraph("3. IMPLEMENTASI ALGORITMA", heading_style))
        story.append(Paragraph("3.1 Algoritma RSA", styles['Heading3']))
        
        story.append(Paragraph(
            "RSA (Rivest-Shamir-Adleman) adalah algoritma kriptografi asimetris "
            "yang menggunakan pasangan kunci publik dan privat. Implementasi dalam "
            "sistem ini menggunakan parameter-parameter berikut:",
            styles['Normal']
        ))
        
        rsa_params = [
            ["Parameter", "Nilai", "Keterangan"],
            ["Key Size", "2048-bit", "Ukuran kunci yang aman menurut standar saat ini"],
            ["Public Exponent", "65537", "Bilangan prima yang umum digunakan"],
            ["Padding Scheme", "PSS", "Probabilistic Signature Scheme"],
            ["MGF", "MGF1", "Mask Generation Function dengan SHA-256"]
        ]
        
        table = Table(rsa_params, colWidths=[100, 80, 280])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ]))
        story.append(table)
        
        story.append(Paragraph("3.2 Fungsi Hash SHA-256", styles['Heading3']))
        story.append(Paragraph(
            "SHA-256 (Secure Hash Algorithm 256-bit) adalah fungsi hash kriptografi "
            "yang menghasilkan output 256-bit. Karakteristik SHA-256:",
            styles['Normal']
        ))
        
        sha256_features = [
            "• <b>One-way function</b>: Tidak dapat direkonstruksi dari hash",
            "• <b>Collision resistant</b>: Sulit menemukan dua input dengan hash sama",
            "• <b>Avalanche effect</b>: Perubahan kecil input menghasilkan perubahan besar output",
            "• <b>Fixed output size</b>: Selalu menghasilkan 256-bit (64 karakter hex)"
        ]
        
        for feature in sha256_features:
            story.append(Paragraph(feature, styles['Normal']))
        
        # Chapter 4: Implementation Results
        story.append(Paragraph("4. HASIL IMPLEMENTASI", heading_style))
        
        if test_results:
            passed = sum(1 for r in test_results if r.get('status') == 'PASSED')
            total = len(test_results)
            success_rate = (passed / total * 100) if total > 0 else 0
            
            story.append(Paragraph(
                f"Sistem berhasil diimplementasikan dengan tingkat keberhasilan "
                f"<b>{success_rate:.1f}%</b> ({passed} dari {total} test berhasil).",
                styles['Normal']
            ))
            
            # Test Results Table
            test_data = [["Test", "Status", "Keterangan"]]
            for result in test_results:
                status = result.get('status', 'UNKNOWN')
                status_color = colors.green if status == 'PASSED' else colors.red
                
                test_data.append([
                    result.get('test', ''),
                    status,
                    result.get('message', '')[:50] + '...'
                ])
            
            if len(test_data) > 1:
                table = Table(test_data, colWidths=[150, 80, 220])
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('TEXTCOLOR', (1, 1), (1, -1), 
                     lambda r, c, v: colors.green if v == 'PASSED' else colors.red),
                ]))
                story.append(table)
        
        # Chapter 5: Security Analysis
        story.append(Paragraph("5. ANALISIS KEAMANAN", heading_style))
        
        security_analysis = [
            ("Autentikasi", 
             "RSA public key digunakan untuk memverifikasi identitas penandatangan. "
             "Hanya pemilik private key yang sesuai yang dapat membuat tanda tangan valid."),
            
            ("Integritas", 
             "SHA-256 hash memastikan dokumen tidak berubah setelah ditandatangani. "
             "Perubahan sekecil apapun akan menghasilkan hash yang berbeda."),
            
            ("Non-repudiasi", 
             "Private key yang unik mencegah penandatangan menyangkal telah menandatangani dokumen. "
             "Tanda tangan hanya dapat dibuat dengan private key yang sesuai."),
            
            ("Resistensi Serangan", 
             "RSA 2048-bit tahan terhadap serangan brute-force. "
             "SHA-256 resisten terhadap collision attack. "
             "Timestamp mencegah replay attack.")
        ]
        
        for title, content in security_analysis:
            story.append(Paragraph(f"<b>{title}</b>", styles['Normal']))
            story.append(Paragraph(content, styles['Normal']))
            story.append(Spacer(1, 0.1*inch))
        
        # Chapter 6: Conclusion
        story.append(Paragraph("6. KESIMPULAN", heading_style))
        
        story.append(Paragraph(
            "Sistem tanda tangan digital berhasil diimplementasikan menggunakan "
            "algoritma RSA 2048-bit dan fungsi hash SHA-256. Sistem ini memenuhi "
            "semua persyaratan keamanan kriptografi: autentikasi, integritas, "
            "dan non-repudiasi.",
            styles['Normal']
        ))
        
        story.append(Spacer(1, 0.2*inch))
        story.append(Paragraph(
            "<b>Kontribusi:</b> Sistem ini dapat diaplikasikan dalam berbagai "
            "skenario nyata seperti tanda tangan kontrak digital, verifikasi "
            "sertifikat, dan pengamanan dokumen penting.",
            styles['Normal']
        ))
        
        story.append(Spacer(1, 0.2*inch))
        story.append(Paragraph(
            "<b>Rekomendasi Pengembangan:</b>",
            styles['Normal']
        ))
        
        recommendations = [
            "1. Implementasi sertifikat digital untuk autentikasi lebih kuat",
            "2. Integrasi dengan sistem blockchain untuk decentralized verification",
            "3. Penggunaan hardware security module untuk penyimpanan kunci",
            "4. Pengembangan mobile application untuk kemudahan akses"
        ]
        
        for rec in recommendations:
            story.append(Paragraph(rec, styles['Normal']))
        
        # Appendix
        story.append(Paragraph("LAMPIRAN", heading_style))
        
        if signature_log:
            story.append(Paragraph(
                f"<b>Log Aktivitas Sistem:</b> Total {len(signature_log)} aktivitas tercatat",
                styles['Normal']
            ))
            
            # Show last 5 activities
            recent_logs = signature_log[-5:] if len(signature_log) > 5 else signature_log
            log_data = [["Timestamp", "Activity", "Description"]]
            
            for log in recent_logs:
                timestamp = log.get('timestamp', '')
                activity = log.get('activity', '')
                description = log.get('description', '')
                
                log_data.append([
                    timestamp[:19],
                    activity,
                    description[:40] + '...' if len(description) > 40 else description
                ])
            
            table = Table(log_data, colWidths=[100, 100, 260])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
            ]))
            story.append(table)
        
        # Final page
        story.append(Spacer(1, inch))
        story.append(Paragraph(
            "<i>Laporan ini dibuat secara otomatis oleh Sistem Tanda Tangan Digital "
            "untuk keperluan UAS Kriptografi.</i>",
            styles['Italic']
        ))
        
        story.append(Spacer(1, 0.5*inch))
        story.append(Paragraph(
            f"Dokumen ID: {hashlib.md5(filename.encode()).hexdigest()[:16].upper()}",
            ParagraphStyle(
                'DocID',
                parent=styles['Normal'],
                fontSize=8,
                textColor=colors.grey
            )
        ))
        
        # Build the document
        doc.build(story)
        
        print(f"✅ Final report generated: {filename}")
        return filename

def main():
    """Main function for standalone report generation"""
    generator = UASReportGenerator()
    
    # Sample data for testing
    student_info = {
        'name': 'Mahasiswa Kriptografi',
        'nim': '123456789',
        'program': 'Teknik Informatika',
        'lecturer': 'Dr. Kriptografer, M.Kom.'
    }
    
    test_results = [
        {'test': 'RSA Key Generation', 'status': 'PASSED', 'message': '2048-bit keys generated successfully'},
        {'test': 'SHA-256 Hashing', 'status': 'PASSED', 'message': 'Hash function working correctly'},
        {'test': 'Signature Creation', 'status': 'PASSED', 'message': 'Digital signatures created successfully'},
        {'test': 'Signature Verification', 'status': 'PASSED', 'message': 'Signatures verified correctly'},
        {'test': 'Tamper Detection', 'status': 'PASSED', 'message': 'Document tampering detected successfully'}
    ]
    
    signature_log = [
        {
            'timestamp': datetime.now().isoformat(),
            'activity': 'TEST_RUN',
            'description': 'Complete test suite executed'
        }
    ]
    
    # Generate report
    report_file = generator.generate_final_report(student_info, test_results, signature_log)
    
    print(f"\n📄 Report generated successfully!")
    print(f"📁 Location: {report_file}")
    print(f"👤 Student: {student_info['name']}")
    print(f"🎓 NIM: {student_info['nim']}")
    
    # Calculate file hash
    with open(report_file, 'rb') as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()
    
    print(f"🔒 Report Hash (SHA-256): {file_hash}")
    
    return report_file

if __name__ == '__main__':
    main()