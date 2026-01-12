GASSS 🔥
ini aku bikinin **README.md FULL, RAPII, AMAN LISENSI, SIAP UPLOAD GITHUB**, **relevan 100% sama program kamu** (Digital Signature PDF – UAS Kriptografi) **dan sudah nyambung dengan semua revisi & perbaikan yang tadi**.

Kamu **tinggal COPAS → simpan sebagai `README.md` → push ke GitHub**.
Tidak ada bagian abu-abu. Tidak setengah-setengah.

---

# 📄 Digital Signature PDF System

### UAS Kriptografi – Implementasi RSA 2048-bit & SHA-256

---

## 📌 Deskripsi Umum

**Digital Signature PDF System** adalah aplikasi berbasis Python & Web yang dikembangkan untuk memenuhi **Ujian Akhir Semester (UAS) Mata Kuliah Kriptografi**.
Aplikasi ini mengimplementasikan **tanda tangan digital pada dokumen PDF** menggunakan algoritma kriptografi modern, dengan fokus pada **integritas, autentikasi, dan non-repudiation**.

Sistem ini mampu:

* Menandatangani dokumen PDF secara digital
* Memverifikasi keaslian dokumen
* Menghasilkan laporan verifikasi
* Mencatat aktivitas ke dalam audit log berbasis hash (tamper-evident)
* Mengemas hasil eksekusi ke dalam satu file ZIP

---

## 🎯 Tujuan Pengembangan

1. Menerapkan konsep kriptografi kunci publik (asymmetric cryptography)
2. Mengimplementasikan algoritma **RSA 2048-bit** dan **SHA-256**
3. Memahami alur kerja sistem tanda tangan digital
4. Mengintegrasikan backend kriptografi dengan antarmuka web
5. Menghasilkan sistem yang siap untuk demonstrasi akademik

---

## 🔐 Algoritma & Konsep Kriptografi

| Komponen          | Implementasi               |
| ----------------- | -------------------------- |
| Hashing           | SHA-256                    |
| Digital Signature | RSA 2048-bit               |
| Tipe Kriptografi  | Asymmetric                 |
| Audit Trail       | Hash Chaining              |
| Metadata PDF      | Embedded Digital Signature |

---

## 🧠 Arsitektur Sistem

### 1️⃣ Upload & Hashing

* User mengunggah file PDF
* Sistem menghitung hash SHA-256 dari dokumen

### 2️⃣ Eksekusi Tanda Tangan

* Hash dokumen ditandatangani menggunakan private key RSA
* Signature disematkan ke metadata PDF
* Manifest eksekusi dibuat (`manifest.json`)

### 3️⃣ Output Eksekusi

Sistem menghasilkan:

* `signed_document.pdf`
* `verification_report.pdf`
* `digital_signature.json`
* `signature_qrcode.png`

### 4️⃣ Audit Logging

Setiap aktivitas dicatat ke:

* `audit_log.json`
* Menggunakan hash chaining untuk mencegah manipulasi log

### 5️⃣ Testing & Verification

* Sistem hanya mengizinkan testing pada file yang **sudah dieksekusi**
* Status file:

  * ✅ Executed
  * ❌ Not Executed

---

## 📂 Struktur Folder Proyek

```
UAS_KRIPTOGRAFI_DIGITAL_SIGNATURE/
│
├── source_code/
│   ├── app.py
│   ├── crypto/
│   │   ├── hashing.py
│   │   ├── signer.py
│   │   └── verifier.py
│   │
│   ├── pdf/
│   │   ├── pdf_signed.py
│   │   └── pdf_report.py
│   │
│   ├── audit/
│   │   └── audit_log.py
│   │
│   ├── outputs/
│   │   └── (hasil eksekusi & zip)
│   │
│   └── static/
│       └── frontend UI
│
├── testpdf/
│   └── sample pdf
│
├── README.md
├── LICENSE
└── requirements.txt
```

---

## 🖥️ Fitur Utama

### ✅ Digital Signature PDF

* Menyematkan signature ke metadata PDF
* Tidak merusak konten asli dokumen

### ✅ Verification Report

* Membandingkan hash dokumen
* Menampilkan status valid / invalid

### ✅ Audit Log System

* Semua aktivitas dicatat
* Menggunakan hash chaining (tamper-evident)

### ✅ ZIP Packaging

* Seluruh output dikemas otomatis dalam satu file ZIP

### ✅ Validasi Status Eksekusi

* File **harus dieksekusi terlebih dahulu**
* Mencegah false-positive testing

---

## 🚀 Cara Menjalankan Program

### 1️⃣ Install Dependency

```bash
pip install -r requirements.txt
```

### 2️⃣ Jalankan Server

```bash
python app.py
```

### 3️⃣ Akses Aplikasi

```
http://localhost:5000
```

---

## 🧪 Alur Demonstrasi (Disarankan)

1. Upload file PDF
2. Jalankan **Execute / Sign**
3. Pastikan status menjadi **Executed**
4. Jalankan **Testing / Verification**
5. Download ZIP hasil eksekusi

---

## ⚠️ Catatan Penting

* File yang belum dieksekusi **tidak boleh langsung diuji**
* Sistem menggunakan manifest eksekusi sebagai acuan validasi
* File ZIP akan gagal di-download jika folder `outputs/` tidak tersedia

---

## 🔒 Keamanan & Batasan

* Project ini **hanya untuk tujuan akademik**
* Tidak digunakan untuk dokumen hukum resmi
* Private key **tidak disarankan untuk dipublikasikan**

---

## 📚 Disclaimer

> This project was developed for academic purposes (UAS Cryptography).
> Some parts of the code were assisted by AI tools as a learning aid.
> The author fully understands and is responsible for the implementation.

---

## 👤 Author

**Nama** : Aldi Satriya
**Program Studi** : Informatics Engineering (S1)
**Mata Kuliah** : Kriptografi
**Dosen** :  Hemdani Rahendra Herlianto, S.Kom., M.T.I.
**Tahun** : 2026

---

## 📜 License

This project is licensed under the **MIT License** – see the `LICENSE` file for details.

---

## 🔥 Penutup

Project ini dirancang untuk:

* Mudah dipahami
* Aman secara akademik
* Siap dipresentasikan
* Siap di-upload ke GitHub

---

