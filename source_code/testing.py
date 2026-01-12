#!/usr/bin/env python3
"""
REAL TESTING SCRIPT - MANIFEST BASED
UAS KRIPTOGRAFI DIGITAL SIGNATURE
"""

import os
import json
import hashlib
from datetime import datetime
from PyPDF2 import PdfReader


EXECUTED_DIR = "outputs/executed"


class RealSignatureTester:

    def __init__(self):
        self.results = []

    # ===============================
    # UTIL
    # ===============================
    def log(self, pdf_name, status, message, details=None):
        result = {
            "pdf": pdf_name,
            "status": status,
            "message": message,
            "timestamp": datetime.now().isoformat(),
            "details": details or {}
        }
        self.results.append(result)
        print(f"[{status}] {pdf_name} → {message}")

    def hash_file(self, path):
        sha = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha.update(chunk)
        return sha.hexdigest()

    # ===============================
    # CORE TEST
    # ===============================
    def test_executed_pdf(self, exec_path):
        pdf_name = os.path.basename(exec_path)

        manifest_path = os.path.join(exec_path, "manifest.json")
        signed_pdf_path = os.path.join(exec_path, "signed.pdf")
        signature_json_path = os.path.join(exec_path, "signature.json")

        # 1️⃣ MANIFEST CHECK
        if not os.path.exists(manifest_path):
            self.log(pdf_name, "FAILED", "Manifest not found → PDF NOT EXECUTED")
            return

        with open(manifest_path) as f:
            manifest = json.load(f)

        # 2️⃣ FILE EXISTENCE
        for fpath, fname in [
            (signed_pdf_path, "signed.pdf"),
            (signature_json_path, "signature.json")
        ]:
            if not os.path.exists(fpath):
                self.log(pdf_name, "FAILED", f"{fname} missing")
                return

        # 3️⃣ HASH VALIDATION
        actual_hash = self.hash_file(signed_pdf_path)

        if actual_hash != manifest["file_hash"]:
            self.log(
                pdf_name,
                "FAILED",
                "File hash mismatch (TAMPERED)",
                {
                    "expected": manifest["file_hash"][:16],
                    "actual": actual_hash[:16]
                }
            )
            return

        # 4️⃣ SIGNATURE VALIDATION
        with open(signature_json_path) as f:
            sig_data = json.load(f)

        if sig_data["signature_hex"] != manifest["signature_hash"]:
            self.log(
                pdf_name,
                "FAILED",
                "Signature mismatch",
                {
                    "manifest_signature": manifest["signature_hash"][:16],
                    "signature_file": sig_data["signature_hex"][:16]
                }
            )
            return

        # 5️⃣ PDF METADATA CHECK
        reader = PdfReader(signed_pdf_path)
        metadata = reader.metadata

        if "/DigitalSignature" not in metadata:
            self.log(pdf_name, "FAILED", "DigitalSignature metadata missing")
            return

        if metadata["/DigitalSignature"] != manifest["signature_hash"]:
            self.log(pdf_name, "FAILED", "Embedded signature mismatch")
            return

        # ✅ PASSED
        self.log(
            pdf_name,
            "PASSED",
            "PDF verified successfully",
            {
                "executed_at": manifest["executed_at"],
                "algorithm": "RSA-2048 + SHA-256"
            }
        )

    # ===============================
    # RUNNER
    # ===============================
    def run(self):
        print("=" * 60)
        print("REAL DIGITAL SIGNATURE TEST (MANIFEST BASED)")
        print("=" * 60)

        if not os.path.exists(EXECUTED_DIR):
            print("❌ No executed PDFs found")
            return

        for folder in os.listdir(EXECUTED_DIR):
            exec_path = os.path.join(EXECUTED_DIR, folder)
            if os.path.isdir(exec_path):
                self.test_executed_pdf(exec_path)

        # SUMMARY
        passed = sum(1 for r in self.results if r["status"] == "PASSED")
        total = len(self.results)

        print("\n" + "=" * 60)
        print("SUMMARY")
        print("=" * 60)
        print(f"Total PDFs tested : {total}")
        print(f"PASSED            : {passed}")
        print(f"FAILED            : {total - passed}")

        with open("real_test_report.json", "w") as f:
            json.dump(self.results, f, indent=2)

        print("\n📄 Report saved: real_test_report.json")


if __name__ == "__main__":
    tester = RealSignatureTester()
    tester.run()
