/* =====================================================
   DIGITAL SIGNATURE PDF - SCRIPT
   Galaxy UI Version (Fixed & Clean)
===================================================== */

document.addEventListener("DOMContentLoaded", () => {
    console.log("🚀 Script Loaded Successfully");

    App.init();
});

/* =====================================================
   MAIN APP OBJECT
===================================================== */
const App = {

    /* ================= INIT ================= */
    init() {
        this.bindButtons();
        this.createClock("clock");
        this.fixBootstrapModal();
    },

    /* ================= CLOCK ================= */
    createClock(elementId, format = "HH:mm:ss") {
        const element = document.getElementById(elementId);
        if (!element) return;

        function updateClock() {
            const now = new Date();
            const hours = String(now.getHours()).padStart(2, "0");
            const minutes = String(now.getMinutes()).padStart(2, "0");
            const seconds = String(now.getSeconds()).padStart(2, "0");

            let timeString = format
                .replace("HH", hours)
                .replace("mm", minutes)
                .replace("ss", seconds);

            element.textContent = timeString;
        }

        updateClock();
        setInterval(updateClock, 1000);
    },

    /* ================= BUTTONS ================= */
    bindButtons() {

        const btnGenerate = document.getElementById("btn-generate");
        if (btnGenerate) {
            btnGenerate.addEventListener("click", () => {
                this.generateKeys();
            });
        }

        const btnSign = document.getElementById("btn-sign");
        if (btnSign) {
            btnSign.addEventListener("click", () => {
                this.signPDF();
            });
        }

        const btnVerify = document.getElementById("btn-verify");
        if (btnVerify) {
            btnVerify.addEventListener("click", () => {
                this.verifyPDF();
            });
        }
    },

    /* ================= API ================= */
    async generateKeys() {
        try {
            this.toast("🔐 Generating RSA Keys...", "info");

            const res = await fetch("/api/generate-keys");
            const data = await res.json();

            this.toast("✅ RSA Key Generated", "success");
            console.log(data);
        } catch (err) {
            console.error(err);
            this.toast("❌ Failed Generate Keys", "error");
        }
    },

    async signPDF() {
        this.toast("✍️ Signing PDF...", "info");
        // Implement upload logic here
    },

    async verifyPDF() {
        this.toast("🔍 Verifying Signature...", "info");
        // Implement verify logic here
    },

    /* ================= UI HELPERS ================= */
    toast(message, type = "info") {
        console.log(`[${type.toUpperCase()}] ${message}`);
        alert(message); // simple fallback
    },

    /* ================= MODAL FIX ================= */
    fixBootstrapModal() {
        const modal = document.getElementById("modal");
        if (!modal) return;

        modal.addEventListener("hidden.bs.modal", () => {
            if (document.activeElement) {
                document.activeElement.blur();
            }
        });
    }
};
