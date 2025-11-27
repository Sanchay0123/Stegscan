# 🕵️‍♂️ Steganography Detection Toolkit

A multi-detector steganalysis system capable of detecting hidden data inside
**PNG**, **JPEG**, **PDF**, and **DOCX** files using multiple forensic techniques.

This project is developed as a University submission focusing on **real-world steganography detection** and **malware-style hidden payload forensics**.

---

## 🚀 Features

✔ Supports multiple file types:  
PNG • JPEG • PDF • DOCX/DOC  

✔ Multiple detectors combined with weighted scoring  
✔ Hard-evidence override for hidden binaries (EXE/ZIP/PDF)  
✔ Full forensic reasoning in report output  
✔ CLI with JSON export option  
✔ Modular design → easy to extend with new detectors  

---

## 🔍 Detection Techniques

| Detector | Targets | What it Finds |
|---------|---------|---------------|
| **LSB Steganalysis** | PNG/BMP | Pixel bit-plane anomalies |
| **JPEG DCT Analysis** | JPEG | Frequency coefficient deviation |
| **Appended Payload Detector** | Images | Hidden ZIP/EXE after image EOF |
| **PNG Chunk Integrity Scan** | PNG | Non-standard / payload chunks |
| **PDF Stream Steganalysis** | PDF | High entropy streams, embedded binary signatures |
| **DOCX Macro/Object Scan** | DOCX/DOC | Malicious embedded files or VBA macros |

Uses **numeric score + heuristic classification** with explainable results.

---

## 🧠 Architecture


---

## 📦 Installation

```bash
git clone https://github.com/<your-username>/stegscan.git
cd stegscan
python3 -m venv venv
source venv/bin/activate   # Linux / macOS
# or venv\Scripts\activate for Windows

pip install -r requirements.txt
```

## Usage

./stegscan.py <file>

./stegscan.py <file> --json

./stegscan.py <file> --threshold 0.35

./stegscan.py <file> --heuristic



