# 🔍 File Type Identifier — Cybersecurity Tool

A web-based cybersecurity tool that identifies true file types using **magic byte analysis**, detects disguised/malicious files, calculates Shannon entropy, generates cryptographic hashes, and integrates with the VirusTotal API for real-time threat intelligence.

> Final Semester Cybersecurity Project | Built with Python, Flask, SQLite

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [System Architecture](#system-architecture)
- [Project Structure](#project-structure)
- [Tech Stack](#tech-stack)
- [How It Works](#how-it-works)
- [Detection Parameters](#detection-parameters)
- [Installation](#installation)
- [Usage](#usage)
- [API Endpoints](#api-endpoints)
- [Test Suite](#test-suite)
- [Database Schema](#database-schema)
- [Screenshots](#screenshots)
- [Future Improvements](#future-improvements)
- [References](#references)

---

## 📌 Overview

File Type Identifier is a cybersecurity tool designed to detect **file type spoofing** — a common attack technique where malicious files are disguised with a fake extension (e.g., a virus renamed as `photo.jpg`).

The tool uses **magic byte signature analysis** to read the true file type from raw bytes, independent of the filename extension. It combines this with entropy analysis, cryptographic hashing, and VirusTotal API integration to provide a comprehensive threat assessment.

**Real-world relevance:** This technique is used by professional tools like VirusTotal, Windows Defender, and digital forensics software to identify malware delivered through disguised file extensions.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔬 Magic Byte Analysis | Detects true file type from first 16 bytes — 50+ file signatures |
| 🔀 Extension Mismatch Detection | Compares detected type vs claimed extension |
| 📊 Shannon Entropy Analysis | Measures byte randomness to detect encrypted/packed malware |
| 🔐 Hash Generation | MD5 and SHA256 cryptographic fingerprints |
| 🦠 VirusTotal Integration | Cross-references SHA256 hash against 70+ antivirus engines |
| 📁 Metadata Extraction | Extracts EXIF data, PDF author, GPS location, creation dates |
| 📦 Batch File Scanning | Scan multiple files simultaneously |
| 🗃️ Scan History | SQLite database stores all scan results permanently |
| 📈 Statistics Dashboard | Charts showing risk breakdown and file type distribution |
| 🧪 Automated Test Suite | 12 built-in test cases with pass/fail reporting |
| 🖱️ Drag and Drop UI | Drag files directly onto the upload zone |

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        CLIENT SIDE                          │
│                     (Browser / index.html)                  │
│                                                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │  Single  │  │  Batch   │  │  Scan    │  │Dashboard │  │
│  │   Scan   │  │   Scan   │  │ History  │  │+ Charts  │  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘  │
│       │              │              │              │         │
│  ┌────┴──────────────┴──────────────┴──────────────┴─────┐ │
│  │              JavaScript (Fetch API)                    │ │
│  └────────────────────────┬───────────────────────────────┘ │
└───────────────────────────┼─────────────────────────────────┘
                            │ HTTP POST/GET
┌───────────────────────────┼─────────────────────────────────┐
│                      SERVER SIDE                            │
│                    (Python / Flask)                         │
│                                                             │
│  ┌─────────────────────────▼───────────────────────────┐   │
│  │                   app.py (Flask)                    │   │
│  │                                                     │   │
│  │  ┌────────────┐  ┌────────────┐  ┌──────────────┐  │   │
│  │  │Magic Byte  │  │ Extension  │  │   Shannon    │  │   │
│  │  │ Detection  │  │ Mismatch   │  │   Entropy    │  │   │
│  │  │detect_type │  │  Check     │  │  Calculator  │  │   │
│  │  └────────────┘  └────────────┘  └──────────────┘  │   │
│  │                                                     │   │
│  │  ┌────────────┐  ┌────────────┐  ┌──────────────┐  │   │
│  │  │   Hash     │  │ Metadata   │  │  Risk Level  │  │   │
│  │  │Generation  │  │Extraction  │  │ Classifier   │  │   │
│  │  │MD5+SHA256  │  │EXIF / PDF  │  │HIGH/MED/LOW  │  │   │
│  │  └────────────┘  └────────────┘  └──────────────┘  │   │
│  └──────────────────────┬──────────────────────────────┘   │
│                         │                                   │
│  ┌──────────────────────┴──────────────────────────────┐   │
│  │              SQLite Database                        │   │
│  │              scan_history.db                        │   │
│  └─────────────────────────────────────────────────────┘   │
└───────────────────────────┬─────────────────────────────────┘
                            │ HTTPS API call
┌───────────────────────────▼─────────────────────────────────┐
│                   EXTERNAL SERVICE                          │
│                  VirusTotal API v3                          │
│           https://www.virustotal.com/api/v3/                │
│         70+ antivirus engines database lookup               │
└─────────────────────────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
file_type_identifier/
│
├── app.py                  # Main Flask application
│   ├── Magic byte signatures dictionary (50+ file types)
│   ├── detect_type_by_magic()     — reads first 16 bytes
│   ├── get_extension()            — extracts filename extension
│   ├── calculate_entropy()        — Shannon entropy formula
│   ├── get_file_hashes()          — MD5 + SHA256 generation
│   ├── extract_metadata()         — EXIF / PDF metadata
│   ├── check_virustotal()         — VirusTotal API call
│   ├── analyze_single_file()      — combines all checks
│   ├── init_db()                  — SQLite database setup
│   ├── save_scan()                — saves result to DB
│   └── Routes: /, /analyze, /analyze_batch,
│               /history, /stats, /clear_history
│
├── templates/
│   └── index.html          # Complete frontend (single file)
│       ├── Page 1: Single Scan    — file upload + analysis
│       ├── Page 2: Batch Scan     — multiple files at once
│       ├── Page 3: Scan History   — table of past scans
│       ├── Page 4: Dashboard      — charts and statistics
│       └── Page 5: Test Suite     — 12 automated test cases
│
├── scan_history.db         # SQLite database (auto-created)
│   └── Table: scans        — stores all scan results
│
├── uploads/                # Temporary folder (auto-created)
│   └── Files deleted immediately after analysis
│
└── requirements.txt        # Python dependencies
```

---

## 🛠️ Tech Stack

### Backend
| Technology | Version | Purpose |
|---|---|---|
| Python | 3.8+ | Core programming language |
| Flask | 3.1.3 | Web framework — handles routes and HTTP requests |
| python-magic | Latest | MIME type detection using libmagic |
| hashlib | Built-in | MD5 and SHA256 hash generation |
| sqlite3 | Built-in | Database — stores scan history |
| requests | Latest | HTTP calls to VirusTotal API |
| Pillow | Latest | Image EXIF metadata extraction |
| pypdf | Latest | PDF metadata extraction |
| math | Built-in | Shannon entropy calculation |
| os | Built-in | File system operations |

### Frontend
| Technology | Purpose |
|---|---|
| HTML5 | Page structure |
| CSS3 | Styling and dark theme |
| Vanilla JavaScript | API calls, DOM manipulation, drag and drop |
| Chart.js 4.4.1 | Dashboard charts (doughnut + bar charts) |
| Fetch API | Async HTTP requests to Flask backend |

### Database
| Technology | Purpose |
|---|---|
| SQLite | Lightweight file-based database |
| scan_history.db | Stores all scan results permanently |

### External API
| Service | Purpose |
|---|---|
| VirusTotal API v3 | Cross-references SHA256 hash against 70+ antivirus engines |

---

## ⚙️ How It Works

### Step-by-step flow for every file upload:

```
1. User uploads file via browser
        ↓
2. Flask receives file → saves temporarily to /uploads
        ↓
3. Magic bytes read (first 16 bytes)
   e.g. FF D8 FF → JPEG Image
        ↓
4. File extension extracted from filename
   e.g. invoice.pdf → "pdf"
        ↓
5. Mismatch check: jpeg ≠ pdf → MISMATCH DETECTED
        ↓
6. Shannon entropy calculated
   H(F) = -Σ P(xᵢ) × log₂(P(xᵢ)) → 6.8 (high)
        ↓
7. MD5 + SHA256 hashes generated
        ↓
8. SHA256 sent to VirusTotal API
   Response: MALICIOUS / CLEAN / NOT FOUND
        ↓
9. Risk level decided:
   HIGH / MEDIUM / LOW
        ↓
10. Result saved to SQLite database
        ↓
11. Result sent back to browser as JSON
        ↓
12. index.html displays full analysis
        ↓
13. Uploaded file deleted from server
```

---

## 🔬 Detection Parameters

### 1. Magic Byte Signature Matching

Every file format starts with unique bytes identifying its true type:

| File Type | Magic Bytes (Hex) | ASCII | Extension |
|---|---|---|---|
| JPEG Image | FF D8 FF | — | .jpg |
| PNG Image | 89 50 4E 47 | .PNG | .png |
| PDF Document | 25 50 44 46 | %PDF | .pdf |
| ZIP Archive | 50 4B 03 04 | PK.. | .zip |
| Windows EXE | 4D 5A | MZ | .exe |
| Linux ELF | 7F 45 4C 46 | .ELF | .elf |
| GIF Image | 47 49 46 38 | GIF8 | .gif |
| MP3 Audio | 49 44 33 | ID3 | .mp3 |

### 2. Extension Mismatch Detection

```
M(F) = 0  if  Extension == Detected_Type  →  MATCH
M(F) = 1  if  Extension ≠  Detected_Type  →  MISMATCH
```

### 3. Shannon Entropy

```
        255
H(F) = - Σ  P(xᵢ) × log₂(P(xᵢ))
        i=0

Range: 0.0 (lowest) to 8.0 (highest)

0.0 – 3.0  →  Very low   — simple text
3.0 – 5.0  →  Normal     — typical documents
5.0 – 6.5  →  Medium     — images, audio
6.5 – 7.5  →  High       — compressed files
7.5 – 8.0  →  Very high  — encrypted/malware
```

### 4. Risk Classification

```
R(F) = HIGH    if  VirusTotal = MALICIOUS
R(F) = HIGH    if  Mismatch = true  AND  type ∈ {exe, elf, bat, sh...}
R(F) = MEDIUM  if  Mismatch = false AND  type ∈ dangerous types
R(F) = MEDIUM  if  Mismatch = true  AND  type ∉ dangerous types
R(F) = MEDIUM  if  Entropy > 7.5
R(F) = LOW     otherwise
```

---

## 🚀 Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager
- Homebrew (Mac only)

### Step 1 — Clone the repository
```bash
git clone https://github.com/yourusername/file-type-identifier.git
cd file-type-identifier
```

### Step 2 — Install system dependency (Mac only)
```bash
brew install libmagic
```

### Step 3 — Install Python dependencies
```bash
pip install flask python-magic requests pillow pypdf
```

### Step 4 — Add VirusTotal API key (optional)
Open `app.py` and replace line 13:
```python
VT_API_KEY = "PASTE_YOUR_API_KEY_HERE"
```
Get a free key at: https://www.virustotal.com

### Step 5 — Run the application
```bash
python app.py
```

### Step 6 — Open in browser
```
http://127.0.0.1:5000
```

---

## 📖 Usage

### Single File Scan
1. Go to **Single Scan** tab
2. Click the upload area or drag and drop a file
3. Click **Analyze File**
4. View complete analysis — type, risk, entropy, hashes, VirusTotal result, metadata

### Batch Scan
1. Go to **Batch Scan** tab
2. Select multiple files at once
3. Click **Analyze All Files**
4. View results table for all files

### Scan History
1. Go to **Scan History** tab
2. View all past scans with filename, type, risk, and timestamp
3. Click **Clear History** to reset

### Dashboard
1. Go to **Dashboard** tab
2. View total scans, high risk count, clean files count
3. See risk breakdown doughnut chart and top file types bar chart

### Test Suite
1. Go to **🧪 Test Suite** tab
2. Click **▶ Run All Tests**
3. Watch 12 automated tests run with live pass/fail results
4. View final score (e.g. 10/12 passed — 83%)

---

## 🔌 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/` | Serves the main HTML page |
| POST | `/analyze` | Analyze a single file |
| POST | `/analyze_batch` | Analyze multiple files |
| GET | `/history` | Returns all scan history as JSON |
| GET | `/stats` | Returns statistics for dashboard |
| POST | `/clear_history` | Clears all scan history |

### Example Response from `/analyze`:
```json
{
  "filename"      : "invoice.pdf",
  "extension"     : "pdf",
  "detected_type" : "Windows Executable",
  "detected_ext"  : "exe",
  "mime_type"     : "application/x-dosexec",
  "size_kb"       : 142.5,
  "is_match"      : false,
  "entropy"       : 6.821,
  "entropy_note"  : "High — may be compressed or packed",
  "sha256"        : "275a021bbfb6489e54d471899f7db9d1...",
  "md5"           : "44d88612fea8a8f36de82e1278abb02f",
  "risk"          : "HIGH",
  "message"       : "DANGER: Disguised file! True type is Windows Executable but has .pdf extension.",
  "virustotal"    : {
    "status"      : "found",
    "verdict"     : "MALICIOUS",
    "malicious"   : 67,
    "total"       : 69,
    "message"     : "67/69 engines flagged this file",
    "link"        : "https://www.virustotal.com/gui/file/275a021b..."
  },
  "metadata"      : {
    "created"     : "2026-03-17 18:17:18",
    "modified"    : "2026-03-17 18:17:18"
  }
}
```

---

## 🧪 Test Suite

The built-in automated test suite runs 12 predefined test cases using synthetic files created from raw magic bytes — no real files needed.

| # | Test Name | Expected Risk | Expected Match |
|---|---|---|---|
| 1 | JPEG correct extension | LOW | ✅ Match |
| 2 | JPEG disguised as PDF | MEDIUM | ❌ Mismatch |
| 3 | PNG correct extension | LOW | ✅ Match |
| 4 | PNG disguised as DOCX | MEDIUM | ❌ Mismatch |
| 5 | EXE correct extension | MEDIUM | ✅ Match |
| 6 | EXE disguised as JPG | HIGH | ❌ Mismatch |
| 7 | EXE disguised as PDF | HIGH | ❌ Mismatch |
| 8 | PDF correct extension | LOW | ✅ Match |
| 9 | ZIP correct extension | LOW | ✅ Match |
| 10 | ZIP disguised as PNG | MEDIUM | ❌ Mismatch |
| 11 | Linux ELF disguised as TXT | HIGH | ❌ Mismatch |
| 12 | GIF correct extension | LOW | ✅ Match |

---

## 🗄️ Database Schema

```sql
CREATE TABLE scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    filename      TEXT    NOT NULL,
    extension     TEXT,
    detected_type TEXT,
    mime_type     TEXT,
    size_kb       REAL,
    is_match      INTEGER,        -- 0 = mismatch, 1 = match
    entropy       REAL,
    md5           TEXT,
    sha256        TEXT,
    risk          TEXT,           -- HIGH / MEDIUM / LOW
    message       TEXT,
    vt_status     TEXT,           -- found / not_found / skipped / error
    vt_malicious  INTEGER DEFAULT 0,
    vt_total      INTEGER DEFAULT 0,
    metadata      TEXT,           -- JSON string
    scanned_at    TEXT    NOT NULL -- YYYY-MM-DD HH:MM:SS
);
```

---

## 🔮 Future Improvements

- [ ] **PDF Report Export** — download scan result as formatted PDF
- [ ] **User Login System** — individual scan history per user
- [ ] **Steganography Detection** — detect hidden data in image files
- [ ] **URL Scanner** — check URLs against VirusTotal malicious site database
- [ ] **Email Alerts** — notify when HIGH risk file is detected
- [ ] **Machine Learning Classification** — Random Forest model trained on byte patterns
- [ ] **REST API** — expose tool as API for integration with other systems
- [ ] **Docker Container** — containerized deployment
- [ ] **File Quarantine** — isolate dangerous files instead of deleting

---

## 🔒 Security Notes

- All uploaded files are **immediately deleted** after analysis
- No file content is stored — only metadata and hashes
- VirusTotal API only receives the SHA256 hash — not the actual file
- The tool is for **analysis and education** — not for production antivirus use

---



---

## 👨‍💻 Author

**Your Name**
Final Year Engineering Student
Cybersecurity Subject Project — 2026

---

## 📄 License

This project is for educational purposes as part of a final semester engineering cybersecurity subject.
