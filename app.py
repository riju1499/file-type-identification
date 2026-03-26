import os
import magic
import hashlib
import math
import requests
import sqlite3
import json
from datetime import datetime
from flask import Flask, request, render_template, jsonify, g
from werkzeug.utils import secure_filename

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# ── Paste your VirusTotal API key here ────────────────────────────────────────
VT_API_KEY = "a70a66cf7ca03a12158e3a72bc2723e474daefd16cbbf5f0eb065a2732e0fedb"

DATABASE = 'scan_history.db'

# ── Extended magic byte signatures (50+) ──────────────────────────────────────
MAGIC_SIGNATURES = {
    # Images
    b'\xFF\xD8\xFF'            : ('jpg',  'JPEG Image'),
    b'\x89PNG\r\n\x1a\n'       : ('png',  'PNG Image'),
    b'GIF87a'                  : ('gif',  'GIF Image'),
    b'GIF89a'                  : ('gif',  'GIF Image'),
    b'BM'                      : ('bmp',  'BMP Image'),
    b'II\x2A\x00'              : ('tiff', 'TIFF Image'),
    b'MM\x00\x2A'              : ('tiff', 'TIFF Image'),
    b'RIFF'                    : ('webp', 'WebP/WAV File'),
    b'\x00\x00\x01\x00'        : ('ico',  'ICO Icon'),
    b'\x38\x42\x50\x53'        : ('psd',  'Photoshop File'),

    # Documents
    b'%PDF'                    : ('pdf',  'PDF Document'),
    b'\xD0\xCF\x11\xE0'        : ('doc',  'MS Office (Old Format)'),
    b'PK\x03\x04\x14\x00\x06'  : ('docx', 'MS Word (Modern)'),
    b'PK\x03\x04\x14\x00\x08'  : ('xlsx', 'MS Excel (Modern)'),

    # Archives
    b'PK\x03\x04'              : ('zip',  'ZIP Archive'),
    b'Rar!\x1a\x07'            : ('rar',  'RAR Archive'),
    b'\x1f\x8b'                : ('gz',   'GZIP Archive'),
    b'\x42\x5A\x68'            : ('bz2',  'BZIP2 Archive'),
    b'\x37\x7A\xBC\xAF'        : ('7z',   '7-Zip Archive'),
    b'\xFD\x37\x7A\x58\x5A'    : ('xz',   'XZ Archive'),
    b'MSCF'                    : ('cab',  'CAB Archive'),

    # Executables
    b'MZ'                      : ('exe',  'Windows Executable'),
    b'\x7fELF'                 : ('elf',  'Linux Executable'),
    b'\xCA\xFE\xBA\xBE'        : ('class','Java Class File'),
    b'PK\x03\x04'              : ('jar',  'Java JAR File'),
    b'\xCE\xFA\xED\xFE'        : ('macho','macOS Executable'),
    b'\xCF\xFA\xED\xFE'        : ('macho','macOS Executable (64-bit)'),

    # Audio
    b'ID3'                     : ('mp3',  'MP3 Audio'),
    b'\xFF\xFB'                : ('mp3',  'MP3 Audio'),
    b'fLaC'                    : ('flac', 'FLAC Audio'),
    b'OggS'                    : ('ogg',  'OGG Audio'),
    b'RIFF'                    : ('wav',  'WAV Audio'),

    # Video
    b'\x00\x00\x00\x20ftyp'    : ('mp4',  'MP4 Video'),
    b'\x00\x00\x00\x18ftyp'    : ('mp4',  'MP4 Video'),
    b'\x1a\x45\xdf\xa3'        : ('mkv',  'MKV Video'),
    b'FLV\x01'                 : ('flv',  'Flash Video'),
    b'\x00\x00\x01\xBA'        : ('mpeg', 'MPEG Video'),
    b'AVI '                    : ('avi',  'AVI Video'),

    # Code / Text
    b'<?xml'                   : ('xml',  'XML File'),
    b'<html'                   : ('html', 'HTML File'),
    b'<HTML'                   : ('html', 'HTML File'),
    b'#!/'                     : ('sh',   'Shell Script'),
    b'\xef\xbb\xbf'            : ('txt',  'UTF-8 Text File'),

    # Other
    b'SQLite format 3'         : ('db',   'SQLite Database'),
    b'\x50\x4B\x05\x06'        : ('zip',  'Empty ZIP Archive'),
    b'ANDROIDAPP'              : ('apk',  'Android APK'),
    b'\x25\x21\x50\x53'        : ('ps',   'PostScript File'),
}

DANGEROUS_TYPES = ['exe', 'elf', 'bat', 'cmd', 'sh', 'ps1',
                   'vbs', 'js', 'jar', 'macho', 'class']

METADATA_SUPPORTED = ['jpg', 'jpeg', 'png', 'tiff', 'pdf', 'doc', 'docx']


# ── Database setup ─────────────────────────────────────────────────────────────

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_db(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def init_db():
    with app.app_context():
        db = get_db()
        db.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                filename      TEXT    NOT NULL,
                extension     TEXT,
                detected_type TEXT,
                mime_type     TEXT,
                size_kb       REAL,
                is_match      INTEGER,
                entropy       REAL,
                md5           TEXT,
                sha256        TEXT,
                risk          TEXT,
                message       TEXT,
                vt_status     TEXT,
                vt_malicious  INTEGER DEFAULT 0,
                vt_total      INTEGER DEFAULT 0,
                metadata      TEXT,
                scanned_at    TEXT    NOT NULL
            )
        ''')
        db.commit()


def save_scan(result):
    db = get_db()
    vt  = result.get('virustotal', {})
    db.execute('''
        INSERT INTO scans
        (filename, extension, detected_type, mime_type, size_kb,
         is_match, entropy, md5, sha256, risk, message,
         vt_status, vt_malicious, vt_total, metadata, scanned_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    ''', (
        result['filename'],
        result['extension'],
        result['detected_type'],
        result['mime_type'],
        result['size_kb'],
        1 if result['is_match'] else 0,
        result['entropy'],
        result['md5'],
        result['sha256'],
        result['risk'],
        result['message'],
        vt.get('status', 'skipped'),
        vt.get('malicious', 0),
        vt.get('total', 0),
        json.dumps(result.get('metadata', {})),
        datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    ))
    db.commit()


# ── Analysis helpers ───────────────────────────────────────────────────────────

def get_file_hashes(file_path):
    sha256 = hashlib.sha256()
    md5    = hashlib.md5()
    with open(file_path, 'rb') as f:
        data = f.read()
    sha256.update(data)
    md5.update(data)
    return sha256.hexdigest(), md5.hexdigest()


def detect_type_by_magic(file_path):
    try:
        with open(file_path, 'rb') as f:
            header = f.read(16)
        for sig, (ext, name) in MAGIC_SIGNATURES.items():
            if header.startswith(sig):
                return ext, name
        return 'unknown', 'Unknown File Type'
    except Exception as e:
        return 'error', str(e)


def get_extension(filename):
    return filename.rsplit('.', 1)[1].lower() if '.' in filename else 'none'


def calculate_entropy(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()
    if not data:
        return 0.0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    entropy = 0.0
    length  = len(data)
    for count in freq:
        if count > 0:
            p        = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def extract_metadata(file_path, detected_ext):
    """
    Extract hidden metadata from files.
    - Images : EXIF data (GPS, camera, date)
    - PDFs   : author, creator, creation date
    - Others : basic file stats
    """
    metadata = {}
    try:
        # ── Image EXIF metadata ──
        if detected_ext in ['jpg', 'jpeg', 'tiff', 'png']:
            try:
                from PIL import Image
                from PIL.ExifTags import TAGS, GPSTAGS
                img  = Image.open(file_path)
                info = img._getexif()
                if info:
                    for tag_id, value in info.items():
                        tag = TAGS.get(tag_id, tag_id)
                        if tag in ['Make', 'Model', 'DateTime',
                                   'Software', 'Artist', 'Copyright',
                                   'GPSInfo', 'ImageWidth', 'ImageLength']:
                            if tag == 'GPSInfo':
                                gps = {}
                                for k, v in value.items():
                                    gps[GPSTAGS.get(k, k)] = str(v)
                                metadata['GPS'] = gps
                            else:
                                metadata[str(tag)] = str(value)
            except Exception:
                metadata['note'] = 'No EXIF data found'

        # ── PDF metadata ──
        elif detected_ext == 'pdf':
            try:
                import pypdf
                reader = pypdf.PdfReader(file_path)
                info   = reader.metadata
                if info:
                    for key, val in info.items():
                        clean_key = key.lstrip('/')
                        metadata[clean_key] = str(val)
                metadata['pages'] = len(reader.pages)
            except Exception:
                metadata['note'] = 'Could not read PDF metadata'

        # ── Basic stats for everything else ──
        stat = os.stat(file_path)
        metadata['created']  = datetime.fromtimestamp(stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
        metadata['modified'] = datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')

    except Exception as e:
        metadata['error'] = str(e)

    return metadata


def check_virustotal(sha256_hash):
    if VT_API_KEY == "PASTE_YOUR_API_KEY_HERE":
        return {"status": "skipped", "message": "VirusTotal API key not configured"}

    url     = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 404:
            return {
                "status"    : "not_found",
                "message"   : "File not seen by VirusTotal before",
                "malicious" : 0, "suspicious": 0,
                "harmless"  : 0, "undetected": 0,
                "total"     : 0,
                "link"      : f"https://www.virustotal.com/gui/file/{sha256_hash}",
            }
        if response.status_code == 401:
            return {"status": "error", "message": "Invalid VirusTotal API key"}
        if response.status_code != 200:
            return {"status": "error", "message": f"VT error {response.status_code}"}

        stats      = response.json()["data"]["attributes"]["last_analysis_stats"]
        malicious  = stats.get("malicious",  0)
        suspicious = stats.get("suspicious", 0)
        harmless   = stats.get("harmless",   0)
        undetected = stats.get("undetected", 0)
        total      = malicious + suspicious + harmless + undetected

        verdict = ("MALICIOUS"  if malicious >= 5 else
                   "SUSPICIOUS" if malicious >= 1 or suspicious >= 3 else
                   "CLEAN")

        return {
            "status"    : "found",
            "verdict"   : verdict,
            "malicious" : malicious,
            "suspicious": suspicious,
            "harmless"  : harmless,
            "undetected": undetected,
            "total"     : total,
            "message"   : f"{malicious}/{total} engines flagged this file",
            "link"      : f"https://www.virustotal.com/gui/file/{sha256_hash}",
        }
    except requests.exceptions.Timeout:
        return {"status": "error", "message": "VirusTotal request timed out"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def analyze_single_file(file_path, original_filename):
    extension                   = get_extension(original_filename)
    detected_ext, detected_name = detect_type_by_magic(file_path)
    mime_type                   = magic.from_file(file_path, mime=True)
    sha256_hash, md5_hash       = get_file_hashes(file_path)
    entropy                     = calculate_entropy(file_path)
    size_kb                     = round(os.path.getsize(file_path) / 1024, 2)
    metadata                    = extract_metadata(file_path, detected_ext)
    vt_result                   = check_virustotal(sha256_hash)
    is_match                    = (extension == detected_ext)

    if entropy > 7.5:
        entropy_note = "Very high — possibly encrypted or compressed"
    elif entropy > 6.5:
        entropy_note = "High — may be compressed or packed"
    elif entropy > 4.0:
        entropy_note = "Normal — typical for most files"
    else:
        entropy_note = "Low — plain text or simple data"

    vt_verdict = vt_result.get("verdict", "")

    if vt_verdict == "MALICIOUS":
        risk    = "HIGH"
        message = (f"DANGER: VirusTotal flagged as MALICIOUS — "
                   f"{vt_result.get('malicious',0)} engines detected threats.")
    elif vt_verdict == "SUSPICIOUS":
        risk    = "HIGH"
        message = "WARNING: VirusTotal marked this file as SUSPICIOUS."
    elif detected_ext in DANGEROUS_TYPES and not is_match:
        risk    = "HIGH"
        message = (f"DANGER: Disguised file! True type is {detected_name} "
                   f"but has .{extension} extension.")
    elif detected_ext in DANGEROUS_TYPES and is_match:
        risk    = "MEDIUM"
        message = f"Executable file ({detected_name}). Verify source before running."
    elif not is_match and detected_ext != "unknown":
        risk    = "MEDIUM"
        message = (f"Mismatch: appears to be {detected_name} "
                   f"but has .{extension} extension.")
    elif entropy > 7.5:
        risk    = "MEDIUM"
        message = "Very high entropy — may be encrypted or packed."
    else:
        risk    = "LOW"
        message = "File type matches extension. No threats detected."

    return {
        "filename"      : original_filename,
        "extension"     : extension,
        "detected_type" : detected_name,
        "detected_ext"  : detected_ext,
        "mime_type"     : mime_type,
        "size_kb"       : size_kb,
        "is_match"      : is_match,
        "entropy"       : entropy,
        "entropy_note"  : entropy_note,
        "sha256"        : sha256_hash,
        "md5"           : md5_hash,
        "risk"          : risk,
        "message"       : message,
        "virustotal"    : vt_result,
        "metadata"      : metadata,
    }


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    """Single file analysis."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    filename  = secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)

    result = analyze_single_file(file_path, file.filename)
    os.remove(file_path)

    save_scan(result)
    return jsonify(result)


@app.route('/analyze_batch', methods=['POST'])
def analyze_batch():
    """Batch: analyze multiple files at once."""
    files = request.files.getlist('files')
    if not files:
        return jsonify({'error': 'No files uploaded'}), 400

    results = []
    for file in files:
        if file.filename == '':
            continue
        filename  = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        result = analyze_single_file(file_path, file.filename)
        os.remove(file_path)
        save_scan(result)
        results.append(result)

    return jsonify(results)


@app.route('/history')
def history():
    """Return all past scans from the database."""
    db   = get_db()
    rows = db.execute(
        'SELECT * FROM scans ORDER BY scanned_at DESC LIMIT 100'
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route('/stats')
def stats():
    """Return statistics for the dashboard charts."""
    db = get_db()

    total       = db.execute('SELECT COUNT(*) FROM scans').fetchone()[0]
    risk_counts = db.execute(
        'SELECT risk, COUNT(*) as count FROM scans GROUP BY risk'
    ).fetchall()
    type_counts = db.execute(
        'SELECT detected_type, COUNT(*) as count FROM scans '
        'GROUP BY detected_type ORDER BY count DESC LIMIT 8'
    ).fetchall()
    recent      = db.execute(
        'SELECT scanned_at, risk FROM scans ORDER BY scanned_at DESC LIMIT 20'
    ).fetchall()

    return jsonify({
        'total'      : total,
        'by_risk'    : [dict(r) for r in risk_counts],
        'by_type'    : [dict(r) for r in type_counts],
        'recent'     : [dict(r) for r in recent],
    })


@app.route('/clear_history', methods=['POST'])
def clear_history():
    db = get_db()
    db.execute('DELETE FROM scans')
    db.commit()
    return jsonify({'success': True})


# ── Start ──────────────────────────────────────────────────────────────────────
init_db()

if __name__ == '__main__':
    app.run(debug=True)