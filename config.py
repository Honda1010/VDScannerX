import re
import os

class Config:
    # API Configuration
    VIRUSTOTAL_API_KEY = '1f943b55964dc8763921324f04fe0885fa7d212e10502e11320446c2e28278bb'
    VT_DYNAMIC_API_KEY = 'af327565c031af77d58d9f5b062e2840c7bb2e269802ff087d70d6a81484e8d5'
    HYBRID_ANALYSIS_API_KEY = 'swwy0tx86d507b75m4e63m05848d6fcfl7q9hpxqecfd1030vdiw15jv8a3fcdf7'
    # File System Configuration
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    OUTPUT_FOLDER = os.path.join(BASE_DIR, 'output_pdf')
    OUTPUT_HTML = os.path.join(BASE_DIR, 'output_html')
    OUTPUT_JSON = os.path.join(BASE_DIR, 'output_json')
    
    # Create output directories if they don't exist
    for directory in [OUTPUT_FOLDER, OUTPUT_HTML, OUTPUT_JSON]:
        os.makedirs(directory, exist_ok=True)
    
    # String Filters
    FILTERS = {
        "All": None,
        "URLs":      re.compile(rb"https?://[^\s\"']+"), # Matches URLs not followed by space, double quotes or single quotes
        "IPs":       re.compile(rb"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"), #matches IP addresses 1–3 digits followed by a dot
        "Registry":  re.compile(rb"HKEY_[A-Z_\\]+"), #matches the prefix, matches uppercase letters, underscores, and backslashes
        "Paths":     re.compile(rb"[A-Za-z]:\\[^:*?\"<>|\r\n]+"), #followed by a colon, and then any characters except for the special characters
        "DLLs":      re.compile(rb"[a-zA-Z0-9_]+\.(dll|DLL)"), #matches DLL files which are alphanumeric characters followed by a dot and then dll or DLL
        "Commands":  re.compile(rb"\b(cmd\.exe|powershell|wmic|whoami|tasklist|netstat|curl|wget)\b", re.IGNORECASE), #\b(...)\b: ensures the whole word is matched
    }
    
    # PDF Report Configuration
    PDF_STYLES = {
        'title': {
            'font': 'Helvetica-Bold',
            'size': 24,
            'color': (0.2, 0.3, 0.7),  # Blue
        },
        'section_header': {
            'font': 'Helvetica-Bold',
            'size': 14,
            'color': (0.2, 0.3, 0.7),  # Blue
            'background': (0.95, 0.95, 0.95),  # Light Gray
        },
        'normal_text': {
            'font': 'Helvetica',
            'size': 11,
            'color': (0, 0, 0),  # Black
        },
        'page_number': {
            'font': 'Helvetica',
            'size': 8,
            'color': (0, 0, 0),  # Black
        }
    }

    # HTML Report Styling
    HTML_STYLES = """
        body {
            font-family: Arial, sans-serif;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f6fa;
            max-width: 1200px;
            color: #202124;
        }
        .report-header {
            color: #1a73e8;
            text-align: center;
            padding: 20px 0;
            border-bottom: 2px solid #4285f4;
            margin-bottom: 30px;
        }
        .timestamp {
            color: #5f6368;
            font-size: 12px;
            text-align: right;
            margin-bottom: 20px;
        }
        .section {
            margin: 15px 0;
            padding: 20px;
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .section:hover {
            transform: translateY(-3px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.15);
        }
        .section-header {
            color: #1a73e8;
            border-bottom: 1px solid #dadce0;
            padding-bottom: 10px;
            margin-top: 0;
        }
        .key-value {
            margin: 10px 0;
            padding: 5px;
            border-radius: 4px;
            transition: background-color 0.2s;
        }
        .key-value:hover {
            background-color: rgba(0,0,0,0.03);
        }
        .key {
            font-weight: bold;
            color: #202124;
        }
        .value {
            color: #5f6368;
        }
        .file-info {
            background-color: #e8f0fe;
        }
        .hash-info {
            background-color: #f3e5f5;
        }
        .pe-info {
            background-color: #f1f3f4;
        }
        .strings-info {
            background-color: #f1f8e9;
        }
        .vt-info {
            background-color: #fef6e0;
        }
        .dynamic-info {
            background-color: #ebf5fb;
        }
        .dll-name {
            font-weight: bold;
            color: #1a73e8;
            margin-top: 15px;
            padding: 5px;
            border-radius: 4px;
            transition: background-color 0.2s;
        }
        .dll-name:hover {
            background-color: rgba(26, 115, 232, 0.1);
        }
        .function-list {
            margin-left: 20px;
            color: #5f6368;
            font-family: 'Courier New', monospace;
        }
        .function-list div {
            padding: 2px 5px;
            border-radius: 2px;
            transition: background-color 0.2s;
        }
        .function-list div:hover {
            background-color: #f1f3f4;
        }
        .malicious {
            color: #ea4335;
        }
        .warning {
            background-color: #ffebee;
            border-left: 4px solid #ea4335;
            padding: 10px;
            margin: 10px 0;
        }
        .success {
            background-color: #e0f2f1;
            border-left: 4px solid #34a853;
            padding: 10px;
            margin: 10px 0;
        }
        .separator {
            height: 1px;
            background-color: #dadce0;
            margin: 10px 0;
        }
        pre {
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 4px;
            overflow-x: auto;
        }
        li {
            margin: 5px 0;
            transition: background-color 0.2s;
            padding: 3px;
            border-radius: 3px;
        }
        li:hover {
            background-color: rgba(0,0,0,0.03);
        }
        a {
            color: #1967d2;
            text-decoration: none;
            transition: color 0.2s;
        }
        a:hover {
            color: #174ea6;
            text-decoration: underline;
        }
    """ 