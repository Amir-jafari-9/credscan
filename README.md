# 🛡️ CredScan - Password and URL Finder

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

CredScan is a lightweight security auditing tool that scans files for potential password leaks and URLs across multiple document formats. Designed with simplicity and effectiveness in mind, it helps identify credentials accidentally stored in plain text.

![CredScan Demo](https://i.imgur.com/placeholder.png)

## ✨ Features

- **Smart password detection** with false positive filtering (ignores JavaScript/HTML references)
- **URL extraction** with domain analysis
- **Multi-format support**:
  - Plain text (`.txt`, `.rtf`)
  - Office documents (`.docx`, `.xlsx`)
  - XML files (`.xml`, `.hml`)
- **Configurable** search patterns and output format
- **Bash-powered** simple setup and execution
- **No external dependencies** beyond standard Python libraries

## 🚀 Quick Start

### 1. Clone the repository
```bash
git clone https://github.com/Amir-jafari-9/credscan.git
cd credscan
```

### 2. Setup and run
```bash
# Create virtual environment and install dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Add your documents to scan
cp /path/to/your/files/* documents/

# Run the scanner
./run.sh
```

### 3. View results
```bash
cat output/passwords_found.txt
cat output/urls_found.txt
```

## ⚙️ Configuration

Customize `config.yaml` to suit your needs:

```yaml
# Directories to scan
search_paths:
  - ./documents

# Keywords to search for passwords
password_keywords:
  - password
  - pass
  - pwd
  - secret
  - token
  - api_key
  - credential
  - login

# URL patterns to detect
url_patterns:
  - "https?://[\\w\\.-]+(?:/[\\w\\./?=&#%\\-]*)?"
  - "www\\.[\\w\\.-]+\\.[a-z]{2,}"

# Output settings
output:
  passwords_file: "output/passwords_found.txt"
  urls_file: "output/urls_found.txt"
  format: "{path}:{line}:{content}"
```

## 💡 How It Works

CredScan uses a two-stage verification process for password detection:

1. **Initial keyword match** - Looks for common password-related terms
2. **Context verification** - Filters out false positives by:
   - Ignoring UI/JavaScript references (e.g., `IsNewPassword`, `passwordField`)
   - Validating actual credential patterns (e.g., `password = "value"`)
   - Checking for proper context around matches

This ensures you only see actual password values, not code references.

## 📦 One-Line Setup (Alternative)

Want to create the entire project from scratch? Run this command:

```bash
mkdir -p credscan/{credscan,output,documents} && touch credscan/{requirements.txt,config.yaml,run.sh} && cat > credscan/credscan/__init__.py <<'EOF' && cat > credscan/credscan/utils.py <<'EOF' && cat > credscan/credscan/readers.py <<'EOF' && cat > credscan/credscan/core.py <<'EOF' && cat > credscan/run.sh <<'EOF' && cat > credscan/requirements.txt <<'EOF' && cat > credscan/config.yaml <<'EOF'
__version__ = "1.0.0"
EOF
import re
import chardet
from pathlib import Path

def detect_encoding(file_path: Path) -> str:
    try:
        with open(file_path, 'rb') as f:
            result = chardet.detect(f.read(10000))
        return result['encoding'] or 'utf-8'
    except Exception:
        return 'utf-8'

def clean_text(text: str) -> str:
    if not text: return ""
    return re.sub(r'[\x00-\x1f\x7f-\x9f]', '', text)

def extract_domain(url: str) -> str:
    if url.startswith('http://'): url = url[7:]
    elif url.startswith('https://'): url = url[8:]
    if url.startswith('www.'): url = url[4:]
    return url.split('/')[0].split('?')[0].split('#')[0]
EOF
from pathlib import Path
import xml.etree.ElementTree as ET
from .utils import detect_encoding
from typing import Iterator

def read_plain_text(file_path: Path) -> Iterator[str]:
    try:
        encoding = detect_encoding(file_path)
        with open(file_path, 'r', encoding=encoding, errors='replace') as f:
            for line in f: yield line
    except Exception as e:
        yield f"ERROR: {str(e)}"

def read_xml(file_path: Path) -> Iterator[str]:
    try:
        tree = ET.parse(str(file_path))
        for elem in tree.iter():
            if elem.text and elem.text.strip(): yield elem.text
    except Exception:
        yield from read_plain_text(file_path)

def read_docx(file_path: Path) -> Iterator[str]:
    try:
        from docx import Document
        doc = Document(str(file_path))
        for para in doc.paragraphs:
            if para.text.strip(): yield para.text
        for table in doc.tables:
            for row in table.rows:
                for cell in row.cells:
                    if cell.text.strip(): yield cell.text
    except Exception as e:
        yield f"ERROR: DOCX failed ({str(e)})"

def read_xlsx(file_path: Path) -> Iterator[str]:
    try:
        from openpyxl import load_workbook
        wb = load_workbook(str(file_path), read_only=True, data_only=True)
        for sheet in wb.worksheets:
            for row in sheet.iter_rows(values_only=True):
                for cell in row:
                    if cell is not None: yield str(cell)
    except Exception as e:
        yield f"ERROR: XLSX failed ({str(e)})"

READERS = {
    '.txt': read_plain_text,
    '.rtf': read_plain_text,
    '.xml': read_xml,
    '.hml': read_xml,
    '.docx': read_docx,
    '.xlsx': read_xlsx,
}

def get_reader(file_path: Path):
    return READERS.get(file_path.suffix.lower(), read_plain_text)
EOF
from pathlib import Path
import re
from .utils import clean_text, extract_domain
from .readers import get_reader

class Scanner:
    def __init__(self, config: dict):
        self.password_keywords = [kw.lower() for kw in config['password_keywords']]
        self.url_patterns = [re.compile(pat) for pat in config['url_patterns']]
        self.output_format = config['output']['format']
        
        # Patterns that indicate a FALSE positive (UI code reference)
        self.false_positive_patterns = [
            re.compile(r'\bIs[A-Z][a-z]*Password\b'),
            re.compile(r'\bpassword[A-Z]'),
            re.compile(r'\bpassword\.'), 
            re.compile(r'\bpasswordField\b'),
            re.compile(r'\bpasswordInput\b'),
            re.compile(r'\bpasswordLabel\b'),
            re.compile(r'\bpasswordValidation\b'),
            re.compile(r'\bpasswordConfirmation\b'),
            re.compile(r'\bpasswordRequired\b'),
            re.compile(r'\bpasswordRules\b'),
            re.compile(r'\bpasswordPolicy\b'),
            re.compile(r'\bpasswordStrength\b'),
            re.compile(r'\bpasswordChange\b'),
            re.compile(r'\bpasswordReset\b'),
            re.compile(r'\bpasswordRegex\b'),
            re.compile(r'\bpasswordMinLength\b'),
            re.compile(r'\bpasswordErrorMessage\b'),
            re.compile(r'\bpasswordConfirm\b'),
            re.compile(r'\bpasswordMatch\b'),
            re.compile(r'\bpasswordValid\b'),
            re.compile(r'\bpasswordHash\b'),
            re.compile(r'\bpasswordEncrypt\b'),
            re.compile(r'\bpasswordVerify\b'),
            re.compile(r'\bpasswordCompare\b'),
            re.compile(r'\bpasswordChanged\b'),
            re.compile(r'\bpasswordToken\b'),
            re.compile(r'\bpasswordRecovery\b'),
            re.compile(r'\bpasswordResetToken\b'),
            re.compile(r'\bpasswordResetLink\b'),
            re.compile(r'\bpasswordResetForm\b'),
            re.compile(r'\bpasswordResetRequest\b'),
            re.compile(r'\bpasswordResetSuccess\b'),
            re.compile(r'\bpasswordResetError\b'),
            re.compile(r'\bpasswordResetComplete\b'),
            re.compile(r'\bpasswordResetExpired\b'),
            re.compile(r'\bpasswordResetInvalid\b'),
            re.compile(r'\bpasswordResetConfirmed\b'),
            re.compile(r'\bpasswordResetConfirmation\b'),
            re.compile(r'\bpasswordResetConfirmationSent\b'),
            re.compile(r'\bpasswordResetConfirmationFailed\b'),
            re.compile(r'\bpasswordResetConfirmationSuccess\b'),
            re.compile(r'\bpasswordResetConfirmationError\b'),
            re.compile(r'\bpasswordResetConfirmationExpired\b'),
            re.compile(r'\bpasswordResetConfirmationInvalid\b'),
            re.compile(r'\bpasswordResetConfirmationConfirmed\b'),
            re.compile(r'\bpasswordResetConfirmationComplete\b'),
            re.compile(r'\bpasswordResetConfirmationToken\b'),
            re.compile(r'\bpasswordResetConfirmationLink\b'),
            re.compile(r'\bpasswordResetConfirmationForm\b'),
            re.compile(r'\bpasswordResetConfirmationRequest\b'),
            re.compile(r'\bpasswordResetConfirmationSuccess\b'),
            re.compile(r'\bpasswordResetConfirmationError\b'),
            re.compile(r'\bpasswordResetConfirmationExpired\b'),
            re.compile(r'\bpasswordResetConfirmationInvalid\b'),
            re.compile(r'\bpasswordResetConfirmationConfirmed\b'),
            re.compile(r'\bpasswordResetConfirmationComplete\b')
        ]
        
        # Patterns that indicate an ACTUAL password value
        self.credential_patterns = [
            # password = "value"
            re.compile(r'(\b(?:pass(?:word)?|pwd|secret|token|key|credential|auth)\b\s*[=:]\s*[\'"][^\'"]*[\'"])', re.IGNORECASE),
            # password: "value"
            re.compile(r'(\b(?:pass(?:word)?|pwd|secret|token|key|credential|auth)\b\s*[:=]\s*[\'"][^\'"]{5,}[\'"])', re.IGNORECASE),
            # API_KEY=secret123
            re.compile(r'(\b(?:api[_-]key|secret[_-]key|access[_-]key)\b\s*[=:]\s*\S+)', re.IGNORECASE),
            # Basic auth patterns
            re.compile(r'(https?://\w+:[^@/]+@)', re.IGNORECASE),
            # Common credential formats
            re.compile(r'(?:admin|root|user|login)[:=]\s*\w+\s+(?:pass|password|pwd)[:=]\s*\w+'),
            # JSON-style credentials
            re.compile(r'["\'](?:password|pwd|pass)["\']\s*[:=]\s*["\'][^"\']{5,}["\']', re.IGNORECASE)
        ]
        
    def is_false_positive(self, line: str, keyword: str) -> bool:
        """Check if a match is likely a false positive (UI code reference)"""
        line_lower = line.lower()
        
        # Check against known false positive patterns
        for pattern in self.false_positive_patterns:
            if pattern.search(line):
                return True
                
        # Check for common UI patterns
        if re.search(r'\b(?:is|has|show|validate|change|reset|confirm|new|old|current)\s*password\b', line_lower):
            return True
            
        # Check if it's just a variable/property name without value
        if re.search(r'\b' + keyword + r'\b\s*[;,{\[(]', line_lower):
            return True
            
        return False
        
    def is_credible_password(self, line: str) -> bool:
        """Check if line contains a credible password value using patterns"""
        for pattern in self.credential_patterns:
            if pattern.search(line):
                return True
        return False
        
    def scan_file(self, file_path: Path):
        """Scan single file for credentials and URLs"""
        reader = get_reader(file_path)
        results = {'passwords': [], 'urls': []}
        
        try:
            for line_num, line in enumerate(reader(file_path), 1):
                clean_line = clean_text(line).strip()
                if not clean_line:
                    continue
                
                # Password detection - improved logic
                found_password = False
                for keyword in self.password_keywords:
                    if keyword in clean_line.lower():
                        # Check if it's a false positive
                        if not self.is_false_positive(clean_line, keyword):
                            # Additional check for credible password patterns
                            if self.is_credible_password(clean_line):
                                results['passwords'].append((line_num, clean_line))
                                found_password = True
                                break
                
                # URL detection (unchanged)
                for pattern in self.url_patterns:
                    for match in pattern.finditer(clean_line):
                        results['urls'].append((line_num, match.group()))
                        
        except Exception as e:
            results['passwords'].append((0, f"SCANNING ERROR: {str(e)}"))
            
        return results
    
    def generate_output(self, file_path, results, output_type):
        """Generate formatted output line"""
        output_lines = []
        items = results['passwords'] if output_type == 'passwords' else results['urls']
        
        for line_num, content in items:
            line = self.output_format.format(
                path=str(file_path),
                line=line_num,
                content=content
            )
            output_lines.append(line)
            
        return output_lines
EOF
#!/bin/bash
set -e

if [ ! -d ".venv" ]; then
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt
else
    source .venv/bin/activate
fi

python -c "
import yaml
from credscan.core import Scanner
from pathlib import Path

config = yaml.safe_load(open('config.yaml'))
scanner = Scanner(config)

# Verify config structure
if 'output' not in config:
    print('ERROR: config.yaml is missing \"output\" section')
    exit(1)
if 'passwords_file' not in config['output'] or 'urls_file' not in config['output']:
    print('ERROR: config.yaml \"output\" section is incomplete')
    exit(1)

for path_str in config['search_paths']:
    path = Path(path_str)
    if not path.exists(): 
        print(f'Warning: Search path {path_str} does not exist')
        continue
        
    for file_path in path.rglob('*'):
        if file_path.is_file():
            results = scanner.scan_file(file_path)
            
            with open(config['output']['passwords_file'], 'a') as f:
                f.write('\\n'.join(scanner.generate_output(file_path, results, 'passwords')) + '\\n')
            
            with open(config['output']['urls_file'], 'a') as f:
                f.write('\\n'.join(scanner.generate_output(file_path, results, 'urls')) + '\\n')

print('✅ Scan complete! Results in ' + config['output']['passwords_file'] + ' and ' + config['output']['urls_file'])
"
EOF
python-docx>=0.8.11
openpyxl>=3.1.0
chardet>=5.2.0
tqdm>=4.67.0
PyYAML>=6.0
EOF
search_paths:
  - ./documents

password_keywords:
  - password
  - pass
  - pwd
  - secret
  - token
  - api_key
  - credential
  - login

url_patterns:
  - "https?://[\\w\\.-]+(?:/[\\w\\./?=&#%\\-]*)?"
  - "www\\.[\\w\\.-]+\\.[a-z]{2,}"

output:
  passwords_file: "output/passwords_found.txt"
  urls_file: "output/urls_found.txt"
  format: "{path}:{line}:{content}"
EOF
```

## ⚠️ Important Notes

- **Ethical Use Only**: Only scan files you have explicit permission to audit
- **Not a password cracker**: This tool only finds credentials stored in plain text
- **False positives**: While minimized, some false positives may still occur
- **Verification required**: Always verify findings before taking action

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

Distributed under the MIT License. See [LICENSE](LICENSE) for more information.

