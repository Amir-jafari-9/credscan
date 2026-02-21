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
