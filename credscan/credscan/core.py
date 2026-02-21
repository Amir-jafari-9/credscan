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
