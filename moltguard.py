#!/usr/bin/env python3
"""
moltguard - Skill file security scanner for Clawdbot agents
Detects credential stealers, prompt injections, and malicious patterns
"""

import re
import sys
import json
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Optional

@dataclass
class Finding:
    severity: str  # critical, high, medium, low
    category: str
    line: int
    snippet: str
    explanation: str

class MoltGuard:
    """Security scanner for Clawdbot skill files"""
    
    # Patterns that indicate credential theft
    CRED_THEFT_PATTERNS = [
        (r'api[_-]?key', 'API key access'),
        (r'password', 'Password access'),
        (r'token', 'Token access'),
        (r'secret', 'Secret access'),
        (r'credential', 'Credential access'),
        (r'\.env', 'Environment file access'),
        (r'clawdbot.*credential', 'Clawdbot credentials'),
        (r'~/.clawdbot', 'Clawdbot config directory'),
    ]
    
    # Patterns that indicate data exfiltration
    EXFIL_PATTERNS = [
        (r'webhook\.site', 'Known exfiltration endpoint'),
        (r'requestbin', 'Known exfiltration endpoint'),
        (r'POST.*http', 'HTTP POST (potential exfil)'),
        (r'curl.*-X POST', 'cURL POST (potential exfil)'),
        (r'fetch\(.*http', 'HTTP fetch (potential exfil)'),
    ]
    
    # Patterns that indicate prompt injection attempts
    INJECTION_PATTERNS = [
        (r'\[IGNORE\]', 'Prompt injection: [IGNORE] tag'),
        (r'System:', 'Prompt injection: System override'),
        (r'previous instructions', 'Prompt injection: instruction override'),
        (r'ignore (all|your) (previous|prior)', 'Prompt injection: ignore previous'),
        (r'you are (now|no longer)', 'Prompt injection: role override'),
        (r'OVERRIDE', 'Prompt injection: OVERRIDE directive'),
        (r'system override', 'Prompt injection: system override'),
    ]
    
    # Dangerous permissions
    DANGEROUS_PATTERNS = [
        (r'rm -rf', 'Destructive file operation'),
        (r'> /dev/null', 'Output suppression (suspicious)'),
        (r'eval\(', 'Code evaluation (dangerous)'),
        (r'exec\(', 'Code execution (dangerous)'),
        (r'__import__', 'Dynamic import (suspicious)'),
    ]
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.findings: List[Finding] = []
    
    def scan_file(self, filepath: Path) -> List[Finding]:
        """Scan a single skill file"""
        self.findings = []
        
        try:
            content = filepath.read_text(encoding='utf-8', errors='ignore')
            lines = content.split('\n')
        except Exception as e:
            print(f"Error reading {filepath}: {e}")
            return []
        
        for line_num, line in enumerate(lines, 1):
            self._check_line(line, line_num)
        
        return self.findings
    
    def _check_line(self, line: str, line_num: int):
        """Check a single line against all patterns"""
        line_lower = line.lower()
        
        # Check credential theft
        for pattern, description in self.CRED_THEFT_PATTERNS:
            if re.search(pattern, line_lower):
                self.findings.append(Finding(
                    severity='critical',
                    category='credential_theft',
                    line=line_num,
                    snippet=line.strip()[:100],
                    explanation=f'{description} - may steal your API keys'
                ))
        
        # Check exfiltration
        for pattern, description in self.EXFIL_PATTERNS:
            if re.search(pattern, line_lower):
                self.findings.append(Finding(
                    severity='critical',
                    category='data_exfiltration',
                    line=line_num,
                    snippet=line.strip()[:100],
                    explanation=f'{description} - may send your data to external server'
                ))
        
        # Check prompt injection
        for pattern, description in self.INJECTION_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                self.findings.append(Finding(
                    severity='high',
                    category='prompt_injection',
                    line=line_num,
                    snippet=line.strip()[:100],
                    explanation=f'{description} - attempts to override your instructions'
                ))
        
        # Check dangerous operations
        for pattern, description in self.DANGEROUS_PATTERNS:
            if re.search(pattern, line_lower):
                self.findings.append(Finding(
                    severity='high',
                    category='dangerous_operation',
                    line=line_num,
                    snippet=line.strip()[:100],
                    explanation=f'{description} - could harm your system'
                ))
    
    def generate_report(self, filepath: Path, findings: List[Finding]) -> str:
        """Generate a human-readable report"""
        if not findings:
            return f"✅ {filepath}: Clean - no issues found"
        
        lines = [f"\n{'='*60}", f"🚨 SECURITY REPORT: {filepath}", f"{'='*60}"]
        
        # Group by severity
        critical = [f for f in findings if f.severity == 'critical']
        high = [f for f in findings if f.severity == 'high']
        medium = [f for f in findings if f.severity == 'medium']
        
        if critical:
            lines.append(f"\n🔴 CRITICAL ISSUES ({len(critical)}):")
            for f in critical:
                lines.append(f"  Line {f.line}: {f.explanation}")
                lines.append(f"    {f.snippet[:80]}")
        
        if high:
            lines.append(f"\n🟠 HIGH RISK ({len(high)}):")
            for f in high:
                lines.append(f"  Line {f.line}: {f.explanation}")
                lines.append(f"    {f.snippet[:80]}")
        
        lines.append(f"\n{'='*60}")
        lines.append(f"RECOMMENDATION: {'DO NOT INSTALL' if critical else 'Review carefully'}")
        lines.append(f"{'='*60}\n")
        
        return '\n'.join(lines)

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='moltguard - Security scanner for Clawdbot skill files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  moltguard skill.md              Scan a single file
  moltguard ~/skills/*.md         Scan all skill files
  moltguard --json skill.md       Output JSON for automation
        '''
    )
    
    parser.add_argument('files', nargs='+', help='Skill files to scan')
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    guard = MoltGuard(verbose=args.verbose)
    all_results = []
    
    for file_path in args.files:
        path = Path(file_path)
        if not path.exists():
            print(f"❌ File not found: {path}")
            continue
        
        findings = guard.scan_file(path)
        
        if args.json:
            all_results.append({
                'file': str(path),
                'findings': [asdict(f) for f in findings],
                'safe': len(findings) == 0
            })
        else:
            print(guard.generate_report(path, findings))
    
    if args.json:
        print(json.dumps(all_results, indent=2))

if __name__ == '__main__':
    main()
