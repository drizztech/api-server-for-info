"""
LLM Security Core Framework
Comprehensive security checks, binary analysis, and memory inspection for LLM implementations.
"""

import ast
import re
import json
from typing import Dict, List, Tuple, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum
import hashlib
import inspect


class SecurityLevel(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class VulnerabilityType(Enum):
    INJECTION = "injection"
    XSS = "cross_site_scripting"
    BUFFER_OVERFLOW = "buffer_overflow"
    MEMORY_LEAK = "memory_leak"
    USE_AFTER_FREE = "use_after_free"
    RACE_CONDITION = "race_condition"
    INSECURE_CRYPTO = "insecure_crypto"
    UNSAFE_DESERIALIZATION = "unsafe_deserialization"
    UNVALIDATED_INPUT = "unvalidated_input"
    HARDCODED_SECRETS = "hardcoded_secrets"
    LOGIC_ERROR = "logic_error"
    PATH_TRAVERSAL = "path_traversal"


@dataclass
class SecurityIssue:
    vulnerability_type: VulnerabilityType
    severity: SecurityLevel
    line_number: int
    code_snippet: str
    description: str
    remediation: str
    confidence: float  # 0.0 to 1.0


@dataclass
class MemoryLocation:
    address: int
    size: int
    permission: str
    function_name: Optional[str] = None
    hex_dump: Optional[str] = None
    hash: Optional[str] = None


@dataclass
class FunctionSignature:
    name: str
    address: int
    size: int
    parameters: List[str]
    return_type: str
    referenced_functions: List[str]
    memory_operations: List[str]


class LLMSecurityAnalyzer:
    """Core security analysis engine for LLM implementations."""

    def __init__(self):
        self.issues: List[SecurityIssue] = []
        self.patterns = self._init_security_patterns()

    def _init_security_patterns(self) -> Dict[VulnerabilityType, List[re.Pattern]]:
        """Initialize regex patterns for detecting vulnerabilities."""
        return {
            VulnerabilityType.HARDCODED_SECRETS: [
                re.compile(r'(?:api[_-]?key|password|secret|token)\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE),
                re.compile(r'(?:AWS|AZURE|GCP)_KEY\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE),
            ],
            VulnerabilityType.INJECTION: [
                re.compile(r'eval\s*\('),
                re.compile(r'exec\s*\('),
                re.compile(r'__import__\s*\('),
                re.compile(r'pickle\.loads'),
            ],
            VulnerabilityType.UNVALIDATED_INPUT: [
                re.compile(r'(?:user_input|request\.args|request\.form|sys\.argv)\['),
                re.compile(r'input\s*\('),
            ],
            VulnerabilityType.PATH_TRAVERSAL: [
                re.compile(r'open\s*\(\s*["\']?\.\.[/\\]'),
                re.compile(r'os\.path\.join.*\$|\.\.'),
            ],
            VulnerabilityType.UNSAFE_DESERIALIZATION: [
                re.compile(r'json\.loads\s*\(.*untrusted'),
                re.compile(r'yaml\.load\s*\('),
            ],
        }

    def analyze_code(self, code: str, filename: str = "unknown") -> List[SecurityIssue]:
        """Analyze Python/source code for security issues."""
        self.issues.clear()

        lines = code.split('\n')

        # Pattern-based detection
        for line_num, line in enumerate(lines, 1):
            for vuln_type, patterns in self.patterns.items():
                for pattern in patterns:
                    if pattern.search(line):
                        severity = self._determine_severity(vuln_type)
                        issue = SecurityIssue(
                            vulnerability_type=vuln_type,
                            severity=severity,
                            line_number=line_num,
                            code_snippet=line.strip(),
                            description=f"Potential {vuln_type.value} detected",
                            remediation=self._get_remediation(vuln_type),
                            confidence=0.8
                        )
                        self.issues.append(issue)

        # AST-based analysis
        try:
            tree = ast.parse(code)
            self._analyze_ast(tree, lines)
        except SyntaxError:
            pass

        return self.issues

    def _analyze_ast(self, tree: ast.AST, lines: List[str]):
        """Analyze AST for logical and security issues."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                self._check_dangerous_calls(node, lines)
            elif isinstance(node, ast.FunctionDef):
                self._check_function_security(node, lines)

    def _check_dangerous_calls(self, node: ast.Call, lines: List[str]):
        """Check for dangerous function calls."""
        dangerous_functions = {'eval', 'exec', '__import__', 'compile', 'input'}
        if isinstance(node.func, ast.Name) and node.func.id in dangerous_functions:
            line_num = node.lineno
            code_snippet = lines[line_num - 1].strip() if line_num <= len(lines) else ""
            issue = SecurityIssue(
                vulnerability_type=VulnerabilityType.INJECTION,
                severity=SecurityLevel.CRITICAL,
                line_number=line_num,
                code_snippet=code_snippet,
                description=f"Dangerous function '{node.func.id}' detected",
                remediation="Use safer alternatives or validate all inputs strictly",
                confidence=0.95
            )
            self.issues.append(issue)

    def _check_function_security(self, node: ast.FunctionDef, lines: List[str]):
        """Check function for security best practices."""
        # Check for missing input validation
        has_validation = False
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Attribute):
                    if child.func.attr in ('validate', 'check', 'verify', 'sanitize'):
                        has_validation = True

        if not has_validation and node.name not in ('__init__', '__str__', '__repr__'):
            # Check if function takes parameters
            if node.args.args:
                issue = SecurityIssue(
                    vulnerability_type=VulnerabilityType.UNVALIDATED_INPUT,
                    severity=SecurityLevel.MEDIUM,
                    line_number=node.lineno,
                    code_snippet=f"def {node.name}({', '.join(arg.arg for arg in node.args.args)}):",
                    description="Function accepts input without apparent validation",
                    remediation="Add input validation at the start of the function",
                    confidence=0.6
                )
                self.issues.append(issue)

    def _determine_severity(self, vuln_type: VulnerabilityType) -> SecurityLevel:
        """Determine severity based on vulnerability type."""
        critical = {VulnerabilityType.INJECTION, VulnerabilityType.BUFFER_OVERFLOW, VulnerabilityType.USE_AFTER_FREE}
        high = {VulnerabilityType.HARDCODED_SECRETS, VulnerabilityType.UNSAFE_DESERIALIZATION, VulnerabilityType.PATH_TRAVERSAL}
        medium = {VulnerabilityType.UNVALIDATED_INPUT, VulnerabilityType.INSECURE_CRYPTO}

        if vuln_type in critical:
            return SecurityLevel.CRITICAL
        elif vuln_type in high:
            return SecurityLevel.HIGH
        elif vuln_type in medium:
            return SecurityLevel.MEDIUM
        return SecurityLevel.LOW

    def _get_remediation(self, vuln_type: VulnerabilityType) -> str:
        """Get remediation advice for vulnerability type."""
        remediations = {
            VulnerabilityType.INJECTION: "Never use eval/exec on user input. Use safe parsing libraries.",
            VulnerabilityType.HARDCODED_SECRETS: "Move secrets to environment variables or secure vaults.",
            VulnerabilityType.UNVALIDATED_INPUT: "Validate and sanitize all user inputs before use.",
            VulnerabilityType.PATH_TRAVERSAL: "Use os.path.abspath() to validate file paths.",
            VulnerabilityType.UNSAFE_DESERIALIZATION: "Use json.loads for untrusted data, avoid pickle.",
            VulnerabilityType.BUFFER_OVERFLOW: "Use bounds checking and safe string functions.",
            VulnerabilityType.MEMORY_LEAK: "Ensure proper cleanup of allocated memory.",
            VulnerabilityType.USE_AFTER_FREE: "Track object lifetimes carefully, use smart pointers.",
            VulnerabilityType.RACE_CONDITION: "Use locks/mutexes for shared resource access.",
            VulnerabilityType.INSECURE_CRYPTO: "Use modern cryptographic algorithms (AES-256, SHA-256).",
        }
        return remediations.get(vuln_type, "Review this code section for security issues.")

    def generate_report(self) -> Dict[str, Any]:
        """Generate a detailed security report."""
        issues_by_severity = {}
        for severity in SecurityLevel:
            issues_by_severity[severity.value] = [
                asdict(i) for i in self.issues if i.severity == severity
            ]

        return {
            "total_issues": len(self.issues),
            "issues_by_severity": issues_by_severity,
            "critical_count": len([i for i in self.issues if i.severity == SecurityLevel.CRITICAL]),
            "high_count": len([i for i in self.issues if i.severity == SecurityLevel.HIGH]),
            "risk_score": self._calculate_risk_score(),
        }

    def _calculate_risk_score(self) -> float:
        """Calculate overall risk score 0-100."""
        if not self.issues:
            return 0.0
        severity_weights = {
            SecurityLevel.CRITICAL: 25,
            SecurityLevel.HIGH: 15,
            SecurityLevel.MEDIUM: 8,
            SecurityLevel.LOW: 3,
            SecurityLevel.INFO: 1,
        }
        total_score = sum(
            severity_weights.get(i.severity, 0) * i.confidence for i in self.issues
        )
        return min(100.0, total_score)


class BinaryAnalyzer:
    """Binary and memory layout analysis."""

    def __init__(self):
        self.memory_map: Dict[int, MemoryLocation] = {}
        self.function_signatures: Dict[str, FunctionSignature] = {}
        self.hooked_processes: Dict[int, Dict[str, Any]] = {}

    def register_memory_location(self, address: int, size: int, permission: str, 
                                 function_name: Optional[str] = None) -> MemoryLocation:
        """Register a memory location for tracking."""
        mem_loc = MemoryLocation(
            address=address,
            size=size,
            permission=permission,
            function_name=function_name,
            hash=hashlib.sha256(f"{address}:{size}".encode()).hexdigest()
        )
        self.memory_map[address] = mem_loc
        return mem_loc

    def register_function(self, name: str, address: int, size: int,
                         parameters: List[str] = None, return_type: str = "void") -> FunctionSignature:
        """Register function signature and metadata."""
        sig = FunctionSignature(
            name=name,
            address=address,
            size=size,
            parameters=parameters or [],
            return_type=return_type,
            referenced_functions=[],
            memory_operations=[]
        )
        self.function_signatures[name] = sig
        return sig

    def hook_process(self, pid: int, process_name: str, base_address: int) -> Dict[str, Any]:
        """Hook a process and save metadata."""
        hook_info = {
            "pid": pid,
            "name": process_name,
            "base_address": hex(base_address),
            "hook_time": self._get_timestamp(),
            "memory_regions": [],
            "functions": [],
        }
        self.hooked_processes[pid] = hook_info
        return hook_info

    def find_function_in_memory(self, process_id: int, function_name: str) -> Optional[FunctionSignature]:
        """Find function in hooked process memory."""
        if function_name in self.function_signatures:
            return self.function_signatures[function_name]
        return None

    def analyze_binary_structure(self, binary_path: str) -> Dict[str, Any]:
        """Analyze binary structure and layout."""
        # Simulate binary analysis
        return {
            "file": binary_path,
            "sections": [".text", ".data", ".rodata", ".bss"],
            "imports": [],
            "exports": [],
            "relocs": [],
            "symbols": []
        }

    def get_hooked_process_info(self, pid: int) -> Optional[Dict[str, Any]]:
        """Retrieve hooked process information."""
        return self.hooked_processes.get(pid)

    def list_hooked_processes(self) -> List[Dict[str, Any]]:
        """List all hooked processes."""
        return list(self.hooked_processes.values())

    def _get_timestamp(self) -> str:
        """Get current timestamp."""
        from datetime import datetime
        return datetime.now().isoformat()


class SourceCodeValidator:
    """Validate source code for security and logical errors."""

    def __init__(self):
        self.analyzer = LLMSecurityAnalyzer()
        self.binary_analyzer = BinaryAnalyzer()

    def validate_python_code(self, code: str, filename: str = "unknown") -> Dict[str, Any]:
        """Validate Python code comprehensively."""
        issues = self.analyzer.analyze_code(code, filename)
        return {
            "file": filename,
            "issues": [asdict(i) for i in issues],
            "report": self.analyzer.generate_report(),
        }

    def validate_c_code(self, code: str) -> Dict[str, Any]:
        """Analyze C code for common vulnerabilities."""
        issues = []
        
        # Check for buffer overflow patterns
        patterns = {
            r'strcpy\s*\(': ("Buffer overflow risk", SecurityLevel.CRITICAL),
            r'gets\s*\(': ("Buffer overflow risk", SecurityLevel.CRITICAL),
            r'sprintf\s*\(': ("Format string vulnerability", SecurityLevel.HIGH),
            r'malloc.*sizeof': ("Memory allocation pattern", SecurityLevel.INFO),
            r'memcpy\s*\([^,]*,[^,]*,\s*[^)]*\)': ("Potential buffer overflow in memcpy", SecurityLevel.HIGH),
        }
        
        for i, line in enumerate(code.split('\n'), 1):
            for pattern, (desc, severity) in patterns.items():
                if re.search(pattern, line):
                    issue = SecurityIssue(
                        vulnerability_type=VulnerabilityType.BUFFER_OVERFLOW if "overflow" in desc else VulnerabilityType.LOGIC_ERROR,
                        severity=severity,
                        line_number=i,
                        code_snippet=line.strip(),
                        description=desc,
                        remediation="Use safe functions (strncpy, fgets, snprintf)",
                        confidence=0.85
                    )
                    issues.append(issue)
        
        return {
            "language": "C",
            "issues": [asdict(i) for i in issues],
            "total_issues": len(issues),
        }

    def validate_typescript_code(self, code: str) -> Dict[str, Any]:
        """Analyze TypeScript code for type and security issues."""
        issues = []
        
        patterns = {
            r'any\s*[\)=:,;]': ("Use of 'any' type", SecurityLevel.MEDIUM),
            r'eval\s*\(': ("eval() usage", SecurityLevel.CRITICAL),
            r'Function\s*\(': ("Dynamic function creation", SecurityLevel.HIGH),
            r'innerHTML\s*=': ("Potential XSS vulnerability", SecurityLevel.HIGH),
        }
        
        for i, line in enumerate(code.split('\n'), 1):
            for pattern, (desc, severity) in patterns.items():
                if re.search(pattern, line):
                    issue = SecurityIssue(
                        vulnerability_type=VulnerabilityType.XSS if "XSS" in desc else VulnerabilityType.INJECTION,
                        severity=severity,
                        line_number=i,
                        code_snippet=line.strip(),
                        description=desc,
                        remediation="Use strict types, avoid dynamic evaluation, sanitize DOM operations",
                        confidence=0.8
                    )
                    issues.append(issue)
        
        return {
            "language": "TypeScript",
            "issues": [asdict(i) for i in issues],
            "total_issues": len(issues),
        }


# Singleton instances
security_analyzer = LLMSecurityAnalyzer()
binary_analyzer = BinaryAnalyzer()
source_validator = SourceCodeValidator()
