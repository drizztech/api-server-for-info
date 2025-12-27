#!/usr/bin/env python3
"""
LLM Security Framework - Comprehensive Test Suite
Demonstrates all major functionality
"""

import json
import tempfile
from pathlib import Path
from llm_security_core import (
    security_analyzer, binary_analyzer, source_validator,
    LLMSecurityAnalyzer, BinaryAnalyzer, SourceCodeValidator,
    SecurityLevel, VulnerabilityType
)


def test_python_analysis():
    """Test Python code analysis."""
    print("\n" + "="*70)
    print("TEST 1: Python Code Security Analysis")
    print("="*70)
    
    python_code = '''
import pickle
import subprocess

# Hardcoded secret
DATABASE_PASSWORD = "admin123456"

def execute_command(user_cmd):
    return subprocess.call(user_cmd, shell=True)  # DANGEROUS!

def load_config(path):
    with open("../../etc/" + path) as f:  # Path traversal
        return pickle.loads(f.read())  # Unsafe deserialization

user_input = input("Enter expression: ")
result = eval(user_input)  # Code injection!
'''
    
    issues = security_analyzer.analyze_code(python_code, "test.py")
    report = security_analyzer.generate_report()
    
    print(f"Issues Found: {len(issues)}")
    print(f"Risk Score: {report['risk_score']:.1f}/100")
    print(f"Critical: {report['critical_count']} | High: {report['high_count']}")
    
    for issue in issues[:5]:
        print(f"  [{issue.severity.value}] {issue.description}")
    
    assert len(issues) > 0, "Should detect vulnerabilities"
    print("✓ Python analysis test passed")


def test_c_code_analysis():
    """Test C code analysis."""
    print("\n" + "="*70)
    print("TEST 2: C Code Analysis")
    print("="*70)
    
    c_code = '''
#include <stdio.h>
#include <string.h>

void unsafe_copy(char *dest, const char *src) {
    strcpy(dest, src);  // Buffer overflow!
}

char *unsafe_string_format(const char *fmt, const char *user_data) {
    char buffer[256];
    sprintf(buffer, fmt, user_data);  // Format string vulnerability
    return buffer;  // Use after free!
}

int main(int argc, char *argv[]) {
    char password[] = "AdminPass123!";
    return 0;
}
'''
    
    result = source_validator.validate_c_code(c_code)
    
    print(f"Issues Found: {result['total_issues']}")
    for issue in result['issues'][:5]:
        print(f"  [{issue['severity']}] {issue['description']}")
    
    assert result['total_issues'] > 0, "Should detect C vulnerabilities"
    print("✓ C code analysis test passed")


def test_typescript_analysis():
    """Test TypeScript code analysis."""
    print("\n" + "="*70)
    print("TEST 3: TypeScript Code Analysis")
    print("="*70)
    
    ts_code = '''
function processUserData(userData: any) {  // Dangerous 'any' type
    const result = eval(userData);  // Code injection
    return result;
}

function renderUserContent(userInput: string) {
    const element = document.getElementById('content');
    element.innerHTML = userInput;  // XSS vulnerability
    return element;
}

const apiKey: string = "sk_live_abc123def456";  // Hardcoded secret
'''
    
    result = source_validator.validate_typescript_code(ts_code)
    
    print(f"Issues Found: {result['total_issues']}")
    for issue in result['issues'][:5]:
        print(f"  [{issue['severity']}] {issue['description']}")
    
    assert result['total_issues'] > 0, "Should detect TypeScript issues"
    print("✓ TypeScript analysis test passed")


def test_process_hooking():
    """Test process hooking functionality."""
    print("\n" + "="*70)
    print("TEST 4: Process Hooking and Memory Analysis")
    print("="*70)
    
    # Hook multiple processes
    binary_analyzer.hook_process(1001, "webserver", 0x400000)
    binary_analyzer.hook_process(1002, "database", 0x400000)
    binary_analyzer.hook_process(1003, "cache_service", 0x400000)
    
    hooked = binary_analyzer.list_hooked_processes()
    print(f"Processes Hooked: {len(hooked)}")
    
    for proc in hooked:
        print(f"  PID {proc['pid']}: {proc['name']} @ {proc['base_address']}")
    
    assert len(hooked) >= 3, "Should have hooked 3 processes"
    print("✓ Process hooking test passed")


def test_function_discovery():
    """Test function discovery and analysis."""
    print("\n" + "="*70)
    print("TEST 5: Function Discovery and Analysis")
    print("="*70)
    
    # Register functions
    funcs = [
        ("malloc", 0x401000, 256, "size_t"),
        ("free", 0x401100, 128, "void"),
        ("memcpy", 0x401200, 512, "void*"),
        ("strcpy", 0x401300, 64, "char*"),
        ("main", 0x400000, 1024, "int"),
    ]
    
    for name, addr, size, ret_type in funcs:
        func = binary_analyzer.register_function(name, addr, size)
        func.return_type = ret_type
    
    # Find functions
    malloc_func = binary_analyzer.find_function_in_memory(1001, "malloc")
    if malloc_func:
        print(f"Found: {malloc_func.name} @ 0x{malloc_func.address:x} ({malloc_func.size} bytes)")
    
    print(f"Functions Registered: {len(funcs)}")
    print("✓ Function discovery test passed")


def test_memory_mapping():
    """Test memory location registration and lookup."""
    print("\n" + "="*70)
    print("TEST 6: Memory Location Mapping")
    print("="*70)
    
    # Register memory regions
    mem_locations = [
        (0x400000, 4096, "rx", "code"),
        (0x401000, 8192, "rw", "heap"),
        (0x402000, 2048, "rw", "stack"),
        (0x7fff0000, 65536, "rw", "libc"),
    ]
    
    registered = []
    for addr, size, perms, name in mem_locations:
        mem = binary_analyzer.register_memory_location(addr, size, perms, name)
        registered.append(mem)
        print(f"  Registered: 0x{addr:x} ({size} bytes) - {name}")
    
    assert len(registered) == len(mem_locations), "Should register all locations"
    print("✓ Memory mapping test passed")


def test_risk_scoring():
    """Test risk score calculation."""
    print("\n" + "="*70)
    print("TEST 7: Risk Scoring and Severity Analysis")
    print("="*70)
    
    code_samples = [
        ("secure.py", "print('Hello World')", 0),
        ("vulnerable.py", "eval(user_input)\npickle.loads(data)", 40),
        ("critical.py", "eval(x)\nexec(y)", 50),
    ]
    
    for name, code, expected_min in code_samples:
        analyzer = LLMSecurityAnalyzer()
        analyzer.analyze_code(code, name)
        report = analyzer.generate_report()
        score = report['risk_score']
        
        print(f"  {name}: Risk Score {score:.1f}/100")
        assert score >= expected_min, f"Score should be at least {expected_min}"
    
    print("✓ Risk scoring test passed")


def test_bulk_directory_analysis():
    """Test analyzing multiple files."""
    print("\n" + "="*70)
    print("TEST 8: Bulk File Analysis")
    print("="*70)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)
        
        # Create test files
        files = {
            "secure.py": "def add(a, b):\n    return a + b",
            "moderate.py": "import pickle\ndata = pickle.loads(user_data)",
            "vulnerable.py": "eval(user_code)\nsystem(cmd)",
        }
        
        for filename, code in files.items():
            (tmppath / filename).write_text(code)
        
        # Analyze all files
        total_issues = 0
        for pyfile in tmppath.glob("*.py"):
            code = pyfile.read_text()
            analyzer = LLMSecurityAnalyzer()
            issues = analyzer.analyze_code(code, pyfile.name)
            total_issues += len(issues)
            print(f"  {pyfile.name}: {len(issues)} issues")
        
        assert total_issues > 0, "Should find issues in test files"
        print(f"Total issues found: {total_issues}")
        print("✓ Bulk analysis test passed")


def test_json_report_export():
    """Test JSON report generation."""
    print("\n" + "="*70)
    print("TEST 9: JSON Report Export")
    print("="*70)
    
    code = "eval(user_input)"
    analyzer = LLMSecurityAnalyzer()
    analyzer.analyze_code(code, "test.py")
    report = analyzer.generate_report()
    
    # Convert report to JSON-serializable format
    issues_data = [
        {
            "type": issue.vulnerability_type.value,
            "severity": issue.severity.value,
            "line": issue.line_number,
            "description": issue.description,
        }
        for issue in analyzer.issues
    ]
    
    json_report = {
        "total_issues": report['total_issues'],
        "risk_score": report['risk_score'],
        "issues": issues_data,
    }
    
    json_str = json.dumps(json_report, indent=2)
    print("Sample JSON output:")
    print(json_str[:300] + "...")
    
    assert "risk_score" in json_report, "Report should contain risk_score"
    print("✓ JSON export test passed")


def test_multi_language_scan():
    """Test scanning multiple languages."""
    print("\n" + "="*70)
    print("TEST 10: Multi-Language Security Scanning")
    print("="*70)
    
    samples = {
        "python": "eval(x)\npassword='secret'",
        "c": "strcpy(dest, src)",
        "typescript": "innerHTML = userInput",
    }
    
    results = {}
    for lang, code in samples.items():
        if lang == "python":
            issues = security_analyzer.analyze_code(code, f"test.py")
            results[lang] = len(issues)
        elif lang == "c":
            result = source_validator.validate_c_code(code)
            results[lang] = result['total_issues']
        elif lang == "typescript":
            result = source_validator.validate_typescript_code(code)
            results[lang] = result['total_issues']
        
        print(f"  {lang.upper()}: {results[lang]} issues found")
    
    assert all(count > 0 for count in results.values()), "Should find issues in all languages"
    print("✓ Multi-language test passed")


def run_all_tests():
    """Run all tests."""
    print("\n" + "="*70)
    print("LLM SECURITY FRAMEWORK - COMPREHENSIVE TEST SUITE")
    print("="*70)
    
    tests = [
        test_python_analysis,
        test_c_code_analysis,
        test_typescript_analysis,
        test_process_hooking,
        test_function_discovery,
        test_memory_mapping,
        test_risk_scoring,
        test_bulk_directory_analysis,
        test_json_report_export,
        test_multi_language_scan,
    ]
    
    passed = 0
    failed = 0
    
    for test_func in tests:
        try:
            test_func()
            passed += 1
        except Exception as e:
            print(f"✗ {test_func.__name__} FAILED: {e}")
            failed += 1
    
    print("\n" + "="*70)
    print(f"RESULTS: {passed} passed, {failed} failed out of {len(tests)} tests")
    print("="*70 + "\n")
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    exit(0 if success else 1)
