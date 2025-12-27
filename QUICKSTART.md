# LLM Security Framework - Quick Start Guide

## Installation

### Python (No Dependencies)
```bash
# The framework is ready to use immediately
python3 llm_security_cli.py --help
```

### C Library (Optional)
```bash
mkdir build && cd build
cmake ..
make
sudo make install
```

### TypeScript/Node.js
```bash
cp llm_security.ts your_project/
```

---

## 5-Minute Quickstart

### 1. Analyze a Python File
```bash
python3 llm_security_cli.py analyze vulnerable.py
```

**Output:**
```
Found 5 security issues:
[CRITICAL] Line 12: eval() detected
[HIGH] Line 4: Hardcoded secrets detected
...
Risk Score: 75.5/100
```

### 2. Scan an Entire Directory
```bash
python3 llm_security_cli.py analyze-dir ./src --json report.json
```

### 3. Programmatic Use (Python)
```python
from llm_security_core import security_analyzer

code = open('app.py').read()
issues = security_analyzer.analyze_code(code)
report = security_analyzer.generate_report()

print(f"Risk Score: {report['risk_score']}/100")
print(f"Critical Issues: {report['critical_count']}")
```

### 4. Memory & Process Analysis (Python)
```python
from llm_security_core import binary_analyzer

# Hook a process
binary_analyzer.hook_process(1234, "myapp", 0x400000)

# Register function
func = binary_analyzer.register_function("malloc", 0x401000, 256)

# List hooked processes
for proc in binary_analyzer.list_hooked_processes():
    print(f"PID {proc['pid']}: {proc['name']}")
```

### 5. C/C++ Integration
```cpp
#include "llm_security.hpp"
using namespace llm_security;

SecurityAnalyzer analyzer;
analyzer.analyzeCode(code_string);
float risk = analyzer.calculateRiskScore();
```

---

## Common Tasks

### Analyze for Secrets
```bash
# Find hardcoded API keys, passwords
python3 llm_security_cli.py analyze myapp.py | grep -i secret
```

### Check Code Injection Risks
```python
from llm_security_core import security_analyzer, VulnerabilityType

issues = security_analyzer.analyze_code(code)
injection_issues = [i for i in issues 
                    if i.vulnerability_type == VulnerabilityType.INJECTION]
```

### Export JSON Report
```bash
python3 llm_security_cli.py analyze app.py --json report.json
cat report.json | jq '.report.critical_count'
```

### Hook Running Process
```bash
# Find PID
ps aux | grep myapp

# Hook it
python3 llm_security_cli.py hook-process 12345 --name myapp --base-address 0x400000

# List hooked
python3 llm_security_cli.py list-hooked

# Find function
python3 llm_security_cli.py find-function 12345 malloc
```

---

## Interpretation Guide

### Risk Scores
- **0-20**: Minimal risk (GOOD) ✓
- **20-40**: Low-moderate risk (REVIEW)
- **40-60**: Moderate risk (ATTENTION NEEDED)
- **60-80**: High risk (URGENT)
- **80-100**: Critical risk (IMMEDIATE ACTION)

### Severity Levels
- **CRITICAL**: Exploitable vulnerabilities
- **HIGH**: Serious security issues
- **MEDIUM**: Notable weaknesses
- **LOW**: Minor issues
- **INFO**: Informational

### Example Output
```
[CRITICAL] Line 42: eval(user_input)
└─ Fix: Never eval untrusted input. Use json.loads() instead.

[HIGH] Line 8: password = "admin123"
└─ Fix: Move to environment variables or secure vault.

[MEDIUM] Line 15: user_data = sys.argv[1]
└─ Fix: Validate and sanitize command-line arguments.
```

---

## Remediation Examples

### eval() → Safe Alternative
```python
# BAD
result = eval(user_input)

# GOOD
import ast
try:
    node = ast.parse(user_input, mode='eval')
    result = eval(compile(node, '<string>', 'eval'))
except:
    result = None
```

### strcpy() → Safe Alternative
```c
// BAD
strcpy(dest, src);

// GOOD
strncpy(dest, src, sizeof(dest) - 1);
dest[sizeof(dest) - 1] = '\0';
```

### Hardcoded Secrets → Environment Variables
```python
# BAD
API_KEY = "sk-abc123def456"

# GOOD
import os
API_KEY = os.getenv('API_KEY')
if not API_KEY:
    raise ValueError("API_KEY not set")
```

---

## Advanced Features

### Run Full Test Suite
```bash
python3 test_llm_security.py
```

### Enable Detailed Logging
```python
import logging
logging.basicConfig(level=logging.DEBUG)

from llm_security_core import security_analyzer
issues = security_analyzer.analyze_code(code)
```

### Custom Analyzers
```python
from llm_security_core import LLMSecurityAnalyzer, SecurityIssue

analyzer = LLMSecurityAnalyzer()
issues = analyzer.analyze_code(code)

# Filter by type
critical = [i for i in issues 
           if i.severity.value == 'CRITICAL']
```

---

## Performance Tips

1. **Batch Analysis**: Analyze multiple files in one pass
   ```bash
   python3 llm_security_cli.py analyze-dir ./src
   ```

2. **Parallel Processing**: Use for large codebases
   ```python
   from pathlib import Path
   from concurrent.futures import ThreadPoolExecutor
   
   with ThreadPoolExecutor(max_workers=4) as executor:
       futures = [executor.submit(analyze, f) 
                  for f in Path('.').glob('*.py')]
   ```

3. **Memory Efficient**: Stream large files
   ```python
   analyzer = LLMSecurityAnalyzer()
   for chunk in read_file_chunks(file):
       analyzer.analyze_code(chunk)
   ```

---

## Troubleshooting

### ImportError: llm_security_core not found
```bash
# Make sure you're in the right directory
cd /path/to/llm_security_framework
python3 llm_security_cli.py analyze file.py
```

### C library build fails
```bash
# Install dependencies
brew install cmake openssl  # macOS
apt-get install cmake libssl-dev  # Ubuntu

# Retry build
cd build && cmake -DENABLE_OPENSSL=ON ..
make
```

### No issues detected in vulnerable code
```bash
# Ensure Python files use .py extension
# Try explicit language specification
python3 llm_security_cli.py analyze file --language python
```

---

## Next Steps

1. **Integrate into CI/CD**: Use in GitHub Actions or GitLab CI
2. **Monitor Production**: Hook running services
3. **Audit Codebase**: Run across all source code
4. **Track Trends**: Export JSON reports over time
5. **Custom Rules**: Extend with domain-specific checks

---

## Support & Examples

See **LLM_SECURITY_README.md** for comprehensive documentation.

Test files: `test_llm_security.py` and `examples/` directory
