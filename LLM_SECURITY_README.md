# LLM Security Framework

A comprehensive, high-performance security analysis and binary inspection framework designed for LLM implementations, source code analysis, and memory inspection. Includes **Python core**, **C/C++ libraries**, and **TypeScript bindings** for deep code analysis and process hooking.

## Features

### 🔍 **Security Analysis**
- **Code Analysis**: Python, C/C++, and TypeScript code scanning
- **Vulnerability Detection**: Injection, buffer overflows, use-after-free, memory leaks, race conditions, path traversal, and more
- **Pattern Matching**: Fast regex and binary pattern detection
- **Risk Scoring**: Intelligent risk calculation (0-100 scale)
- **Remediation Advice**: Actionable fixes for each vulnerability

### 🎯 **Binary & Memory Analysis**
- **Process Hooking**: Hook and track process execution
- **Function Discovery**: Find and analyze functions in memory
- **Memory Mapping**: Register and track memory regions
- **Pattern Searching**: Fast binary pattern matching with masks
- **Symbol Resolution**: Locate symbols and debug information

### ⚡ **Performance**
- Optimized C implementation for speed
- Pattern matching with early termination
- Memory-efficient data structures
- Suitable for large-scale analysis

### 🛠️ **Multi-Language Support**
- **Python**: Full security analyzer and CLI tool
- **C**: High-performance core library
- **C++**: Modern wrapper with STL integration
- **TypeScript**: Web and Node.js bindings

## Installation

### Python

```bash
# No external dependencies required for core functionality
python3 -m pip install --upgrade pip
```

### C/C++ Library

```bash
# With CMake
mkdir build && cd build
cmake -DBUILD_EXAMPLES=ON ..
make
make install

# Or compile directly
gcc -O2 -Wall llm_security.c -o libllm_security.a
```

### TypeScript

```bash
npm install --save llm_security
# Or copy llm_security.ts to your project
```

## Quick Start

### Python CLI

```bash
# Analyze a single file
python3 llm_security_cli.py analyze vulnerable.py

# Analyze entire directory
python3 llm_security_cli.py analyze-dir ./src --json report.json

# Hook a process
python3 llm_security_cli.py hook-process 1234 --name myapp

# List hooked processes
python3 llm_security_cli.py list-hooked

# Find function in memory
python3 llm_security_cli.py find-function 1234 malloc

# Dump memory region
python3 llm_security_cli.py memory-dump 0x400000 --size 4096
```

### Python API

```python
from llm_security_core import (
    security_analyzer, binary_analyzer, source_validator
)

# Analyze code
code = open('vulnerable.py').read()
issues = security_analyzer.analyze_code(code)

# Generate report
report = security_analyzer.generate_report()
print(f"Risk Score: {report['risk_score']}")

# Binary analysis
binary_analyzer.hook_process(1234, "myapp", 0x400000)
func = binary_analyzer.find_function_in_memory(1234, "malloc")
```

### C API

```c
#include "llm_security.h"

// Hook a process
hooked_process_t *proc = proc_hook(1234, "myapp");

// Register function
function_signature_t *func = func_register("malloc", 0x401000, 256, 1);

// Find function by name
function_signature_t *found = func_find_by_name("malloc");

// Cleanup
proc_unhook(proc);
```

### C++ API

```cpp
#include "llm_security.hpp"
using namespace llm_security;

// Create analyzer
SecurityAnalyzer analyzer;
analyzer.analyzeCode(code);

// Get results
auto issues = analyzer.getIssues();
auto risk_score = analyzer.calculateRiskScore();

// Binary analysis
BinaryAnalyzer binary;
binary.hook_process(1234, "myapp", 0x400000);
auto func = binary.find_function("malloc");
```

### TypeScript

```typescript
import { LLMSecurityFramework } from './llm_security';

const framework = new LLMSecurityFramework();

// Analyze source code
const report = framework.analyzeSourceCode(code, 'typescript');
console.log(`Risk Score: ${report.risk_score}`);

// Hook process
const proc = framework.hookProcess(1234, 'myapp', 0x400000);

// Find function
const func = framework.findFunctionInProcess(1234, 'malloc');
```

## Vulnerability Types

- **INJECTION**: eval(), exec(), pickle.loads
- **BUFFER_OVERFLOW**: strcpy, gets, memcpy issues
- **USE_AFTER_FREE**: Memory access after deallocation
- **MEMORY_LEAK**: Unreleased allocated memory
- **RACE_CONDITION**: Concurrent access without synchronization
- **PATH_TRAVERSAL**: Directory traversal vulnerabilities
- **UNVALIDATED_INPUT**: User input without validation
- **LOGIC_ERROR**: Logical flaws and incorrect algorithms
- **HARDCODED_SECRETS**: API keys, passwords in code
- **XSS**: Cross-site scripting vulnerabilities

## Architecture

```
llm_security_core.py         # Python security analyzer
├── LLMSecurityAnalyzer      # Core analysis engine
├── BinaryAnalyzer           # Memory/binary inspection
└── SourceCodeValidator      # Multi-language validation

llm_security.h/c             # C core library
├── Memory analysis
├── Process hooking
├── Function discovery
├── Binary analysis
└── Pattern matching

llm_security.hpp             # C++ wrapper
├── SecurityAnalyzer
├── BinaryAnalyzer
└── FastPatternMatcher

llm_security.ts              # TypeScript bindings
├── SecurityAnalyzer
├── BinaryAnalyzer
└── LLMSecurityFramework
```

## Performance Characteristics

| Operation | Time | Notes |
|-----------|------|-------|
| Code scanning (1000 LOC) | <10ms | Single-threaded |
| Pattern matching | O(n) | Linear search, early termination |
| Memory registration | O(1) | Hash table lookup |
| Function discovery | O(n) | Linear scan through symbols |
| Process hooking | <5ms | Platform dependent |

## Security Considerations

1. **Secrets Handling**: Never log API keys or passwords
2. **Memory Safety**: Use secure_memzero for sensitive data
3. **Process Privileges**: Requires elevated privileges for some operations
4. **Safe Patterns**: Always validate and sanitize user input
5. **Error Handling**: Check return values for all operations

## Remediation Examples

### Injection
```python
# BAD
result = eval(user_input)

# GOOD
import ast
node = ast.parse(user_input, mode='eval')
```

### Buffer Overflow
```c
// BAD
strcpy(dest, src);

// GOOD
strncpy(dest, src, sizeof(dest) - 1);
dest[sizeof(dest) - 1] = '\0';
```

### Hardcoded Secrets
```python
# BAD
API_KEY = "sk-1234567890abcdef"

# GOOD
import os
API_KEY = os.getenv('API_KEY')
```

### Path Traversal
```python
# BAD
file = open(user_path)

# GOOD
import os
real_path = os.path.abspath(user_path)
if not real_path.startswith(base_dir):
    raise ValueError("Path traversal attempt")
```

## Building from Source

```bash
# Clone repository
git clone <repo> llm_security
cd llm_security

# Build C library
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
sudo make install

# Build examples
cmake -DBUILD_EXAMPLES=ON ..
make examples

# Run tests
./examples/example_c
./examples/example_cpp
```

## Advanced Usage

### Custom Pattern Matching

```c
// C
uint8_t pattern[] = {0x55, 0x48, 0x89};  // push rbp; mov rsp,rbp
uint8_t mask[] = {1, 1, 1};
match_pattern_t p = {pattern, 3, mask};
uint64_t *matches = pattern_find_all(code, code_len, &p, &count);
```

```cpp
// C++
auto pattern = FastPatternMatcher::create_pattern("5548", "");
auto matches = FastPatternMatcher::find_pattern(buffer, pattern);
```

### Multi-File Analysis

```python
from pathlib import Path
from llm_security_cli import cmd_analyze_directory

cmd_analyze_directory(Path("./src"))
```

### Memory Inspection Workflow

```python
# 1. Hook process
binary_analyzer.hook_process(pid, "app_name", base_addr)

# 2. Register known functions
binary_analyzer.register_function("main", 0x400000, 512)
binary_analyzer.register_function("malloc", 0x401000, 256)

# 3. Find related functions
func = binary_analyzer.find_function_in_memory(pid, "malloc")

# 4. Dump memory region
mem_loc = binary_analyzer.register_memory_location(addr, size, "rwx")

# 5. Analyze for issues
# Pattern matching, symbol resolution, etc.
```

## Troubleshooting

### CMake Not Found
```bash
brew install cmake  # macOS
apt-get install cmake  # Ubuntu
```

### OpenSSL Not Found
```bash
brew install openssl  # macOS
# Or disable: cmake -DENABLE_OPENSSL=OFF ..
```

### Python Version
```bash
python3 --version  # Requires 3.7+
```

## Contributing

1. Follow existing code style
2. Add tests for new features
3. Update documentation
4. Run linters before commit

## License

MIT License - See LICENSE file

## Contact & Support

For issues, questions, or contributions, please open an issue in the repository.

---

**LLM Security Framework** - Making AI systems safer through intelligent code analysis.
