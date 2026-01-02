# CLAUDE.md - AI Assistant Guide for White Fatalis Framework

> Comprehensive guide for AI assistants working with this multi-language security and AI orchestration framework

## Project Overview

This repository contains **White Fatalis Framework** - a sophisticated multi-agent AI security testing platform that combines:

1. **AI Orchestration Server** (`index.js`) - Multi-agent coordination using Ollama Kimi K2 Thinking + Google Gemini 2.0 Flash
2. **Bug Bounty Automation Framework** (`main_agent.py`) - Autonomous security testing with AI-driven decision making
3. **LLM Security Analysis Framework** (`llm_security_core.py`) - Production-grade vulnerability detection for Python/C/C++/TypeScript
4. **High-Performance Proxy** (`rust-mcp-server/`) - Rust-based SOCKS/HTTP proxy with packet capture
5. **Web Scraper** (`main.go`) - Rate-limited Go scraper for reconnaissance

**Project Purpose**: Autonomous bug bounty hunting and security analysis using multiple AI models for reasoning, planning, and execution.

**Key Statistics**:
- 3,700+ lines of code across 7 languages
- 3 integrated AI models (Kimi K2, Gemini 2.0, Gemini 1.5 Pro)
- 10+ vulnerability types detected
- Multi-language support (Python, JavaScript, Rust, Go, C/C++, TypeScript)

## Codebase Structure

```
/home/user/api-server-for-info/
├── Core AI Components
│   ├── index.js                # AI Orchestration Server (Node.js, 620 lines)
│   ├── main_agent.py           # White Fatalis Main Agent (Flask, 87 lines)
│   ├── brain.py                # AI Decision Engine (Gemini 1.5 Pro, 99 lines)
│   ├── knowledge_base.py       # SQLite data persistence (101 lines)
│   └── config.py               # Tool paths and configuration (50 lines)
│
├── Security Analysis Framework
│   ├── llm_security_core.py    # Python security analyzer (580+ lines)
│   ├── llm_security.c          # C implementation (480+ lines)
│   ├── llm_security.h          # C API header (160+ lines)
│   ├── llm_security.hpp        # C++ wrapper (240+ lines)
│   ├── llm_security.ts         # TypeScript bindings (500+ lines)
│   ├── llm_security_cli.py     # CLI tool (360+ lines)
│   └── test_llm_security.py    # Comprehensive test suite (350+ lines)
│
├── Agent Tools Framework
│   └── tools/
│       ├── base_agent.py       # Abstract base class for all agents
│       └── nmap_agent.py       # Nmap wrapper implementation
│
├── Infrastructure Tools
│   ├── rust-mcp-server/        # Rust MCP server & proxy
│   │   └── src/
│   │       ├── main.rs         # CLI entry point (140 lines)
│   │       ├── proxy.rs        # SOCKS4/5/HTTP proxy (265 lines)
│   │       └── wifi.rs         # WiFi auto-connect utility
│   ├── main.go                 # Go web scraper (207 lines)
│   └── ip_server.py            # IP display utility (37 lines)
│
├── Documentation
│   ├── README.md               # Main readme
│   ├── CLAUDE.md               # This file (AI assistant guide)
│   ├── GEMINI.md               # Gemini integration guide
│   ├── QUICKSTART.md           # Quick start guide
│   ├── LLM_SECURITY_README.md  # Security framework docs
│   ├── LLM_SECURITY_SUMMARY.md # Security framework overview
│   └── LLM_SECURITY_INDEX.md   # File index
│
├── Web Frontend
│   └── public/
│       └── index.html          # Dashboard (29KB)
│
├── Examples & Tests
│   ├── examples/               # C/C++ example code
│   │   ├── example.c
│   │   └── example.cpp
│   └── tests/
│       └── test_main.py        # Agent unit tests
│
└── Build Configuration
    ├── package.json            # Node.js dependencies
    ├── requirements.txt        # Python dependencies
    ├── Cargo.toml              # Rust dependencies (in rust-mcp-server/)
    ├── go.mod                  # Go module definition
    ├── CMakeLists.txt          # C/C++ build configuration
    └── .gitignore              # Git ignore rules
```

## Technology Stack

### Languages & Versions
- **Python 3.7+**: Core AI agents, security analysis, CLI tools
- **Node.js 18+**: AI orchestration server, Express backend
- **Rust (2021 edition)**: High-performance proxy and MCP server
- **Go 1.x**: Web scraper with rate limiting
- **C99/C++11**: Security library implementation
- **TypeScript**: Type-safe bindings for security framework

### Key Dependencies

**Node.js** (`package.json`):
```json
{
  "express": "^4.21.2",           // Web server framework
  "axios": "^1.6.2",              // HTTP client
  "@google/generative-ai": "^0.11.1",  // Gemini SDK
  "dotenv": "^16.3.1"             // Environment variables
}
```

**Python** (`requirements.txt`):
```
flask              # Web framework for agents
google-generativeai  # Gemini AI SDK
requests           # HTTP client
pydantic           # Data validation
```

**Rust** (`rust-mcp-server/Cargo.toml`):
```toml
rmcp = { version = "0.10.0", features = ["server"] }
tokio = { version = "1.0", features = ["full"] }
anyhow = "1.0"
serde_json = "1.0"
clap = "4.0"
pcap-file = "2.0"
```

### AI Models Configuration
- **Ollama Kimi K2 Thinking** (`kimi-k2-thinking:cloud`) - Deep reasoning and analysis
- **Google Gemini 2.0 Flash** (`gemini-2.0-flash`) - Fast action generation
- **Google Gemini 1.5 Pro** (`gemini-1.5-pro`) - Strategic planning in brain.py

## Development Workflows

### Initial Setup

```bash
# 1. Clone repository (if needed)
git clone <repository-url>
cd api-server-for-info

# 2. Set up Node.js application
npm install

# 3. Set up Python environment
pip install -r requirements.txt

# 4. Configure environment variables
cat > .env << EOF
GEMINI_API_KEY=your_gemini_api_key_here
OLLAMA_BASE_URL=http://localhost:11434
MCP_SERVER_URL=http://localhost:3001
PORT=3000
DATA_DIR=./data
EOF

# 5. Build Rust components (optional)
cd rust-mcp-server
cargo build --release
cd ..

# 6. Build C/C++ library (optional)
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
cd ..
```

### Running Services

**Start AI Orchestration Server**:
```bash
# Development mode (with auto-reload)
npm run dev

# Production mode
npm start
# Server runs on http://localhost:3000
```

**Start White Fatalis Agent**:
```bash
python3 main_agent.py
# Agent runs on http://localhost:5000
```

**Start Rust Proxy**:
```bash
cd rust-mcp-server
cargo run -- proxy -P 8080
# Proxy runs on 127.0.0.1:8080
```

**Run Web Scraper**:
```bash
go run main.go https://example.com
```

### Git Workflow

**Current Branch**: `claude/add-claude-documentation-WAnxr`

**Branching Strategy**:
- Main development on feature branches starting with `claude/`
- Always include session ID suffix for authentication
- Never push to branches without proper naming convention

**Common Git Operations**:
```bash
# Check current status
git status

# Create and switch to feature branch
git checkout -b claude/feature-name-<session-id>

# Stage changes
git add <files>

# Commit with descriptive message
git commit -m "feat: Add new feature description"

# Push to remote (CRITICAL: use -u flag)
git push -u origin claude/feature-name-<session-id>

# Pull latest changes
git pull origin <branch-name>
```

**Commit Message Conventions**:
- `feat:` - New features
- `fix:` - Bug fixes
- `docs:` - Documentation changes
- `refactor:` - Code refactoring
- `test:` - Test additions/changes
- `chore:` - Build process or auxiliary tool changes

### Testing

**Run Python Tests**:
```bash
# Unit tests for agents
python3 -m unittest tests/test_main.py

# LLM Security framework tests (10 comprehensive tests)
python3 test_llm_security.py
```

**Manual API Testing**:
```bash
# Health check
curl http://localhost:3000/api/health

# Test orchestration
curl -X POST http://localhost:3000/api/orchestrate \
  -H "Content-Type: application/json" \
  -d '{"request": "analyze security of example.com", "automation": false}'

# Start security mission
curl -X POST http://localhost:5000/mission \
  -H "Content-Type: application/json" \
  -d '{"target": "127.0.0.1", "goal": "Find vulnerabilities"}'

# Check mission status
curl http://localhost:5000/mission/1
```

**Security CLI Testing**:
```bash
# Analyze Python file
python3 llm_security_cli.py analyze path/to/file.py

# Analyze directory
python3 llm_security_cli.py analyze-dir /path/to/project

# Hook process
python3 llm_security_cli.py hook-process 1234 process_name
```

### Building Components

**Build C/C++ Library**:
```bash
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_EXAMPLES=ON ..
make -j$(nproc)
sudo make install  # Optional: install system-wide
./example_c        # Run C example
./example_cpp      # Run C++ example
cd ..
```

**Build Rust Binary**:
```bash
cd rust-mcp-server
cargo build --release
# Binary: target/release/rust-mcp-tool
cargo run -- server  # Start MCP server
cd ..
```

**Build Go Scraper**:
```bash
go build -o webscraper main.go
./webscraper https://example.com
```

## Code Patterns & Conventions

### Architectural Patterns

**1. Agent Pattern** (Polymorphic tool execution)
```python
# Location: tools/base_agent.py, tools/nmap_agent.py
class BaseAgent:
    """Abstract base class for all security tool agents"""
    def run(self, params):
        raise NotImplementedError("Subclasses must implement run()")

class NmapAgent(BaseAgent):
    """Concrete implementation for Nmap scanning"""
    def run(self, params):
        # Execute nmap command
        # Return structured results
```

**When to use**: Creating new security tool integrations (nuclei, gobuster, ffuf, etc.)

**2. Orchestrator Pattern** (Multi-agent coordination)
```javascript
// Location: index.js:140-220
class AIOrchestrator {
    async orchestrate(request, automation) {
        // Stage 1: Deep thinking with Ollama Kimi
        const analysis = await this.thinkDeep(request);

        // Stage 2: Tool selection with Gemini
        const tools = await this.analyzeTools(analysis);

        // Stage 3: Execute automation
        if (automation) {
            await this.executeTools(tools);
        }

        // Stage 4: Synthesize results
        return await this.synthesize(results);
    }
}
```

**When to use**: Coordinating multiple AI models or agents for complex tasks

**3. Brain-Agent Pattern** (AI decision making)
```python
# Location: brain.py, main_agent.py
# Brain generates plans, Agents execute them
def execute_mission(target, goal):
    # 1. Brain analyzes and plans
    plan = brain.think(context=scan_results, goal=goal)

    # 2. Execute plan steps
    for step in plan['steps']:
        agent = get_agent(step['tool'])
        result = agent.run(step['params'])

    # 3. Brain learns from results
    brain.learn(finding)
```

**When to use**: Autonomous workflows requiring AI-driven decision making

**4. Data Manager Pattern** (Centralized data handling)
```javascript
// Location: index.js:430-520
class DataManager {
    saveApiRequest(request, response) { /* ... */ }
    getApiStats() { /* ... */ }
    recordToolMetric(tool, success, duration) { /* ... */ }
    getToolGrowthAnalytics(days) { /* ... */ }
}
```

**When to use**: Managing metrics, analytics, or persistent data

### Naming Conventions

**Python**:
- Functions/variables: `snake_case` (e.g., `execute_plan`, `api_key`)
- Classes: `PascalCase` (e.g., `NmapAgent`, `KnowledgeBase`)
- Constants: `UPPER_SNAKE_CASE` (e.g., `TOOL_PATHS`, `DB_FILE`)
- Private methods: `_leading_underscore` (e.g., `_sanitize_input`)

**JavaScript/Node.js**:
- Functions/variables: `camelCase` (e.g., `orchestrateRequest`, `dataManager`)
- Classes: `PascalCase` (e.g., `AIOrchestrator`, `DataManager`)
- Constants: `UPPER_SNAKE_CASE` (e.g., `GEMINI_API_KEY`, `PORT`)
- Prefer arrow functions: `const func = () => {}`
- Always use async/await for asynchronous operations

**Rust**:
- Functions/variables: `snake_case` (e.g., `start_proxy`, `packet_count`)
- Types/Structs: `PascalCase` (e.g., `ProxyServer`, `WifiConfig`)
- Use `Result<T, E>` for error handling
- Async functions with Tokio runtime

**C/C++**:
- C functions: `snake_case` (e.g., `llm_security_analyze`)
- C++ classes: `PascalCase` (e.g., `LLMSecurityAnalyzer`)
- Macros: `UPPER_SNAKE_CASE` (e.g., `MAX_BUFFER_SIZE`)
- Use namespaces in C++ (e.g., `llm_security::Analyzer`)

### Error Handling Patterns

**Python - Try/Except with Logging**:
```python
try:
    result = api_call()
except Exception as e:
    logger.error(f"API call failed: {e}")
    return {"success": False, "error": str(e)}
```

**JavaScript - Async/Await with Try/Catch**:
```javascript
try {
    const result = await operation();
    return { success: true, data: result };
} catch (error) {
    console.error('Operation failed:', error.message);
    return { success: false, error: error.message };
}
```

**Rust - Result Type**:
```rust
async fn operation() -> Result<Data, Error> {
    let value = fallible_operation()?;
    Ok(value)
}
```

**Go - Explicit Error Checking**:
```go
result, err := operation()
if err != nil {
    log.Printf("Operation failed: %v", err)
    return err
}
```

### Security Best Practices

**1. Never Hardcode Secrets**:
```javascript
// GOOD: Use environment variables
const apiKey = process.env.GEMINI_API_KEY;

// BAD: Hardcoded secret
const apiKey = "AIzaSy...";
```

**2. SQL Parameterization**:
```python
# GOOD: Parameterized query
cursor.execute("INSERT INTO findings VALUES (?, ?, ?)", (id, target, data))

# BAD: String concatenation (SQL injection)
cursor.execute(f"INSERT INTO findings VALUES ({id}, '{target}', '{data}')")
```

**3. Input Validation**:
```javascript
// Validate all user inputs
if (!request || typeof request !== 'string' || request.length > 10000) {
    return { error: 'Invalid request' };
}
```

**4. Timeout Protection**:
```python
# Always set timeouts for subprocess calls
subprocess.run(cmd, timeout=300, capture_output=True)
```

**5. Rate Limiting**:
```go
// Implement rate limiting for external requests
limiter := rate.NewLimiter(5, 10)  // 5 req/sec, burst of 10
limiter.Wait(context.Background())
```

## Key Modules Deep Dive

### Module 1: AI Orchestration Server (`index.js`)

**Purpose**: Coordinates between Ollama (thinking) and Gemini (action) for complex AI workflows.

**Key Functions**:
- `POST /api/orchestrate` - Main orchestration endpoint (index.js:250)
- `POST /api/think` - Ollama thinking (index.js:280)
- `POST /api/generate` - Gemini generation (index.js:310)
- `POST /api/execute-tool` - MCP tool execution (index.js:340)

**Data Flow**:
```
User Request → Ollama (Deep Thinking) → Gemini (Tool Analysis) →
MCP Tools (Execution) → Gemini (Synthesis) → Response
```

**When to modify**:
- Adding new AI models
- Implementing new orchestration patterns
- Changing conversation history management
- Adding analytics/metrics

### Module 2: White Fatalis Agent (`main_agent.py`, `brain.py`)

**Purpose**: Autonomous bug bounty hunting with AI-driven planning.

**Key Components**:
- `POST /mission` - Start new security mission (main_agent.py:40)
- `GET /mission/<id>` - Check mission status (main_agent.py:60)
- `brain.think()` - Generate execution plan (brain.py:30)
- `brain.learn()` - Learn from findings (brain.py:60)

**Data Flow**:
```
Mission Request → Brain Planning → Tool Execution →
Results → Knowledge Base → Brain Learning → Mission Complete
```

**Database Schema** (white_fatalis.db):
```sql
CREATE TABLE findings (id, timestamp, target, type, severity, details);
CREATE TABLE knowledge (id, timestamp, summary, source);
CREATE TABLE missions (id, start_time, status, target, goal);
```

**When to modify**:
- Adding new security tools (create new agent in tools/)
- Changing AI planning logic
- Modifying knowledge retention
- Adding new mission types

### Module 3: LLM Security Framework (`llm_security_core.py`)

**Purpose**: Production-grade vulnerability detection for multiple languages.

**Key Classes**:
- `LLMSecurityAnalyzer` - Main analyzer (llm_security_core.py:50)
- `BinaryAnalyzer` - Process hooking (llm_security_core.py:300)
- `SourceCodeValidator` - Multi-language validation (llm_security_core.py:450)

**Supported Vulnerability Types**:
1. Command Injection (`eval`, `exec`, `subprocess`)
2. SQL Injection (`execute`, string concatenation)
3. Path Traversal (`../`, `..\\`)
4. XSS (`innerHTML`, `document.write`)
5. Buffer Overflow (C: `strcpy`, `gets`, `sprintf`)
6. Memory Leaks (missing `free()`, `delete`)
7. Use After Free (pointer usage after free)
8. Integer Overflow (unchecked arithmetic)
9. Unsafe Deserialization (`pickle.loads`, `eval`)
10. Hardcoded Secrets (API keys, passwords in code)

**Usage**:
```python
from llm_security_core import LLMSecurityAnalyzer

analyzer = LLMSecurityAnalyzer()
issues = analyzer.analyze_code(source_code, language="python")
report = analyzer.generate_report()
```

**When to modify**:
- Adding new vulnerability patterns
- Supporting new languages
- Changing risk scoring algorithm
- Adding new analysis modes

### Module 4: Rust Proxy (`rust-mcp-server/src/proxy.rs`)

**Purpose**: High-performance SOCKS4/5 and HTTP proxy with packet capture.

**Key Features**:
- SOCKS4/SOCKS5/HTTP proxy support
- Packet capture to PCAP files
- Async tunneling with Tokio
- Connection tracking and metrics

**Usage**:
```bash
cargo run -- proxy -P 8080 -o capture.pcap
```

**When to modify**:
- Adding proxy authentication
- Implementing request/response modification
- Adding custom routing rules
- Enhancing packet analysis

### Module 5: Knowledge Base (`knowledge_base.py`)

**Purpose**: Persistent storage for findings, knowledge, and missions.

**Key Methods**:
- `add_finding(target, type, severity, details)` - Store vulnerability
- `get_all_findings(target=None)` - Retrieve findings
- `log_knowledge(summary, source)` - Store AI-generated insights
- `create_mission(target, goal)` - Create new mission
- `update_mission_status(id, status)` - Update mission state

**When to modify**:
- Adding new data tables
- Implementing data export features
- Adding search/filter capabilities
- Changing schema

## Common Tasks Guide

### Task 1: Add a New Security Tool Agent

**Steps**:
1. Create new agent class in `tools/` directory:
```python
# tools/nuclei_agent.py
from tools.base_agent import BaseAgent
import subprocess
import json

class NucleiAgent(BaseAgent):
    def __init__(self):
        super().__init__("nuclei", "/path/to/nuclei")

    def run(self, params):
        """Run Nuclei vulnerability scan"""
        target = params.get("target")
        templates = params.get("templates", "all")

        cmd = [self.tool_path, "-u", target, "-json"]
        if templates != "all":
            cmd.extend(["-t", templates])

        try:
            result = subprocess.run(cmd, timeout=300, capture_output=True)
            # Parse JSON output
            findings = [json.loads(line) for line in result.stdout.decode().splitlines()]
            return {"success": True, "findings": findings}
        except Exception as e:
            return {"success": False, "error": str(e)}
```

2. Register tool in `config.py`:
```python
TOOL_PATHS = {
    "nmap": "/usr/bin/nmap",
    "nuclei": "~/go/bin/nuclei",  # Add this line
}
```

3. Add tool import in `main_agent.py`:
```python
from tools.nuclei_agent import NucleiAgent

AVAILABLE_AGENTS = {
    "nmap": NmapAgent(),
    "nuclei": NucleiAgent(),  # Add this line
}
```

4. Test the agent:
```python
# tests/test_nuclei_agent.py
import unittest
from tools.nuclei_agent import NucleiAgent

class TestNucleiAgent(unittest.TestCase):
    def test_initialization(self):
        agent = NucleiAgent()
        self.assertEqual(agent.name, "nuclei")
```

### Task 2: Add New Vulnerability Pattern to LLM Security

**Steps**:
1. Add pattern to `llm_security_core.py`:
```python
# In LLMSecurityAnalyzer class, add to analyze_code() method
patterns = {
    # ... existing patterns ...
    "xxe": r"(parse|parseString|XMLParser)\s*\([^)]*\)",  # XML External Entity
}

# Add checker function
def check_xxe(self, code, language):
    """Detect XML External Entity (XXE) vulnerabilities"""
    if language not in ["python", "java"]:
        return []

    issues = []
    for match in re.finditer(self.patterns["xxe"], code):
        # Check if external entity processing is disabled
        if "resolve_entities=False" not in code:
            issues.append({
                "type": "XXE Vulnerability",
                "severity": "high",
                "line": code[:match.start()].count('\n') + 1,
                "code": match.group(),
                "description": "XML parser may be vulnerable to XXE attacks"
            })
    return issues
```

2. Add to vulnerability checkers list:
```python
def analyze_code(self, code, language="python"):
    all_issues = []
    all_issues.extend(self.check_command_injection(code, language))
    all_issues.extend(self.check_sql_injection(code, language))
    # ... existing checks ...
    all_issues.extend(self.check_xxe(code, language))  # Add this
    return all_issues
```

3. Add test case:
```python
# test_llm_security.py
def test_xxe_detection():
    analyzer = LLMSecurityAnalyzer()
    code = "tree = etree.parse(user_input)"  # Vulnerable
    issues = analyzer.analyze_code(code, "python")
    assert any(issue["type"] == "XXE Vulnerability" for issue in issues)
```

### Task 3: Add New API Endpoint to Orchestrator

**Steps**:
1. Add endpoint handler in `index.js`:
```javascript
// Add after existing endpoints (around line 400)
app.post('/api/custom-workflow', async (req, res) => {
    try {
        const { input, options } = req.body;

        // Validate input
        if (!input || typeof input !== 'string') {
            return res.status(400).json({
                error: 'Invalid input parameter'
            });
        }

        // Process workflow
        const result = await processCustomWorkflow(input, options);

        // Save metrics
        dataManager.recordToolMetric('custom-workflow', true, Date.now());

        res.json({ success: true, result });
    } catch (error) {
        console.error('Custom workflow error:', error);
        dataManager.recordToolMetric('custom-workflow', false, Date.now());
        res.status(500).json({
            error: 'Workflow failed',
            message: error.message
        });
    }
});

async function processCustomWorkflow(input, options) {
    // Implementation
    const thinking = await ollamaClient.thinkDeep(input);
    const action = await geminiClient.generate(thinking);
    return { thinking, action };
}
```

2. Update health check (optional):
```javascript
app.get('/api/health', async (req, res) => {
    // ... existing checks ...
    checks.customWorkflow = 'enabled';  // Add this
    res.json({ status: 'ok', checks, timestamp: new Date() });
});
```

3. Test endpoint:
```bash
curl -X POST http://localhost:3000/api/custom-workflow \
  -H "Content-Type: application/json" \
  -d '{"input": "test", "options": {}}'
```

### Task 4: Modify Brain AI Logic

**Steps**:
1. Update planning logic in `brain.py`:
```python
def think(self, context, goal):
    """Generate strategic plan based on context and goal"""

    # Prepare enhanced prompt
    prompt = f"""
    You are an expert security researcher. Given:

    Context: {context}
    Goal: {goal}

    Generate a detailed execution plan with:
    1. Reconnaissance steps
    2. Vulnerability scanning
    3. Exploitation strategy
    4. Reporting format

    Return JSON with: {{"steps": [...], "priority": "high|medium|low"}}
    """

    try:
        model = genai.GenerativeModel("gemini-1.5-pro")
        response = model.generate_content(prompt)
        plan = json.loads(response.text)

        # Add your custom logic here
        plan = self._enhance_plan(plan, context)

        return plan
    except Exception as e:
        logger.error(f"Brain thinking failed: {e}")
        return self._fallback_plan(goal)

def _enhance_plan(self, plan, context):
    """Add custom enhancement logic"""
    # Add timing estimates
    for step in plan['steps']:
        step['estimated_duration'] = self._estimate_duration(step['tool'])
    return plan
```

2. Update learning function:
```python
def learn(self, finding):
    """Learn from security findings"""
    prompt = f"""
    Analyze this security finding and provide insights:

    Finding: {finding}

    Provide:
    1. Root cause analysis
    2. Similar vulnerability patterns
    3. Remediation strategy
    4. Future prevention tips
    """

    try:
        model = genai.GenerativeModel("gemini-1.5-pro")
        response = model.generate_content(prompt)
        insights = response.text

        # Store in knowledge base
        self.kb.log_knowledge(insights, f"Finding: {finding['type']}")

        return insights
    except Exception as e:
        logger.error(f"Brain learning failed: {e}")
        return "Learning failed"
```

### Task 5: Add Data Export Feature

**Steps**:
1. Add export method to `knowledge_base.py`:
```python
def export_findings_json(self, output_file):
    """Export all findings to JSON file"""
    findings = self.get_all_findings()

    export_data = {
        "export_timestamp": datetime.now().isoformat(),
        "total_findings": len(findings),
        "findings": findings
    }

    with open(output_file, 'w') as f:
        json.dump(export_data, f, indent=2)

    return output_file

def export_findings_csv(self, output_file):
    """Export findings to CSV file"""
    import csv

    findings = self.get_all_findings()

    with open(output_file, 'w', newline='') as f:
        if not findings:
            return output_file

        writer = csv.DictWriter(f, fieldnames=findings[0].keys())
        writer.writeheader()
        writer.writerows(findings)

    return output_file
```

2. Add API endpoint in `main_agent.py`:
```python
@app.route("/export/<format>", methods=["GET"])
def export_data(format):
    """Export findings in specified format"""
    try:
        if format == "json":
            file = kb.export_findings_json("findings_export.json")
        elif format == "csv":
            file = kb.export_findings_csv("findings_export.csv")
        else:
            return jsonify({"error": "Unsupported format"}), 400

        return send_file(file, as_attachment=True)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
```

## Important Gotchas & Tips

### Critical Issues to Avoid

**1. Git Push Authentication**
```bash
# CRITICAL: Always use branch naming convention
# CORRECT: claude/feature-name-<session-id>
git push -u origin claude/add-feature-WAnxr

# WRONG: Will fail with 403
git push origin main
git push origin feature-branch
```

**2. API Key Management**
```bash
# NEVER commit .env file
# ALWAYS check before commit:
git status | grep .env
# If .env is staged, unstage it:
git reset .env
```

**3. Database Locking**
```python
# ALWAYS use context managers with SQLite
with sqlite3.connect(DB_FILE) as conn:
    cursor = conn.cursor()
    # ... operations ...
# Connection auto-closes, prevents locking
```

**4. Subprocess Timeouts**
```python
# ALWAYS set timeouts to prevent hanging
subprocess.run(cmd, timeout=300)  # 5 minutes max

# Handle timeout exceptions
try:
    subprocess.run(cmd, timeout=300)
except subprocess.TimeoutExpired:
    # Handle timeout
```

**5. Async/Await in JavaScript**
```javascript
// ALWAYS await async operations
// CORRECT:
const result = await asyncOperation();

// WRONG: Will not work as expected
const result = asyncOperation();  // Returns Promise, not value
```

### Performance Optimization Tips

**1. Batch Database Operations**:
```python
# Instead of multiple inserts:
for item in items:
    kb.add_finding(item)  # Slow

# Use batch insert:
cursor.executemany("INSERT INTO findings VALUES (?, ?)", items)
```

**2. Parallel Tool Execution**:
```python
# Use threading for parallel agent execution
from concurrent.futures import ThreadPoolExecutor

with ThreadPoolExecutor(max_workers=3) as executor:
    futures = [executor.submit(agent.run, params) for agent in agents]
    results = [f.result() for f in futures]
```

**3. Cache AI Responses**:
```python
# Cache expensive AI calls
from functools import lru_cache

@lru_cache(maxsize=128)
def get_ai_analysis(code_hash):
    return model.generate_content(code)
```

### Debugging Tips

**1. Enable Verbose Logging**:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
logger.debug("Detailed debug info")
```

**2. Inspect Database**:
```bash
sqlite3 white_fatalis.db
> SELECT * FROM findings;
> SELECT * FROM missions;
> .schema findings
> .quit
```

**3. Monitor API Metrics**:
```bash
# Check analytics files
cat data/api-requests.jsonl | jq .
cat data/tool-metrics.jsonl | jq .
cat data/project-progress.json | jq .
```

**4. Test Individual Components**:
```python
# Test agent independently
from tools.nmap_agent import NmapAgent
agent = NmapAgent()
result = agent.run({"target": "127.0.0.1"})
print(result)
```

### Environment-Specific Notes

**Development Environment**:
- Use `npm run dev` for auto-reload
- Set `NODE_ENV=development`
- Enable verbose logging
- Use mock API keys for testing

**Production Environment**:
- Use `npm start` or process manager (PM2)
- Set `NODE_ENV=production`
- Disable debug logging
- Use real API keys from secure storage
- Set up monitoring and alerting

### File Locations Quick Reference

**Configuration**:
- Environment: `.env` (root)
- Tool paths: `config.py`
- Node packages: `package.json`
- Python deps: `requirements.txt`

**Data Storage**:
- Database: `white_fatalis.db`
- Analytics: `data/api-requests.jsonl`
- Metrics: `data/tool-metrics.jsonl`
- Progress: `data/project-progress.json`

**Logs**:
- Node.js: stdout/stderr
- Python: stdout/stderr
- Agent logs: Check Flask output on port 5000

**Documentation**:
- This guide: `CLAUDE.md`
- Security framework: `LLM_SECURITY_README.md`
- Quick start: `QUICKSTART.md`
- Gemini setup: `GEMINI.md`

## Security Considerations

### Sensitive Operations

**1. Never Log Secrets**:
```python
# WRONG:
logger.info(f"API Key: {api_key}")

# CORRECT:
logger.info("API Key loaded successfully")
```

**2. Validate All Inputs**:
```python
def validate_target(target):
    """Validate target before scanning"""
    # Check for private IPs if needed
    # Validate format
    # Check against whitelist/blacklist
    if not re.match(r'^[a-zA-Z0-9.-]+$', target):
        raise ValueError("Invalid target format")
```

**3. Sandbox Tool Execution**:
```python
# Consider using subprocess with restricted permissions
import subprocess
subprocess.run(cmd, timeout=300,
               user='nobody',  # Run as unprivileged user
               cwd='/tmp')     # Restrict working directory
```

**4. Rate Limit API Calls**:
```python
from time import sleep

def rate_limited_call(func, calls_per_minute=60):
    sleep(60 / calls_per_minute)
    return func()
```

### Code Review Checklist

Before committing, verify:
- [ ] No hardcoded API keys or secrets
- [ ] All subprocess calls have timeouts
- [ ] All database queries use parameterization
- [ ] All user inputs are validated
- [ ] Error messages don't leak sensitive info
- [ ] All file operations use safe paths (no path traversal)
- [ ] All AI prompts are sanitized
- [ ] Logging doesn't expose secrets
- [ ] Dependencies are up to date
- [ ] Tests pass successfully

## Additional Resources

**External Documentation**:
- [Google Gemini API](https://ai.google.dev/docs)
- [Ollama Documentation](https://ollama.ai/docs)
- [MCP Protocol Spec](https://modelcontextprotocol.io/)
- [Flask Documentation](https://flask.palletsprojects.com/)
- [Express.js Guide](https://expressjs.com/en/guide/)
- [Tokio Async Runtime](https://tokio.rs/)

**Related Files**:
- `LLM_SECURITY_README.md` - Complete security framework documentation
- `GEMINI.md` - Gemini AI integration guide
- `QUICKSTART.md` - Quick start guide for new users

**Useful Commands**:
```bash
# Monitor logs in real-time
tail -f /path/to/log | grep ERROR

# Check API health
watch -n 5 'curl -s http://localhost:3000/api/health | jq .'

# Monitor database size
watch -n 10 'ls -lh white_fatalis.db'

# Check running processes
ps aux | grep -E '(node|python3|rust-mcp)'

# Monitor network connections
netstat -tlnp | grep -E '(3000|5000|8080)'
```

---

**Last Updated**: 2026-01-02
**Version**: 1.0.0
**Maintained By**: drizztech

For questions or issues with this guide, create an issue in the repository.
