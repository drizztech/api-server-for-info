#include <iostream>
#include <iomanip>
#include "../llm_security.hpp"

using namespace llm_security;
using namespace std;

int main() {
    cout << "=== LLM Security Framework - C++ Example ===" << endl << endl;
    
    /* Security Analysis */
    cout << "[1] Analyzing code for security issues..." << endl;
    SecurityAnalyzer analyzer;
    
    string vulnerable_code = R"(
import pickle
def load_user_data(filename):
    with open(filename, 'rb') as f:
        data = pickle.loads(f.read())  // UNSAFE!
    return data

password = "hardcoded_secret_12345"
user_input = input("Enter query: ")
eval(user_input)  // CRITICAL!
)";
    
    analyzer.analyzeCode(vulnerable_code, "vulnerable.py");
    auto issues = analyzer.getIssues();
    
    cout << "✓ Found " << issues.size() << " security issues" << endl << endl;
    
    /* Binary Analysis */
    cout << "[2] Binary and memory analysis..." << endl;
    BinaryAnalyzer binary;
    
    binary.register_memory(0x400000, 4096, "rx", "main");
    binary.register_memory(0x601000, 8192, "rw", "heap");
    cout << "✓ Registered memory regions" << endl << endl;
    
    /* Function Signatures */
    cout << "[3] Function signature registration..." << endl;
    auto main_func = binary.register_function("main", 0x400000, 512);
    main_func->add_parameter("int argc");
    main_func->add_parameter("char** argv");
    
    auto malloc_func = binary.register_function("malloc", 0x401000, 256);
    malloc_func->add_parameter("size_t size");
    
    cout << "✓ Registered function signatures" << endl << endl;
    
    /* Process Hooking */
    cout << "[4] Process hooking..." << endl;
    if (binary.hook_process(1234, "example_app", 0x400000)) {
        cout << "✓ Process 1234 hooked" << endl;
    }
    
    if (binary.hook_process(5678, "test_service", 0x400000)) {
        cout << "✓ Process 5678 hooked" << endl << endl;
    }
    
    /* Function Lookup */
    cout << "[5] Looking up functions..." << endl;
    auto found = binary.find_function("malloc");
    if (found) {
        cout << "✓ Found function: " << found->name 
             << " at 0x" << hex << found->address << dec << endl << endl;
    }
    
    /* Risk Assessment */
    cout << "[6] Risk assessment..." << endl;
    float risk = analyzer.calculateRiskScore();
    cout << "✓ Overall risk score: " << fixed << setprecision(1) << risk << "/100" << endl;
    
    if (risk >= 70) {
        cout << "  WARNING: High security risk detected!" << endl;
    } else if (risk >= 40) {
        cout << "  CAUTION: Medium security risk detected" << endl;
    } else {
        cout << "  GOOD: Low security risk" << endl;
    }
    cout << endl;
    
    /* Pattern Matching */
    cout << "[7] Fast pattern matching..." << endl;
    uint8_t data[] = {0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x10};
    FastPatternMatcher::Pattern pattern = FastPatternMatcher::create_pattern("5548");
    
    cout << "✓ Pattern matching initialized" << endl << endl;
    
    /* List hooked processes */
    cout << "[8] Active hooked processes:" << endl;
    auto hooked = binary.list_hooked();
    for (const auto &proc : hooked) {
        cout << "  - " << proc.name << " (PID: " << proc.pid << ")" << endl;
    }
    cout << endl;
    
    /* Generate security report */
    cout << "[9] Security report:" << endl;
    analyzer.print_report();
    
    cout << "=== C++ Example completed ===" << endl;
    return 0;
}
