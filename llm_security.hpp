#ifndef LLM_SECURITY_HPP
#define LLM_SECURITY_HPP

#include "llm_security.h"
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <stdexcept>

namespace llm_security {

class MemoryLocation {
public:
    uint64_t address;
    size_t size;
    uint32_t permissions;
    std::string function_name;
    
    MemoryLocation(uint64_t addr, size_t sz, uint32_t perms, const std::string &fname = "")
        : address(addr), size(sz), permissions(perms), function_name(fname) {}
};

class FunctionSignature {
public:
    std::string name;
    uint64_t address;
    size_t size;
    std::vector<std::string> parameters;
    std::string return_type;
    
    FunctionSignature(const std::string &n, uint64_t addr, size_t sz)
        : name(n), address(addr), size(sz), return_type("void") {}
    
    void add_parameter(const std::string &param) {
        parameters.push_back(param);
    }
};

class SecurityIssue {
public:
    enum class Type {
        Injection,
        BufferOverflow,
        UseAfterFree,
        MemoryLeak,
        RaceCondition,
        PathTraversal,
        UnvalidatedInput,
        LogicError
    };
    
    enum class Severity {
        Critical,
        High,
        Medium,
        Low,
        Info
    };
    
    Type type;
    Severity severity;
    uint32_t line_number;
    std::string code_snippet;
    std::string description;
    std::string remediation;
    float confidence;
    
    SecurityIssue(Type t, Severity s, uint32_t line, const std::string &snippet,
                  const std::string &desc, const std::string &rem, float conf = 0.8f)
        : type(t), severity(s), line_number(line), code_snippet(snippet),
          description(desc), remediation(rem), confidence(conf) {}
};

class BinaryAnalyzer {
private:
    std::map<uint64_t, MemoryLocation> memory_map;
    std::map<std::string, FunctionSignature> functions;
    std::map<uint32_t, std::string> hooked_processes;
    
public:
    BinaryAnalyzer() = default;
    ~BinaryAnalyzer() = default;
    
    MemoryLocation *register_memory(uint64_t address, size_t size, 
                                    uint32_t permissions, const std::string &fname = "") {
        memory_map[address] = MemoryLocation(address, size, permissions, fname);
        return &memory_map[address];
    }
    
    FunctionSignature *register_function(const std::string &name, uint64_t address, size_t size) {
        functions[name] = FunctionSignature(name, address, size);
        return &functions[name];
    }
    
    bool hook_process(uint32_t pid, const std::string &process_name) {
        hooked_processes[pid] = process_name;
        return proc_hook(pid, process_name.c_str()) != nullptr;
    }
    
    bool unhook_process(uint32_t pid) {
        hooked_process_t *proc = proc_get_hooked(pid);
        if (proc) {
            proc_unhook(proc);
            hooked_processes.erase(pid);
            return true;
        }
        return false;
    }
    
    bool is_hooked(uint32_t pid) const {
        return hooked_processes.find(pid) != hooked_processes.end();
    }
    
    FunctionSignature *find_function(const std::string &name) {
        auto it = functions.find(name);
        if (it != functions.end()) {
            return &it->second;
        }
        return nullptr;
    }
    
    FunctionSignature *find_function_by_address(uint64_t address) {
        for (auto &pair : functions) {
            if (pair.second.address <= address && 
                address < (pair.second.address + pair.second.size)) {
                return &pair.second;
            }
        }
        return nullptr;
    }
    
    std::vector<std::string> list_hooked() const {
        std::vector<std::string> result;
        for (const auto &pair : hooked_processes) {
            result.push_back(pair.second + " (PID: " + std::to_string(pair.first) + ")");
        }
        return result;
    }
};

class SecurityAnalyzer {
private:
    std::vector<SecurityIssue> issues;
    
public:
    SecurityAnalyzer() = default;
    ~SecurityAnalyzer() = default;
    
    void analyze_code(const std::string &code, const std::string &filename = "unknown") {
        issues.clear();
        
        // Fast pattern matching
        std::vector<std::string> patterns = {
            "eval(", "exec(", "__import__", "pickle.loads",
            "strcpy(", "gets(", "sprintf(",
            "system(", "popen("
        };
        
        size_t line = 1;
        size_t pos = 0;
        
        for (size_t i = 0; i < code.length(); ++i) {
            if (code[i] == '\n') {
                line++;
                continue;
            }
            
            for (const auto &pattern : patterns) {
                if (code.substr(i, pattern.length()) == pattern) {
                    SecurityIssue issue(
                        SecurityIssue::Type::Injection,
                        SecurityIssue::Severity::High,
                        line,
                        pattern,
                        "Dangerous function detected: " + pattern,
                        "Use safe alternatives and validate inputs",
                        0.85f
                    );
                    issues.push_back(issue);
                }
            }
        }
    }
    
    const std::vector<SecurityIssue> &get_issues() const {
        return issues;
    }
    
    float calculate_risk_score() const {
        float score = 0.0f;
        
        for (const auto &issue : issues) {
            float severity_weight = 0.0f;
            switch (issue.severity) {
                case SecurityIssue::Severity::Critical: severity_weight = 25.0f; break;
                case SecurityIssue::Severity::High: severity_weight = 15.0f; break;
                case SecurityIssue::Severity::Medium: severity_weight = 8.0f; break;
                case SecurityIssue::Severity::Low: severity_weight = 3.0f; break;
                case SecurityIssue::Severity::Info: severity_weight = 1.0f; break;
            }
            score += severity_weight * issue.confidence;
        }
        
        return (score > 100.0f) ? 100.0f : score;
    }
    
    void print_report() const {
        if (issues.empty()) {
            printf("No security issues found.\n");
            return;
        }
        
        printf("Security Analysis Report\n");
        printf("========================\n");
        printf("Total issues: %zu\n\n", issues.size());
        
        for (const auto &issue : issues) {
            printf("Line %u: %s\n", issue.line_number, issue.description.c_str());
            printf("  Code: %s\n", issue.code_snippet.c_str());
            printf("  Fix:  %s\n\n", issue.remediation.c_str());
        }
        
        printf("Risk Score: %.1f/100\n", calculate_risk_score());
    }
};

class FastPatternMatcher {
public:
    struct Pattern {
        std::vector<uint8_t> bytes;
        std::vector<uint8_t> mask;
    };
    
    static Pattern create_pattern(const std::string &pattern_str, const std::string &mask_str = "") {
        Pattern p;
        for (size_t i = 0; i < pattern_str.length(); i += 2) {
            p.bytes.push_back(static_cast<uint8_t>(std::stoi(pattern_str.substr(i, 2), nullptr, 16)));
            if (i / 2 < mask_str.length()) {
                p.mask.push_back(mask_str[i / 2] == '?' ? 0 : 1);
            } else {
                p.mask.push_back(1);
            }
        }
        return p;
    }
    
    static std::vector<uint64_t> find_pattern(const uint8_t *haystack, size_t haystack_len,
                                             const Pattern &pattern) {
        std::vector<uint64_t> matches;
        
        for (size_t i = 0; i <= haystack_len - pattern.bytes.size(); ++i) {
            bool match = true;
            for (size_t j = 0; j < pattern.bytes.size(); ++j) {
                if (pattern.mask[j] && haystack[i + j] != pattern.bytes[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                matches.push_back(reinterpret_cast<uint64_t>(haystack + i));
            }
        }
        
        return matches;
    }
};

}  // namespace llm_security

#endif  // LLM_SECURITY_HPP
