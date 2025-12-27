#ifndef LLM_SECURITY_H
#define LLM_SECURITY_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
   Memory Analysis and Process Hooking
   ============================================================================ */

typedef struct {
    uint64_t address;
    size_t size;
    uint32_t permissions;  /* RWX flags */
    char function_name[256];
    unsigned char hash[32];  /* SHA256 */
} memory_location_t;

typedef struct {
    char name[128];
    uint64_t address;
    size_t size;
    uint32_t num_params;
    char *param_types[16];
    char return_type[64];
} function_signature_t;

typedef struct {
    uint32_t pid;
    char process_name[256];
    uint64_t base_address;
    memory_location_t *memory_regions;
    size_t num_regions;
    function_signature_t *functions;
    size_t num_functions;
} hooked_process_t;

/* Memory analysis functions */
memory_location_t *mem_register_location(uint64_t address, size_t size, 
                                          uint32_t permissions, const char *func_name);
void mem_free_location(memory_location_t *loc);
memory_location_t *mem_find_by_address(uint64_t address);
uint64_t mem_find_pattern(uint64_t base, size_t size, const uint8_t *pattern, 
                           size_t pattern_size, size_t *matches);

/* Process hooking functions */
hooked_process_t *proc_hook(uint32_t pid, const char *process_name);
void proc_unhook(hooked_process_t *proc);
hooked_process_t *proc_get_hooked(uint32_t pid);
bool proc_is_hooked(uint32_t pid);
void proc_list_hooked(hooked_process_t **procs, size_t *count);

/* Function discovery */
function_signature_t *func_find_by_name(const char *name);
function_signature_t *func_find_by_address(uint64_t address);
function_signature_t *func_register(const char *name, uint64_t address, 
                                    size_t size, uint32_t num_params);
void func_free_signature(function_signature_t *sig);
void func_analyze_calls(function_signature_t *func, function_signature_t **called_funcs,
                        size_t *count);

/* Binary analysis */
typedef struct {
    uint64_t offset;
    uint64_t vaddr;
    size_t size;
    char name[64];
    uint32_t flags;
} binary_section_t;

typedef struct {
    char filename[512];
    binary_section_t *sections;
    size_t num_sections;
    uint8_t *mapped_image;
    size_t image_size;
} binary_info_t;

binary_info_t *bin_load(const char *filename);
void bin_free(binary_info_t *bin);
binary_section_t *bin_get_section(binary_info_t *bin, const char *name);
uint64_t bin_get_export_address(binary_info_t *bin, const char *export_name);
void bin_find_imports(binary_info_t *bin, char **imports, size_t *count);

/* ============================================================================
   Security Analysis
   ============================================================================ */

typedef enum {
    SEC_CRITICAL = 0,
    SEC_HIGH = 1,
    SEC_MEDIUM = 2,
    SEC_LOW = 3,
    SEC_INFO = 4
} severity_level_t;

typedef enum {
    VULN_INJECTION = 0,
    VULN_BUFFER_OVERFLOW = 1,
    VULN_USE_AFTER_FREE = 2,
    VULN_MEMORY_LEAK = 3,
    VULN_RACE_CONDITION = 4,
    VULN_PATH_TRAVERSAL = 5,
    VULN_UNVALIDATED_INPUT = 6,
    VULN_LOGIC_ERROR = 7
} vulnerability_type_t;

typedef struct {
    vulnerability_type_t type;
    severity_level_t severity;
    uint32_t line_number;
    char code_snippet[512];
    char description[256];
    char remediation[512];
    float confidence;
} security_issue_t;

/* Security analysis functions */
security_issue_t *sec_analyze_code(const char *code, size_t code_len, 
                                    const char *filename, size_t *issue_count);
void sec_free_issues(security_issue_t *issues);
float sec_calculate_risk_score(security_issue_t *issues, size_t count);
void sec_print_report(security_issue_t *issues, size_t count);

/* ============================================================================
   Fast Pattern Matching for Binary Analysis
   ============================================================================ */

typedef struct {
    uint8_t *pattern;
    size_t pattern_len;
    uint8_t *mask;
} match_pattern_t;

uint64_t *pattern_find_all(const uint8_t *haystack, size_t haystack_len,
                           const match_pattern_t *pattern, size_t *match_count);
void pattern_free_matches(uint64_t *matches);

/* ============================================================================
   Debugging and Introspection
   ============================================================================ */

typedef struct {
    uint64_t address;
    uint64_t size;
    char symbol_name[256];
    char source_file[512];
    uint32_t line_number;
} debug_symbol_t;

debug_symbol_t *dbg_get_symbol_at(uint64_t address);
void dbg_print_stack_trace(hooked_process_t *proc, void *context);
void dbg_dump_memory_region(uint64_t address, size_t size);
char *dbg_disassemble(const uint8_t *code, size_t len, uint64_t base_address);

/* ============================================================================
   Utility Functions
   ============================================================================ */

void *safe_malloc(size_t size);
void safe_free(void *ptr);
void secure_memzero(void *ptr, size_t size);
uint8_t *calculate_sha256(const uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* LLM_SECURITY_H */
