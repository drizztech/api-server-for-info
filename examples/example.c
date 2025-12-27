#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../llm_security.h"

int main() {
    printf("=== LLM Security Framework - C Example ===\n\n");
    
    /* Hook a process */
    printf("[1] Hooking process...\n");
    hooked_process_t *proc = proc_hook(1234, "example_app");
    if (!proc) {
        fprintf(stderr, "Failed to hook process\n");
        return 1;
    }
    printf("✓ Process hooked: PID %u, Base: 0x%llx\n\n", proc->pid, 
           (unsigned long long)proc->base_address);
    
    /* Register memory locations */
    printf("[2] Registering memory locations...\n");
    memory_location_t *loc1 = mem_register_location(0x400000, 4096, 0x5, "main");
    memory_location_t *loc2 = mem_register_location(0x401000, 8192, 0x3, "malloc");
    printf("✓ Registered: 0x400000 (main), 0x401000 (malloc)\n\n");
    
    /* Register function signatures */
    printf("[3] Registering function signatures...\n");
    function_signature_t *main_func = func_register("main", 0x400000, 512, 2);
    function_signature_t *malloc_func = func_register("malloc", 0x401000, 128, 1);
    printf("✓ Registered: main() at 0x400000, malloc() at 0x401000\n\n");
    
    /* Find function by name */
    printf("[4] Finding function by name...\n");
    function_signature_t *found = func_find_by_name("malloc");
    if (found) {
        printf("✓ Found: %s at 0x%llx (size: %zu)\n\n", found->name,
               (unsigned long long)found->address, found->size);
    }
    
    /* Find memory location by address */
    printf("[5] Finding memory location by address...\n");
    memory_location_t *mem = mem_find_by_address(0x400500);
    if (mem) {
        printf("✓ Found: 0x%llx (size: %zu, function: %s)\n\n",
               (unsigned long long)mem->address, mem->size, mem->function_name);
    }
    
    /* Pattern matching */
    printf("[6] Pattern matching in memory...\n");
    uint8_t pattern[] = {0x55, 0x48, 0x89};  /* push rbp; mov rsp,rbp */
    size_t matches = 0;
    uint64_t result = mem_find_pattern(0x400000, 4096, pattern, sizeof(pattern), &matches);
    printf("✓ Found %zu pattern matches, first at 0x%llx\n\n",
           matches, (unsigned long long)result);
    
    /* List hooked processes */
    printf("[7] Listing hooked processes...\n");
    hooked_process_t *procs[128] = {NULL};
    size_t count = 0;
    proc_list_hooked(procs, &count);
    printf("✓ %zu processes hooked\n", count);
    for (size_t i = 0; i < count && i < 128; i++) {
        if (procs[i]) {
            printf("  - PID %u: %s\n", procs[i]->pid, procs[i]->process_name);
        }
    }
    printf("\n");
    
    /* Cleanup */
    printf("[8] Cleaning up...\n");
    mem_free_location(loc1);
    mem_free_location(loc2);
    func_free_signature(main_func);
    func_free_signature(malloc_func);
    proc_unhook(proc);
    printf("✓ All resources freed\n\n");
    
    printf("=== Example completed successfully ===\n");
    return 0;
}
