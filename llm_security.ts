/**
 * LLM Security Framework - TypeScript Bindings
 * Fast, intelligent security analysis and binary inspection
 */

export enum SecurityLevel {
    CRITICAL = 'CRITICAL',
    HIGH = 'HIGH',
    MEDIUM = 'MEDIUM',
    LOW = 'LOW',
    INFO = 'INFO',
}

export enum VulnerabilityType {
    INJECTION = 'injection',
    BUFFER_OVERFLOW = 'buffer_overflow',
    USE_AFTER_FREE = 'use_after_free',
    MEMORY_LEAK = 'memory_leak',
    RACE_CONDITION = 'race_condition',
    PATH_TRAVERSAL = 'path_traversal',
    UNVALIDATED_INPUT = 'unvalidated_input',
    LOGIC_ERROR = 'logic_error',
    HARDCODED_SECRETS = 'hardcoded_secrets',
    XSS = 'cross_site_scripting',
}

export interface SecurityIssue {
    vulnerability_type: VulnerabilityType;
    severity: SecurityLevel;
    line_number: number;
    code_snippet: string;
    description: string;
    remediation: string;
    confidence: number;
}

export interface MemoryLocation {
    address: number;
    size: number;
    permission: string;
    function_name?: string;
    hash?: string;
}

export interface FunctionSignature {
    name: string;
    address: number;
    size: number;
    parameters: string[];
    return_type: string;
    referenced_functions: string[];
    memory_operations: string[];
}

export interface HookedProcess {
    pid: number;
    name: string;
    base_address: string;
    hook_time: string;
    memory_regions: MemoryLocation[];
    functions: FunctionSignature[];
}

export interface SecurityReport {
    total_issues: number;
    critical_count: number;
    high_count: number;
    issues_by_severity: Record<SecurityLevel, SecurityIssue[]>;
    risk_score: number;
}

/**
 * LLM Security Analyzer - Core security analysis engine
 */
export class SecurityAnalyzer {
    private issues: SecurityIssue[] = [];
    private patterns: Map<VulnerabilityType, RegExp[]> = new Map();

    constructor() {
        this.initPatterns();
    }

    private initPatterns(): void {
        this.patterns.set(VulnerabilityType.HARDCODED_SECRETS, [
            /(?:api[_-]?key|password|secret|token)\s*=\s*["']([^"']+)["']/gi,
            /(?:AWS|AZURE|GCP)_KEY\s*=\s*["']([^"']+)["']/gi,
        ]);

        this.patterns.set(VulnerabilityType.INJECTION, [
            /eval\s*\(/g,
            /exec\s*\(/g,
            /__import__\s*\(/g,
            /pickle\.loads/g,
        ]);

        this.patterns.set(VulnerabilityType.UNVALIDATED_INPUT, [
            /(?:user_input|request\.args|request\.form|sys\.argv)\[/g,
            /input\s*\(/g,
        ]);

        this.patterns.set(VulnerabilityType.PATH_TRAVERSAL, [
            /open\s*\(\s*["']?\.\.\/[^)]*\)/g,
            /os\.path\.join.*\.\./g,
        ]);

        this.patterns.set(VulnerabilityType.XSS, [
            /innerHTML\s*=/g,
            /document\.write\s*\(/g,
            /eval\s*\(/g,
        ]);
    }

    analyzeCode(code: string, filename: string = 'unknown'): SecurityIssue[] {
        this.issues = [];
        const lines = code.split('\n');

        // Pattern-based detection
        for (let lineNum = 0; lineNum < lines.length; lineNum++) {
            const line = lines[lineNum];

            for (const [vulnType, patterns] of this.patterns) {
                for (const pattern of patterns) {
                    if (pattern.test(line)) {
                        const issue: SecurityIssue = {
                            vulnerability_type: vulnType,
                            severity: this.determineSeverity(vulnType),
                            line_number: lineNum + 1,
                            code_snippet: line.trim(),
                            description: `Potential ${vulnType} detected`,
                            remediation: this.getRemediation(vulnType),
                            confidence: 0.8,
                        };
                        this.issues.push(issue);
                        pattern.lastIndex = 0;  // Reset regex
                    }
                }
            }
        }

        return this.issues;
    }

    private determineSeverity(vulnType: VulnerabilityType): SecurityLevel {
        const critical = [
            VulnerabilityType.INJECTION,
            VulnerabilityType.BUFFER_OVERFLOW,
        ];
        const high = [
            VulnerabilityType.HARDCODED_SECRETS,
            VulnerabilityType.PATH_TRAVERSAL,
        ];
        const medium = [
            VulnerabilityType.UNVALIDATED_INPUT,
            VulnerabilityType.XSS,
        ];

        if (critical.includes(vulnType)) return SecurityLevel.CRITICAL;
        if (high.includes(vulnType)) return SecurityLevel.HIGH;
        if (medium.includes(vulnType)) return SecurityLevel.MEDIUM;
        return SecurityLevel.LOW;
    }

    private getRemediation(vulnType: VulnerabilityType): string {
        const remediations: Record<VulnerabilityType, string> = {
            [VulnerabilityType.INJECTION]: 'Never use eval/exec on user input. Use safe parsing libraries.',
            [VulnerabilityType.HARDCODED_SECRETS]: 'Move secrets to environment variables or secure vaults.',
            [VulnerabilityType.UNVALIDATED_INPUT]: 'Validate and sanitize all user inputs before use.',
            [VulnerabilityType.PATH_TRAVERSAL]: 'Use path resolution functions to validate file paths.',
            [VulnerabilityType.BUFFER_OVERFLOW]: 'Use bounds checking and safe string functions.',
            [VulnerabilityType.USE_AFTER_FREE]: 'Track object lifetimes, use safe memory management.',
            [VulnerabilityType.MEMORY_LEAK]: 'Ensure proper cleanup of allocated resources.',
            [VulnerabilityType.RACE_CONDITION]: 'Use locks/mutexes for shared resource access.',
            [VulnerabilityType.LOGIC_ERROR]: 'Review logic carefully and add comprehensive tests.',
            [VulnerabilityType.XSS]: 'Sanitize all user input, use textContent instead of innerHTML.',
        };
        return remediations[vulnType] || 'Review this code section for security issues.';
    }

    getIssues(): SecurityIssue[] {
        return this.issues;
    }

    calculateRiskScore(): number {
        if (this.issues.length === 0) return 0;

        const severityWeights: Record<SecurityLevel, number> = {
            [SecurityLevel.CRITICAL]: 25,
            [SecurityLevel.HIGH]: 15,
            [SecurityLevel.MEDIUM]: 8,
            [SecurityLevel.LOW]: 3,
            [SecurityLevel.INFO]: 1,
        };

        let totalScore = this.issues.reduce((sum, issue) => {
            return sum + (severityWeights[issue.severity] * issue.confidence);
        }, 0);

        return Math.min(100, totalScore);
    }

    generateReport(): SecurityReport {
        const issuesBySeverity: Record<SecurityLevel, SecurityIssue[]> = {
            [SecurityLevel.CRITICAL]: [],
            [SecurityLevel.HIGH]: [],
            [SecurityLevel.MEDIUM]: [],
            [SecurityLevel.LOW]: [],
            [SecurityLevel.INFO]: [],
        };

        for (const issue of this.issues) {
            issuesBySeverity[issue.severity].push(issue);
        }

        return {
            total_issues: this.issues.length,
            critical_count: issuesBySeverity[SecurityLevel.CRITICAL].length,
            high_count: issuesBySeverity[SecurityLevel.HIGH].length,
            issues_by_severity: issuesBySeverity,
            risk_score: this.calculateRiskScore(),
        };
    }
}

/**
 * Binary Analyzer - Memory and process inspection
 */
export class BinaryAnalyzer {
    private memoryMap: Map<number, MemoryLocation> = new Map();
    private functionSignatures: Map<string, FunctionSignature> = new Map();
    private hookedProcesses: Map<number, HookedProcess> = new Map();

    registerMemoryLocation(
        address: number,
        size: number,
        permission: string,
        functionName?: string
    ): MemoryLocation {
        const location: MemoryLocation = {
            address,
            size,
            permission,
            function_name: functionName,
            hash: this.sha256Hash(`${address}:${size}`),
        };
        this.memoryMap.set(address, location);
        return location;
    }

    registerFunction(
        name: string,
        address: number,
        size: number,
        parameters: string[] = [],
        returnType: string = 'void'
    ): FunctionSignature {
        const sig: FunctionSignature = {
            name,
            address,
            size,
            parameters,
            return_type: returnType,
            referenced_functions: [],
            memory_operations: [],
        };
        this.functionSignatures.set(name, sig);
        return sig;
    }

    hookProcess(pid: number, processName: string, baseAddress: number): HookedProcess {
        const hookInfo: HookedProcess = {
            pid,
            name: processName,
            base_address: `0x${baseAddress.toString(16)}`,
            hook_time: new Date().toISOString(),
            memory_regions: [],
            functions: [],
        };
        this.hookedProcesses.set(pid, hookInfo);
        return hookInfo;
    }

    unhookProcess(pid: number): boolean {
        return this.hookedProcesses.delete(pid);
    }

    isProcessHooked(pid: number): boolean {
        return this.hookedProcesses.has(pid);
    }

    getHookedProcess(pid: number): HookedProcess | undefined {
        return this.hookedProcesses.get(pid);
    }

    listHookedProcesses(): HookedProcess[] {
        return Array.from(this.hookedProcesses.values());
    }

    findFunction(name: string): FunctionSignature | undefined {
        return this.functionSignatures.get(name);
    }

    findFunctionByAddress(address: number): FunctionSignature | undefined {
        for (const sig of this.functionSignatures.values()) {
            if (sig.address <= address && address < sig.address + sig.size) {
                return sig;
            }
        }
        return undefined;
    }

    findMemoryLocation(address: number): MemoryLocation | undefined {
        for (const loc of this.memoryMap.values()) {
            if (loc.address <= address && address < loc.address + loc.size) {
                return loc;
            }
        }
        return undefined;
    }

    private sha256Hash(data: string): string {
        // Simple hash simulation (in production, use crypto.subtle)
        let hash = 0;
        for (let i = 0; i < data.length; i++) {
            const char = data.charCodeAt(i);
            hash = (hash << 5) - hash + char;
            hash = hash & hash;
        }
        return Math.abs(hash).toString(16);
    }
}

/**
 * Fast Pattern Matcher for binary analysis
 */
export class FastPatternMatcher {
    static createPattern(
        patternHex: string,
        maskStr: string = ''
    ): { bytes: number[]; mask: number[] } {
        const bytes: number[] = [];
        const mask: number[] = [];

        for (let i = 0; i < patternHex.length; i += 2) {
            bytes.push(parseInt(patternHex.substr(i, 2), 16));
            mask.push(maskStr[i / 2] === '?' ? 0 : 1);
        }

        return { bytes, mask };
    }

    static findPattern(
        haystack: ArrayBuffer,
        pattern: { bytes: number[]; mask: number[] }
    ): number[] {
        const matches: number[] = [];
        const data = new Uint8Array(haystack);

        for (let i = 0; i <= data.length - pattern.bytes.length; i++) {
            let match = true;
            for (let j = 0; j < pattern.bytes.length; j++) {
                if (pattern.mask[j] && data[i + j] !== pattern.bytes[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                matches.push(i);
            }
        }

        return matches;
    }
}

/**
 * Integrated LLM Security Framework
 */
export class LLMSecurityFramework {
    private securityAnalyzer: SecurityAnalyzer;
    private binaryAnalyzer: BinaryAnalyzer;

    constructor() {
        this.securityAnalyzer = new SecurityAnalyzer();
        this.binaryAnalyzer = new BinaryAnalyzer();
    }

    analyzeSourceCode(code: string, language: 'python' | 'typescript' | 'c' = 'python'): SecurityReport {
        this.securityAnalyzer.analyzeCode(code);
        return this.securityAnalyzer.generateReport();
    }

    hookProcess(pid: number, name: string, baseAddress: number): HookedProcess {
        return this.binaryAnalyzer.hookProcess(pid, name, baseAddress);
    }

    findFunctionInProcess(pid: number, functionName: string): FunctionSignature | undefined {
        const func = this.binaryAnalyzer.findFunction(functionName);
        if (func && this.binaryAnalyzer.isProcessHooked(pid)) {
            return func;
        }
        return undefined;
    }

    getSecurityAnalyzer(): SecurityAnalyzer {
        return this.securityAnalyzer;
    }

    getBinaryAnalyzer(): BinaryAnalyzer {
        return this.binaryAnalyzer;
    }
}

export default LLMSecurityFramework;
