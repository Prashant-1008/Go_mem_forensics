# CLAUDE.md

# GoMemForensics
## Automated Go Malware Memory Forensics and Runtime Artifact Analysis

---

## 1. PROJECT MISSION

You are working on **GoMemForensics**, a defensive digital-forensics and malware-analysis framework designed to analyze Windows and Linux memory images and identify, reconstruct, correlate, and report artifacts associated with Go-based executables, including potentially malicious Go programs.

The objective is to transform the research concepts described in the reference paper:

> "Memory Forensics Techniques for Automated Detection and Analysis of Go Malware"

into a practical, reproducible, investigator-oriented forensic tool.

This is a **DFIR / malware-analysis project**.

The software must operate on acquired memory images and must not modify the original evidence.

The project must prioritize:

1. Forensic correctness
2. Evidence provenance
3. Reproducibility
4. Deterministic behavior
5. Transparent confidence levels
6. Testability
7. Clear separation between recovered evidence and analytical interpretation
8. Cross-platform memory-image support
9. Architecture-aware implementation
10. Investigator-friendly reporting

---

# 2. PRIMARY REFERENCE

The repository contains the research paper:

```text
reference/Memory Forensics Techniques for Automated Detection and Analysis of Go Malware.pdf
```

This paper is the **primary technical reference** for implementing the research-derived functionality.

Before implementing the core Go runtime analysis functionality:

1. Read the paper.
2. Understand its methodology.
3. Identify its data structures and analysis workflow.
4. Identify the functionality represented by:
   - go_strings
   - go_functions
   - go_goroutines
5. Identify its limitations.
6. Identify which functionality can be directly reproduced.
7. Clearly distinguish paper-derived functionality from engineering additions.

Do NOT claim that a capability is supported merely because it sounds theoretically possible.

Every significant implementation decision should be classified as one of:

### A. Paper-derived

Functionality explicitly described or demonstrated by the paper.

### B. Engineering addition

Functionality added to make the research usable as a practical forensic tool.

### C. Experimental

Functionality whose correctness is not yet sufficiently validated.

### D. Future work

Functionality intentionally not implemented yet.

Do not silently convert an experimental feature into a production claim.

---

# 3. CORE PAPER-DERIVED FUNCTIONALITY

The project should aim to implement the following research concepts.

## 3.1 Go runtime identification

Identify candidate Go processes and recover relevant Go runtime structures.

Important structures include, where applicable:

- pclntab
- pcHeader
- moduledata
- ftab
- funcnametab
- filetab
- pctab
- typelinks
- itablinks
- Go type metadata
- interface metadata

The implementation must account for differences between Go versions where possible.

Do not hard-code one Go version.

---

# 4. GO STRING FORENSICS

Implement a Go-aware string recovery subsystem.

The goal is not merely to run the equivalent of:

```text
strings memory.raw
```

Instead, reconstruct Go string objects using Go runtime information and memory structures.

For every recovered string, preserve:

- process ID
- virtual address
- backing-data address where available
- string length
- string value
- memory region
- heap/static classification
- source classification where recoverable
- confidence
- extraction method

Example conceptual output:

```json
{
  "pid": 1234,
  "string_address": "0x12345678",
  "data_address": "0x12345000",
  "length": 42,
  "value": "example string",
  "region": "heap",
  "classification": "runtime",
  "confidence": "high"
}
```

Never alter recovered strings.

Do not silently concatenate adjacent memory data and call the result a Go string.

---

# 5. GO FUNCTION FORENSICS

Implement recovery and classification of Go functions using available runtime metadata.

Where possible recover:

- function address
- function name
- source file
- package
- module
- function boundaries
- function origin
- relevant runtime metadata

Support classification such as:

```text
runtime
standard library
third-party module
application
unknown
```

The classification must be evidence-based.

Do not infer maliciousness from a package name alone.

Where appropriate, use Capstone for architecture-specific disassembly.

---

# 6. GOROUTINE FORENSICS

Implement Go goroutine discovery and analysis.

The implementation should investigate relevant runtime structures such as:

```text
runtime.allgs
```

Candidate goroutines must be validated structurally before being reported.

Where recoverable, extract:

- goroutine ID
- goroutine state
- wait reason
- stack information
- saved PC
- saved SP
- current function
- call stack
- relevant runtime arguments
- associated process
- evidence addresses

Stack reconstruction must be architecture-aware.

Do not report a memory region as a goroutine simply because it resembles a Go structure.

Use validation rules and confidence levels.

---

# 7. ARCHITECTURE STRATEGY

The architecture must NOT be designed as permanently x86-64-only.

The implementation priority is:

## Phase 1

```text
Windows x86-64
Linux x86-64
```

## Phase 2

```text
Linux ARM64
```

## Phase 3

```text
Windows ARM64
```

Potential future support:

```text
x86 / 32-bit
```

Use an architecture abstraction layer wherever architecture-specific behavior exists.

Do NOT scatter architecture-specific constants throughout the code.

Prefer structures such as:

```text
architecture/
    base.py
    x86_64.py
    arm64.py
```

Architecture-dependent functionality includes, but is not limited to:

- pointer size
- register names
- calling convention
- stack layout
- instruction decoding
- function argument recovery
- stack unwinding
- saved execution state

The x86-64 implementation should be the first complete implementation, but the APIs must permit ARM64 implementations later.

---

# 8. OPERATING SYSTEM STRATEGY

The project must support memory images from:

```text
Windows
Linux
```

Use Volatility 3 as the primary memory-forensics framework.

The project should integrate with Volatility rather than reimplementing operating-system memory parsing unnecessarily.

Potential input formats may include:

```text
.raw
.mem
.dmp
.lime
```

Actual support must depend on the underlying Volatility 3 capabilities.

Never claim a format is supported without testing it.

---

# 9. VOLATILITY 3 INTEGRATION

Use Volatility 3 as the forensic memory-analysis foundation.

The project may use relevant existing functionality such as:

```text
linux.pagecache
windows.dumpfiles
```

where appropriate.

The Go-specific functionality should be implemented as reusable Volatility-compatible components/plugins where practical.

The architecture should allow:

```text
Volatility Layer
        ↓
OS Process Layer
        ↓
Go Runtime Detection Layer
        ↓
Go Runtime Reconstruction Layer
        ↓
Artifact Extraction Layer
        ↓
Correlation Layer
        ↓
Reporting Layer
```

Avoid tightly coupling the entire project to one Volatility plugin.

---

# 10. HIGH-LEVEL SYSTEM ARCHITECTURE

Target architecture:

```text
                    +----------------------+
                    |   Memory Image       |
                    | Windows / Linux      |
                    +----------+-----------+
                               |
                               v
                    +----------------------+
                    | Evidence Validation  |
                    | Hash / Metadata       |
                    +----------+-----------+
                               |
                               v
                    +----------------------+
                    | Volatility 3 Layer   |
                    +----------+-----------+
                               |
                               v
                    +----------------------+
                    | Process Enumeration   |
                    +----------+-----------+
                               |
                               v
                    +----------------------+
                    | Go Process Detector   |
                    +----------+-----------+
                               |
                               v
                    +----------------------+
                    | Go Runtime Parser     |
                    | pclntab/moduledata    |
                    +----------+-----------+
                               |
              +----------------+----------------+
              |                |                |
              v                v                v
       +-------------+  +-------------+  +-------------+
       | Go Strings  |  | Go Functions|  | Goroutines  |
       +------+------+  +------+------+  +------+------+
              |                |                |
              +----------------+----------------+
                               |
                               v
                    +----------------------+
                    | Artifact Correlation |
                    +----------+-----------+
                               |
             +-----------------+------------------+
             |                 |                  |
             v                 v                  v
          Network          Credentials        Execution
          Artifacts        / Secrets          Artifacts
             |                 |                  |
             +-----------------+------------------+
                               |
                               v
                    +----------------------+
                    | IOC Extraction       |
                    +----------+-----------+
                               |
                               v
                    +----------------------+
                    | Findings / Confidence|
                    +----------+-----------+
                               |
                               v
                    +----------------------+
                    | Forensic Report      |
                    | JSON / HTML / PDF    |
                    +----------------------+
```

---

# 11. PROJECT DIRECTORY STRUCTURE

Use a maintainable structure similar to:

```text
GoMemForensics/
│
├── CLAUDE.md
├── README.md
├── LICENSE
├── pyproject.toml
├── requirements.txt
│
├── reference/
│   └── Memory Forensics Techniques for Automated Detection and Analysis of Go Malware.pdf
│
├── src/
│   └── gomemforensics/
│       ├── __init__.py
│       │
│       ├── cli/
│       │   ├── __init__.py
│       │   └── main.py
│       │
│       ├── acquisition/
│       │   ├── __init__.py
│       │   └── evidence.py
│       │
│       ├── volatility/
│       │   ├── __init__.py
│       │   ├── runner.py
│       │   └── integration.py
│       │
│       ├── os/
│       │   ├── __init__.py
│       │   ├── windows.py
│       │   └── linux.py
│       │
│       ├── architecture/
│       │   ├── __init__.py
│       │   ├── base.py
│       │   ├── x86_64.py
│       │   └── arm64.py
│       │
│       ├── go_runtime/
│       │   ├── __init__.py
│       │   ├── detector.py
│       │   ├── pclntab.py
│       │   ├── moduledata.py
│       │   ├── types.py
│       │   └── version.py
│       │
│       ├── analyzers/
│       │   ├── __init__.py
│       │   ├── strings.py
│       │   ├── functions.py
│       │   ├── goroutines.py
│       │   ├── network.py
│       │   ├── credentials.py
│       │   ├── crypto.py
│       │   └── persistence.py
│       │
│       ├── correlation/
│       │   ├── __init__.py
│       │   ├── engine.py
│       │   └── relationships.py
│       │
│       ├── detection/
│       │   ├── __init__.py
│       │   ├── indicators.py
│       │   ├── scoring.py
│       │   └── ioc.py
│       │
│       ├── reporting/
│       │   ├── __init__.py
│       │   ├── models.py
│       │   ├── json_report.py
│       │   ├── html_report.py
│       │   └── pdf_report.py
│       │
│       └── common/
│           ├── logging.py
│           ├── hashing.py
│           ├── memory.py
│           └── utils.py
│
├── plugins/
│   ├── go_strings.py
│   ├── go_functions.py
│   └── go_goroutines.py
│
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── regression/
│   └── fixtures/
│
├── docs/
│   ├── architecture.md
│   ├── forensic-methodology.md
│   ├── supported-platforms.md
│   └── validation.md
│
├── evidence/
│   └── README.md
│
├── reports/
│
└── scripts/
```

The structure may be improved during implementation if there is a clear technical reason.

Do not create unnecessary files merely to make the repository look large.

---

# 12. FORENSIC EVIDENCE HANDLING

This is a forensic tool.

Original evidence must be treated as read-only.

The software must never:

- modify the original memory image
- overwrite the input image
- modify evidence metadata
- alter recovered bytes
- silently normalize evidence
- silently discard ambiguous artifacts

Before analysis, calculate a cryptographic hash when feasible.

At minimum support:

```text
SHA-256
```

Record:

```text
case_id
input_path
file_size
SHA-256
analysis_timestamp
tool_version
Volatility version
OS
architecture
analysis configuration
```

The report must distinguish:

```text
Observed Evidence
```

from:

```text
Analytical Interpretation
```

and:

```text
Detection Heuristic
```

---

# 13. EVIDENCE PROVENANCE

Every significant artifact should preserve provenance.

For example:

```json
{
  "artifact_type": "go_string",
  "pid": 1337,
  "virtual_address": "0x7f123456",
  "memory_region": "heap",
  "value": "example.com",
  "source": "go_string_reconstruction",
  "confidence": "high"
}
```

Where available also preserve:

- physical address
- process
- virtual address
- module
- function
- source file
- extraction method
- analyzer version
- related artifacts

Do not generate an artifact without recording where it came from.

---

# 14. CONFIDENCE MODEL

The system must not present every result as equally certain.

Use explicit confidence:

```text
HIGH
MEDIUM
LOW
UNKNOWN
```

Confidence must be based on technical evidence.

Example:

A string recovered from a validated Go string header:

```text
HIGH
```

A suspicious ASCII sequence found through generic memory scanning:

```text
LOW
```

Do not use a numerical "malware score" unless the scoring methodology is explicitly documented and validated.

Avoid pretending that heuristic scores are forensic facts.

---

# 15. ARTIFACT CORRELATION

The correlation engine should connect artifacts rather than simply producing large lists.

Example:

```text
PID 1420
   │
   ├── Go runtime
   │
   ├── Function: main.connectC2
   │
   ├── String: 192.168.1.10:443
   │
   ├── Goroutine: 17
   │
   ├── Stack frame: main.connectC2
   │
   └── Network artifact: TCP connection
```

Possible relationships:

```text
process → Go runtime
process → function
process → goroutine
function → string
function → network artifact
goroutine → function
goroutine → argument
process → persistence artifact
process → credential artifact
```

The purpose is to help an investigator understand the evidence.

---

# 16. IOC EXTRACTION

Where supported by evidence, identify:

- IPv4 addresses
- IPv6 addresses
- domains
- URLs
- ports
- email addresses
- file paths
- registry paths
- mutex-like strings
- cryptocurrency addresses
- hashes
- user agents
- HTTP paths
- TLS-related artifacts

Do not automatically classify every IP/domain as malicious.

Use neutral labels such as:

```text
Observed IP
Observed Domain
Observed URL
Potential C2 Indicator
Potential Persistence Artifact
```

Any stronger classification must be supported by evidence or an explicitly documented heuristic.

---

# 17. NETWORK ARTIFACT ANALYSIS

Search recovered runtime memory for network-related artifacts.

Potential evidence includes:

- IP addresses
- domain names
- hostnames
- ports
- URLs
- HTTP request paths
- HTTP methods
- request buffers
- response buffers
- TLS state
- certificate information
- connection metadata

Runtime-constructed artifacts are especially important because they may not appear as simple static strings.

The implementation must distinguish:

```text
static artifact
```

from:

```text
runtime-generated artifact
```

when technically possible.

---

# 18. CREDENTIAL / SECRET DETECTION

The tool may identify potential:

- usernames
- passwords
- API keys
- tokens
- authentication headers
- configuration values
- private keys
- cryptographic keys

However:

Do not expose secrets unnecessarily in logs.

Provide configurable redaction.

Example:

```text
full value:
[redacted in console]

report:
SHA-256: ...
location: ...
length: ...
```

Allow investigators to explicitly request full values when appropriate.

---

# 19. CRYPTOGRAPHIC ARTIFACT DETECTION

Identify potential cryptographic material where supported.

Examples:

- public keys
- private keys
- symmetric keys
- certificate material
- cryptographic configuration
- algorithm names

Do not automatically claim that arbitrary random bytes are cryptographic keys.

Use contextual evidence.

---

# 20. MALWARE CLASSIFICATION

The tool is an evidence extraction and analysis platform.

It should NOT claim:

```text
"This process is definitely malware."
```

based only on one heuristic.

Prefer:

```text
Potentially suspicious Go process
```

and explain why.

Findings should contain:

```text
Finding
Evidence
Source
Address
Confidence
Interpretation
```

Example:

```text
Finding:
Potential C2 configuration

Evidence:
Runtime-reconstructed string containing an IP:port

Process:
PID 1337

Address:
0x7f123456

Confidence:
Medium

Interpretation:
The artifact may represent a network endpoint used by the process.
```

---

# 21. CLI DESIGN

The initial CLI should support something similar to:

```bash
gomemforensics analyze memory.raw
```

Example options:

```bash
gomemforensics analyze memory.raw \
    --output reports/case001 \
    --format html,json
```

Potential commands:

```bash
gomemforensics analyze
gomemforensics info
gomemforensics validate
gomemforensics report
gomemforensics version
```

The CLI should provide useful progress information without flooding the terminal.

Example:

```text
[+] Evidence validated
[+] SHA-256 calculated
[+] Operating system: Windows
[+] Architecture: x86-64
[+] Processes discovered: 184
[+] Candidate Go processes: 3
[+] Go runtimes reconstructed: 2
[+] Strings recovered: 1,247
[+] Functions recovered: 8,932
[+] Goroutines recovered: 76
[+] Network artifacts: 21
[+] Potentially suspicious artifacts: 8
[+] Report generated
```

---

# 22. MACHINE-READABLE OUTPUT

JSON is a first-class output format.

The JSON schema should be stable and documented.

Suggested top-level structure:

```json
{
  "case": {},
  "evidence": {},
  "environment": {},
  "processes": [],
  "go_runtimes": [],
  "strings": [],
  "functions": [],
  "goroutines": [],
  "network_artifacts": [],
  "credentials": [],
  "crypto_artifacts": [],
  "persistence_artifacts": [],
  "iocs": [],
  "findings": [],
  "errors": [],
  "statistics": {}
}
```

Do not mix human-readable narrative into machine-readable fields unnecessarily.

---

# 23. FORENSIC REPORT

Generate an investigator-readable report.

Preferred structure:

```text
1. Case Information
2. Evidence Information
3. Analysis Environment
4. Memory Image Information
5. Operating System Information
6. Process Inventory
7. Go Process Identification
8. Go Runtime Analysis
9. Go String Analysis
10. Go Function Analysis
11. Goroutine Analysis
12. Network Artifacts
13. Potential C2 Indicators
14. Credential / Secret Artifacts
15. Cryptographic Artifacts
16. Persistence Artifacts
17. Correlated Findings
18. IOC Summary
19. Evidence Locations
20. Limitations
21. Tool Information
22. Conclusion
```

The report must clearly state limitations.

Do not hide failed analyzers.

Example:

```text
Goroutine analysis:
FAILED / NOT AVAILABLE

Reason:
Required runtime structure could not be reliably reconstructed.
```

This is preferable to silently producing incomplete output.

---

# 24. ERROR HANDLING

Memory forensics is inherently messy.

The tool must gracefully handle:

- corrupted images
- incomplete dumps
- paged-out memory
- inaccessible pages
- unsupported Go versions
- stripped binaries
- partially overwritten runtime structures
- invalid pointers
- architecture mismatch
- missing Volatility symbols
- unsupported OS versions

Never crash the entire analysis because one process or one artifact cannot be reconstructed.

Use:

```text
recover → record error → continue
```

where safe.

Errors must be included in the final report.

---

# 25. LOGGING

Use structured logging.

Support:

```text
quiet
normal
verbose
debug
```

Debug logs may include detailed addresses and parser information.

Normal logs should be suitable for investigators.

Do not print recovered passwords, tokens, private keys, or other sensitive values by default.

---

# 26. TESTING REQUIREMENTS

Every major component requires tests.

Minimum categories:

```text
Unit tests
Integration tests
Regression tests
Negative tests
```

Test:

- valid Go runtime structures
- invalid runtime structures
- corrupted structures
- incorrect pointers
- unsupported versions
- architecture mismatch
- empty memory regions
- partial memory
- false positives

A parser must not be considered reliable merely because it works on one sample.

---

# 27. TEST MATRIX

Target test matrix:

| OS | Architecture | Go |
|---|---|---|
| Windows | x86-64 | multiple versions |
| Linux | x86-64 | multiple versions |
| Linux | ARM64 | later phase |
| Windows | ARM64 | later phase |

Include both:

```text
clean Go applications
```

and:

```text
controlled malware-analysis samples
```

where legally and safely available.

Never make testing dependent on downloading unknown malware automatically.

---

# 28. PAPER REPRODUCTION TESTING

Where the paper provides concrete examples or expected artifact categories, attempt to reproduce them in a controlled environment.

Document:

```text
Paper expectation
Implementation result
Difference
Reason
```

Do not fabricate successful reproduction.

If the exact sample is unavailable, say so.

---

# 29. STATIC VS RUNTIME EVIDENCE

Always distinguish:

```text
Static evidence
```

from:

```text
Runtime evidence
```

Examples:

Static:

```text
function name
module path
compile-time string
```

Runtime:

```text
constructed HTTP request
runtime token
live goroutine state
runtime argument
active connection state
```

This distinction is important because the research motivation is specifically the recovery of runtime information that may not be visible through ordinary static analysis.

---

# 30. GO VERSION HANDLING

Go runtime structures change across versions.

Do not assume:

```text
one structure = all Go versions
```

Create version-aware definitions.

Prefer:

```text
GoVersionDetector
RuntimeLayout
ArchitectureLayout
```

Example conceptual design:

```python
layout = RuntimeLayout.for_version(
    go_version,
    architecture
)
```

If the version cannot be determined confidently:

```text
unknown
```

Do not guess.

---

# 31. MEMORY ACCESS ABSTRACTION

Create a clean memory-reader abstraction.

Example conceptual interface:

```python
read(address, length)
read_pointer(address)
is_valid(address)
read_string(address, length)
```

All memory access should pass through this abstraction where practical.

This makes the code:

- testable
- architecture-aware
- easier to adapt to Volatility
- easier to mock in unit tests

---

# 32. SECURITY REQUIREMENTS

This is defensive forensic software.

The tool must analyze evidence but must not:

- execute recovered malware
- execute recovered commands
- establish connections to recovered C2 infrastructure
- automatically contact recovered domains/IPs
- download payloads
- modify the evidence image

IOC enrichment, if added later, must be explicitly controlled and separated from core offline analysis.

Default mode should be:

```text
OFFLINE / PASSIVE
```

---

# 33. NO ACTIVE NETWORKING BY DEFAULT

If the memory image contains:

```text
example.com
192.0.2.10
```

the tool must not automatically connect to them.

The core forensic analysis should remain offline.

Any future enrichment system must require explicit investigator configuration.

---

# 34. REPRODUCIBILITY

A report should be reproducible as far as technically possible.

Record:

```text
Tool version
Git commit
Python version
Volatility version
OS
Architecture
Input hash
Configuration
Timestamp
Enabled analyzers
```

If possible, generate:

```text
analysis-manifest.json
```

---

# 35. DEVELOPMENT METHODOLOGY

Do NOT implement the entire project in one giant step.

Work incrementally.

Recommended sequence:

## Phase 0 — Repository foundation

Create:

- project structure
- Python packaging
- logging
- configuration
- CLI skeleton
- test framework
- documentation skeleton

No complex Go parsing yet.

---

## Phase 1 — Evidence and Volatility foundation

Implement:

- input validation
- SHA-256
- Volatility integration
- OS detection
- architecture detection
- process enumeration
- JSON output

Acceptance criterion:

```text
A Windows/Linux memory image can be opened and basic metadata/process information can be produced without modifying the image.
```

---

## Phase 2 — Go process detection

Implement:

- candidate Go process detection
- Go runtime identification
- pclntab detection
- moduledata detection
- Go version estimation

Acceptance criterion:

```text
Known Go processes can be distinguished from ordinary processes with documented confidence.
```

---

## Phase 3 — Go strings

Implement:

- Go string reconstruction
- heap/static classification
- provenance
- confidence
- JSON output
- tests

Acceptance criterion:

```text
Known Go strings can be recovered with correct boundaries and addresses.
```

---

## Phase 4 — Functions

Implement:

- function metadata recovery
- function names
- source files
- classification
- architecture-specific disassembly
- tests

---

## Phase 5 — Goroutines

Implement:

- goroutine discovery
- structural validation
- PC/SP recovery
- stack reconstruction
- function mapping
- architecture abstraction
- tests

This is a high-risk component.

Do not rush it.

---

## Phase 6 — Artifact extraction

Implement:

- network artifacts
- URLs
- IPs
- ports
- HTTP artifacts
- potential credentials
- crypto artifacts
- persistence artifacts

All must preserve provenance.

---

## Phase 7 — Correlation

Implement relationships between:

```text
process
runtime
string
function
goroutine
network
artifact
finding
```

---

## Phase 8 — Reporting

Implement:

```text
JSON
HTML
PDF
CSV where appropriate
```

---

## Phase 9 — Investigator UX

Improve:

- CLI
- report presentation
- filtering
- artifact search
- process selection
- analyzer selection
- case metadata

---

## Phase 10 — ARM64

Implement architecture-specific ARM64 functionality.

Do not retrofit ARM64 by copying x86-64 constants.

---

# 36. CODE QUALITY RULES

Prefer:

- small modules
- type hints
- dataclasses / structured models
- explicit exceptions
- clear interfaces
- unit-testable functions
- deterministic output
- documentation

Avoid:

- giant files
- global mutable state
- hidden magic constants
- duplicated parser logic
- silent exception swallowing
- unexplained heuristics
- hard-coded addresses
- hard-coded Go versions

---

# 37. DOCUMENTATION REQUIREMENTS

Every major subsystem must have documentation.

At minimum:

```text
docs/architecture.md
docs/forensic-methodology.md
docs/supported-platforms.md
docs/validation.md
```

Document:

- what the component does
- how it works
- assumptions
- limitations
- supported versions
- test coverage
- known failure modes

---

# 38. CHANGE MANAGEMENT

Before making a large architectural change:

1. Inspect existing code.
2. Understand dependencies.
3. Identify affected tests.
4. Make the smallest reasonable change.
5. Run tests.
6. Update documentation.
7. Report what changed.

Do not rewrite working modules unnecessarily.

---

# 39. CLAUDE CODE WORKFLOW

When asked to implement a feature:

### Step 1

Inspect the repository.

### Step 2

Read relevant documentation.

### Step 3

Read the reference paper sections relevant to the feature.

### Step 4

Inspect existing implementation.

### Step 5

Explain the planned change briefly.

### Step 6

Implement.

### Step 7

Run relevant tests.

### Step 8

Fix failures.

### Step 9

Run broader regression tests.

### Step 10

Update documentation.

### Step 11

Summarize:

```text
Implemented
Tests
Known limitations
Next recommended step
```

Do not skip testing.

---

# 40. IMPORTANT: DO NOT HALLUCINATE

Never invent:

- Go runtime structure layouts
- offsets
- field names
- Volatility APIs
- Go version behavior
- expected forensic artifacts
- test results
- malware behavior
- successful extraction

If uncertain:

1. Inspect source.
2. Inspect the paper.
3. Inspect Volatility implementation/documentation available locally.
4. Build a minimal test.
5. Clearly state uncertainty.

Never hide uncertainty behind confident language.

---

# 41. PAPER TERMINOLOGY

When describing functionality derived from the research paper, preserve the paper's terminology where practical.

Important terms include:

```text
Go runtime
pclntab
moduledata
Go string headers
heap objects
Go functions
function table
goroutines
runtime.allgs
goroutine stack
ABI-aware analysis
runtime artifacts
```

Do not rename concepts unnecessarily.

---

# 42. FORENSIC REPORTING PRINCIPLE

The tool must answer:

```text
WHAT was recovered?
WHERE was it recovered?
FROM WHICH PROCESS?
HOW was it recovered?
HOW CONFIDENT are we?
WHAT other evidence is it correlated with?
```

Every important finding should answer these questions.

---

# 43. EXAMPLE FINDING MODEL

Use a structure similar to:

```json
{
  "id": "F-0001",
  "type": "potential_network_endpoint",
  "severity": "informational",
  "confidence": "high",
  "pid": 1337,
  "process": "example",
  "value": "192.168.1.10:443",
  "source_artifacts": [
    "STR-0123",
    "FUNC-0042",
    "GOR-0017"
  ],
  "evidence": {
    "virtual_address": "0x7f123456",
    "memory_region": "heap"
  },
  "interpretation": "A runtime-reconstructed network endpoint was observed in the process memory."
}
```

Severity and confidence must remain separate concepts.

---

# 44. PERFORMANCE

Memory images can be large.

Avoid:

```text
reading the entire image repeatedly
```

where unnecessary.

Prefer:

- indexed memory access
- caching
- bounded scans
- process-specific analysis
- lazy parsing
- streaming where practical

However:

**Do not sacrifice forensic correctness for performance.**

Any optimization must preserve results.

---

# 45. LARGE MEMORY IMAGE SUPPORT

The tool should eventually be usable with memory images in the multi-gigabyte range.

Design analyzers so that:

```text
entire image in Python RAM
```

is not a mandatory requirement.

Where Volatility already provides appropriate memory abstractions, use them.

---

# 46. OUTPUT DIRECTORY

Never place generated reports beside the original evidence unless explicitly requested.

Default:

```text
reports/<case-id>/
```

Example:

```text
reports/case-001/
├── report.html
├── report.pdf
├── results.json
├── iocs.csv
├── findings.json
├── analysis-manifest.json
└── logs/
```

---

# 47. EVIDENCE DIRECTORY

The repository may contain an:

```text
evidence/
```

directory for local controlled testing.

Do not commit real investigative evidence into Git.

Add appropriate `.gitignore` rules.

Never include:

- real victim data
- real credentials
- private memory dumps
- confidential case material

in source control.

---

# 48. GIT REQUIREMENTS

Use meaningful commits.

Examples:

```text
feat: add evidence validation
feat: add Go runtime detector
feat: implement Go string reconstruction
feat: implement Go function recovery
feat: implement goroutine analysis
test: add Go runtime regression fixtures
docs: document supported Go versions
```

Do not commit generated reports or evidence by default.

---

# 49. DEFINITION OF DONE

A feature is NOT complete merely because the code executes.

A feature is complete only when:

```text
[ ] Implementation exists
[ ] Unit tests exist
[ ] Negative tests exist where relevant
[ ] Integration test exists where practical
[ ] Error handling exists
[ ] Evidence provenance exists
[ ] Documentation exists
[ ] CLI/output integration exists where applicable
[ ] Regression tests pass
[ ] Limitations are documented
```

---

# 50. MVP DEFINITION

The first useful release should provide:

```text
Windows x86-64 memory image
        +
Linux x86-64 memory image
        ↓
Volatility analysis
        ↓
Go process detection
        ↓
Go runtime detection
        ↓
pclntab/moduledata recovery
        ↓
Go string extraction
        ↓
Go function extraction
        ↓
basic goroutine analysis
        ↓
network/IOC extraction
        ↓
correlation
        ↓
JSON + HTML forensic report
```

This is the minimum target for a meaningful working forensic tool.

---

# 51. IMPORTANT LIMITATION

The research reference currently focuses on x86-64 analysis.

Do not represent ARM64 support as inherited from the paper.

ARM64 support is an engineering extension and must be separately implemented and validated.

Similarly, do not claim universal Windows/Linux compatibility.

Supported OS versions, architectures, and Go versions must be documented based on actual testing.

---

# 52. FINAL DEVELOPMENT PRINCIPLE

Build this as a **real forensic engineering project**, not as a paper reproduction demo.

The final tool should be:

```text
Evidence-aware
Offline-first
Architecture-aware
Version-aware
Tested
Reproducible
Explainable
Extensible
Investigator-friendly
```

The primary objective is not to produce the largest number of artifacts.

The objective is to produce **trustworthy artifacts with traceable forensic provenance**.

When there is a conflict between:

```text
more output
```

and:

```text
more reliable output
```

prefer reliable output.

When there is a conflict between:

```text
fast implementation
```

and:

```text
forensically defensible implementation
```

prefer the latter.

---

# 53. FIRST TASK FOR CLAUDE CODE

When this project is first opened, DO NOT immediately start writing the complete implementation.

First:

1. Inspect the repository.
2. Locate the reference paper.
3. Read the paper.
4. Extract its implementation methodology.
5. Identify the exact functionality represented by:
   - go_strings
   - go_functions
   - go_goroutines
6. Identify implementation dependencies.
7. Identify Go-version dependencies.
8. Identify architecture-specific components.
9. Identify Volatility 3 integration points.
10. Produce a technical implementation plan.
11. Produce a dependency graph.
12. Produce a proposed test strategy.
13. Identify risks and unknowns.

Then STOP and present the plan.

Do not implement the entire system until the implementation plan has been reviewed.

---

# 54. FIRST RESPONSE FORMAT

For the first planning response, provide:

```text
## Repository Assessment

## Reference Paper Assessment

## Proposed Architecture

## Core Components

## Dependency Analysis

## Implementation Phases

## Test Strategy

## Forensic Integrity Strategy

## Known Risks

## Paper-derived vs Engineering-added Features

## Recommended First Implementation Step
```

Do not claim that any code has been implemented during this first step.

---

# END OF CLAUDE.md