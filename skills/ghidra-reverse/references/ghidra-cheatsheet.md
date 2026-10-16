# Ghidra quick reference

These are navigation/API notes, not authorization to execute tools or modify projects. Use the consent gates in `../SKILL.md` first.

| GUI task | Default action/location |
|---|---|
| Decompile | Open function → Decompile window |
| Rename | L (requires separately approved project edits) |
| Comment | ; (requires separately approved project edits) |
| Cross-references | Right-click → References |
| Strings | Search → For Strings |
| Scripts | Window → Script Manager |

## Bundled offline workflow

`../scripts/analyze.py` invokes official `analyzeHeadless` with fresh import, `-readOnly`, a resolved `-scriptPath`, and `ExportAnalysis.java` as a post-script. It does not save edits into an existing project. See [usage](usage.md) for installation and official links.

| Java API | Purpose |
|---|---|
| `HeadlessScript.analysisTimeoutOccurred()` | Detect automatic analysis timeout in post-script |
| `currentProgram.getExecutableSHA256()` | Imported sample identity (wrapper independently verifies file digest) |
| `currentProgram.getLanguageID()` | Language identity |
| `FunctionManager.getFunctions(true)` | Functions in address order |
| `DecompInterface.decompileFunction(function, seconds, monitor)` | Bounded C decompilation; inspect completion/failure |
| `ReferenceManager.getReferencesTo(entry)` | Incoming references to exact function entry only |
| `FunctionManager.getFunctionContaining(from)` | Containing caller when available; may be null for data |

The Java exporter is not a Jython/PyGhidra script. Missing C or a failed/timed-out function causes wrapper failure. C is an approximation, not original source; references are static evidence, not proof of execution. Review analysis language and addresses before interpreting results. Any later dynamic analysis, renaming, patching, or additional tooling needs its own approved scope.
