// Bounded offline exporter; invoked by analyze.py after automatic analysis.
// @category Analysis
import com.google.gson.*;
import ghidra.app.decompiler.*;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

public class ExportAnalysis extends HeadlessScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1 || currentProgram == null) {
            throw new IllegalArgumentException("Expected one wrapper request and an imported program");
        }
        Gson gson = new GsonBuilder().serializeNulls().setPrettyPrinting().create();
        JsonObject request = JsonParser.parseString(Files.readString(Path.of(args[0]))).getAsJsonObject();
        JsonObject limits = request.getAsJsonObject("limits");
        int maxFunctions = limits.get("max_functions").getAsInt();
        int maxXrefs = limits.get("max_xrefs").getAsInt();
        int functionTimeout = limits.get("function_timeout").getAsInt();
        List<String> selectors = new ArrayList<>();
        for (JsonElement value : request.getAsJsonArray("selectors")) selectors.add(value.getAsString());
        Map<String, Integer> matches = new LinkedHashMap<>();
        for (String selector : selectors) matches.put(selector, 0);
        List<Function> selected = new ArrayList<>();
        boolean truncated = false;
        FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            Function function = iterator.next();
            if (selectors.isEmpty()) {
                if (selected.size() == maxFunctions) { truncated = true; break; }
                selected.add(function);
            } else {
                boolean wanted = false;
                for (String selector : selectors) {
                    Address address = null;
                    try { address = currentProgram.getAddressFactory().getAddress(selector); }
                    catch (IllegalArgumentException ignored) { /* selector may be a name */ }
                    if (function.getName().equals(selector) || function.getEntryPoint().equals(address)) {
                        matches.put(selector, matches.get(selector) + 1);
                        wanted = true;
                    }
                }
                if (wanted) {
                    if (selected.size() < maxFunctions) selected.add(function);
                    else truncated = true;
                }
            }
        }
        JsonObject report = new JsonObject();
        report.addProperty("schema_version", 1);
        report.addProperty("sample_sha256", currentProgram.getExecutableSHA256());
        report.addProperty("ghidra_version", Application.getApplicationVersion());
        report.addProperty("program", currentProgram.getName());
        report.addProperty("language", currentProgram.getLanguageID().toString());
        report.addProperty("analysis_timed_out", analysisTimeoutOccurred());
        report.add("selectors", request.get("selectors"));
        report.add("limits", limits);
        report.addProperty("functions_truncated", truncated);
        JsonArray unmatched = new JsonArray();
        for (Map.Entry<String, Integer> entry : matches.entrySet()) {
            // Ambiguous exact names are not silently accepted either.
            if (entry.getValue() != 1) unmatched.add(entry.getKey());
        }
        report.add("unmatched_selectors", unmatched);
        JsonArray functions = new JsonArray();
        DecompInterface decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(currentProgram)) {
                throw new IllegalStateException("Decompiler could not open imported program");
            }
            for (Function function : selected) {
                monitor.checkCancelled();
                JsonObject item = new JsonObject();
                item.addProperty("name", function.getName());
                item.addProperty("address", function.getEntryPoint().toString());
                try {
                    DecompileResults result = decompiler.decompileFunction(function, functionTimeout, monitor);
                    if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                        String c = result.getDecompiledFunction().getC();
                        if (c.length() > 100000) {
                            item.addProperty("status", "failed");
                            item.addProperty("error", "C output exceeded 100000 character bound");
                        } else {
                            item.addProperty("status", "ok");
                            item.addProperty("c", c);
                        }
                    } else {
                        item.addProperty("status", "failed");
                        item.addProperty("error", result.getErrorMessage());
                    }
                } catch (Exception error) {
                    item.addProperty("status", "failed");
                    item.addProperty("error", error.getClass().getSimpleName());
                }
                JsonArray xrefs = new JsonArray();
                ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(function.getEntryPoint());
                while (refs.hasNext() && xrefs.size() < maxXrefs) {
                    Reference reference = refs.next();
                    JsonObject xref = new JsonObject();
                    xref.addProperty("from_address", reference.getFromAddress().toString());
                    xref.addProperty("type", reference.getReferenceType().toString());
                    Function caller = currentProgram.getFunctionManager().getFunctionContaining(reference.getFromAddress());
                    xref.addProperty("caller", caller == null ? null : caller.getName());
                    xrefs.add(xref);
                }
                item.add("xrefs", xrefs);
                item.addProperty("xrefs_truncated", refs.hasNext());
                functions.add(item);
            }
        } finally {
            decompiler.dispose();
        }
        report.add("functions", functions);
        report.addProperty("complete", true);
        Files.writeString(Path.of(request.get("output").getAsString()), gson.toJson(report),
                          StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW);
    }
}
