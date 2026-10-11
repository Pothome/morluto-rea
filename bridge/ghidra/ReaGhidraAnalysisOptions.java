import java.util.Map;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.headless.HeadlessScript;

/** Disable the named auto-analyzers before default auto-analysis. */
public final class ReaGhidraAnalysisOptions extends HeadlessScript {
    @Override
    public void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length != 1 || arguments[0].isBlank()) {
            throw new IllegalArgumentException(
                "ReaGhidraAnalysisOptions requires one comma-separated analyzer-name argument");
        }
        String[] names = arguments[0].split(",");
        AutoAnalysisManager analysis = AutoAnalysisManager.getAnalysisManager(currentProgram);
        Map<String, String> options = getCurrentAnalysisOptionsAndValues(currentProgram);
        for (String requestedName : names) {
            monitor.checkCancelled();
            String name = requestedName.trim();
            if (analysis.getAnalyzer(name) == null || !options.containsKey(name)) {
                throw new IllegalArgumentException("Unknown Ghidra analyzer for this program: " + name);
            }
        }
        for (String requestedName : names) {
            monitor.checkCancelled();
            setAnalysisOption(currentProgram, requestedName.trim(), "false");
        }
        options = getCurrentAnalysisOptionsAndValues(currentProgram);
        for (String requestedName : names) {
            monitor.checkCancelled();
            String name = requestedName.trim();
            if (!"false".equals(options.get(name))) {
                throw new IllegalStateException("Ghidra analyzer remained enabled: " + name);
            }
        }
    }
}
