// Read-only decompilation of selected functions for liebert_re.tools.ghidra.ghidra_decompile.
//
// Run by analyzeHeadless as a post-script. Script arguments, in order:
//   0  path of the result file to write
//   1  path of the request file: one request per line, UTF-8, "A<TAB><hex address>" or "N<TAB><function name>"
//   2  decompile timeout per function, in seconds
//   3  the most functions one run may decompile
// Nothing here changes the program: no transaction is opened, nothing is renamed, created, retyped or saved,
// and the decompiler is only asked to read. A function that cannot be resolved or decompiled is reported
// with c_code null and the reason in "error"; it is never replaced by a guess. Every request gets exactly
// one entry in "functions", in request order. "script_completed" is the last key written, so a truncated
// result file is detectable.
//
// @category Liebert

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class DecompileFunctions extends GhidraScript {

    private static final int CODE_CHAR_CAP = 200000;
    private static final int AMBIGUOUS_LIST_CAP = 8;
    private static final String[] WARNING_MARKERS = {"halt_baddata", "Bad instruction", "Unable to decode"};

    private final List<String> errors = new ArrayList<>();

    private static String q(String s) {
        if (s == null) {
            return "null";
        }
        StringBuilder b = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        b.append(String.format("\\u%04x", (int) c));
                    } else {
                        b.append(c);
                    }
            }
        }
        return b.append('"').toString();
    }

    private static String list(List<String> quoted) {
        return quoted == null ? "null" : "[" + String.join(",", quoted) + "]";
    }

    /** One entry of "functions". Absent facts are JSON null, never an empty string. */
    private static String entry(String requested, String address, String name, String signature,
                                String decompiledSignature, String code, boolean truncated,
                                boolean completed, String error, List<String> warnings) {
        List<String> w = new ArrayList<>();
        for (String s : warnings) {
            w.add(q(s));
        }
        return "{\"requested\":" + q(requested)
            + ",\"address\":" + q(address)
            + ",\"name\":" + q(name)
            + ",\"signature\":" + q(signature)
            + ",\"decompiled_signature\":" + q(decompiledSignature)
            + ",\"c_code\":" + q(code)
            + ",\"c_code_truncated\":" + truncated
            + ",\"decompile_completed\":" + completed
            + ",\"warnings\":" + list(w)
            + ",\"error\":" + q(error) + "}";
    }

    private String failed(String requested, String address, String name, String signature, String error) {
        return entry(requested, address, name, signature, null, null, false, false, error, new ArrayList<>());
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args == null || args.length < 4 || args[0].isEmpty() || args[1].isEmpty()) {
            throw new IllegalArgumentException(
                "DecompileFunctions needs: result file, request file, per-function timeout, function limit");
        }
        if (currentProgram == null) {
            throw new IllegalStateException("no current program");
        }
        int perFunctionSeconds = Integer.parseInt(args[2].trim());
        int maxFunctions = Integer.parseInt(args[3].trim());

        List<String> lines = new ArrayList<>();
        for (String line : Files.readAllLines(Paths.get(args[1]), StandardCharsets.UTF_8)) {
            if (!line.isEmpty()) {
                lines.add(line);
            }
        }
        if (lines.isEmpty()) {
            throw new IllegalArgumentException("the request file holds no request");
        }
        if (lines.size() > maxFunctions) {
            throw new IllegalArgumentException("more requests than the limit of " + maxFunctions);
        }

        DecompInterface ifc = new DecompInterface();
        String openError = null;
        try {
            ifc.setOptions(new DecompileOptions());
            if (!ifc.openProgram(currentProgram)) {
                openError = "DECOMPILER_OPEN_FAILED: " + ifc.getLastMessage();
            }
        } catch (Exception e) {
            openError = "DECOMPILER_OPEN_FAILED: " + e.getClass().getSimpleName();
        }

        List<String> functions = new ArrayList<>();
        try {
            for (String line : lines) {
                int tab = line.indexOf('\t');
                String kind = tab < 0 ? "" : line.substring(0, tab);
                String value = tab < 0 ? "" : line.substring(tab + 1);
                String requested = value;
                Function f = null;
                String resolveError = null;
                try {
                    if (kind.equals("A")) {
                        Address a = currentProgram.getAddressFactory().getDefaultAddressSpace()
                            .getAddress(Long.parseUnsignedLong(value, 16));
                        f = currentProgram.getFunctionManager().getFunctionContaining(a);
                        if (f == null) {
                            resolveError = "FUNCTION_NOT_FOUND: no function contains this address";
                        }
                    } else if (kind.equals("N")) {
                        List<Function> found = getGlobalFunctions(value);
                        if (found == null || found.isEmpty()) {
                            resolveError = "FUNCTION_NOT_FOUND: no function has this name";
                        } else if (found.size() > 1) {
                            List<String> where = new ArrayList<>();
                            for (Function c : found) {
                                if (where.size() < AMBIGUOUS_LIST_CAP) {
                                    where.add(c.getEntryPoint().toString());
                                }
                            }
                            resolveError = "AMBIGUOUS_FUNCTION_NAME: " + found.size()
                                + " functions have this name, use an address: " + String.join(",", where);
                        } else {
                            f = found.get(0);
                        }
                    } else {
                        resolveError = "REQUEST_MALFORMED";
                    }
                } catch (Exception e) {
                    f = null;
                    resolveError = "FUNCTION_NOT_FOUND: " + e.getClass().getSimpleName() + " while resolving";
                }
                if (f == null) {
                    functions.add(failed(requested, null, null, null, resolveError));
                    continue;
                }
                String address = f.getEntryPoint().toString();
                String name = f.getName();
                String signature = null;
                try {
                    signature = f.getPrototypeString(false, false);
                } catch (Exception e) {
                    errors.add("signature " + address + ": " + e.getClass().getSimpleName());
                }
                if (openError != null) {
                    functions.add(failed(requested, address, name, signature, openError));
                    continue;
                }
                try {
                    DecompileResults res = ifc.decompileFunction(f, perFunctionSeconds, monitor);
                    if (res == null) {
                        functions.add(failed(requested, address, name, signature, "DECOMPILE_FAILED: no result"));
                    } else if (res.isTimedOut()) {
                        functions.add(failed(requested, address, name, signature,
                            "DECOMPILE_TIMEOUT: no answer within " + perFunctionSeconds + " s"));
                    } else if (!res.decompileCompleted()) {
                        String msg = res.getErrorMessage();
                        functions.add(failed(requested, address, name, signature,
                            "DECOMPILE_FAILED: " + (msg == null || msg.isEmpty() ? "no message" : msg)));
                    } else {
                        DecompiledFunction df = res.getDecompiledFunction();
                        String code = df == null ? null : df.getC();
                        if (code == null) {
                            functions.add(failed(requested, address, name, signature,
                                "DECOMPILE_FAILED: completed without C output"));
                        } else {
                            boolean truncated = code.length() > CODE_CHAR_CAP;
                            if (truncated) {
                                code = code.substring(0, CODE_CHAR_CAP);
                            }
                            List<String> warnings = new ArrayList<>();
                            for (String marker : WARNING_MARKERS) {
                                if (code.contains(marker)) {
                                    warnings.add(marker);
                                }
                            }
                            functions.add(entry(requested, address, name, signature, df.getSignature(), code,
                                truncated, true, null, warnings));
                        }
                    }
                } catch (Exception e) {
                    functions.add(failed(requested, address, name, signature,
                        "DECOMPILE_EXCEPTION: " + e.getClass().getSimpleName()));
                }
            }
        } finally {
            ifc.dispose();
        }

        List<String> errorJson = new ArrayList<>();
        for (String e : errors) {
            errorJson.add(q(e));
        }
        StringBuilder out = new StringBuilder();
        out.append("{\n");
        out.append("\"schema\": 1,\n");
        out.append("\"requested_count\": ").append(lines.size()).append(",\n");
        out.append("\"functions\": ").append(list(functions)).append(",\n");
        out.append("\"errors\": ").append(list(errorJson)).append(",\n");
        out.append("\"script_completed\": true\n}\n");

        try (PrintWriter w = new PrintWriter(
                Files.newBufferedWriter(Paths.get(args[0]), StandardCharsets.UTF_8))) {
            w.write(out.toString());
        }
    }
}
