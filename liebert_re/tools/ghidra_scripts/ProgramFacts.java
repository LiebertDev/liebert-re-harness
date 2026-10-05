// Read-only program facts for liebert_re.tools.ghidra.ghidra_program_facts.
//
// Run by analyzeHeadless as a post-script. The single script argument is the
// path of the result file. Nothing here changes the program, and no fact that
// cannot be read is guessed: each one is read inside its own guard, a failure
// stores null and appends a line to "errors". The result is written to the
// file rather than parsed out of the log; "script_completed" is the last key
// written, so a truncated file is detectable.
//
// @category Liebert

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.lang.Language;
import ghidra.program.model.mem.MemoryBlock;

import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class ProgramFacts extends GhidraScript {

    private static final int BLOCK_LIST_CAP = 256;
    private static final int ENTRY_LIST_CAP = 64;
    private static final int LIBRARY_LIST_CAP = 512;

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

    private void note(String fact, Exception e) {
        errors.add(fact + ": " + e.getClass().getSimpleName());
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args == null || args.length < 1 || args[0].isEmpty()) {
            throw new IllegalArgumentException("ProgramFacts needs the result file path as its argument");
        }
        if (currentProgram == null) {
            throw new IllegalStateException("no current program");
        }

        String loader = null;
        try {
            loader = currentProgram.getExecutableFormat();
        } catch (Exception e) {
            note("loader", e);
        }

        String languageId = null, processor = null, endian = null, variant = null, compiler = null;
        Integer addressBits = null;
        try {
            Language lang = currentProgram.getLanguage();
            languageId = lang.getLanguageID().getIdAsString();
            processor = lang.getProcessor().toString();
            endian = lang.isBigEndian() ? "big" : "little";
            variant = lang.getLanguageDescription().getVariant();
            addressBits = lang.getLanguageDescription().getSize();
        } catch (Exception e) {
            note("language", e);
        }
        try {
            compiler = currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString();
        } catch (Exception e) {
            note("compiler_spec", e);
        }

        String imageBase = null;
        try {
            imageBase = currentProgram.getImageBase().toString();
        } catch (Exception e) {
            note("image_base", e);
        }

        List<String> entries = null;
        Integer entryCount = null;
        try {
            entries = new ArrayList<>();
            int n = 0;
            AddressIterator it = currentProgram.getSymbolTable().getExternalEntryPointIterator();
            while (it.hasNext()) {
                Address a = it.next();
                n++;
                if (entries.size() < ENTRY_LIST_CAP) {
                    entries.add(q(a.toString()));
                }
            }
            entryCount = n;
        } catch (Exception e) {
            entries = null;
            note("entry_points", e);
        }

        Integer blockCount = null;
        List<String> blockJson = null;
        try {
            MemoryBlock[] blocks = currentProgram.getMemory().getBlocks();
            blockCount = blocks.length;
            blockJson = new ArrayList<>();
            for (MemoryBlock b : blocks) {
                if (blockJson.size() >= BLOCK_LIST_CAP) {
                    break;
                }
                blockJson.add("{\"name\":" + q(b.getName())
                    + ",\"start\":" + q(b.getStart().toString())
                    + ",\"size\":" + b.getSize()
                    + ",\"read\":" + b.isRead()
                    + ",\"write\":" + b.isWrite()
                    + ",\"execute\":" + b.isExecute()
                    + ",\"initialized\":" + b.isInitialized() + "}");
            }
        } catch (Exception e) {
            blockCount = null;
            blockJson = null;
            note("memory_blocks", e);
        }

        Integer functionCount = null;
        try {
            functionCount = currentProgram.getFunctionManager().getFunctionCount();
        } catch (Exception e) {
            note("function_count", e);
        }

        List<String> libs = null;
        Integer libCount = null;
        try {
            String[] names = currentProgram.getExternalManager().getExternalLibraryNames();
            libCount = names.length;
            libs = new ArrayList<>();
            for (String name : names) {
                if (libs.size() < LIBRARY_LIST_CAP) {
                    libs.add(q(name));
                }
            }
        } catch (Exception e) {
            libs = null;
            note("external_libraries", e);
        }

        List<String> errorJson = new ArrayList<>();
        for (String e : errors) {
            errorJson.add(q(e));
        }

        StringBuilder out = new StringBuilder();
        out.append("{\n");
        out.append("\"schema\": 1,\n");
        out.append("\"loader\": ").append(q(loader)).append(",\n");
        out.append("\"language_id\": ").append(q(languageId)).append(",\n");
        out.append("\"processor\": ").append(q(processor)).append(",\n");
        out.append("\"endian\": ").append(q(endian)).append(",\n");
        out.append("\"variant\": ").append(q(variant)).append(",\n");
        out.append("\"address_size_bits\": ").append(addressBits == null ? "null" : addressBits).append(",\n");
        out.append("\"compiler_spec\": ").append(q(compiler)).append(",\n");
        out.append("\"image_base\": ").append(q(imageBase)).append(",\n");
        out.append("\"entry_point_count\": ").append(entryCount == null ? "null" : entryCount).append(",\n");
        out.append("\"entry_points\": ").append(list(entries)).append(",\n");
        out.append("\"memory_block_count\": ").append(blockCount == null ? "null" : blockCount).append(",\n");
        out.append("\"memory_blocks\": ").append(list(blockJson)).append(",\n");
        out.append("\"function_count\": ").append(functionCount == null ? "null" : functionCount).append(",\n");
        out.append("\"external_library_count\": ").append(libCount == null ? "null" : libCount).append(",\n");
        out.append("\"external_libraries\": ").append(list(libs)).append(",\n");
        out.append("\"errors\": ").append(list(errorJson)).append(",\n");
        out.append("\"script_completed\": true\n}\n");

        try (PrintWriter w = new PrintWriter(
                Files.newBufferedWriter(Paths.get(args[0]), StandardCharsets.UTF_8))) {
            w.write(out.toString());
        }
    }
}
