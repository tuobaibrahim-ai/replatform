// سكربت Ghidra headless — يصدّر الدوال وتفكيك نقطة الدخول وكود pseudocode.
// يُستدعى عبر: analyzeHeadless ... -postScript ExportFunctions.java <out.json> [decompile] [limit]

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.SourceType;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public class ExportFunctions extends GhidraScript {

    private static String esc(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\\", "\\\\")
                    .replace("\"", "\\\"")
                    .replace("\t", " ")
                    .replace("\r", " ");
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outPath = (args != null && args.length > 0) ? args[0] : "ghidra_export.json";
        boolean decompile = args != null && args.length > 1
                && args[1].equalsIgnoreCase("decompile");
        int decompileLimit = 6;
        if (args != null && args.length > 2) {
            try {
                decompileLimit = Math.max(0, Math.min(Integer.parseInt(args[2]), 50));
            } catch (NumberFormatException ignored) {
                decompileLimit = 6;
            }
        }

        FunctionManager manager = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();
        List<Function> functions = new ArrayList<>();
        for (Function function : manager.getFunctions(true)) {
            functions.add(function);
        }
        functions.sort(Comparator.comparingLong(
                (Function f) -> f.getBody().getNumAddresses()).reversed());

        int renamed = 0;
        List<String> renameErrors = new ArrayList<>();
        String renameSpec = (args != null && args.length > 3) ? args[3] : "";
        if (!renameSpec.isEmpty()) {
            for (String pair : renameSpec.split(",")) {
                int separator = pair.indexOf('~');
                if (separator <= 0 || separator >= pair.length() - 1) {
                    renameErrors.add("صيغة غير صالحة: " + pair);
                    continue;
                }
                String oldName = pair.substring(0, separator);
                String newName = pair.substring(separator + 1);
                boolean found = false;
                for (Function function : functions) {
                    if (!function.getName().equals(oldName)) {
                        continue;
                    }
                    found = true;
                    try {
                        function.setName(newName, SourceType.USER_DEFINED);
                        renamed++;
                    } catch (Exception exc) {
                        renameErrors.add(oldName + " -> " + newName + ": " + exc);
                    }
                    break;
                }
                if (!found) {
                    renameErrors.add("لم تُوجد الدالة: " + oldName);
                }
            }
        }

        DecompInterface decompiler = null;
        if (decompile && decompileLimit > 0) {
            decompiler = new DecompInterface();
            decompiler.openProgram(currentProgram);
        }

        StringBuilder json = new StringBuilder();
        json.append("{\n");
        json.append("\"program\": \"").append(esc(currentProgram.getName())).append("\",\n");
        json.append("\"language\": \"").append(esc(currentProgram.getLanguageID().toString())).append("\",\n");
        json.append("\"image_base\": \"").append(currentProgram.getImageBase()).append("\",\n");
        json.append("\"functions\": [\n");

        int count = 0;
        int decompiledCount = 0;
        for (Function function : functions) {
            if (count > 0) {
                json.append(",\n");
            }
            json.append("{\"name\": \"").append(esc(function.getName())).append("\", ");
            json.append("\"entry\": \"").append(function.getEntryPoint()).append("\", ");
            json.append("\"size\": ").append(function.getBody().getNumAddresses());

            if (decompiler != null && decompiledCount < decompileLimit) {
                try {
                    DecompileResults results = decompiler.decompileFunction(
                            function, 45, monitor);
                    if (results != null && results.decompileCompleted()
                            && results.getDecompiledFunction() != null) {
                        String code = results.getDecompiledFunction().getC();
                        String[] lines = code.split("\\R", -1);
                        json.append(", \"pseudocode\": [");
                        int shown = Math.min(lines.length, 240);
                        for (int index = 0; index < shown; index++) {
                            if (index > 0) {
                                json.append(", ");
                            }
                            json.append("\"").append(esc(lines[index])).append("\"");
                        }
                        json.append("]");
                        decompiledCount++;
                    }
                } catch (Exception exc) {
                    // فشل دالة واحدة لا يوقف التصدير.
                }
            }
            json.append("}");
            count++;
        }

        if (decompiler != null) {
            decompiler.dispose();
        }

        json.append("\n],\n");
        json.append("\"entry_disasm\": [\n");

        int shown = 0;
        Address entry = null;
        AddressIterator entries = currentProgram.getSymbolTable().getExternalEntryPointIterator();
        if (entries.hasNext()) {
            entry = entries.next();
        }
        if (entry != null) {
            Instruction instruction = listing.getInstructionAt(entry);
            while (instruction != null && shown < 40) {
                if (shown > 0) {
                    json.append(",\n");
                }
                json.append("\"").append(esc(instruction.toString())).append("\"");
                instruction = instruction.getNext();
                shown++;
            }
        }

        json.append("\n],\n");
        json.append("\"function_count\": ").append(count).append(",\n");
        json.append("\"decompiled_count\": ").append(decompiledCount).append(",\n");
        json.append("\"renamed_count\": ").append(renamed).append(",\n");
        json.append("\"rename_errors\": [");
        for (int index = 0; index < renameErrors.size(); index++) {
            if (index > 0) {
                json.append(", ");
            }
            json.append("\"").append(esc(renameErrors.get(index))).append("\"");
        }
        json.append("]\n");
        json.append("}\n");

        try (PrintWriter writer = new PrintWriter(outPath, "UTF-8")) {
            writer.print(json.toString());
        }
        println("REPLATFORM: exported " + count + " functions, "
                + decompiledCount + " decompiled to " + outPath);
    }
}
