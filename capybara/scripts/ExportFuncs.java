import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;

public class ExportFuncs extends GhidraScript {

    private boolean isSystemFunc(String name) {
        if (name == null) return true;
        // Ignorar basura de inicialización de C
        return name.startsWith("_") || 
               name.equals("entry") ||
               name.contains("@plt") || 
               name.equals("deregister_tm_clones") ||
               name.equals("register_tm_clones") ||
               name.equals("frame_dummy") ||
               name.equals("data_start");
    }

    @Override
    public void run() throws Exception {
        SymbolTable st = currentProgram.getSymbolTable();
        for (Symbol s : st.getAllSymbols(true)) {
            if (s.getSource() != SourceType.DEFAULT) {
                createFunction(s.getAddress(), s.getName());
            }
        }

        DecompInterface iface = new DecompInterface();
        iface.openProgram(currentProgram);

        FunctionIterator iter = currentProgram.getFunctionManager().getFunctions(true);
        while (iter.hasNext() && !monitor.isCancelled()) {
            Function f = iter.next();
            
            if (isSystemFunc(f.getName())) continue;
            
            // OMITIR FUNCIONES DE LIBRERÍA (puts, strlen, exit...) 
            // Queremos ver que "main" las llama, pero no queremos analizar su ASM vacío.
            if (f.isThunk() || f.isExternal()) continue;

            // USAMOS System.out.println PARA EVITAR LA BASURA DE (GhidraScript)
            System.out.println("---START_FUNC:" + f.getName() + "---");
            System.out.println("---ADDR:" + f.getEntryPoint().toString() + "---");

            System.out.println("---START_CALLS---");
            for (Address addr : f.getBody().getAddresses(true)) {
                for (Reference ref : currentProgram.getReferenceManager().getReferencesFrom(addr)) {
                    // Detectar llamadas (Calls) y saltos ciegos a librerías (Jumps)
                    if (ref.getReferenceType().isCall() || ref.getReferenceType().isJump()) {
                        Function callee = currentProgram.getFunctionManager().getFunctionAt(ref.getToAddress());
                        if (callee != null) {
                            String calleeName = callee.getName();
                            // EVITAR BUCLES HACIA SÍ MISMO
                            if (!calleeName.equals(f.getName())) {
                                // Limpiar el sufijo @plt si existe (puts@plt -> puts)
                                if (calleeName.endsWith("@plt")) {
                                    calleeName = calleeName.substring(0, calleeName.length() - 4);
                                }
                                System.out.println("CALL:" + calleeName);
                            }
                        }
                    }
                }
            }
            System.out.println("---END_CALLS---");

            System.out.println("---START_ASM---");
            InstructionIterator insIter = currentProgram.getListing().getInstructions(f.getBody(), true);
            while (insIter.hasNext()) {
                Instruction ins = insIter.next();
                System.out.println(ins.getAddress() + ": " + ins.toString());
            }
            System.out.println("---END_ASM---");

            System.out.println("---START_C---");
            DecompileResults res = iface.decompileFunction(f, 60, monitor);
            if (res != null && res.getDecompiledFunction() != null) {
                System.out.println(res.getDecompiledFunction().getC());
            }
            System.out.println("---END_C---");

            System.out.println("---END_FUNC---");
        }
    }
}
