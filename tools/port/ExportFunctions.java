// Export every function (address, size, name) of the current program as CSV.
//
// Headless usage:
//   analyzeHeadless <projectDir> SA_COOP -process <program> -noanalysis \
//     -scriptPath tools/port -postScript ExportFunctions.java <csvPath>
//
//@category SA:COOP
import java.io.File;
import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class ExportFunctions extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		String path = args.length > 0 ? args[0] : "functions.csv";
		FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
		int n = 0;
		try (PrintWriter out = new PrintWriter(new File(path))) {
			out.println("addr,size,name");
			for (Function f : it) {
				out.printf("0x%08X,%d,%s%n", f.getEntryPoint().getOffset(),
					(int) f.getBody().getNumAddresses(), f.getName());
				n++;
			}
		}
		println("exported " + n + " functions to " + path);
	}
}
