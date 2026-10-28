// Create a Version Tracking session between gta_sa_analysis.exe (1.0 US, source) and gta-sa.exe
// (3.0, destination), run the exact correlators and export every candidate match as CSV.
//
// Headless usage:
//   analyzeHeadless <projectDir> SA_COOP -process gta-sa.exe -noanalysis \
//     -scriptPath tools/port -postScript VtExport.java <csvPath>
//
//@category SA:COOP
import java.io.File;
import java.io.PrintWriter;
import java.util.Collection;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.feature.vt.api.correlator.program.*;
import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.util.VTOptions;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;

public class VtExport extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		String csvPath = args.length > 0 ? args[0] : "vt_matches.csv";

		Program destination = currentProgram;
		if (destination == null) {
			println("no current program");
			return;
		}

		DomainFile sourceFile = destination.getDomainFile().getParent().getFile("gta_sa_analysis.exe");
		if (sourceFile == null) {
			println("source program gta_sa_analysis.exe not found in project folder");
			return;
		}
		Program source = (Program) sourceFile.getDomainObject(this, true, false, monitor);

		DomainFolder folder = destination.getDomainFile().getParent();
		String sessionName = "vt_10_to_30";
		DomainFile existing = folder.getFile(sessionName);
		if (existing != null) {
			existing.delete();
		}

		// The script runs inside a transaction on the destination; VTSessionDB needs both programs
		// out of any transaction so that it can add them to its own synchronized transaction manager.
		end(true);

		VTSession session = new VTSessionDB(sessionName, source, destination, this);
		folder.createFile(sessionName, session, monitor);

		int tx = session.startTransaction("correlate");
		try {
			AddressSetView sa = source.getMemory().getLoadedAndInitializedAddressSet();
			AddressSetView da = destination.getMemory().getLoadedAndInitializedAddressSet();

			run(session, new ExactDataMatchProgramCorrelatorFactory(), source, sa, destination, da);
			run(session, new ExactMatchBytesProgramCorrelatorFactory(), source, sa, destination, da);
			run(session, new ExactMatchInstructionsProgramCorrelatorFactory(), source, sa, destination, da);
			run(session, new ExactMatchMnemonicsProgramCorrelatorFactory(), source, sa, destination, da);

			// Accept the exact matches; the reference correlators use accepted matches as anchors.
			// The same source can be proposed by several exact correlators, so accept only the
			// first available one and leave blocked duplicates alone.
			int accepted = 0;
			java.util.Set<Long> seen = new java.util.HashSet<>();
			for (VTMatchSet set : session.getMatchSets()) {
				for (VTMatch match : set.getMatches()) {
					long src = match.getSourceAddress().getOffset();
					if (seen.contains(src)) {
						continue;
					}
					VTAssociation a = match.getAssociation();
					if (a.getStatus() != VTAssociationStatus.AVAILABLE) {
						continue;
					}
					if (match.getConfidenceScore().getScore() < 10.0) {
						continue;
					}
					a.setAccepted();
					seen.add(src);
					accepted++;
				}
			}
			println("accepted " + accepted + " exact matches");

			run(session, new FunctionReferenceProgramCorrelatorFactory(), source, sa, destination, da);
			run(session, new DataReferenceProgramCorrelatorFactory(), source, sa, destination, da);
			run(session, new CombinedFunctionAndDataReferenceProgramCorrelatorFactory(), source, sa,
				destination, da);
		}
		finally {
			session.endTransaction(tx, true);
		}

		int count = 0;
		try (PrintWriter out = new PrintWriter(new File(csvPath))) {
			out.println("src,dst,type,similarity,confidence,length_src,length_dst,set");
			List<VTMatchSet> sets = session.getMatchSets();
			for (VTMatchSet set : sets) {
				Collection<VTMatch> matches = set.getMatches();
				for (VTMatch match : matches) {
					VTAssociation a = match.getAssociation();
					out.printf("%s,%s,%s,%.4f,%.4f,%d,%d,%s%n",
						match.getSourceAddress(), match.getDestinationAddress(), a.getType(),
						match.getSimilarityScore().getScore(),
						match.getConfidenceScore().getScore(),
						match.getSourceLength(), match.getDestinationLength(),
						set.getProgramCorrelatorInfo().getName());
					count++;
				}
			}
		}
		println("exported " + count + " matches to " + csvPath);

		session.release(this);
		source.release(this);
	}

	private void run(VTSession session, VTProgramCorrelatorFactory factory, Program source,
			AddressSetView sa, Program destination, AddressSetView da) throws Exception {
		VTOptions options = factory.createDefaultOptions();
		VTProgramCorrelator correlator =
			factory.createCorrelator(source, sa, destination, da, options);
		VTMatchSet set = correlator.correlate(session, monitor);
		println(factory.getName() + ": " + set.getMatchCount());
	}
}
