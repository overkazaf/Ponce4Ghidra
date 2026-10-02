package ponce4ghidra;

import java.io.IOException;

import com.google.gson.JsonArray;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ponce4ghidra.actions.*;
import ponce4ghidra.engine.EngineManager;
import ponce4ghidra.engine.EngineProtocol;
import ponce4ghidra.highlight.PathHighlighter;
import ponce4ghidra.ui.SymbolicStateProvider;

//@formatter:off
@PluginInfo(
	status = PluginStatus.UNSTABLE,
	packageName = "Ponce4Ghidra",
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "Interactive Symbolic Execution",
	description = "Interactive symbolic execution plugin powered by angr. " +
		"Symbolize registers/memory, set find/avoid targets, and solve constraints."
)
//@formatter:on
public class Ponce4GhidraPlugin extends Plugin {

	private EngineManager engineManager;
	private SymbolicStateProvider stateProvider;
	private PathHighlighter pathHighlighter;

	public Ponce4GhidraPlugin(PluginTool tool) {
		super(tool);

		engineManager = new EngineManager();
		pathHighlighter = new PathHighlighter(tool);
		stateProvider = new SymbolicStateProvider(this);

		registerActions();
	}

	private void registerActions() {
		new SymbolizeRegisterAction(this);
		new SymbolizeMemoryAction(this);
		new SymbolizeFunctionArgumentAction(this);
		new SymbolizeArgvAction(this);
		new SetFindAction(this);
		new SetAvoidAction(this);
		new SolveAction(this);
		new SaveSessionAction(this);
		new RestoreSessionAction(this);
		new HelpAction(this);
	}

	public EngineManager getEngineManager() {
		return engineManager;
	}

	public SymbolicStateProvider getStateProvider() {
		return stateProvider;
	}

	public PathHighlighter getPathHighlighter() {
		return pathHighlighter;
	}

	public void ensureEngineStarted() {
		if (!engineManager.isRunning()) {
			try {
				engineManager.start();
			}
			catch (Exception e) {
				Msg.showError(this, null, "Ponce4Ghidra",
					"Failed to start symbolic execution engine: " + e.getMessage(), e);
				return;
			}
		}
		ensureInitialized();
	}

	/**
	 * Makes sure the engine has the current program loaded, and reports why not
	 * if it cannot.
	 *
	 * @return true if the engine is ready to accept commands for this program
	 */
	public boolean ensureInitialized() {
		ProgramManager pm = tool.getService(ProgramManager.class);
		if (pm == null) {
			return false;
		}
		Program program = pm.getCurrentProgram();
		if (program == null) {
			return false;
		}

		String path = program.getExecutablePath();
		if (path == null || path.isBlank()) {
			Msg.showError(this, null, "Ponce4Ghidra",
				"Could not determine the file path of the current program. " +
				"The original binary must exist on disk for angr to load it.");
			return false;
		}

		if (!engineManager.isRunning()) {
			Msg.showError(this, null, "Ponce4Ghidra",
				"Symbolic execution engine is not running.");
			return false;
		}

		try {
			// Ask the engine which binary it has rather than trusting a field of our
			// own. The field goes stale whenever the engine is restarted, and calling
			// init again for a binary that is already loaded is not harmless: init()
			// clears the engine's symbolized variables, which exist nowhere else.
			// The user sees that as "Nothing is symbolized" on a search they had
			// already set up, with no hint that the inputs were dropped in between.
			EngineProtocol.Response state = engineManager.getState();
			if (!state.isOk()) {
				Msg.showError(this, null, "Ponce4Ghidra",
					"The symbolic execution engine did not answer the state query: " +
					state.getMessage());
				return false;
			}

			if (!state.hasData("binary")) {
				// A missing "binary" key is not a null one. Null says nothing is
				// loaded and initializing is the right move; missing says this engine
				// predates the field and cannot tell us what it holds. Loading anyway
				// would clear whatever it does hold, blind -- and the symbolized
				// variables live in the engine and nowhere else, so that is the user's
				// work going away with no way to notice in advance.
				Msg.showError(this, null, "Ponce4Ghidra",
					"The running angr engine does not report which binary it has loaded, " +
					"so the plugin cannot tell whether loading\n" + path +
					"\nwould discard your symbolized variables. Nothing was sent.\n\n" +
					"This means the engine is an older build than the plugin. Note that " +
					"the plugin attaches to whatever already holds port 13370, including " +
					"an engine started by hand. Restart that engine (or restart Ghidra) " +
					"and try again.");
				return false;
			}

			String loaded = state.getDataString("binary");
			if (path.equals(loaded)) {
				return true;
			}
			if (loaded != null) {
				// Something else is loaded, so everything on the panel describes that
				// binary and none of it applies to this program.
				stateProvider.clearAll();
			}

			EngineProtocol.Response resp = engineManager.sendCommand(
				EngineProtocol.initCmd(path));
			if (resp.isOk()) {
				Msg.info(this, "Initialized angr with: " + path);
				return true;
			}

			Msg.showError(this, null, "Ponce4Ghidra",
				"Failed to load binary in angr: " + resp.getMessage() +
				"\n\nPath: " + path +
				"\nMake sure the original binary file exists at this path.");
			return false;
		}
		catch (IOException e) {
			// The socket is broken (engine died or was restarted under us). Drop it
			// so the next attempt starts a fresh engine instead of retrying a dead one.
			Msg.showError(this, null, "Ponce4Ghidra",
				"Lost connection to the symbolic execution engine: " + e.getMessage() +
				"\nIt will be restarted on the next command.");
			engineManager.stop();
			return false;
		}
	}

	public void saveSession() {
		ProgramManager pm = tool.getService(ProgramManager.class);
		if (pm == null) {
			return;
		}
		Program program = pm.getCurrentProgram();
		if (program == null) {
			return;
		}

		try {
			EngineProtocol.Response state = engineManager.getState();
			if (!state.isOk()) {
				return;
			}

			JsonArray logArray = state.getData().getAsJsonArray("command_log");
			String logJson = logArray != null ? logArray.toString() : "[]";

			SessionPersistence.save(program,
				stateProvider.getFindAddresses(),
				stateProvider.getAvoidAddresses(),
				logJson);
			stateProvider.setStatus("Session saved");
			Msg.info(this, "Session saved");
		}
		catch (Exception e) {
			Msg.warn(this, "Could not save session: " + e.getMessage());
		}
	}

	public void restoreSession() {
		ProgramManager pm = tool.getService(ProgramManager.class);
		if (pm == null) {
			return;
		}
		Program program = pm.getCurrentProgram();
		if (program == null || !SessionPersistence.hasSavedSession(program)) {
			stateProvider.setStatus("No saved session found");
			return;
		}

		for (String addr : SessionPersistence.loadFind(program)) {
			stateProvider.addFindAddress(addr);
		}
		for (String addr : SessionPersistence.loadAvoid(program)) {
			stateProvider.addAvoidAddress(addr);
		}

		String logJson = SessionPersistence.loadCommandLog(program);
		if (logJson != null && !"[]".equals(logJson)) {
			try {
				ensureEngineStarted();
				if (engineManager.isRunning()) {
					EngineProtocol.Response resp = engineManager.sendCommand(
						EngineProtocol.replayCmd(logJson));
					if (resp.isOk()) {
						stateProvider.setStatus("Session restored");
						Msg.info(this, "Session restored from saved data");
					}
					else {
						stateProvider.setStatus("Restore failed: " + resp.getMessage());
						Msg.warn(this, "Session replay failed: " + resp.getMessage());
					}
				}
			}
			catch (Exception e) {
				stateProvider.setStatus("Restore failed");
				Msg.warn(this, "Could not replay session: " + e.getMessage());
			}
		}
		else {
			stateProvider.setStatus("Session restored (targets only, no commands to replay)");
		}
	}

	@Override
	protected void dispose() {
		pathHighlighter.clearAll();
		engineManager.dispose();
		super.dispose();
	}
}
