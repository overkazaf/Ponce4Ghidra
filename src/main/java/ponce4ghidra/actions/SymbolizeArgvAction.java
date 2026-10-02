package ponce4ghidra.actions;

import javax.swing.SwingUtilities;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.util.Msg;
import ponce4ghidra.Ponce4GhidraPlugin;
import ponce4ghidra.engine.EngineProtocol;
import ponce4ghidra.ui.Icons;

/**
 * Runs the search from the program entry point with argv[index] pointing at a
 * symbolic buffer - the command line as the program itself sees it.
 * <p>
 * Where "Symbolize Function Argument" jumps straight into a check, this keeps
 * everything the program does on the way there, which is what makes it the way
 * to reproduce a real run.
 */
public class SymbolizeArgvAction extends DockingAction {

	private final Ponce4GhidraPlugin plugin;

	public SymbolizeArgvAction(Ponce4GhidraPlugin plugin) {
		super("Symbolize argv", plugin.getName());
		this.plugin = plugin;

		setPopupMenuData(new MenuData(
			new String[] { "Ponce4Ghidra", "Symbolize Program Argument (argv)..." },
			Icons.SYMBOLIZE, "Ponce"));

		plugin.getTool().addAction(this);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		// This one acts on the program rather than on the clicked address, but it
		// still needs a program context: right-clicking somewhere in the code is
		// what says which program is meant.
		return ActionContexts.isTarget(context);
	}

	@Override
	public void actionPerformed(ActionContext context) {
		if (ActionContexts.target(context) == null) {
			return;
		}

		Integer size = Prompts.askInt(plugin, "Symbolize argv",
			"Buffer size in bytes for the argument:", "8");
		if (size == null) {
			return;
		}

		Integer index = Prompts.askInt(plugin, "Symbolize argv",
			"Which argument (1 means argv[1]):", "1");
		if (index == null) {
			return;
		}

		plugin.ensureEngineStarted();

		plugin.getEngineManager().sendCommandAsync(
			EngineProtocol.symbolizeArgvCmd(size, index, null))
			.thenAccept(response -> SwingUtilities.invokeLater(() -> {
				if (response.isOk()) {
					String varName = response.getDataString("name");
					if (varName == null) {
						varName = "argv" + index;
					}
					plugin.getStateProvider().addVariable(varName, "argv",
						"argv[" + index + "] at " + response.getDataString("addr") +
							" (" + size + " bytes)", "pending");
					plugin.getStateProvider().setStatus(
						"Search starts at the entry point with argv[" + index + "] symbolized");
					Msg.info(this, "Symbolized argv[" + index + "] as " + varName +
						" (" + size + " bytes at " + response.getDataString("addr") + ")." +
						"\n\nThe search now starts at the program's entry point, so set a " +
						"Find target - where the program accepts the argument - and run Solve.");
				}
				else {
					Msg.showError(this, null, "Ponce4Ghidra",
						"Failed to symbolize argv: " + response.getMessage());
				}
			}))
			.exceptionally(e -> {
				Msg.showError(this, null, "Ponce4Ghidra",
					"Failed to symbolize argv: " + e.getMessage());
				return null;
			});
	}
}
