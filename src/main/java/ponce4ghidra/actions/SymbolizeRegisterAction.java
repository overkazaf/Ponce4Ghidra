package ponce4ghidra.actions;

import java.util.Collections;

import javax.swing.SwingUtilities;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.context.NavigatableActionContext;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ponce4ghidra.Ponce4GhidraPlugin;
import ponce4ghidra.engine.EngineProtocol;
import ponce4ghidra.engine.EngineProtocol.Response;
import ponce4ghidra.ui.Icons;

public class SymbolizeRegisterAction extends DockingAction {

	private final Ponce4GhidraPlugin plugin;

	public SymbolizeRegisterAction(Ponce4GhidraPlugin plugin) {
		super("Symbolize Register", plugin.getName());
		this.plugin = plugin;

		setPopupMenuData(new MenuData(
			new String[] { "Ponce4Ghidra", "Symbolize Register..." },
			Icons.SYMBOLIZE, "Ponce"));

		plugin.getTool().addAction(this);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return ActionContexts.isTarget(context);
	}

	@Override
	public void actionPerformed(ActionContext context) {
		NavigatableActionContext target = ActionContexts.target(context);
		if (target == null) {
			return;
		}

		String regName = Prompts.ask(plugin, "Symbolize Register",
			"Register name (e.g., rdi, rsi, eax):", "rdi");
		if (regName == null) {
			return;
		}

		Address addr = target.getAddress();
		Program program = target.getProgram();

		plugin.ensureEngineStarted();

		plugin.getEngineManager().sendCommandAsync(
			EngineProtocol.symbolizeRegCmd(regName, addr.getOffset()))
			.thenAccept(response -> SwingUtilities.invokeLater(
				() -> handleResponse(response, regName, addr, program)))
			.exceptionally(e -> {
				Msg.showError(this, null, "Ponce4Ghidra",
					"Failed to symbolize register: " + e.getMessage());
				return null;
			});
	}

	private void handleResponse(Response response, String regName, Address addr, Program program) {
		if (!response.isOk()) {
			Msg.showError(this, null, "Ponce4Ghidra",
				"Failed to symbolize: " + response.getMessage());
			return;
		}

		// Use the engine's name for the variable. Showing the register name instead
		// would leave this row unmatchable against the names in the solution set,
		// which is what a per-variable solve keys off.
		String varName = response.getDataString("name");
		if (varName == null) {
			varName = regName;
		}

		plugin.getStateProvider().addVariable(varName, "register", addr.toString(), "pending");
		plugin.getPathHighlighter().highlightSymbolic(Collections.singletonList(addr), program);
		Msg.info(this, "Symbolized " + varName + " at " + addr);
	}
}
