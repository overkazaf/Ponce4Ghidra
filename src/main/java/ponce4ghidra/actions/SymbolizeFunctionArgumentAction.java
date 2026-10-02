package ponce4ghidra.actions;

import java.util.Collections;

import javax.swing.SwingUtilities;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.context.NavigatableActionContext;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ponce4ghidra.Ponce4GhidraPlugin;
import ponce4ghidra.engine.EngineProtocol;
import ponce4ghidra.ui.Icons;

/**
 * Starts a search at a function, with one of its argument registers pointing at
 * a symbolic buffer.
 * <p>
 * Exploring from the program entry only finds a path if reaching the function is
 * part of that path. Starting inside the function skips whatever has to happen
 * first, and symbolizing the argument is what lets a check that branches on its
 * input produce more than one path.
 */
public class SymbolizeFunctionArgumentAction extends DockingAction {

	private final Ponce4GhidraPlugin plugin;

	public SymbolizeFunctionArgumentAction(Ponce4GhidraPlugin plugin) {
		super("Symbolize Function Argument", plugin.getName());
		this.plugin = plugin;

		setPopupMenuData(new MenuData(
			new String[] { "Ponce4Ghidra", "Symbolize Function Argument..." },
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
		Program program = target.getProgram();

		// Start at the function's entry point, not the line that was clicked:
		// the input has to be in place before the function runs, so a click on
		// any of its instructions should mean the same thing as a click on the
		// first one.
		Function function = program.getFunctionManager()
			.getFunctionContaining(target.getAddress());
		Address entry = function != null
			? function.getEntryPoint()
			: target.getAddress();

		String reg = Prompts.ask(plugin, "Symbolize Function Argument",
			"Argument register (e.g. rdi, rsi):", "rdi");
		if (reg == null) {
			return;
		}

		Integer size = Prompts.askInt(plugin, "Symbolize Function Argument",
			"Buffer size in bytes:", "8");
		if (size == null) {
			return;
		}

		plugin.ensureEngineStarted();

		plugin.getEngineManager().sendCommandAsync(
			EngineProtocol.symbolizeFunctionArgCmd(entry.getOffset(), reg, size, null))
			.thenAccept(response -> SwingUtilities.invokeLater(() -> {
				if (response.isOk()) {
					String varName = response.getDataString("name");
					if (varName == null) {
						varName = "arg_" + reg;
					}
					plugin.getStateProvider().addVariable(varName, "function argument",
						reg + " -> " + response.getDataString("addr") +
							" (" + size + " bytes)", "pending");
					plugin.getPathHighlighter().highlightSymbolic(
						Collections.singletonList(entry), program);
					plugin.getStateProvider().setStatus(
						"Search starts at " + entry + " with " + reg + " symbolized");
					Msg.info(this, "Symbolized " + reg + " at " + entry + " as " + varName +
						" (" + size + " bytes at " + response.getDataString("addr") + ")." +
						"\n\nSet a Find target - the address the function returns success " +
						"from - then run Solve.");
				}
				else {
					Msg.showError(this, null, "Ponce4Ghidra",
						"Failed to symbolize the argument: " + response.getMessage());
				}
			}))
			.exceptionally(e -> {
				Msg.showError(this, null, "Ponce4Ghidra",
					"Failed to symbolize the argument: " + e.getMessage());
				return null;
			});
	}
}
