package ponce4ghidra.actions;

import javax.swing.SwingUtilities;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.context.NavigatableActionContext;
import ghidra.program.model.address.Address;
import ghidra.util.Msg;
import ponce4ghidra.Ponce4GhidraPlugin;
import ponce4ghidra.engine.EngineProtocol;
import ponce4ghidra.ui.Icons;

public class SymbolizeMemoryAction extends DockingAction {

	private final Ponce4GhidraPlugin plugin;

	public SymbolizeMemoryAction(Ponce4GhidraPlugin plugin) {
		super("Symbolize Memory", plugin.getName());
		this.plugin = plugin;

		setPopupMenuData(new MenuData(
			new String[] { "Ponce4Ghidra", "Symbolize Memory..." },
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

		Integer size = Prompts.askInt(plugin, "Symbolize Memory",
			"Size in bytes:", "4");
		if (size == null) {
			return;
		}

		Address addr = target.getAddress();

		plugin.ensureEngineStarted();

		plugin.getEngineManager().sendCommandAsync(
			EngineProtocol.symbolizeMemCmd(addr.getOffset(), size, addr.getOffset()))
			.thenAccept(response -> SwingUtilities.invokeLater(() -> {
				if (!response.isOk()) {
					Msg.showError(this, null, "Ponce4Ghidra",
						"Failed to symbolize: " + response.getMessage());
					return;
				}

				// The engine's own name for the buffer, so this row matches the names
				// that come back in the solution set.
				String varName = response.getDataString("name");
				if (varName == null) {
					varName = String.format("mem_0x%x_%d", addr.getOffset(), size);
				}

				plugin.getStateProvider().addVariable(varName, "memory",
					addr.toString() + " [" + size + " bytes]", "pending");
				Msg.info(this, "Symbolized " + varName + " at " + addr +
					" (" + size + " bytes)");
			}))
			.exceptionally(e -> {
				Msg.showError(this, null, "Ponce4Ghidra",
					"Failed to symbolize memory: " + e.getMessage());
				return null;
			});
	}
}
