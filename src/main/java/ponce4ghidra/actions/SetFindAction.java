package ponce4ghidra.actions;

import java.util.Collections;

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

public class SetFindAction extends DockingAction {

	private final Ponce4GhidraPlugin plugin;

	public SetFindAction(Ponce4GhidraPlugin plugin) {
		super("Set Find Target", plugin.getName());
		this.plugin = plugin;

		setPopupMenuData(new MenuData(
			new String[] { "Ponce4Ghidra", "Set as Find Target" },
			Icons.FIND, "Ponce"));

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
		Address addr = target.getAddress();
		long offset = addr.getOffset();

		plugin.getStateProvider().addFindAddress(addr.toString());
		plugin.getPathHighlighter().highlightFound(
			Collections.singletonList(addr),
			target.getProgram());

		plugin.ensureEngineStarted();

		plugin.getEngineManager().sendCommandAsync(
			EngineProtocol.setFindCmd(Collections.singletonList(offset)))
			.thenAccept(response -> SwingUtilities.invokeLater(() -> {
				if (response.isOk()) {
					Msg.info(this, "Find target set: " + addr);
				}
				else {
					Msg.showError(this, null, "Ponce4Ghidra",
						"Failed to set find target: " + response.getMessage());
				}
			}))
			.exceptionally(e -> {
				Msg.showError(this, null, "Ponce4Ghidra", e.getMessage());
				return null;
			});
	}
}
