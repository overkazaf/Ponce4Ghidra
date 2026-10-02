package ponce4ghidra.actions;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ponce4ghidra.Ponce4GhidraPlugin;
import ponce4ghidra.ui.Icons;

public class RestoreSessionAction extends DockingAction {

	private final Ponce4GhidraPlugin plugin;

	public RestoreSessionAction(Ponce4GhidraPlugin plugin) {
		super("Restore Session", plugin.getName());
		this.plugin = plugin;

		setMenuBarData(new MenuData(
			new String[] { "Ponce4Ghidra", "Restore Session" },
			Icons.RESTORE, "Ponce"));

		plugin.getTool().addAction(this);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return true;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		plugin.restoreSession();
	}
}
