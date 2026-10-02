package ponce4ghidra.actions;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ponce4ghidra.Ponce4GhidraPlugin;
import ponce4ghidra.ui.Icons;

public class SaveSessionAction extends DockingAction {

	private final Ponce4GhidraPlugin plugin;

	public SaveSessionAction(Ponce4GhidraPlugin plugin) {
		super("Save Session", plugin.getName());
		this.plugin = plugin;

		setMenuBarData(new MenuData(
			new String[] { "Ponce4Ghidra", "Save Session" },
			Icons.SAVE, "Ponce"));

		plugin.getTool().addAction(this);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return true;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		plugin.saveSession();
	}
}
