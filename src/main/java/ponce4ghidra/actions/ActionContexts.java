package ponce4ghidra.actions;

import docking.ActionContext;
import ghidra.app.context.NavigatableActionContext;

/**
 * The single place that decides where a Ponce4Ghidra action may run.
 * <p>
 * The Listing and the Decompiler hand actions <em>sibling</em> context types --
 * {@code ListingActionContext} and
 * {@code ghidra.app.plugin.core.decompile.DecompilerActionContext} both extend
 * {@code NavigatableActionContext}, neither extends the other. Gating on
 * {@code ListingActionContext} therefore looks correct from the Listing while
 * leaving every menu item greyed out in the Decompiler, which is how you get a
 * user right-clicking the decompiled code and concluding the plugin is broken.
 * <p>
 * Ask here for the clicked address rather than naming a concrete context class,
 * so that a new action cannot repeat the mistake.
 */
final class ActionContexts {

	private ActionContexts() {
	}

	/**
	 * The right-clicked program location, or null when this context carries no
	 * address for the action to act on.
	 */
	static NavigatableActionContext target(ActionContext context) {
		if (context instanceof NavigatableActionContext navigable && navigable.getAddress() != null) {
			return navigable;
		}
		return null;
	}

	/** Whether an action should be enabled for this context. */
	static boolean isTarget(ActionContext context) {
		return target(context) != null;
	}
}
