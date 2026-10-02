package ponce4ghidra.actions;

import docking.widgets.OptionDialog;
import ghidra.util.Msg;
import ponce4ghidra.Ponce4GhidraPlugin;

/**
 * One-line input for the symbolize actions.
 * <p>
 * A dialog that closes and leaves the status bar untouched is indistinguishable
 * from a menu item that does nothing at all: press Escape, the window goes away,
 * and the user is left deciding whether the plugin worked. Every prompt here
 * reports what happened instead.
 * <p>
 * Cancelling and typing nothing get the same quiet treatment -- a status line,
 * no dialog -- because neither is a mistake worth interrupting for. A value that
 * cannot be parsed is, and gets a dialog.
 */
final class Prompts {

	private Prompts() {
	}

	/**
	 * Asks for one line of text.
	 *
	 * @return the trimmed answer, or null when the user cancelled or left it empty
	 */
	static String ask(Ponce4GhidraPlugin plugin, String title, String message, String initial) {
		String answer = OptionDialog.showInputSingleLineDialog(null, title, message, initial);
		if (answer == null) {
			plugin.getStateProvider().setStatus("Cancelled - nothing was sent");
			return null;
		}
		if (answer.isBlank()) {
			plugin.getStateProvider().setStatus("Nothing entered - nothing was sent");
			return null;
		}
		return answer.strip();
	}

	/**
	 * Asks for one line of text that has to parse as a number.
	 *
	 * @return the number, or null when the user cancelled, left it empty, or
	 *         typed something that is not a number
	 */
	static Integer askInt(Ponce4GhidraPlugin plugin, String title, String message, String initial) {
		String answer = ask(plugin, title, message, initial);
		if (answer == null) {
			return null;
		}
		try {
			return Integer.valueOf(answer);
		}
		catch (NumberFormatException e) {
			Msg.showError(Prompts.class, null, "Ponce4Ghidra",
				"\"" + answer + "\" is not a number, so nothing was sent.");
			plugin.getStateProvider().setStatus("Cancelled - not a number: " + answer);
			return null;
		}
	}
}
