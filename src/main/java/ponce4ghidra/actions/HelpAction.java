package ponce4ghidra.actions;

import javax.swing.JOptionPane;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ponce4ghidra.Ponce4GhidraPlugin;
import ponce4ghidra.ui.Icons;

public class HelpAction extends DockingAction {

	private static final String GUIDE =
		"Ponce4Ghidra — Quick Start Guide\n" +
		"=================================\n\n" +
		"1. SET FIND TARGET\n" +
		"   Right-click an address > Ponce4Ghidra > Set as Find Target\n" +
		"   Pick the address you WANT the solver to reach.\n" +
		"   Example: the instruction that returns \"success\" or 1.\n\n" +
		"2. SET AVOID (optional)\n" +
		"   Right-click another address > Set as Avoid Target\n" +
		"   Pick addresses the solver should NOT reach.\n" +
		"   Example: the instruction that returns \"failure\" or 0.\n\n" +
		"3. SYMBOLIZE THE INPUT\n" +
		"   Tell the engine which part of the input is unknown:\n\n" +
		"   • Symbolize argv[N]  —  a command-line argument\n" +
		"     Size = expected input length in bytes (guess high if unsure).\n\n" +
		"   • Symbolize Function Argument  —  a function's parameter\n" +
		"     Right-click inside the function. Size = byte length of the\n" +
		"     buffer the parameter points to (4 for a 4-char password, etc.).\n\n" +
		"   • Symbolize Register  —  mark a CPU register as symbolic\n" +
		"     Use when the unknown is a scalar (int/long), not a buffer.\n\n" +
		"   • Symbolize Memory  —  mark a memory range as symbolic\n" +
		"     Use when the unknown lives at a known fixed address.\n\n" +
		"   Without this step the engine explores concretely (one fixed path)\n" +
		"   and has nothing to solve for.\n\n" +
		"4. SOLVE CONSTRAINTS\n" +
		"   Menu bar or right-click > Ponce4Ghidra > Solve Constraints.\n" +
		"   The engine explores all paths, finds one that reaches the\n" +
		"   Find target while avoiding the Avoid targets, then solves\n" +
		"   for the symbolic variable values that make it happen.\n\n" +
		"5. READ THE RESULTS\n" +
		"   The Results tab shows one row per symbolic variable:\n" +
		"     Variable — the name you gave it (e.g. argv1)\n" +
		"     String   — printable ASCII (the answer for text inputs)\n" +
		"     Hex      — raw bytes in address order\n" +
		"     Int      — numeric value\n" +
		"   Right-click a row to copy any column to the clipboard.\n\n" +
		"SIZE GUIDE\n" +
		"   Too short = may miss the answer (not enough bytes to express it).\n" +
		"   Too long  = slower, but still correct. When in doubt, go bigger.\n\n" +
		"HOW IT WORKS (SAT/SMT Solving)\n" +
		"   Ponce4Ghidra uses angr's symbolic execution engine + Z3 SMT solver.\n\n" +
		"   1. Symbolic variables replace concrete input with math unknowns\n" +
		"   2. Each branch the program takes adds a constraint:\n" +
		"        if (input[0] == 'P')  ->  constraint: byte0 == 0x50\n" +
		"   3. Both sides of every branch are explored simultaneously (fork)\n" +
		"   4. When a path reaches the Find target, all its constraints\n" +
		"      are sent to Z3 (an SMT solver -- not linear algebra, but\n" +
		"      boolean satisfiability + bit-vector arithmetic)\n" +
		"   5. Z3 finds concrete values satisfying all constraints at once\n\n" +
		"   The Constraints tab shows exactly which constraints were collected.\n\n" +
		"   Key concept: this is equation solving, not brute force.\n" +
		"   A 16-byte input has 2^128 possibilities -- too many to try.\n" +
		"   But the constraints reduce it to a system Z3 solves in seconds.\n\n" +
		"WHEN TO USE WHICH SYMBOLIZE\n" +
		"   Symbolize argv[N]:\n" +
		"     - The program reads input from the command line\n" +
		"     - You want to explore from the entry point (main)\n" +
		"     - The binary is small/simple (angr runs the whole program)\n" +
		"     - Example: ./crackme <password>\n\n" +
		"   Symbolize Function Argument:\n" +
		"     - You know which function checks the input\n" +
		"     - The binary is large or complex (skip everything before the function)\n" +
		"     - You are analyzing a .so library (no entry point)\n" +
		"     - You only care about one function's logic, not the whole program\n" +
		"     - Example: validate_license(char *key) -- symbolize rdi, size=19\n\n" +
		"   Symbolize Register:\n" +
		"     - The unknown is a scalar value (int, long), not a buffer\n" +
		"     - Example: a function returns different values based on a flag register\n\n" +
		"   Symbolize Memory:\n" +
		"     - The unknown is at a known fixed memory address\n" +
		"     - Example: a global variable or a struct field at a computed address\n\n" +
		"   Rule of thumb: start with Function Argument (faster, targeted).\n" +
		"   Use argv only when you need the whole program's execution context.";

	public HelpAction(Ponce4GhidraPlugin plugin) {
		super("Quick Start Guide", plugin.getName());

		setMenuBarData(new MenuData(
			new String[] { "Ponce4Ghidra", "Quick Start Guide" },
			Icons.HELP, "Ponce"));

		plugin.getTool().addAction(this);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return true;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		JOptionPane.showMessageDialog(null, GUIDE,
			"Ponce4Ghidra — Quick Start Guide",
			JOptionPane.INFORMATION_MESSAGE);
	}
}
