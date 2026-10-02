package ponce4ghidra.actions;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.action.ToolBarData;
import ghidra.util.Msg;
import ponce4ghidra.Ponce4GhidraPlugin;
import ponce4ghidra.engine.EngineProtocol;
import ponce4ghidra.engine.EngineProtocol.Response;
import ponce4ghidra.ui.Icons;
import ponce4ghidra.ui.Solution;

public class SolveAction extends DockingAction {

	private static final int DEFAULT_TIMEOUT = 60;
	private static final int MAX_SOLUTIONS = 5;
	private final Ponce4GhidraPlugin plugin;

	public SolveAction(Ponce4GhidraPlugin plugin) {
		super("Solve Constraints", plugin.getName());
		this.plugin = plugin;

		setMenuBarData(new MenuData(
			new String[] { "Ponce4Ghidra", "Solve Constraints" },
			Icons.SOLVE, "Ponce"));

		setToolBarData(new ToolBarData(Icons.SOLVE, "Ponce"));

		plugin.getTool().addAction(this);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		// The solve itself acts on engine state rather than on the click, but being
		// enabled in every context -- including ones with no program at all -- is
		// what turns "right-click in the wrong pane" into a confusing error.
		return ActionContexts.isTarget(context);
	}

	@Override
	public void actionPerformed(ActionContext context) {
		plugin.ensureEngineStarted();

		if (!plugin.getEngineManager().isRunning()) {
			return;
		}

		if (!initAndSyncTargets()) {
			return;
		}

		plugin.getStateProvider().setStatus("Exploring paths...");

		plugin.getEngineManager().sendCommandWithProgressAsync(
			EngineProtocol.exploreCmdWithProgress(DEFAULT_TIMEOUT, true, true),
			progress -> SwingUtilities.invokeLater(() -> {
				JsonObject d = progress.getData();
				if (d != null) {
					plugin.getStateProvider().setStatus(String.format(
						"Exploring: %d active, %d found, step %d (%ss)",
						intField(d, "active"), intField(d, "found"),
						intField(d, "steps"),
						d.has("elapsed") ? d.get("elapsed").getAsString() : "?"));
				}
			}))
			.thenCompose(exploreResponse -> {
				if (exploreResponse.isError()) {
					SwingUtilities.invokeLater(() -> {
						plugin.getStateProvider().setStatus("Exploration failed");
						Msg.showError(this, null, "Ponce4Ghidra",
							"Exploration failed: " + exploreResponse.getMessage());
					});
					return CompletableFuture.completedFuture(null);
				}

				JsonObject data = exploreResponse.getData();
				int found = data != null && data.has("found_count")
					? data.get("found_count").getAsInt() : 0;

				if (found == 0) {
					// Solving now would only report "no solution state available",
					// which hides the reason the search came back empty.
					String detail = describeEmptyExploration(data);
					SwingUtilities.invokeLater(() -> {
						plugin.getStateProvider().setStatus("No path reached a Find target");
						Msg.showError(this, null, "Ponce4Ghidra",
							"Exploration reached no Find target.\n\n" + detail +
							"\nThe engine explores from the program's entry point, so a " +
							"Find target is only reachable if execution can get there " +
							"from the start. Symbolizing the input usually helps: " +
							"without it, branches on the input are taken concretely and " +
							"only one path is followed.");
					});
					return CompletableFuture.completedFuture(null);
				}

				SwingUtilities.invokeLater(() -> plugin.getStateProvider().setStatus(
					"Exploring done (" + found + " paths found). Solving..."));

				return plugin.getEngineManager().sendCommandAsync(
					EngineProtocol.solveAllCmd(MAX_SOLUTIONS));
			})
			.thenAccept(solveResponse -> {
				if (solveResponse == null) {
					return;
				}
				SwingUtilities.invokeLater(() -> handleSolveResult(solveResponse));
			})
			.exceptionally(e -> {
				SwingUtilities.invokeLater(() -> {
					plugin.getStateProvider().setStatus("Error");
					Msg.showError(this, null, "Ponce4Ghidra",
						"Solve failed: " + e.getMessage());
				});
				return null;
			});
	}

	private boolean initAndSyncTargets() {
		List<String> findAddrs = plugin.getStateProvider().getFindAddresses();
		List<String> avoidAddrs = plugin.getStateProvider().getAvoidAddresses();

		if (findAddrs.isEmpty()) {
			JOptionPane.showMessageDialog(null,
				"No Find Target addresses set.\n\n" +
				"How to use Ponce4Ghidra:\n" +
				"  1. Right-click an address in the Listing or Decompiler view\n" +
				"  2. Select 'Ponce4Ghidra > Set as Find Target'\n" +
				"     (the address you WANT the solver to reach)\n" +
				"  3. Optionally: right-click another address\n" +
				"     > 'Set as Avoid' (to skip wrong branches)\n" +
				"  4. Then click 'Solve Constraints'\n\n" +
				"Tip: In check_password, set 'return 1' as Find\n" +
				"and 'return 0' as Avoid.",
				"Ponce4Ghidra - Setup Required",
				JOptionPane.INFORMATION_MESSAGE);
			return false;
		}

		try {
			if (!plugin.ensureInitialized()) {
				return false;
			}

			Response state = plugin.getEngineManager().getState();
			if (state.isOk()) {
				JsonArray vars = state.getData().getAsJsonArray("variables");
				if (vars == null || vars.isEmpty()) {
					JOptionPane.showMessageDialog(null,
						"Nothing is symbolized, so there is nothing to solve for.\n\n" +
						"Before clicking Solve, tell the engine what the unknown input is:\n" +
						"  • Ponce4Ghidra > Symbolize argv[N]  —  the program's command-line argument\n" +
						"  • Ponce4Ghidra > Symbolize Function Argument  —  a function parameter\n" +
						"  • Ponce4Ghidra > Symbolize Register / Memory  —  a raw location\n\n" +
						"Without a symbolic variable the engine explores concretely (only\n" +
						"one fixed path) and has nothing to solve for even if it reaches\n" +
						"the Find target.",
						"Ponce4Ghidra — Symbolize First",
						JOptionPane.WARNING_MESSAGE);
					return false;
				}
			}

			// Sync find/avoid addresses
			List<Long> findLongs = findAddrs.stream()
				.map(s -> Long.decode(s.startsWith("0x") ? s : "0x" + s))
				.collect(Collectors.toList());
			plugin.getEngineManager().sendCommand(EngineProtocol.setFindCmd(findLongs));

			// Always send avoid, even when empty: the engine replaces its avoid list,
			// so skipping this would leave targets from a previous run in place.
			List<Long> avoidLongs = avoidAddrs.stream()
				.map(s -> Long.decode(s.startsWith("0x") ? s : "0x" + s))
				.collect(Collectors.toList());
			plugin.getEngineManager().sendCommand(EngineProtocol.setAvoidCmd(avoidLongs));

			Msg.info(this, "Ready: find=" + findAddrs + " avoid=" + avoidAddrs);
			return true;
		}
		catch (Exception e) {
			Msg.showError(this, null, "Ponce4Ghidra",
				"Failed to init/sync: " + e.getMessage());
			return false;
		}
	}

	/**
	 * Summarizes where the paths went when none of them reached a Find target.
	 */
	private static String describeEmptyExploration(JsonObject data) {
		if (data == null) {
			return "";
		}
		StringBuilder sb = new StringBuilder();
		sb.append("Where the paths ended up:\n");
		sb.append("  dead-ended:  ").append(intField(data, "deadended_count")).append('\n');
		sb.append("  avoided:     ").append(intField(data, "avoided_count")).append('\n');
		sb.append("  still active (hit the timeout): ")
			.append(intField(data, "active_count")).append('\n');
		sb.append("  errored:     ").append(intField(data, "errored_count")).append('\n');

		if (data.has("error_samples")) {
			for (JsonElement sample : data.getAsJsonArray("error_samples")) {
				sb.append("\n  error: ").append(sample.getAsString());
			}
			sb.append('\n');
		}
		return sb.toString();
	}

	private static int intField(JsonObject data, String key) {
		return data.has(key) ? data.get(key).getAsInt() : 0;
	}

	private void handleSolveResult(Response response) {
		if (response.isError()) {
			plugin.getStateProvider().setStatus("Solve failed: " + response.getMessage());
			Msg.showError(this, null, "Ponce4Ghidra", response.getMessage());
			return;
		}

		JsonObject data = response.getData();
		if (data == null) {
			plugin.getStateProvider().setStatus("No solution found");
			return;
		}

		List<Solution> solutions = new ArrayList<>();
		int varCount = 0;
		if (data.has("solutions")) {
			JsonObject reported = data.getAsJsonObject("solutions");
			for (String varName : reported.keySet()) {
				varCount++;
				JsonElement varSolutions = reported.get(varName);
				if (varSolutions.isJsonArray()) {
					JsonArray array = varSolutions.getAsJsonArray();
					int total = array.size();
					for (int i = 0; i < total; i++) {
						JsonObject sol = array.get(i).getAsJsonObject();
						String label = total > 1
							? varName + " [" + (i + 1) + "/" + total + "]"
							: varName;
						Solution solution = new Solution(label, readBytes(sol), readValue(sol));
						solutions.add(solution);
						if (i == 0) {
							plugin.getStateProvider().updateVariableValue(
								varName, solution.valueText());
						}
					}
				}
				else {
					JsonObject sol = varSolutions.getAsJsonObject();
					Solution solution = new Solution(varName, readBytes(sol), readValue(sol));
					solutions.add(solution);
					plugin.getStateProvider().updateVariableValue(varName, solution.valueText());
				}
			}
		}

		plugin.getStateProvider().setSolutions(solutions);
		plugin.getStateProvider().setStatus(describeSolutions(solutions, varCount));

		try {
			Response constraintsResp = plugin.getEngineManager().sendCommand(
				EngineProtocol.getConstraintsCmd("found", 0));
			if (constraintsResp.isOk()) {
				JsonObject cData = constraintsResp.getData();
				if (cData != null && cData.has("constraints")) {
					JsonArray cArray = cData.getAsJsonArray("constraints");
					List<String> texts = new ArrayList<>();
					for (JsonElement c : cArray) {
						JsonObject co = c.getAsJsonObject();
						texts.add(co.has("text") ? co.get("text").getAsString() : c.toString());
					}
					plugin.getStateProvider().setConstraints("found", 0, texts);
				}
			}
		}
		catch (IOException e) {
			Msg.warn(this, "Could not fetch constraints: " + e.getMessage());
		}

		plugin.saveSession();
	}

	private static byte[] readBytes(JsonObject solution) {
		if (!solution.has("value_bytes")) {
			return new byte[0];
		}
		JsonArray array = solution.getAsJsonArray("value_bytes");
		byte[] bytes = new byte[array.size()];
		for (int i = 0; i < bytes.length; i++) {
			bytes[i] = (byte) (array.get(i).getAsInt() & 0xff);
		}
		return bytes;
	}

	/**
	 * The engine reports value_int as an arbitrary-precision number, so a 64-bit
	 * symbol can be larger than a long. Reading it as a BigInteger keeps one
	 * oversized variable from failing the whole solution set; the bytes are
	 * reported separately and are always there.
	 */
	private static BigInteger readValue(JsonObject solution) {
		if (!solution.has("value_int")) {
			return null;
		}
		try {
			return solution.get("value_int").getAsBigInteger();
		}
		catch (RuntimeException e) {
			return null;
		}
	}

	private static String describeSolutions(List<Solution> solutions, int varCount) {
		if (solutions.isEmpty()) {
			return "Solved - the engine reported no variables";
		}
		Solution first = solutions.get(0);
		if (varCount == 1 && solutions.size() == 1 && first.isText()) {
			return "Solved: " + first.name() + " = " + first.text();
		}
		if (solutions.size() > varCount) {
			return "Solved " + varCount + " variable"
				+ (varCount == 1 ? "" : "s") + " (" + solutions.size() + " solutions)";
		}
		return "Solved " + varCount + " variable"
			+ (varCount == 1 ? "" : "s");
	}
}
