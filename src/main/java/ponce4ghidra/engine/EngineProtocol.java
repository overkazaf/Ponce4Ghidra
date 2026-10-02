package ponce4ghidra.engine;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

public class EngineProtocol {

	private static final Gson GSON = new GsonBuilder().create();

	public static class Command {
		private final String type;
		private final Map<String, Object> params;

		public Command(String type, Map<String, Object> params) {
			this.type = type;
			this.params = params;
		}

		public String getType() {
			return type;
		}

		public Map<String, Object> getParams() {
			return params;
		}
	}

	public static class Response {
		private String status;
		private JsonObject data;
		private String message;

		public boolean isOk() {
			return "ok".equals(status);
		}

		public boolean isError() {
			return "error".equals(status);
		}

		public boolean isProgress() {
			return "progress".equals(status);
		}

		public String getStatus() {
			return status;
		}

		public JsonObject getData() {
			return data;
		}

		/**
		 * Whether the engine reported this field at all, as opposed to reporting null
		 * for it. The two mean different things: "binary": null is the engine saying
		 * nothing is loaded, while a missing "binary" is an engine that predates the
		 * field. Reading the second as the first is what turns a stale engine into a
		 * wiped symbolic state.
		 */
		public boolean hasData(String key) {
			return data != null && data.has(key);
		}

		public String getMessage() {
			return message;
		}

		public String getDataString(String key) {
			if (data == null || !data.has(key)) {
				return null;
			}
			JsonElement el = data.get(key);
			return el.isJsonNull() ? null : el.getAsString();
		}

		public long getDataLong(String key, long defaultValue) {
			if (data == null || !data.has(key)) {
				return defaultValue;
			}
			return data.get(key).getAsLong();
		}

		public boolean getDataBoolean(String key, boolean defaultValue) {
			if (data == null || !data.has(key)) {
				return defaultValue;
			}
			JsonElement el = data.get(key);
			return el.isJsonNull() ? defaultValue : el.getAsBoolean();
		}
	}

	public static String serialize(Command cmd) {
		return GSON.toJson(cmd);
	}

	public static Response deserialize(String json) {
		return GSON.fromJson(json, Response.class);
	}

	public static Command initCmd(String binaryPath) {
		Map<String, Object> params = new HashMap<>();
		params.put("binary_path", binaryPath);
		return new Command("init", params);
	}

	public static Command symbolizeRegCmd(String regName, long stateAddr) {
		Map<String, Object> params = new HashMap<>();
		params.put("reg_name", regName);
		params.put("state_addr", stateAddr);
		return new Command("symbolize_register", params);
	}

	public static Command symbolizeMemCmd(long addr, int size, long stateAddr) {
		Map<String, Object> params = new HashMap<>();
		params.put("addr", addr);
		params.put("size", size);
		params.put("state_addr", stateAddr);
		return new Command("symbolize_memory", params);
	}

	public static Command symbolizeFunctionArgCmd(long funcAddr, String regName, int size, String name) {
		Map<String, Object> params = new HashMap<>();
		params.put("func_addr", funcAddr);
		params.put("reg_name", regName);
		params.put("size", size);
		if (name != null && !name.isBlank()) {
			params.put("name", name);
		}
		return new Command("symbolize_function_arg", params);
	}

	public static Command symbolizeArgvCmd(int size, int index, String name) {
		Map<String, Object> params = new HashMap<>();
		params.put("size", size);
		params.put("index", index);
		if (name != null && !name.isBlank()) {
			params.put("name", name);
		}
		return new Command("symbolize_argv", params);
	}

	public static Command setFindCmd(List<Long> addresses) {
		Map<String, Object> params = new HashMap<>();
		params.put("addresses", addresses);
		return new Command("set_find", params);
	}

	public static Command setAvoidCmd(List<Long> addresses) {
		Map<String, Object> params = new HashMap<>();
		params.put("addresses", addresses);
		return new Command("set_avoid", params);
	}

	public static Command exploreCmd(int timeoutSec) {
		return exploreCmd(timeoutSec, false, false);
	}

	public static Command exploreCmd(int timeoutSec, boolean veritesting) {
		return exploreCmd(timeoutSec, veritesting, false);
	}

	public static Command exploreCmd(int timeoutSec, boolean veritesting, boolean unicorn) {
		Map<String, Object> params = new HashMap<>();
		params.put("timeout_sec", timeoutSec);
		if (veritesting) {
			params.put("veritesting", true);
		}
		if (unicorn) {
			params.put("unicorn", true);
		}
		return new Command("explore", params);
	}

	public static Command exploreCmdWithProgress(int timeoutSec) {
		return exploreCmdWithProgress(timeoutSec, false, false);
	}

	public static Command exploreCmdWithProgress(int timeoutSec, boolean veritesting) {
		return exploreCmdWithProgress(timeoutSec, veritesting, false);
	}

	public static Command exploreCmdWithProgress(int timeoutSec, boolean veritesting, boolean unicorn) {
		Map<String, Object> params = new HashMap<>();
		params.put("timeout_sec", timeoutSec);
		params.put("report_progress", true);
		if (veritesting) {
			params.put("veritesting", true);
		}
		if (unicorn) {
			params.put("unicorn", true);
		}
		return new Command("explore", params);
	}

	public static Command solveCmd(String varName) {
		Map<String, Object> params = new HashMap<>();
		params.put("var_name", varName);
		return new Command("solve", params);
	}

	public static Command solveAllCmd() {
		return solveAllCmd(1);
	}

	public static Command solveAllCmd(int maxSolutions) {
		Map<String, Object> params = new HashMap<>();
		if (maxSolutions > 1) {
			params.put("max_solutions", maxSolutions);
		}
		return new Command("solve", params);
	}

	public static Command getConstraintsCmd(String stash, int index) {
		Map<String, Object> params = new HashMap<>();
		params.put("stash", stash);
		params.put("index", index);
		return new Command("get_constraints", params);
	}

	public static Command replayCmd(String commandLogJson) {
		Map<String, Object> params = new HashMap<>();
		params.put("log", GSON.fromJson(commandLogJson, List.class));
		return new Command("replay", params);
	}

	public static Command getStateCmd() {
		return new Command("get_state", new HashMap<>());
	}

	public static Command negateBranchCmd(long branchAddr) {
		Map<String, Object> params = new HashMap<>();
		params.put("branch_addr", branchAddr);
		return new Command("negate_branch", params);
	}
}
