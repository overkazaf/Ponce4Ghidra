package ponce4ghidra;

import java.util.ArrayList;
import java.util.List;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;

public class SessionPersistence {

	private static final String OPTIONS_NAME = "Ponce4Ghidra";
	private static final String KEY_FIND = "findAddresses";
	private static final String KEY_AVOID = "avoidAddresses";
	private static final String KEY_COMMAND_LOG = "commandLog";
	private static final Gson GSON = new Gson();

	public static void save(Program program, List<String> findAddrs,
			List<String> avoidAddrs, String commandLogJson) {
		int txId = program.startTransaction("Ponce4Ghidra save session");
		try {
			Options opts = program.getOptions(OPTIONS_NAME);
			opts.setString(KEY_FIND, GSON.toJson(findAddrs));
			opts.setString(KEY_AVOID, GSON.toJson(avoidAddrs));
			opts.setString(KEY_COMMAND_LOG, commandLogJson);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	public static boolean hasSavedSession(Program program) {
		Options opts = program.getOptions(OPTIONS_NAME);
		return opts.contains(KEY_COMMAND_LOG);
	}

	public static List<String> loadFind(Program program) {
		return loadStringList(program, KEY_FIND);
	}

	public static List<String> loadAvoid(Program program) {
		return loadStringList(program, KEY_AVOID);
	}

	public static String loadCommandLog(Program program) {
		Options opts = program.getOptions(OPTIONS_NAME);
		return opts.getString(KEY_COMMAND_LOG, null);
	}

	public static void clear(Program program) {
		int txId = program.startTransaction("Ponce4Ghidra clear session");
		try {
			Options opts = program.getOptions(OPTIONS_NAME);
			if (opts.contains(KEY_FIND)) {
				opts.removeOption(KEY_FIND);
			}
			if (opts.contains(KEY_AVOID)) {
				opts.removeOption(KEY_AVOID);
			}
			if (opts.contains(KEY_COMMAND_LOG)) {
				opts.removeOption(KEY_COMMAND_LOG);
			}
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	private static List<String> loadStringList(Program program, String key) {
		Options opts = program.getOptions(OPTIONS_NAME);
		String json = opts.getString(key, null);
		if (json == null) {
			return new ArrayList<>();
		}
		try {
			return GSON.fromJson(json, new TypeToken<List<String>>() {}.getType());
		}
		catch (Exception e) {
			return new ArrayList<>();
		}
	}
}
