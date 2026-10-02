package ponce4ghidra.highlight;

import java.awt.Color;
import java.util.List;

import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

public class PathHighlighter {

	private static final Color FIND_COLOR = new Color(0, 180, 0, 80);
	private static final Color AVOID_COLOR = new Color(220, 0, 0, 80);
	private static final Color SYMBOLIC_COLOR = new Color(0, 100, 220, 80);
	private static final Color EXPLORED_COLOR = new Color(180, 180, 0, 60);

	private final PluginTool tool;

	public PathHighlighter(PluginTool tool) {
		this.tool = tool;
	}

	public void highlightFound(List<Address> addresses, Program program) {
		setColors(addresses, FIND_COLOR, program);
	}

	public void highlightAvoided(List<Address> addresses, Program program) {
		setColors(addresses, AVOID_COLOR, program);
	}

	public void highlightSymbolic(List<Address> addresses, Program program) {
		setColors(addresses, SYMBOLIC_COLOR, program);
	}

	public void highlightExplored(List<Address> addresses, Program program) {
		setColors(addresses, EXPLORED_COLOR, program);
	}

	public void clearAll() {
		ColorizingService service = tool.getService(ColorizingService.class);
		if (service == null) {
			return;
		}
		// ColorizingService clears per-program; clearing without a program reference
		// is handled by the plugin's dispose lifecycle
	}

	private void setColors(List<Address> addresses, Color color, Program program) {
		ColorizingService service = tool.getService(ColorizingService.class);
		if (service == null) {
			Msg.warn(this, "ColorizingService not available");
			return;
		}

		int txId = program.startTransaction("Ponce4Ghidra highlight");
		try {
			for (Address addr : addresses) {
				service.setBackgroundColor(addr, addr, color);
			}
		}
		finally {
			program.endTransaction(txId, true);
		}
	}
}
