package ponce4ghidra.ui;

import java.math.BigInteger;

/**
 * One solved variable, as the engine reported it.
 * <p>
 * The reading that matters depends on what the variable is: for a symbolized
 * password buffer the answer <em>is</em> the text, for a symbolized register it
 * is the number. The engine hands back both, so the Results table shows both
 * rather than committing to one and making the user convert in their head --
 * which is what the old display did by leading with a hex integer.
 */
public record Solution(String name, byte[] bytes, BigInteger value) {

	/**
	 * The bytes as text, with anything unprintable escaped as {@code \xNN} --
	 * so a binary value stays readable instead of turning into blank cells,
	 * and the result is what you would paste into a program.
	 */
	public String text() {
		StringBuilder text = new StringBuilder(bytes.length);
		for (byte b : bytes) {
			int unsigned = b & 0xff;
			if (unsigned >= 0x20 && unsigned < 0x7f) {
				text.append((char) unsigned);
			}
			else {
				text.append(String.format("\\x%02x", unsigned));
			}
		}
		return text.toString();
	}

	/** The bytes in address order, e.g. {@code "50 34 52 67"}. */
	public String hex() {
		StringBuilder hex = new StringBuilder(bytes.length * 3);
		for (byte b : bytes) {
			if (hex.length() > 0) {
				hex.append(' ');
			}
			hex.append(String.format("%02x", b & 0xff));
		}
		return hex.toString();
	}

	/** The value as a number, for when the variable is a scalar. Empty if unknown. */
	public String valueText() {
		if (value == null) {
			return "";
		}
		return "0x" + value.toString(16) + " (" + value + ")";
	}

	/** Whether the whole value is printable text, so {@link #text()} is the answer. */
	public boolean isText() {
		if (bytes.length == 0) {
			return false;
		}
		for (byte b : bytes) {
			int unsigned = b & 0xff;
			if (unsigned < 0x20 || unsigned >= 0x7f) {
				return false;
			}
		}
		return true;
	}
}
