package ponce4ghidra.ui;

import java.awt.Color;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;

import javax.swing.Icon;
import javax.swing.ImageIcon;

/**
 * Programmatic 16x16 toolbar icons so the plugin does not depend on external
 * image files or Ghidra's internal icon paths.
 */
public final class Icons {

	private static final int SIZE = 16;

	public static final Icon FIND = badge("F", new Color(0, 160, 0));
	public static final Icon AVOID = badge("A", new Color(200, 0, 0));
	public static final Icon SOLVE = badge("Σ", new Color(0, 100, 220));
	public static final Icon SYMBOLIZE = badge("S", new Color(140, 80, 200));
	public static final Icon CONSTRAINTS = badge("C", new Color(0, 140, 140));
	public static final Icon SAVE = badge("W", new Color(60, 120, 60));
	public static final Icon RESTORE = badge("R", new Color(60, 60, 160));
	public static final Icon HELP = badge("?", new Color(100, 100, 100));

	private Icons() {}

	private static Icon badge(String letter, Color color) {
		BufferedImage img = new BufferedImage(SIZE, SIZE, BufferedImage.TYPE_INT_ARGB);
		Graphics2D g = img.createGraphics();
		g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
		g.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);

		g.setColor(color);
		g.fillRoundRect(0, 0, SIZE, SIZE, 4, 4);

		g.setColor(Color.WHITE);
		g.setFont(new Font("SansSerif", Font.BOLD, 11));
		FontMetrics fm = g.getFontMetrics();
		int x = (SIZE - fm.stringWidth(letter)) / 2;
		int y = (SIZE - fm.getHeight()) / 2 + fm.getAscent();
		g.drawString(letter, x, y);

		g.dispose();
		return new ImageIcon(img);
	}
}
