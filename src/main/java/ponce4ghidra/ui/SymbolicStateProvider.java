package ponce4ghidra.ui;

import java.awt.BorderLayout;
import java.awt.Font;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;

import docking.ComponentProvider;
import ponce4ghidra.Ponce4GhidraPlugin;

public class SymbolicStateProvider extends ComponentProvider {

	private JPanel mainPanel;
	private JTabbedPane tabbedPane;

	private DefaultTableModel variablesModel;
	private JTable variablesTable;

	private DefaultTableModel targetsModel;
	private JTable targetsTable;

	private DefaultTableModel resultsModel;
	private JTable resultsTable;

	private DefaultMutableTreeNode constraintsRoot;
	private DefaultTreeModel constraintsTreeModel;
	private JTree constraintsTree;

	private JLabel statusLabel;

	private final List<String> findAddresses = new ArrayList<>();
	private final List<String> avoidAddresses = new ArrayList<>();

	public SymbolicStateProvider(Ponce4GhidraPlugin plugin) {
		super(plugin.getTool(), "Ponce4Ghidra", plugin.getName());
		buildComponent();
		setTitle("Ponce4Ghidra");
		setVisible(true);
	}

	private void buildComponent() {
		mainPanel = new JPanel(new BorderLayout());
		tabbedPane = new JTabbedPane();

		tabbedPane.addTab("Variables", buildVariablesPanel());
		tabbedPane.addTab("Find/Avoid", buildTargetsPanel());
		tabbedPane.addTab("Results", buildResultsPanel());
		tabbedPane.addTab("Constraints", buildConstraintsPanel());

		statusLabel = new JLabel("Ready");
		statusLabel.setBorder(BorderFactory.createEmptyBorder(2, 5, 2, 5));

		mainPanel.add(tabbedPane, BorderLayout.CENTER);
		mainPanel.add(statusLabel, BorderLayout.SOUTH);
	}

	private JPanel buildVariablesPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		variablesModel = new DefaultTableModel(
			new String[] { "Name", "Type", "Location", "Value" }, 0) {
			@Override
			public boolean isCellEditable(int row, int column) {
				return false;
			}
		};
		variablesTable = new JTable(variablesModel);
		panel.add(new JScrollPane(variablesTable), BorderLayout.CENTER);

		JButton clearBtn = new JButton("Clear All");
		clearBtn.addActionListener(e -> clearVariables());
		JPanel btnPanel = new JPanel();
		btnPanel.add(clearBtn);
		panel.add(btnPanel, BorderLayout.SOUTH);

		return panel;
	}

	private JPanel buildTargetsPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		targetsModel = new DefaultTableModel(
			new String[] { "Address", "Type" }, 0) {
			@Override
			public boolean isCellEditable(int row, int column) {
				return false;
			}
		};
		targetsTable = new JTable(targetsModel);
		panel.add(new JScrollPane(targetsTable), BorderLayout.CENTER);

		JButton clearBtn = new JButton("Clear All");
		clearBtn.addActionListener(e -> clearTargets());
		JPanel btnPanel = new JPanel();
		btnPanel.add(clearBtn);
		panel.add(btnPanel, BorderLayout.SOUTH);

		return panel;
	}

	private JPanel buildResultsPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		resultsModel = new DefaultTableModel(
			new String[] { "Variable", "String", "Hex", "Int" }, 0) {
			@Override
			public boolean isCellEditable(int row, int column) {
				return false;
			}
		};
		resultsTable = new JTable(resultsModel);
		// Monospaced: the columns that matter here are text and hex, and both are
		// easier to compare when the characters line up.
		resultsTable.setFont(new Font("Monospaced", Font.PLAIN, 12));
		resultsTable.setFillsViewportHeight(true);
		resultsTable.setAutoCreateRowSorter(true);
		resultsTable.getTableHeader().setReorderingAllowed(false);
		resultsTable.setComponentPopupMenu(buildResultsMenu());
		panel.add(new JScrollPane(resultsTable), BorderLayout.CENTER);
		return panel;
	}

	private JPanel buildConstraintsPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		constraintsRoot = new DefaultMutableTreeNode("No constraints yet");
		constraintsTreeModel = new DefaultTreeModel(constraintsRoot);
		constraintsTree = new JTree(constraintsTreeModel);
		constraintsTree.setFont(new Font("Monospaced", Font.PLAIN, 12));
		constraintsTree.setRootVisible(true);
		constraintsTree.setShowsRootHandles(true);
		panel.add(new JScrollPane(constraintsTree), BorderLayout.CENTER);
		return panel;
	}

	private JPopupMenu buildResultsMenu() {
		JPopupMenu menu = new JPopupMenu();
		menu.add(copyItem("Copy String", 1));
		menu.add(copyItem("Copy Hex", 2));
		menu.add(copyItem("Copy Int", 3));
		return menu;
	}

	private JMenuItem copyItem(String label, int column) {
		JMenuItem item = new JMenuItem(label);
		item.addActionListener(e -> copyResult(column));
		return item;
	}

	private void copyResult(int column) {
		int row = resultsTable.getSelectedRow();
		if (row < 0) {
			return;
		}
		// The table is sortable, so a view row and its model row are not the same.
		String value = String.valueOf(resultsModel.getValueAt(
			resultsTable.convertRowIndexToModel(row), column));
		Toolkit.getDefaultToolkit().getSystemClipboard()
			.setContents(new StringSelection(value), null);
		setStatus("Copied: " + value);
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	public void addVariable(String name, String type, String location, String value) {
		variablesModel.addRow(new Object[] { name, type, location, value });
	}

	public void updateVariableValue(String name, String value) {
		for (int i = 0; i < variablesModel.getRowCount(); i++) {
			if (name.equals(variablesModel.getValueAt(i, 0))) {
				variablesModel.setValueAt(value, i, 3);
				return;
			}
		}
	}

	public void addFindAddress(String address) {
		findAddresses.add(address);
		targetsModel.addRow(new Object[] { address, "FIND" });
	}

	public void addAvoidAddress(String address) {
		avoidAddresses.add(address);
		targetsModel.addRow(new Object[] { address, "AVOID" });
	}

	/**
	 * Shows the solved values. For a symbolized password buffer the String column
	 * is the answer; the hex and integer columns are there for when it is not text.
	 */
	public void setSolutions(List<Solution> solutions) {
		resultsModel.setRowCount(0);
		for (Solution solution : solutions) {
			resultsModel.addRow(new Object[] {
				solution.name(), solution.text(), solution.hex(), solution.valueText()
			});
		}
		tabbedPane.setSelectedIndex(2);
	}

	public void setConstraints(String stash, int index, List<String> constraints) {
		constraintsRoot.removeAllChildren();
		String label = stash.substring(0, 1).toUpperCase() + stash.substring(1)
			+ " state #" + index + " (" + constraints.size() + " constraints)";
		constraintsRoot.setUserObject(label);
		for (String text : constraints) {
			constraintsRoot.add(new DefaultMutableTreeNode(text));
		}
		constraintsTreeModel.reload();
		for (int i = 0; i < constraintsTree.getRowCount(); i++) {
			constraintsTree.expandRow(i);
		}
	}

	public void setStatus(String status) {
		statusLabel.setText(status);
	}

	public void clearVariables() {
		variablesModel.setRowCount(0);
	}

	public void clearTargets() {
		findAddresses.clear();
		avoidAddresses.clear();
		targetsModel.setRowCount(0);
	}

	public List<String> getFindAddresses() {
		return new ArrayList<>(findAddresses);
	}

	public List<String> getAvoidAddresses() {
		return new ArrayList<>(avoidAddresses);
	}

	public void clearAll() {
		clearVariables();
		clearTargets();
		resultsModel.setRowCount(0);
		constraintsRoot.removeAllChildren();
		constraintsRoot.setUserObject("No constraints yet");
		constraintsTreeModel.reload();
		statusLabel.setText("Ready");
	}
}
