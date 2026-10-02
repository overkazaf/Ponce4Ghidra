package ponce4ghidra.engine;

import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.util.Msg;
import ponce4ghidra.engine.EngineProtocol.Command;
import ponce4ghidra.engine.EngineProtocol.Response;

public class EngineManager {

	private static final String HOST = "127.0.0.1";
	private static final int PORT = 13370;
	private static final int CONNECT_TIMEOUT_MS = 10000;
	private static final int CONNECT_RETRY_DELAY_MS = 500;

	private Process pythonProcess;
	private Socket socket;
	private BufferedWriter writer;
	private BufferedReader reader;
	private final ExecutorService executor = Executors.newSingleThreadExecutor();
	private volatile boolean running;
	private String engineBackend = "angr";

	public void setEngineBackend(String backend) {
		this.engineBackend = backend;
	}

	public String getEngineBackend() {
		return engineBackend;
	}

	public void start() throws IOException {
		if (running) {
			return;
		}

		String pythonPath = findPython();
		String serverModule = findServerModule();

		ProcessBuilder pb = new ProcessBuilder(
			pythonPath, "-m", "ponce4ghidra_engine.server",
			"--engine", engineBackend);
		pb.environment().put("PYTHONPATH", serverModule);
		pb.redirectErrorStream(true);
		pythonProcess = pb.start();

		startLogReader(pythonProcess.getInputStream());
		connectWithRetry();
		running = true;
		Msg.info(this, "Ponce4Ghidra engine started (" + engineBackend + ") on port " + PORT);
	}

	public void stop() {
		running = false;
		closeSocket();
		if (pythonProcess != null && pythonProcess.isAlive()) {
			pythonProcess.destroy();
			try {
				pythonProcess.waitFor(5, TimeUnit.SECONDS);
			}
			catch (InterruptedException e) {
				pythonProcess.destroyForcibly();
			}
		}
		pythonProcess = null;
		Msg.info(this, "Ponce4Ghidra engine stopped");
	}

	public boolean isRunning() {
		return running && socket != null && socket.isConnected() && !socket.isClosed();
	}

	public Response sendCommand(Command cmd) throws IOException {
		if (!isRunning()) {
			throw new IOException("Engine is not running");
		}
		String json = EngineProtocol.serialize(cmd);
		synchronized (this) {
			writer.write(json);
			writer.newLine();
			writer.flush();
			String responseLine = reader.readLine();
			if (responseLine == null) {
				throw new IOException("Engine connection closed");
			}
			return EngineProtocol.deserialize(responseLine);
		}
	}

	/**
	 * The engine's own account of itself: which binary is loaded, what is
	 * symbolized, which targets are set.
	 * <p>
	 * Callers ask this rather than trust their own record of what they last sent,
	 * because that record goes stale whenever the engine is restarted. Note that an
	 * engine predating the "binary" field reports no such key at all, which is not
	 * the same as reporting it null: see Response.hasData.
	 */
	public Response getState() throws IOException {
		return sendCommand(EngineProtocol.getStateCmd());
	}

	public CompletableFuture<Response> sendCommandAsync(Command cmd) {
		return CompletableFuture.supplyAsync(() -> {
			try {
				return sendCommand(cmd);
			}
			catch (IOException e) {
				throw new RuntimeException(e);
			}
		}, executor);
	}

	public Response sendCommandWithProgress(Command cmd,
			Consumer<Response> onProgress) throws IOException {
		if (!isRunning()) {
			throw new IOException("Engine is not running");
		}
		String json = EngineProtocol.serialize(cmd);
		synchronized (this) {
			writer.write(json);
			writer.newLine();
			writer.flush();
			while (true) {
				String responseLine = reader.readLine();
				if (responseLine == null) {
					throw new IOException("Engine connection closed");
				}
				Response resp = EngineProtocol.deserialize(responseLine);
				if (resp.isProgress()) {
					if (onProgress != null) {
						onProgress.accept(resp);
					}
					continue;
				}
				return resp;
			}
		}
	}

	public CompletableFuture<Response> sendCommandWithProgressAsync(
			Command cmd, Consumer<Response> onProgress) {
		return CompletableFuture.supplyAsync(() -> {
			try {
				return sendCommandWithProgress(cmd, onProgress);
			}
			catch (IOException e) {
				throw new RuntimeException(e);
			}
		}, executor);
	}

	public void dispose() {
		stop();
		executor.shutdownNow();
	}

	private void connectWithRetry() throws IOException {
		long deadline = System.currentTimeMillis() + CONNECT_TIMEOUT_MS;
		IOException lastException = null;

		while (System.currentTimeMillis() < deadline) {
			try {
				socket = new Socket(HOST, PORT);
				writer = new BufferedWriter(
					new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8));
				reader = new BufferedReader(
					new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
				return;
			}
			catch (IOException e) {
				lastException = e;
				try {
					Thread.sleep(CONNECT_RETRY_DELAY_MS);
				}
				catch (InterruptedException ie) {
					Thread.currentThread().interrupt();
					throw new IOException("Interrupted while connecting", ie);
				}
			}
		}
		throw new IOException("Failed to connect to engine after " + CONNECT_TIMEOUT_MS + "ms",
			lastException);
	}

	private void closeSocket() {
		try {
			if (writer != null) writer.close();
			if (reader != null) reader.close();
			if (socket != null) socket.close();
		}
		catch (IOException e) {
			Msg.warn(this, "Error closing engine connection", e);
		}
		writer = null;
		reader = null;
		socket = null;
	}

	private void startLogReader(InputStream inputStream) {
		Thread logThread = new Thread(() -> {
			try (BufferedReader br = new BufferedReader(new InputStreamReader(inputStream))) {
				String line;
				while ((line = br.readLine()) != null) {
					Msg.info(this, "[angr] " + line);
				}
			}
			catch (IOException e) {
				if (running) {
					Msg.warn(this, "Engine log reader stopped", e);
				}
			}
		}, "Ponce4Ghidra-LogReader");
		logThread.setDaemon(true);
		logThread.start();
	}

	private String findPython() {
		// Check for venv Python next to the extension's python/ dir
		try {
			ResourceFile moduleDir = Application.getModuleDataSubDirectory("");
			File extRoot = moduleDir.getParentFile().getFile(false);
			// Look for .venv in parent directories (development layout)
			File dir = extRoot;
			for (int i = 0; i < 5 && dir != null; i++) {
				File venvPython = new File(dir, ".venv/bin/python3");
				if (venvPython.isFile()) {
					Msg.info(this, "Using venv Python: " + venvPython.getAbsolutePath());
					return venvPython.getAbsolutePath();
				}
				dir = dir.getParentFile();
			}
		}
		catch (Exception e) {
			// fall through to default search
		}

		String[] candidates = { "python3", "python" };
		for (String candidate : candidates) {
			try {
				Process p = new ProcessBuilder(candidate, "--version")
					.redirectErrorStream(true).start();
				if (p.waitFor(5, TimeUnit.SECONDS) && p.exitValue() == 0) {
					return candidate;
				}
			}
			catch (Exception e) {
				// try next
			}
		}
		return "python3";
	}

	private String findServerModule() {
		try {
			ResourceFile moduleDir = Application.getModuleDataSubDirectory("");
			File pythonDir = new File(moduleDir.getParentFile().getFile(false), "python");
			if (pythonDir.isDirectory()) {
				return pythonDir.getAbsolutePath();
			}
		}
		catch (Exception e) {
			Msg.warn(this, "Could not locate bundled python modules", e);
		}
		return ".";
	}
}
