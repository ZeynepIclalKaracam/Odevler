const { app, BrowserWindow, ipcMain, dialog, Menu, shell } = require("electron");
const path = require("path");
const fs   = require("fs");
const Store = require("electron-store");

const store = new Store();
const isDev = process.env.VITE_DEV === "true";

// ── Window ──────────────────────────────────────────
function createWindow() {
  const win = new BrowserWindow({
    width: 1400,
    height: 860,
    minWidth: 960,
    minHeight: 640,
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
    },
    backgroundColor: "#0B0D12",
    titleBarStyle: process.platform === "darwin" ? "hiddenInset" : "default",
    frame: true,
    show: false,
  });

  win.once("ready-to-show", () => win.show());

  if (isDev) {
    win.loadURL("http://localhost:5173");
    win.webContents.openDevTools({ mode: "detach" });
  } else {
    win.loadFile(path.join(__dirname, "../dist/index.html"));
  }

  buildMenu(win);
  return win;
}

// ── Native Menu ──────────────────────────────────────
function buildMenu(win) {
  const template = [
    {
      label: "File",
      submenu: [
        {
          label: "Open File(s)…",
          accelerator: "CmdOrCtrl+O",
          click: () => win.webContents.send("menu-open-file"),
        },
        {
          label: "Open Folder…",
          accelerator: "CmdOrCtrl+Shift+O",
          click: () => win.webContents.send("menu-open-folder"),
        },
        { type: "separator" },
        {
          label: "New File",
          accelerator: "CmdOrCtrl+N",
          click: () => win.webContents.send("menu-new-file"),
        },
        { type: "separator" },
        { role: "quit" },
      ],
    },
    {
      label: "Analysis",
      submenu: [
        {
          label: "Run Security Analysis",
          accelerator: "F5",
          click: () => win.webContents.send("menu-run-analysis"),
        },
        {
          label: "Clear Results",
          accelerator: "CmdOrCtrl+Shift+C",
          click: () => win.webContents.send("menu-clear"),
        },
      ],
    },
    {
      label: "Edit",
      submenu: [
        { role: "undo" }, { role: "redo" }, { type: "separator" },
        { role: "cut" }, { role: "copy" }, { role: "paste" },
        { role: "selectAll" },
      ],
    },
    {
      label: "View",
      submenu: [
        { role: "reload" }, { role: "forceReload" }, { type: "separator" },
        { role: "resetZoom" }, { role: "zoomIn" }, { role: "zoomOut" },
        { type: "separator" }, { role: "togglefullscreen" },
      ],
    },
    {
      label: "Help",
      submenu: [
        {
          label: "Anthropic API Keys",
          click: () => shell.openExternal("https://console.anthropic.com/api-keys"),
        },
      ],
    },
  ];

  if (process.platform === "darwin") {
    template.unshift({ label: app.name, submenu: [{ role: "about" }, { type: "separator" }, { role: "quit" }] });
  }

  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

// ── IPC Handlers ──────────────────────────────────────
ipcMain.handle("open-file-dialog", async () => {
  const result = await dialog.showOpenDialog({
    properties: ["openFile", "multiSelections"],
    filters: [
      {
        name: "Source Code",
        extensions: [
          "js","jsx","ts","tsx","py","go","java","php","rb","cs",
          "rs","sql","sh","bash","kt","swift","c","cpp","cc","h",
          "hpp","vue","svelte","html","css","scss","yaml","yml","json","toml",
        ],
      },
      { name: "All Files", extensions: ["*"] },
    ],
  });
  if (result.canceled || !result.filePaths.length) return null;
  return result.filePaths;
});

ipcMain.handle("open-folder-dialog", async () => {
  const result = await dialog.showOpenDialog({ properties: ["openDirectory"] });
  if (result.canceled) return null;
  return result.filePaths[0];
});

ipcMain.handle("read-file", async (_, filePath) => {
  try {
    const content = fs.readFileSync(filePath, "utf-8");
    return { ok: true, content };
  } catch (e) {
    return { ok: false, error: e.message };
  }
});

ipcMain.handle("read-folder", async (_, folderPath) => {
  try {
    function walk(dir, depth = 0) {
      if (depth > 3) return [];
      return fs.readdirSync(dir, { withFileTypes: true })
        .filter(e => !e.name.startsWith(".") && e.name !== "node_modules" && e.name !== "__pycache__")
        .map(entry => {
          const full = path.join(dir, entry.name);
          if (entry.isDirectory()) {
            return { name: entry.name, path: full, type: "dir", children: walk(full, depth + 1) };
          }
          return { name: entry.name, path: full, type: "file" };
        });
    }
    return { ok: true, tree: walk(folderPath), root: folderPath };
  } catch (e) {
    return { ok: false, error: e.message };
  }
});

ipcMain.handle("get-api-key", () => store.get("anthropicApiKey", ""));
ipcMain.handle("set-api-key", (_, key) => { store.set("anthropicApiKey", key); return true; });

// ── App lifecycle ──────────────────────────────────────
app.whenReady().then(() => {
  createWindow();
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});
