const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("electronAPI", {
  // File operations
  openFileDialog:   ()           => ipcRenderer.invoke("open-file-dialog"),
  openFolderDialog: ()           => ipcRenderer.invoke("open-folder-dialog"),
  readFile:         (path)       => ipcRenderer.invoke("read-file", path),
  readFolder:       (path)       => ipcRenderer.invoke("read-folder", path),

  // API key storage
  getApiKey:        ()           => ipcRenderer.invoke("get-api-key"),
  setApiKey:        (key)        => ipcRenderer.invoke("set-api-key", key),

  // Menu event listeners
  onMenuOpenFile:     (cb) => ipcRenderer.on("menu-open-file",     () => cb()),
  onMenuOpenFolder:   (cb) => ipcRenderer.on("menu-open-folder",   () => cb()),
  onMenuNewFile:      (cb) => ipcRenderer.on("menu-new-file",      () => cb()),
  onMenuRunAnalysis:  (cb) => ipcRenderer.on("menu-run-analysis",  () => cb()),
  onMenuClear:        (cb) => ipcRenderer.on("menu-clear",         () => cb()),

  removeAllListeners: (channel) => ipcRenderer.removeAllListeners(channel),
});
