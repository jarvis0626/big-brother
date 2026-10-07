'use strict';
const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('bigBrother', Object.freeze({
  invoke: (method, params = {}) => ipcRenderer.invoke('bb:request', method, params),
  selectExecutable: () => ipcRenderer.invoke('bb:select'),
  launchSelected: () => ipcRenderer.invoke('bb:launch-selected'),
  importRecording: () => ipcRenderer.invoke('bb:import-recording'),
  exportReport: (sessionId) => ipcRenderer.invoke('bb:export', sessionId),
  openExternal: (url) => ipcRenderer.invoke('bb:documentation', url)
}));
