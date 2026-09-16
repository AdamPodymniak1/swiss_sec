let port, reader, keepReading = false;
let aesKey = null;
let localKeyPair = null;
let isConnected = false;
let authState = "UNKNOWN";
let pendingAutoGenerate = null;
let pendingGetPassword = null;

const terminal = document.getElementById('terminal');
const connectBtn = document.getElementById('connectBtn');
const inputField = document.getElementById('input');
const sendBtn = document.getElementById('sendBtn');

function setAuthState(newState) {
    if (authState !== newState) {
        authState = newState;
        chrome.runtime.sendMessage({
            target: "background",
            type: "STATE_CHANGED",
            authState: authState
        }).catch(() => {});
    }
}

function bufferToHex(buffer) {
    return Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBuffer(hex) {
    const cleanHex = hex.replace(/[^0-9a-fA-F]/g, '');
    const bytes = new Uint8Array(Math.ceil(cleanHex.length / 2));
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(cleanHex.substring(i * 2, i * 2 + 2), 16);
    }
    return bytes;
}

window.addEventListener('DOMContentLoaded', async () => {
    const ports = await navigator.serial.getPorts();
    if (ports.length > 0) await connect();

    navigator.serial.addEventListener('connect', async () => { if (!isConnected) await connect(); });
    navigator.serial.addEventListener('disconnect', async () => { if (isConnected) await disconnect(); });
});

connectBtn.onclick = async () => {
    if (port && port.readable) await disconnect();
    else await connect();
};

async function connect() {
    try {
        const ports = await navigator.serial.getPorts();
        if (ports.length > 0) port = ports[0];
        else port = await navigator.serial.requestPort();
        
        await port.open({ baudRate: 115200 });
        
        connectBtn.innerText = "Disconnect";
        inputField.disabled = false;
        sendBtn.disabled = false;
        keepReading = true;
        isConnected = true;
        aesKey = null;

        readLoop();

        localKeyPair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
        const pubKeyRaw = await crypto.subtle.exportKey("raw", localKeyPair.publicKey);
        
        terminal.innerText += "[System] Initiating Handshake...\n";
        await sendRaw(`DH_INIT:${bufferToHex(pubKeyRaw)}\n`);
    } catch (err) {
        terminal.innerText += `[System Error] Initialization failed\n`;
    }
}

async function disconnect() {
    if (port && port.writable) {
        try {
            await sendSecure({ cmd: "DISCONNECT" });
            await new Promise(resolve => setTimeout(resolve, 100));
        } catch (err) {}
    }
    keepReading = false;
    isConnected = false;
    setAuthState("UNKNOWN");
    pendingAutoGenerate = null;
    pendingGetPassword = null;

    if (reader) {
        await reader.cancel();
        reader.releaseLock();
    }
    if (port) {
        await port.close();
        port = null;
    }
    window.close();
}

function processIncomingLine(text) {
    let jsonMsg = null;
    try {
        jsonMsg = JSON.parse(text);
    } catch (e) {
        // Fallback for non-JSON or raw system lines
    }

    if (jsonMsg) {
        if (jsonMsg.type === "event") {
            if (jsonMsg.module === "SYS" && jsonMsg.event === "BOOT") {
                setAuthState(jsonMsg.data && jsonMsg.data.pin_set ? "PIN_REQ" : "NEW_PIN_REQ");
            } else if (jsonMsg.module === "AUTH" && jsonMsg.event === "PIN_CREATED") {
                setAuthState("PIN_REQ");
            } else if (jsonMsg.module === "SECURITY" && jsonMsg.event === "PIN_OK") {
                setAuthState("READY");
            } else if (jsonMsg.module === "PASS" && jsonMsg.event === "AWAITING_HARDWARE_APPROVAL") {
                setAuthState("AWAITING_FINGERPRINT");
            } else if (jsonMsg.module === "PASS" && jsonMsg.event === "TRANSMITTED") {
                setAuthState("READY");
                const passwordValue = jsonMsg.data ? jsonMsg.data.password : null;
                if (passwordValue && pendingGetPassword) {
                    const targetObj = pendingGetPassword;
                    pendingGetPassword = null;
                    fillCredentialsInTab(targetObj, passwordValue);
                }
            } else if (jsonMsg.module === "PASS" && jsonMsg.event === "SAVED") {
                setAuthState("READY");
                const passwordValue = jsonMsg.data ? jsonMsg.data.generated_password : null;
                if (passwordValue && pendingAutoGenerate) {
                    const targetObj = pendingAutoGenerate;
                    pendingAutoGenerate = null;
                    fillCredentialsInTab(targetObj, passwordValue);
                }
            } else if (jsonMsg.module === "PASS" && jsonMsg.event === "UPDATED") {
                setAuthState("READY");
            } else if (jsonMsg.module === "BACKUP") {
                if (jsonMsg.event === "EXPORT_START" && jsonMsg.data) {
                    backupExportBuffer = {
                        chunks: new Array(jsonMsg.data.total_chunks).fill(""),
                        totalChunks: jsonMsg.data.total_chunks,
                        totalLen: jsonMsg.data.total_len,
                        sha256: jsonMsg.data.sha256,
                        received: 0
                    };
                    notifyBackupProgress("export", 5, "Receiving encrypted archive...");
                } else if (jsonMsg.event === "EXPORT_CHUNK" && jsonMsg.data && backupExportBuffer) {
                    backupExportBuffer.chunks[jsonMsg.data.seq] = jsonMsg.data.data;
                    backupExportBuffer.received++;
                    const pct = 5 + Math.round((backupExportBuffer.received / backupExportBuffer.totalChunks) * 90);
                    notifyBackupProgress("export", pct, "Receiving encrypted archive...");
                } else {
                    dispatchBackupEvent(jsonMsg);
                }
            }
        } else if (jsonMsg.type === "error") {
            if (jsonMsg.error_code === "PIN_REQ") setAuthState("PIN_REQ");
            else if (jsonMsg.error_code === "NEW_PIN_REQ") setAuthState("NEW_PIN_REQ");
            else if (jsonMsg.error_code === "BAD_PIN_ATTEMPT") terminal.innerText += "Wrong PIN\n";
            else if (jsonMsg.module === "BACKUP") {
                dispatchBackupEvent(jsonMsg);
            }
            else if (jsonMsg.error_code === "NOT_FOUND") {
                if (pendingGetPassword) {
                    terminal.innerText += `[System] Password not found.\n`;
                    pendingGetPassword = null;
                    setAuthState("READY");
                }
            }
        }
    }

    let safeText = text;
    if (jsonMsg && jsonMsg.type === "event" && jsonMsg.event === "TRANSMITTED" && jsonMsg.data && jsonMsg.data.password) {
        const maskedMsg = JSON.parse(JSON.stringify(jsonMsg));
        maskedMsg.data.password = "********";
        safeText = JSON.stringify(maskedMsg);
    } else if (jsonMsg && jsonMsg.type === "event" && jsonMsg.event === "SAVED" && jsonMsg.data && jsonMsg.data.generated_password) {
        const maskedMsg = JSON.parse(JSON.stringify(jsonMsg));
        maskedMsg.data.generated_password = "********";
        safeText = JSON.stringify(maskedMsg);
    }

    terminal.innerText += safeText + "\n";
    terminal.scrollTop = terminal.scrollHeight;

    chrome.runtime.sendMessage({ target: "popup", type: "SERIAL_OUTPUT", text: safeText, json: jsonMsg }).catch(() => {});
}

let backupBusy = false;
let backupExportBuffer = null;
let backupEventListeners = [];

function waitForBackupEvent(matchFn, timeoutMs = 30000) {
    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
            backupEventListeners = backupEventListeners.filter(l => l !== listener);
            reject(new Error("Timed out waiting for the device."));
        }, timeoutMs);
        const listener = (msg) => {
            if (matchFn(msg)) {
                clearTimeout(timer);
                backupEventListeners = backupEventListeners.filter(l => l !== listener);
                resolve(msg);
            }
        };
        backupEventListeners.push(listener);
    });
}

function dispatchBackupEvent(msg) {
    backupEventListeners.slice().forEach(l => l(msg));
}

function notifyBackupProgress(phase, percent, message) {
    chrome.runtime.sendMessage({ target: "popup", type: "BACKUP_PROGRESS", phase, percent, message }).catch(() => {});
}

function notifyBackupResult(phase, success, message) {
    chrome.runtime.sendMessage({ target: "popup", type: "BACKUP_RESULT", phase, success, message }).catch(() => {});
}

async function runBackupExport(passphrase) {
    if (backupBusy) { notifyBackupResult("export", false, "Another backup operation is already running."); return; }
    backupBusy = true;
    backupExportBuffer = null;

    try {
        notifyBackupProgress("export", 0, "Requesting export...");
        await sendSecure({ cmd: "BACKUP_EXPORT", passphrase: passphrase });

        const doneMsg = await waitForBackupEvent((m) =>
            (m.type === "event" && m.module === "BACKUP" && m.event === "EXPORT_DONE") ||
            (m.type === "error" && m.module === "BACKUP"),
        60000);
        if (doneMsg.type === "error") throw new Error(doneMsg.message || doneMsg.error_code);

        const buf = backupExportBuffer;
        if (!buf) throw new Error("No archive data received.");

        const hexBlob = buf.chunks.join("");
        if (hexBlob.length !== buf.totalLen) throw new Error("Incomplete transfer from device.");

        const digestBuf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(hexBlob));
        const actualSha256 = bufferToHex(digestBuf);
        if (actualSha256 !== buf.sha256) throw new Error("Checksum mismatch -- transfer may have been corrupted, try again.");

        const blob = new Blob([hexBlob], { type: "text/plain" });
        const url = URL.createObjectURL(blob);
        const stamp = new Date().toISOString().replace(/[:.]/g, "-");

        await chrome.downloads.download({
            url: url,
            filename: `vault-backup-${stamp}.vbk`,
            saveAs: true
        });
        setTimeout(() => URL.revokeObjectURL(url), 60000);

        notifyBackupResult("export", true, "Backup saved.");
    } catch (err) {
        notifyBackupResult("export", false, err.message || String(err));
    } finally {
        backupExportBuffer = null;
        backupBusy = false;
    }
}

async function runBackupImport(hexBlob, sha256, passphrase, overwrite) {
    if (backupBusy) { notifyBackupResult("import", false, "Another backup operation is already running."); return; }
    backupBusy = true;

    try {
        notifyBackupProgress("import", 0, "Starting restore...");
        await sendSecure({ cmd: "BACKUP_IMPORT_BEGIN", total_len: hexBlob.length, sha256: sha256 });

        const readyMsg = await waitForBackupEvent((m) =>
            (m.type === "event" && m.module === "BACKUP" && m.event === "IMPORT_READY") ||
            (m.type === "error" && m.module === "BACKUP"),
        15000);
        if (readyMsg.type === "error") throw new Error(readyMsg.message || readyMsg.error_code);

        const CHUNK = 2048;
        const totalChunks = Math.max(1, Math.ceil(hexBlob.length / CHUNK));
        for (let i = 0; i < totalChunks; i++) {
            const slice = hexBlob.substring(i * CHUNK, (i + 1) * CHUNK);
            await sendSecure({ cmd: "BACKUP_IMPORT_CHUNK", data: slice });
            notifyBackupProgress("import", 5 + Math.round(((i + 1) / totalChunks) * 70), "Uploading archive...");
        }

        notifyBackupProgress("import", 80, "Decrypting and restoring...");
        await sendSecure({ cmd: "BACKUP_IMPORT_COMMIT", passphrase: passphrase, overwrite: !!overwrite });

        const doneMsg = await waitForBackupEvent((m) =>
            (m.type === "event" && m.module === "BACKUP" && m.event === "IMPORT_DONE") ||
            (m.type === "error" && m.module === "BACKUP"),
        30000);
        if (doneMsg.type === "error") throw new Error(doneMsg.message || doneMsg.error_code);

        const data = doneMsg.data || {};
        notifyBackupResult("import", true, `Restored ${data.imported || 0} item(s), skipped ${data.skipped || 0}.`);
    } catch (err) {
        try { await sendSecure({ cmd: "BACKUP_IMPORT_ABORT" }); } catch (e) {}
        notifyBackupResult("import", false, err.message || String(err));
    } finally {
        backupBusy = false;
    }
}

function fillCredentialsInTab(targetObj, passwordValue) {
    const targetTabId = targetObj ? targetObj.tabId : null;
    const targetLogin = targetObj ? targetObj.login : null;

    if (targetTabId) {
        chrome.tabs.sendMessage(targetTabId, { type: "FILL_CREDENTIALS", password: passwordValue, login: targetLogin }).catch(() => {});
    } else {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            if (tabs.length > 0) chrome.tabs.sendMessage(tabs[0].id, { type: "FILL_CREDENTIALS", password: passwordValue, login: targetLogin }).catch(() => {});
        });
    }
}

async function readLoop() {
    reader = port.readable.getReader();
    let rxBuffer = "";

    while (keepReading) {
        try {
            const { value, done } = await reader.read();
            if (done) break;
            
            rxBuffer += new TextDecoder().decode(value);
            let lines = rxBuffer.split('\n');
            rxBuffer = lines.pop();

            for (let line of lines) {
                line = line.trim();
                if (!line) continue;

                if (line.includes("DH_ACK:")) {
                    try {
                        const rawHexData = line.split("DH_ACK:")[1].trim();
                        let espPubKeyRaw = hexToBuffer(rawHexData);
                        
                        if (espPubKeyRaw.length === 64) {
                            const normalizedKey = new Uint8Array(65);
                            normalizedKey[0] = 0x04;
                            normalizedKey.set(espPubKeyRaw, 1);
                            espPubKeyRaw = normalizedKey;
                        }
                        
                        const espPubKey = await crypto.subtle.importKey(
                            "raw", espPubKeyRaw, { name: 'ECDH', namedCurve: 'P-256' }, true, []
                        );
                        
                        const sharedSecret = await crypto.subtle.deriveBits(
                            { name: 'ECDH', public: espPubKey }, localKeyPair.privateKey, 256
                        );
                        
                        const hash = await crypto.subtle.digest("SHA-256", sharedSecret);
                        aesKey = await crypto.subtle.importKey("raw", hash, {name: "AES-GCM"}, false, ["encrypt", "decrypt"]);
                        
                        terminal.innerText += "[System] Secure Tunnel Established.\n";
                        await sendSecure({ cmd: "RESTART_SYSTEM" });
                    } catch (cryptoErr) {
                        terminal.innerText += `[System Error] Key exchange calculation broken\n`;
                    }
                } 
                else if (line.includes("ENC:")) {
                    if (!aesKey) continue;
                    
                    const cryptoData = line.split("ENC:")[1].trim();
                    const parts = cryptoData.split(":");
                    const iv = hexToBuffer(parts[0]);
                    const cipherWithTag = hexToBuffer(parts[1]);
                    
                    try {
                        const decrypted = await crypto.subtle.decrypt({name: "AES-GCM", iv: iv}, aesKey, cipherWithTag);
                        const text = new TextDecoder().decode(decrypted);
                        processIncomingLine(text);
                    } catch (e) {}
                } 
                else {
                    processIncomingLine(line);
                }
            }
        } catch (e) { break; }
    }
}

async function sendRaw(text) {
    if (!port || !port.writable) return;
    const writer = port.writable.getWriter();
    await writer.write(new TextEncoder().encode(text));
    writer.releaseLock();
}

async function sendSecure(payload) {
    const text = (typeof payload === "object") ? JSON.stringify(payload) : payload;
    if (!aesKey) {
        await sendRaw(text + "\n");
        return;
    }
    const iv = crypto.getRandomValues(new Uint8Array(12));
    
    const cipherBuffer = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv }, aesKey, new TextEncoder().encode(text)
    );
    
    const output = `ENC:${bufferToHex(iv)}:${bufferToHex(cipherBuffer)}\n`;
    await sendRaw(output);
}

const handleSendAction = async () => {
    if (inputField.value.trim() === "") return;
    let payload = inputField.value.trim();
    if (payload.startsWith("{") && payload.endsWith("}")) {
        try { payload = JSON.parse(payload); } catch (e) {}
    }
    await sendSecure(payload); 
    inputField.value = "";
};

document.getElementById('sendBtn').onclick = handleSendAction;
inputField.addEventListener("keyup", async (event) => { if (event.key === "Enter") await handleSendAction(); });

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "PING") {
        sendResponse({ connected: isConnected, authState: authState });
    } else if (message.type === "ACTIVE_SITE") {
        sendResponse({ status: "ok" });
    } else if (message.type === "AUTO_GENERATE") {
        if (isConnected && authState === "READY") {
            if (pendingAutoGenerate) return sendResponse({ status: "busy" });
            pendingAutoGenerate = { 
                domain: message.hostname, 
                login: message.login,
                tabId: message.senderTabId || (sender.tab && sender.tab.id)
            };
            sendSecure({ cmd: "SAVE_PASS", site: message.hostname, login: message.login, autogen: true });
        }
        sendResponse({ status: "ok" });
    } else if (message.type === "GET_PASSWORD") {
        if (isConnected && authState === "READY") {
            if (pendingGetPassword) return sendResponse({ status: "busy" });
            pendingGetPassword = {
                domain: message.hostname,
                login: message.login,
                tabId: message.senderTabId || (sender.tab && sender.tab.id)
            };
            sendSecure({ cmd: "GET_PASS", site: message.hostname, login: message.login });
        }
        sendResponse({ status: "ok" });
    } else if (message.type === "CMD_LIST_PASS") {
        sendSecure({ cmd: "LIST_PASS" });
        sendResponse({ status: "ok" });
    } else if (message.type === "CMD_LIST_FIDO") {
        sendSecure({ cmd: "LIST_FIDO" });
        sendResponse({ status: "ok" });
    } else if (message.type === "CMD_DELETE_PASS") {
        sendSecure({ cmd: "DELETE_PASS", site: message.name, login: message.login });
        sendResponse({ status: "ok" });
    } else if (message.type === "CMD_DELETE_FIDO") {
        sendSecure({ cmd: "DELETE_FIDO", site: message.domain });
        sendResponse({ status: "ok" });
    } else if (message.type === "CMD_UPDATE_SETTINGS") {
        const algId = (message.algId !== undefined) ? parseInt(message.algId, 10) : -7;
        sendSecure({ cmd: "UPDATE_SETTINGS", algId: algId });
        sendResponse({ status: "ok" });
    } else if (message.type === "SEND") {
        sendSecure(message.payload);
        sendResponse({ status: "ok" });
    } else if (message.type === "DISCONNECT") {
        disconnect();
        sendResponse({ status: "ok" });
    } else if (message.type === "CMD_GET_ALL_TOTP") {
        const epochNow = Math.floor(Date.now() / 1000);
        sendSecure({ cmd: "GET_TOTP", epoch: epochNow });
        sendResponse({ status: "ok" });
    } else if (message.type === "CMD_DELETE_TOTP") {
        sendSecure({ cmd: "DELETE_TOTP", name: message.name });
        sendResponse({ status: "ok" });
    } else if (message.type === "BACKUP_EXPORT") {
        runBackupExport(message.passphrase);
        sendResponse({ status: "ok" });
    } else if (message.type === "BACKUP_IMPORT") {
        runBackupImport(message.hex, message.sha256, message.passphrase, message.overwrite);
        sendResponse({ status: "ok" });
    }
    return true;
});