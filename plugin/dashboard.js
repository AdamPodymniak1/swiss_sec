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
            }
        } else if (jsonMsg.type === "error") {
            if (jsonMsg.error_code === "PIN_REQ") setAuthState("PIN_REQ");
            else if (jsonMsg.error_code === "NEW_PIN_REQ") setAuthState("NEW_PIN_REQ");
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
    }
    return true;
});