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
    if (ports.length > 0) {
        await connect();
    }
});

connectBtn.onclick = async () => {
    if (port && port.readable) await disconnect();
    else await connect();
};

async function connect() {
    try {
        const ports = await navigator.serial.getPorts();
        if (ports.length > 0) {
            port = ports[0];
        } else {
            port = await navigator.serial.requestPort();
        }
        
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
            await sendSecure("DISCONNECT");
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
    if (text.includes("[AUTH] STATUS:PIN_REQ")) setAuthState("PIN_REQ");
    else if (text.includes("[AUTH] STATUS:NEW_PIN_REQ")) setAuthState("NEW_PIN_REQ");
    else if (text.includes("[AUTH] STATUS:SUCCESS") || text.includes("[SYS] STATUS:READY")) setAuthState("READY");
    else if (text.includes("[AUTH] STATUS:FACTORY_RESET_COMPLETE")) setAuthState("NEW_PIN_REQ");
    else if (text.includes("[PASS] STATUS:AWAITING_HARDWARE_APPROVAL")) setAuthState("AWAITING_FINGERPRINT");

    if (pendingAutoGenerate) {
        if (text.includes("[PASS] REQ:NAME")) {
            sendSecure(pendingAutoGenerate.domain);
        } else if (text.includes("[PASS] AUTO_GENERATE_PASSWORD?")) {
            sendSecure("Y");
        }
    }

    if (pendingGetPassword) {
        if (text.includes("[PASS] REQ:NAME")) {
            sendSecure(pendingGetPassword.domain);
        } else if (text.includes("[ERR] CODE:NOT_FOUND")) {
            terminal.innerText += `[System] No password found\n`;
            pendingGetPassword = null;
            setAuthState("READY");
        }
    }

    let passwordValue = null;
    let safeText = text;

    if (text.includes("[PASS] GENERATED:")) {
        passwordValue = text.split("[PASS] GENERATED:")[1].trim();
        safeText = text.replace(passwordValue, "********");
    } else if (text.includes("[PASS] VAL:")) {
        passwordValue = text.split("[PASS] VAL:")[1].trim();
        safeText = text.replace(passwordValue, "********");
    } else if (text.includes("[PASS] OUT:") && !text.includes("SAVED") && !text.includes("DELETED")) {
        passwordValue = text.split("[PASS] OUT:")[1].trim();
        safeText = text.replace(passwordValue, "********");
    }

    if (passwordValue) {
        const targetTabId = pendingGetPassword ? pendingGetPassword.tabId : (pendingAutoGenerate ? pendingAutoGenerate.tabId : null);
        pendingAutoGenerate = null;
        pendingGetPassword = null;
        setAuthState("READY");

        if (targetTabId) {
            chrome.tabs.sendMessage(targetTabId, {
                type: "FILL_CREDENTIALS",
                password: passwordValue
            }).catch(() => {});
        } else {
            chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
                if (tabs.length > 0) {
                    chrome.tabs.sendMessage(tabs[0].id, {
                        type: "FILL_CREDENTIALS",
                        password: passwordValue
                    }).catch(() => {});
                }
            });
        }
    }

    terminal.innerText += safeText + "\n";
    terminal.scrollTop = terminal.scrollHeight;
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
                        await sendSecure("RESTART_SYSTEM");
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

async function sendSecure(text) {
    if (!aesKey) {
        await sendRaw(text + "\n");
        return;
    }
    const iv = crypto.getRandomValues(new Uint8Array(12));
    
    const cipherBuffer = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv }, aesKey, new TextEncoder().encode(text)
    );
    
    const payload = `ENC:${bufferToHex(iv)}:${bufferToHex(cipherBuffer)}\n`;
    await sendRaw(payload);
}

const handleSendAction = async () => {
    if (inputField.value.trim() === "") return;
    await sendSecure(inputField.value.trim()); 
    inputField.value = "";
};

document.getElementById('sendBtn').onclick = handleSendAction;
inputField.addEventListener("keyup", async (event) => {
    if (event.key === "Enter") await handleSendAction();
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "PING") {
        sendResponse({ connected: isConnected, authState: authState });
    } else if (message.type === "ACTIVE_SITE") {
        terminal.innerText += `[Extension] Active site\n`;
        terminal.scrollTop = terminal.scrollHeight;
        sendResponse({ status: "ok" });
    } else if (message.type === "AUTO_GENERATE") {
        if (isConnected && authState === "READY") {
            pendingAutoGenerate = { 
                domain: message.hostname, 
                tabId: message.senderTabId 
            };
            sendSecure("create");
        }
        sendResponse({ status: "ok" });
    } else if (message.type === "GET_PASSWORD") {
        if (isConnected && authState === "READY") {
            pendingGetPassword = {
                domain: message.hostname,
                tabId: message.senderTabId
            };
            sendSecure("get");
        }
        sendResponse({ status: "ok" });
    } else if (message.type === "SEND") {
        sendSecure(message.payload);
        sendResponse({ status: "ok" });
    } else if (message.type === "DISCONNECT") {
        disconnect();
        sendResponse({ status: "ok" });
    }
    return true;
});