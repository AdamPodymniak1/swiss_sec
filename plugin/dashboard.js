let port, reader, keepReading = false;
let aesKey = null;
let localKeyPair = null;
let isConnected = false;
let authState = "UNKNOWN";

const terminal = document.getElementById('terminal');
const connectBtn = document.getElementById('connectBtn');
const inputField = document.getElementById('input');
const sendBtn = document.getElementById('sendBtn');

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
        terminal.innerText += `[System Error] Initialization failed: ${err.message}\n`;
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
    authState = "UNKNOWN";
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
                        terminal.innerText += `[System Error] Key exchange calculation broken: ${cryptoErr.message}\n`;
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
                        
                        if (text.includes("[AUTH] STATUS:PIN_REQ")) authState = "PIN_REQ";
                        else if (text.includes("[AUTH] STATUS:NEW_PIN_REQ")) authState = "NEW_PIN_REQ";
                        else if (text.includes("[AUTH] STATUS:SUCCESS") || text.includes("[SYS] STATUS:READY")) authState = "READY";
                        else if (text.includes("[AUTH] STATUS:FACTORY_RESET_COMPLETE")) authState = "NEW_PIN_REQ";
                        
                        terminal.innerText += text + "\n";
                        terminal.scrollTop = terminal.scrollHeight;
                    } catch (e) {}
                } 
                else {
                    if (line.includes("[AUTH] STATUS:PIN_REQ")) authState = "PIN_REQ";
                    else if (line.includes("[AUTH] STATUS:NEW_PIN_REQ")) authState = "NEW_PIN_REQ";
                    else if (line.includes("[AUTH] STATUS:SUCCESS") || line.includes("[SYS] STATUS:READY")) authState = "READY";
                    else if (line.includes("[AUTH] STATUS:FACTORY_RESET_COMPLETE")) authState = "NEW_PIN_REQ";

                    terminal.innerText += line + "\n";
                    terminal.scrollTop = terminal.scrollHeight;
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
        terminal.innerText += `[Extension] Active site: ${message.hostname}\n`;
        terminal.scrollTop = terminal.scrollHeight;
    } else if (message.type === "SEND") {
        sendSecure(message.payload);
    } else if (message.type === "DISCONNECT") {
        disconnect();
    }
    return true;
});