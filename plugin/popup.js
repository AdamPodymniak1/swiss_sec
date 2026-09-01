const statusDiv = document.getElementById('status');
const openBtn = document.getElementById('openDashboardBtn');
const authSection = document.getElementById('authSection');
const pinInput = document.getElementById('pinInput');
const navTabs = document.getElementById('navTabs');
const vaultMsg = document.getElementById('vaultMessage');

let isAuthenticated = false;

// Prevent duplicate list entries while refreshing vault data.
let passItemsSet = new Set();
let fidoItemsSet = new Set();

let isFetchingPass = false;
let isFetchingFido = false;

// TOTP state management.
let totpEntries = new Map();
let totpInterval = null;

// Tracks the active CLI workflow state.
let pendingTask = null;

function showMsg(text, color = "#00ffff") {
    vaultMsg.innerText = text;
    vaultMsg.style.color = color;
    setTimeout(() => { if (vaultMsg.innerText === text) vaultMsg.innerText = ""; }, 3500);
}

// Navigation tab switching.
document.querySelectorAll('.tab-btn').forEach(button => {
    button.addEventListener('click', () => {
        if (!isAuthenticated && button.dataset.tab !== "tab-status") return;
        document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));

        button.classList.add('active');
        document.getElementById(button.dataset.tab).classList.add('active');

        if (button.dataset.tab === "tab-dashboard") {
            chrome.runtime.sendMessage({ target: "dashboard", type: "SEND", payload: "info" });
            document.getElementById('btnListPass').click();
            document.getElementById('btnListFido').click();
        } else if (button.dataset.tab === "tab-totp") {
            document.getElementById('btnListTotp').click();
        }
    });
});

// Device connection and authentication status.
function checkStatus() {
    chrome.runtime.sendMessage({ target: "dashboard", type: "PING" }, (response) => {
        if (chrome.runtime.lastError || !response) {
            statusDiv.innerText = "Terminal Closed";
            statusDiv.style.color = "red";
            authSection.style.display = 'none';
            document.getElementById('disconnectBtn').style.display = 'none';
            openBtn.style.display = 'block';
            navTabs.style.display = 'none';
            isAuthenticated = false;
        } else {
            openBtn.style.display = 'none';
            document.getElementById('disconnectBtn').style.display = response.connected ? 'block' : 'none';
            
            if (response.authState === "READY") {
                if (!isAuthenticated) {
                    isAuthenticated = true;
                    navTabs.style.display = 'flex';
                    statusDiv.innerText = "Vault Unlocked";
                    statusDiv.style.color = "lime";
                    authSection.style.display = 'none';
                }
            } else {
                isAuthenticated = false;
                navTabs.style.display = 'none';
                document.querySelector('[data-tab="tab-status"]').click();
                
                if (response.authState === "PIN_REQ" || response.authState === "NEW_PIN_REQ") {
                    statusDiv.innerText = response.authState === "PIN_REQ" ? "PIN REQUIRED" : "NEW PIN REQUIRED";
                    statusDiv.style.color = "orange";
                    authSection.style.display = 'block';
                } else {
                    statusDiv.innerText = response.connected ? "Hardware Connected (Locked)" : "Hardware Disconnected";
                    statusDiv.style.color = "orange";
                    authSection.style.display = 'none';
                }
            }
        }
    });
}

const submitPin = () => {
    if (!pinInput.value) return;
    chrome.runtime.sendMessage({ target: "dashboard", type: "SEND", payload: pinInput.value });
    pinInput.value = "";
};

document.getElementById('submitPinBtn').onclick = submitPin;
pinInput.addEventListener("keyup", (e) => { if (e.key === "Enter") submitPin(); });
openBtn.onclick = () => chrome.tabs.create({ url: "dashboard.html", pinned: true, active: false });

document.getElementById('disconnectBtn').onclick = () => {
    chrome.runtime.sendMessage({ target: "dashboard", type: "SEND", payload: "DISCONNECT" });
    
    chrome.tabs.query({}, (tabs) => {
        tabs.forEach(tab => {
            if (tab.url && tab.url.includes("dashboard.html")) {
                chrome.tabs.remove(tab.id);
            }
        });
    });
};

// Rendering helpers for list entries and favicons.
function getFaviconUrl(domain) {
    let clean = domain.toLowerCase().trim();
    if (clean.includes(':')) clean = clean.split(':')[0];
    if (!clean.includes('.')) clean = 'localhost';
    return `https://www.google.com/s2/favicons?domain=${encodeURIComponent(clean)}&sz=32`;
}

function renderStats(total, used, free, usage, passCount, passkeyCount = 0) {
    document.getElementById('statsVisual').innerHTML = `
        <div class="progress-bg"><div class="progress-fill" style="width: ${usage}%;"></div></div>
        <div class="stats-grid">
            <div><strong>Used:</strong> ${usage}% (${Math.round(used/1024)}KB)</div>
            <div><strong>Free:</strong> ${Math.round(free/1024)}KB</div>
            <div><strong>Passwords:</strong> ${passCount}</div>
            <div><strong>Passkeys:</strong> ${passkeyCount}</div>
        </div>
    `;
}

function renderList(elementId, itemsArray, type) {
    const ul = document.getElementById(elementId);
    ul.innerHTML = "";
    
    if (itemsArray.length === 0) {
        ul.innerHTML = `<div class="empty-state">No items found.</div>`;
        return;
    }
    
    itemsArray.forEach(item => {
        const li = document.createElement('li');
        
        const labelDiv = document.createElement('div');
        labelDiv.className = "item-label";
        
        const img = document.createElement('img');
        img.className = "item-favicon";
        img.src = getFaviconUrl(item);
        img.onerror = () => { 
            img.src = "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16' fill='%2300ffff'><circle cx='8' cy='8' r='5'/></svg>"; 
        };
        
        const textSpan = document.createElement('span');
        textSpan.innerText = item;
        
        labelDiv.appendChild(img);
        labelDiv.appendChild(textSpan);
        
        const delBtn = document.createElement('button');
        delBtn.className = "icon-btn btn-del";
        delBtn.innerHTML = "🗑️";
        delBtn.title = `Delete ${item}`;
        delBtn.onclick = () => window.deleteItem(type, item);
        
        li.appendChild(labelDiv);
        li.appendChild(delBtn);
        ul.appendChild(li);
    });
}

// TOTP list rendering and time-window update.
function renderTotpList() {
    const ul = document.getElementById('totpVisual');
    ul.innerHTML = "";
    
    if (totpEntries.size === 0) {
        ul.innerHTML = `<div class="empty-state">No authenticators found.</div>`;
        return;
    }
    
    totpEntries.forEach((code, name) => {
        const li = document.createElement('li');
        li.style.cursor = "pointer";
        li.title = "Click to copy code";
        li.onclick = () => {
            navigator.clipboard.writeText(code);
            showMsg("Code copied!", "lime");
        };
        
        const formattedCode = code.length === 6 ? `${code.substring(0,3)} ${code.substring(3)}` : code;

        const container = document.createElement('div');
        container.className = "totp-item";
        
        const header = document.createElement('div');
        header.className = "totp-header";
        
        const label = document.createElement('div');
        label.className = "item-label";
        label.innerHTML = `<img class="item-favicon" src="${getFaviconUrl(name)}" onerror="this.src='data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 16 16%22 fill=%22%2300ffff%22><circle cx=%228%22 cy=%228%22 r=%225%22/></svg>'"><span>${name}</span>`;
        
        const actionArea = document.createElement('div');
        actionArea.style.display = "flex";
        actionArea.style.alignItems = "center";
        actionArea.style.gap = "8px";
        
        const codeDiv = document.createElement('div');
        codeDiv.className = "totp-code";
        codeDiv.innerText = formattedCode;
        
        const delBtn = document.createElement('button');
        delBtn.className = "icon-btn btn-del";
        delBtn.innerHTML = "🗑️";
        delBtn.title = `Delete ${name}`;
        delBtn.onclick = (e) => {
            e.stopPropagation();
            window.deleteItem('totp', name);
        };
        
        actionArea.appendChild(codeDiv);
        actionArea.appendChild(delBtn);
        header.appendChild(label);
        header.appendChild(actionArea);
        
        const timerBg = document.createElement('div');
        timerBg.className = "totp-timer-bg";
        timerBg.innerHTML = `<div class="totp-timer-fill"></div>`;
        
        container.appendChild(header);
        container.appendChild(timerBg);
        li.appendChild(container);
        ul.appendChild(li);
    });

    updateTotpTimers();
    if (totpInterval) clearInterval(totpInterval);
    totpInterval = setInterval(updateTotpTimers, 1000);
}

function updateTotpTimers() {
    const epoch = Math.floor(Date.now() / 1000);
    const remaining = 30 - (epoch % 30);
    const pct = (remaining / 30) * 100;
    
    if (remaining === 30 && totpEntries.size > 0) {
        document.getElementById('btnListTotp').click();
    } else {
        document.querySelectorAll('.totp-timer-fill').forEach(bar => {
            bar.style.width = pct + '%';
            bar.style.backgroundColor = remaining <= 5 ? '#ff4444' : '#00ffff';
        });
    }
}

// Core item actions.
window.deleteItem = function(type, item) {
    if (!confirm(`Are you sure you want to permanently delete '${item}'?`)) return;
    
    if (type === 'pass') {
        showMsg(`Deleting '${item}'...`);
        chrome.runtime.sendMessage({ target: "dashboard", type: "CMD_DELETE_PASS", name: item });
    } else if (type === 'fido') {
        showMsg(`Deleting FIDO key '${item}'...`);
        chrome.runtime.sendMessage({ target: "dashboard", type: "CMD_DELETE_FIDO", domain: item });
    } else if (type === 'totp') {
        showMsg(`Deleting TOTP '${item}'...`);
        chrome.runtime.sendMessage({ target: "dashboard", type: "CMD_DELETE_TOTP", name: item });
    }
};

document.getElementById('btnCreatePass').onclick = () => {
    const name = document.getElementById('newPassName').value.trim();
    const val = document.getElementById('newPassValue').value.trim();
    
    if (!name) return showMsg("Account/Site name required!", "orange");
    if (pendingTask) return showMsg("Hardware busy...", "orange");
    
    pendingTask = { type: 'CREATE_PASS', step: 'WAIT_NAME', name: name, val: val };
    showMsg(`Creating '${name}'...`);
    
    document.getElementById('newPassName').value = "";
    document.getElementById('newPassValue').value = "";
    
    chrome.runtime.sendMessage({ target: "dashboard", type: "SEND", payload: "create" });
};

document.getElementById('btnListPass').onclick = () => {
    isFetchingPass = true;
    passItemsSet.clear();
    document.getElementById('passVisual').innerHTML = '<div class="empty-state">Syncing...</div>';
    chrome.runtime.sendMessage({ target: "dashboard", type: "SEND", payload: "list" });
};

document.getElementById('btnListFido').onclick = () => {
    isFetchingFido = true;
    fidoItemsSet.clear();
    document.getElementById('fidoVisual').innerHTML = '<div class="empty-state">Syncing...</div>';
    chrome.runtime.sendMessage({ target: "dashboard", type: "SEND", payload: "list_fido" });
};

// Diagnostics and device management actions.
document.getElementById('btnRunDiag').onclick = () => {
    document.getElementById('diagVisual').innerHTML = '<div class="empty-state">Testing subsystems...</div>';
    chrome.runtime.sendMessage({ target: "dashboard", type: "SEND", payload: "diagnostics" });
};

document.getElementById('btnSetCrypto').onclick = () => {
    pendingTask = { type: 'SET_CRYPTO', val: document.getElementById('cryptoSelect').value };
    chrome.runtime.sendMessage({ target: "dashboard", type: "SEND", payload: "set_crypto" });
};

document.getElementById('btnRegFinger').onclick = () => {
    showMsg("Place finger on sensor...", "orange");
    chrome.runtime.sendMessage({ target: "dashboard", type: "SEND", payload: "register_finger" });
};

document.getElementById('btnWipePass').onclick = () => {
    if (confirm("WARNING: This will permanently delete ALL passwords and passkeys. Continue?")) {
        showMsg("Purging vault...", "red");
        chrome.runtime.sendMessage({ target: "dashboard", type: "SEND", payload: "delete_pass" });
    }
};

document.getElementById('btnFactoryReset').onclick = () => {
    if (confirm("CRITICAL: Factory reset will wipe the PIN, all vault data, and fingerprints. Continue?")) {
        showMsg("Sending reset command...", "red");
        chrome.runtime.sendMessage({ target: "dashboard", type: "SEND", payload: "delete_pin" });
    }
};

// TOTP management actions.
document.getElementById('btnListTotp').onclick = () => {
    document.getElementById('totpVisual').innerHTML = '<div class="empty-state">Syncing...</div>';
    totpEntries.clear();
    chrome.runtime.sendMessage({ target: "dashboard", type: "CMD_GET_ALL_TOTP" });
};

document.getElementById('btnAddTotp').onclick = () => {
    const name = document.getElementById('totpAddName').value.trim();
    const secret = document.getElementById('totpAddSecret').value.trim().replace(/\s+/g, '');
    
    if (!name || !secret) return showMsg("Name and Secret required!", "orange");
    if (pendingTask) return showMsg("Hardware busy...", "orange");
    
    pendingTask = { type: 'ADD_TOTP', step: 'WAIT_NAME', name: name, secret: secret };
    showMsg(`Adding TOTP for '${name}'...`);
    
    document.getElementById('totpAddName').value = "";
    document.getElementById('totpAddSecret').value = "";
    
    chrome.runtime.sendMessage({ target: "dashboard", type: "SEND", payload: "totp_add" });
};

// Serial output parser for the dashboard state machine.
chrome.runtime.onMessage.addListener((message) => {
    if (message.target === "popup" && message.type === "SERIAL_OUTPUT") {
        const lines = (message.text || "").split(/\r?\n/);

        lines.forEach(rawLine => {
            const text = rawLine.trim();
            if (!text) return;

            if (text.startsWith("[STORAGE] STATS:")) {
                const p = text.split(":")[1].split(",");
                if (p.length >= 8) {
                    renderStats(p[0], p[1], p[2], p[3], p[4], p[7]);
                } else if (p.length >= 5) {
                    renderStats(p[0], p[1], p[2], p[3], p[4], 0);
                }
            } else if (text.startsWith("[PASS] ITEM:") && isFetchingPass) {
                const item = text.substring(12).trim();
                if (item) passItemsSet.add(item);
            } else if (text.startsWith("[PASS] OUT:") && isFetchingPass) {
                isFetchingPass = false;
                renderList('passVisual', Array.from(passItemsSet), 'pass');
            } else if (text.startsWith("[FIDO2] ITEM:") && isFetchingFido) {
                const item = text.substring(13).trim();
                if (item) fidoItemsSet.add(item);
            } else if (text.startsWith("[FIDO2] OUT:") && isFetchingFido) {
                isFetchingFido = false;
                renderList('fidoVisual', Array.from(fidoItemsSet), 'fido');
            }

            // Parse device diagnostics output.
            if (text.startsWith("[TEST:PASS] -> ")) {
                const diagName = text.replace("[TEST:PASS] -> ", "");
                const ul = document.getElementById('diagVisual');
                if (ul.innerHTML.includes("Testing subsystems") || ul.innerHTML.includes("Ready")) ul.innerHTML = "";
                ul.innerHTML += `<li><span class="test-pass">✔️</span> ${diagName}</li>`;
            } else if (text.startsWith("[TEST:FAIL] *CRITICAL* -> ")) {
                const diagName = text.replace("[TEST:FAIL] *CRITICAL* -> ", "");
                const ul = document.getElementById('diagVisual');
                if (ul.innerHTML.includes("Testing subsystems") || ul.innerHTML.includes("Ready")) ul.innerHTML = "";
                ul.innerHTML += `<li><span class="test-fail">❌</span> ${diagName}</li>`;
            }

            // Resume pending async workflows.
            if (pendingTask && pendingTask.type === 'SET_CRYPTO' && text.includes("[SYS] REQ:ALG_ID")) {
                chrome.runtime.sendMessage({ target: "dashboard", type: "SEND", payload: pendingTask.val });
            }

            // Surface device status events to the UI.
            if (text.includes("[SYS] DEFAULT_CRYPTO_ALG_SET:")) {
                showMsg("Algorithm updated!", "lime");
                pendingTask = null;
            } else if (text.includes("[SYS] STATUS:FINGERPRINT_REGISTERED")) {
                showMsg("Fingerprint Enrolled!", "lime");
            } else if (text.includes("[SYS] VAULT PURGE SUCCESSFUL")) {
                showMsg("Vault Purged.", "lime");
                document.getElementById('btnListPass').click();
                document.getElementById('btnListFido').click();
            } else if (text.includes("[AUTH] STATUS:FACTORY_RESET_COMPLETE")) {
                chrome.storage.local.clear(() => {
                    showMsg("Factory Reset Complete", "red");
                    setTimeout(() => document.getElementById('disconnectBtn').click(), 1000);
                });
            }

            if (pendingTask && pendingTask.type === 'CREATE_PASS') {
                if (text.includes("[PASS] REQ:NAME") && pendingTask.step === 'WAIT_NAME') {
                    pendingTask.step = 'WAIT_AUTOGEN';
                    chrome.runtime.sendMessage({ target: "dashboard", type: "SEND", payload: pendingTask.name });
                } else if ((text.includes("AUTO_GENERATE") || text.includes("(Y/N)")) && pendingTask.step === 'WAIT_AUTOGEN') {
                    if (!pendingTask.val) {
                        pendingTask.step = 'SENT_FINAL';
                        chrome.runtime.sendMessage({ target: "dashboard", type: "SEND", payload: "Y" });
                    } else {
                        pendingTask.step = 'WAIT_VAL';
                        chrome.runtime.sendMessage({ target: "dashboard", type: "SEND", payload: "N" });
                    }
                } else if (text.includes("[PASS] REQ:VAL") && pendingTask.step === 'WAIT_VAL') {
                    pendingTask.step = 'SENT_FINAL';
                    chrome.runtime.sendMessage({ target: "dashboard", type: "SEND", payload: pendingTask.val });
                }
            }

            if (text === "[PASS] OUT:SAVED" || text.startsWith("[PASS] GENERATED:")) {
                showMsg("Password saved!", "lime");
                pendingTask = null;
                document.getElementById('btnListPass').click();
                chrome.runtime.sendMessage({ target: "dashboard", type: "SEND", payload: "info" });
            } else if (text === "[PASS] OUT:DELETED") {
                showMsg("Password deleted!", "lime");
                document.getElementById('btnListPass').click();
                chrome.runtime.sendMessage({ target: "dashboard", type: "SEND", payload: "info" });
            } else if (text === "[FIDO2] OUT:DELETED") {
                showMsg("FIDO Key deleted!", "lime");
                document.getElementById('btnListFido').click();
            } else if (text === "[TOTP] OUT:DELETED") {
                showMsg("TOTP deleted!", "lime");
                document.getElementById('btnListTotp').click();
            } else if (text.startsWith("[ERR]")) {
                showMsg("Error: " + text, "orange");
            }

            // Parse bulk and single TOTP responses.
            if (text.startsWith("[TOTP] CODE:")) {
                const parts = text.replace("[TOTP] CODE:", "").trim().split(":");
                if (parts.length >= 2) {
                    totpEntries.set(parts[0], parts[1]);
                }
            } else if (text === "[TOTP] OUT: END_ALL" || text === "[TOTP] OUT:END_ALL") {
                renderTotpList();
            }

            // Complete the TOTP registration flow.
            if (pendingTask && pendingTask.type === 'ADD_TOTP') {
                if (text.includes("[TOTP] REQ:NAME") && pendingTask.step === 'WAIT_NAME') {
                    pendingTask.step = 'WAIT_SECRET';
                    chrome.runtime.sendMessage({ target: "dashboard", type: "SEND", payload: pendingTask.name });
                } else if (text.includes("[TOTP] REQ:BASE32_SECRET") && pendingTask.step === 'WAIT_SECRET') {
                    pendingTask.step = 'DONE';
                    chrome.runtime.sendMessage({ target: "dashboard", type: "SEND", payload: pendingTask.secret });
                    
                    setTimeout(() => {
                        showMsg("TOTP Secret Saved!", "lime");
                        pendingTask = null;
                        document.getElementById('btnListTotp').click();
                    }, 400); 
                }
            }
        });
    }
});

setInterval(checkStatus, 1000);
checkStatus();