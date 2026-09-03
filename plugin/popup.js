const statusDiv = document.getElementById('status');
const openBtn = document.getElementById('openDashboardBtn');
const authSection = document.getElementById('authSection');
const pinInput = document.getElementById('pinInput');
const navTabs = document.getElementById('navTabs');
const vaultMsg = document.getElementById('vaultMessage');

let isAuthenticated = false;
let currentAuthState = "UNKNOWN";
let lastRefreshedEpochStep = -1;
let totpAnimationFrameId = null;

function showMsg(text, color = "#00ffff") {
    vaultMsg.innerText = text;
    vaultMsg.style.color = color;
    setTimeout(() => { if (vaultMsg.innerText === text) vaultMsg.innerText = ""; }, 3500);
}

document.querySelectorAll('.tab-btn').forEach(button => {
    button.addEventListener('click', () => {
        if (!isAuthenticated && button.dataset.tab !== "tab-status") return;
        document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));

        button.classList.add('active');
        document.getElementById(button.dataset.tab).classList.add('active');

        if (button.dataset.tab === "tab-dashboard") {
            chrome.runtime.sendMessage({ target: "dashboard", type: "SEND", payload: { cmd: "STORAGE_INFO" } });
            document.getElementById('btnListPass').click();
            document.getElementById('btnListFido').click();
        } else if (button.dataset.tab === "tab-totp") {
            document.getElementById('btnListTotp').click();
        }
    });
});

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
            currentAuthState = response.authState;
            
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
    const commandName = (currentAuthState === "NEW_PIN_REQ") ? "CREATE_PIN" : "VERIFY_PIN";
    chrome.runtime.sendMessage({ target: "dashboard", type: "SEND", payload: { cmd: commandName, pin: pinInput.value } });
    pinInput.value = "";
};

document.getElementById('submitPinBtn').onclick = submitPin;
pinInput.addEventListener("keyup", (e) => { if (e.key === "Enter") submitPin(); });
openBtn.onclick = () => chrome.tabs.create({ url: "dashboard.html", pinned: true, active: false });

document.getElementById('disconnectBtn').onclick = () => {
    chrome.runtime.sendMessage({ target: "dashboard", type: "SEND", payload: { cmd: "DISCONNECT" } });
    chrome.tabs.query({}, (tabs) => {
        tabs.forEach(tab => {
            if (tab.url && tab.url.includes("dashboard.html")) chrome.tabs.remove(tab.id);
        });
    });
};

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
    
    itemsArray.forEach(rawItem => {
        let displayDomain = typeof rawItem === "object" ? rawItem.website : rawItem;
        let displayLabel = typeof rawItem === "object" ? `${rawItem.website} | ${rawItem.login}` : rawItem;
        
        const li = document.createElement('li');
        const labelDiv = document.createElement('div');
        labelDiv.className = "item-label";
        
        const img = document.createElement('img');
        img.className = "item-favicon";
        img.src = getFaviconUrl(displayDomain);
        img.onerror = () => { img.src = "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16' fill='%2300ffff'><circle cx='8' cy='8' r='5'/></svg>"; };
        
        const textSpan = document.createElement('span');
        textSpan.innerText = displayLabel;
        
        labelDiv.appendChild(img);
        labelDiv.appendChild(textSpan);
        
        const delBtn = document.createElement('button');
        delBtn.className = "icon-btn btn-del";
        delBtn.innerHTML = "🗑️";
        delBtn.title = `Delete ${displayLabel}`;
        delBtn.onclick = () => window.deleteItem(type, rawItem);
        
        li.appendChild(labelDiv);
        li.appendChild(delBtn);
        ul.appendChild(li);
    });
}

function renderTotpList(codesObj) {
    const ul = document.getElementById('totpVisual');
    ul.innerHTML = "";
    const entries = Object.entries(codesObj || {});
    
    lastRefreshedEpochStep = Math.floor(Date.now() / 30000);

    if (entries.length === 0) return ul.innerHTML = `<div class="empty-state">No authenticators found.</div>`;
    
    entries.forEach(([name, code]) => {
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
        actionArea.style.display = "flex"; actionArea.style.alignItems = "center"; actionArea.style.gap = "8px";
        
        const codeDiv = document.createElement('div');
        codeDiv.className = "totp-code"; codeDiv.innerText = formattedCode;
        
        const delBtn = document.createElement('button');
        delBtn.className = "icon-btn btn-del"; delBtn.innerHTML = "🗑️"; delBtn.title = `Delete ${name}`;
        delBtn.onclick = (e) => { e.stopPropagation(); window.deleteItem('totp', name); };
        
        actionArea.appendChild(codeDiv); actionArea.appendChild(delBtn);
        header.appendChild(label); header.appendChild(actionArea);
        
        const timerBg = document.createElement('div');
        timerBg.className = "totp-timer-bg"; timerBg.innerHTML = `<div class="totp-timer-fill"></div>`;
        
        container.appendChild(header); container.appendChild(timerBg);
        li.appendChild(container); ul.appendChild(li);
    });
}

function updateTotpTimers() {
    const totpTab = document.getElementById('tab-totp');
    if (totpTab && totpTab.classList.contains('active')) {
        const now = Date.now();
        const remainingMs = 30000 - (now % 30000);
        const remainingSec = remainingMs / 1000;
        const currentStep = Math.floor(now / 30000);
        const ratio = remainingMs / 30000;

        // Ultra-smooth GPU scale transformation
        document.querySelectorAll('.totp-timer-fill').forEach(bar => {
            bar.style.transform = `scaleX(${ratio})`;
            bar.style.backgroundColor = remainingSec <= 5 ? '#ff4444' : '#00ffff';
        });

        // Trigger automatic key rotation on period expiration
        if (lastRefreshedEpochStep !== -1 && lastRefreshedEpochStep !== currentStep) {
            lastRefreshedEpochStep = currentStep;
            document.getElementById('btnListTotp').click();
        }
    }

    totpAnimationFrameId = requestAnimationFrame(updateTotpTimers);
}

// Start frame-rate synced animation loop
if (totpAnimationFrameId) cancelAnimationFrame(totpAnimationFrameId);
requestAnimationFrame(updateTotpTimers);


window.deleteItem = function(type, item) {
    const identifier = (typeof item === "object") ? `${item.website} (${item.login})` : item;
    if (!confirm(`Are you sure you want to permanently delete '${identifier}'?`)) return;
    
    if (type === 'pass') {
        showMsg(`Deleting '${item.website}'...`);
        chrome.runtime.sendMessage({ target: "dashboard", type: "CMD_DELETE_PASS", name: item.website, login: item.login });
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
    const login = document.getElementById('newPassLogin').value.trim();
    const val = document.getElementById('newPassValue').value.trim();
    
    if (!name || !login) return showMsg("Site and Login required!", "orange");
    
    showMsg(`Creating '${name}'...`);
    
    const payload = { cmd: "SAVE_PASS", site: name, login: login };
    if (val) payload.pass = val;
    else payload.autogen = true;

    chrome.runtime.sendMessage({ target: "dashboard", type: "SEND", payload: payload });

    document.getElementById('newPassName').value = "";
    document.getElementById('newPassLogin').value = "";
    document.getElementById('newPassValue').value = "";
};

document.getElementById('btnListPass').onclick = () => {
    document.getElementById('passVisual').innerHTML = '<div class="empty-state">Syncing...</div>';
    chrome.runtime.sendMessage({ target: "dashboard", type: "CMD_LIST_PASS" });
};

document.getElementById('btnListFido').onclick = () => {
    document.getElementById('fidoVisual').innerHTML = '<div class="empty-state">Syncing...</div>';
    chrome.runtime.sendMessage({ target: "dashboard", type: "CMD_LIST_FIDO" });
};

document.getElementById('btnRunDiag').onclick = () => {
    document.getElementById('diagVisual').innerHTML = '<div class="empty-state">Testing subsystems...</div>';
    chrome.runtime.sendMessage({ target: "dashboard", type: "SEND", payload: { cmd: "RUN_DIAGNOSTICS" } });
};

document.getElementById('btnWipePass').onclick = () => {
    if (confirm("WARNING: This will permanently purge the storage vault. Continue?")) {
        showMsg("Purging vault...", "red");
        chrome.runtime.sendMessage({ target: "dashboard", type: "SEND", payload: { cmd: "PURGE_STORAGE" } });
    }
};

document.getElementById('btnListTotp').onclick = () => {
    document.getElementById('totpVisual').innerHTML = '<div class="empty-state">Syncing...</div>';
    chrome.runtime.sendMessage({ target: "dashboard", type: "CMD_GET_ALL_TOTP" });
};

document.getElementById('btnAddTotp').onclick = () => {
    const name = document.getElementById('totpAddName').value.trim();
    const secret = document.getElementById('totpAddSecret').value.trim().replace(/\s+/g, '');
    
    if (!name || !secret) return showMsg("Name and Secret required!", "orange");
    
    showMsg(`Adding TOTP for '${name}'...`);
    chrome.runtime.sendMessage({ target: "dashboard", type: "SEND", payload: { cmd: "SAVE_TOTP", name: name, secret: secret } });
    
    document.getElementById('totpAddName').value = ""; 
    document.getElementById('totpAddSecret').value = "";
};

document.getElementById('btnSetCrypto').onclick = () => {
    const selectedAlg = parseInt(document.getElementById('cryptoSelect').value, 10);
    showMsg("Updating algorithm...");
    chrome.runtime.sendMessage({
        target: "dashboard",
        type: "CMD_UPDATE_SETTINGS",
        algId: selectedAlg
    });
};

chrome.runtime.onMessage.addListener((message) => {
    if (message.target === "popup" && message.type === "SERIAL_OUTPUT") {
        const json = message.json;
        if (!json) return;

        if (json.type === "event") {
            if (json.module === "STORAGE" && json.event === "STATS" && json.data) {
                const d = json.data;
                renderStats(d.total_bytes, d.used_bytes, d.free_bytes, d.usage_percent, d.passwords_count, d.passkeys_count);
            } else if (json.module === "PASS" && json.event === "LIST" && json.data) {
                renderList('passVisual', json.data.items || [], 'pass');
            } else if (json.module === "FIDO2" && json.event === "LIST" && json.data) {
                renderList('fidoVisual', json.data.websites || [], 'fido');
            } else if (json.module === "TOTP" && json.event === "CODES" && json.data) {
                renderTotpList(json.data.codes || {});
            } else if (json.module === "SYS" && json.event === "SETTINGS_UPDATED") {
                showMsg("Crypto algorithm updated!", "lime");
                if (json.data && json.data.algId !== undefined) {
                    document.getElementById('cryptoSelect').value = json.data.algId.toString();
                }
            } else if (json.module === "PASS" && json.event === "SAVED") {
                showMsg("Password saved!", "lime");
                document.getElementById('btnListPass').click();
            } else if (json.module === "PASS" && json.event === "DELETED") {
                showMsg("Password deleted!", "lime");
                document.getElementById('btnListPass').click();
            } else if (json.module === "TOTP" && json.event === "SAVED") {
                showMsg("TOTP Saved!", "lime");
                document.getElementById('btnListTotp').click();
            } else if (json.module === "TOTP" && json.event === "DELETED") {
                showMsg("TOTP deleted!", "lime");
                document.getElementById('btnListTotp').click();
            } else if (json.module === "FIDO2" && json.event === "DELETED") {
                showMsg("FIDO Key deleted!", "lime");
                document.getElementById('btnListFido').click();
            } else if (json.module === "STORAGE" && json.event === "PURGE_COMPLETE") {
                showMsg("Vault Purged.", "lime");
                document.getElementById('btnListPass').click();
                document.getElementById('btnListFido').click();
            } else if (json.module === "SYS" && json.event === "DIAGNOSTICS_COMPLETE" && json.data) {
                const ul = document.getElementById('diagVisual');
                ul.innerHTML = `<li><span class="test-pass">✔️</span> Diagnostics Passed (${json.data.passed}/${json.data.total})</li>`;
            }
        } else if (json.type === "error") {
            showMsg("Error: " + json.error_code, "orange");
        }
    }
});

setInterval(checkStatus, 1000);
checkStatus();