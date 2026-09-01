const statusDiv = document.getElementById('status');
const openBtn = document.getElementById('openDashboardBtn');
const authSection = document.getElementById('authSection');
const pinInput = document.getElementById('pinInput');
const navTabs = document.getElementById('navTabs');
const vaultMsg = document.getElementById('vaultMessage');

let isAuthenticated = false;

// Strict Sets prevent duplicate elements from rendering
let passItemsSet = new Set();
let fidoItemsSet = new Set();

let isFetchingPass = false;
let isFetchingFido = false;

// State machine lock for CLI operations
let pendingTask = null;

function showMsg(text, color = "#00ffff") {
    vaultMsg.innerText = text;
    vaultMsg.style.color = color;
    setTimeout(() => { if (vaultMsg.innerText === text) vaultMsg.innerText = ""; }, 3500);
}

// --- Navigation Tabs ---
document.querySelectorAll('.tab-btn').forEach(button => {
    button.addEventListener('click', () => {
        if (!isAuthenticated && button.dataset.tab === "tab-dashboard") return;
        document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));

        button.classList.add('active');
        document.getElementById(button.dataset.tab).classList.add('active');

        if (button.dataset.tab === "tab-dashboard") {
            chrome.runtime.sendMessage({ target: "dashboard", type: "SEND", payload: "info" });
            document.getElementById('btnListPass').click();
            document.getElementById('btnListFido').click();
        }
    });
});

// --- Hardware Status & Auth ---
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

// --- Favicon & UI Renderers ---
function getFaviconUrl(domain) {
    let clean = domain.toLowerCase().trim();
    if (clean.includes(':')) clean = clean.split(':')[0];
    if (!clean.includes('.')) clean = 'localhost';
    return `https://www.google.com/s2/favicons?domain=${encodeURIComponent(clean)}&sz=32`;
}

function renderStats(total, used, free, usage, count) {
    document.getElementById('statsVisual').innerHTML = `
        <div class="progress-bg"><div class="progress-fill" style="width: ${usage}%;"></div></div>
        <div class="stats-grid">
            <div><strong>Used:</strong> ${usage}% (${Math.round(used/1024)}KB)</div>
            <div><strong>Free:</strong> ${Math.round(free/1024)}KB</div>
            <div><strong>Items:</strong> ${count}</div>
            <div><strong>Cap:</strong> ${Math.round(total/1024)}KB</div>
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

// --- Core Actions ---
window.deleteItem = function(type, item) {
    if (!confirm(`Are you sure you want to permanently delete '${item}'?`)) return;
    
    if (type === 'pass') {
        showMsg(`Deleting '${item}'...`);
        chrome.runtime.sendMessage({ target: "dashboard", type: "CMD_DELETE_PASS", name: item });
    } else {
        showMsg(`Deleting FIDO key '${item}'...`);
        chrome.runtime.sendMessage({ target: "dashboard", type: "CMD_DELETE_FIDO", domain: item });
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

// --- Serial Stream Event Listener & Dynamic CLI State Machine ---
chrome.runtime.onMessage.addListener((message) => {
    if (message.target === "popup" && message.type === "SERIAL_OUTPUT") {
        const lines = (message.text || "").split(/\r?\n/);

        lines.forEach(rawLine => {
            const text = rawLine.trim();
            if (!text) return;

            if (text.startsWith("[STORAGE] STATS:")) {
                const p = text.split(":")[1].split(",");
                if (p.length >= 5) renderStats(p[0], p[1], p[2], p[3], p[4]);
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
            } else if (text.startsWith("[ERR]")) {
                showMsg(`Hardware Error: ${text.replace("[ERR] CODE:", "")}`, "orange");
                pendingTask = null;
            }
        });
    }
});

setInterval(checkStatus, 1000);
checkStatus();