const statusDiv = document.getElementById('status');
const openBtn = document.getElementById('openDashboardBtn');
const authSection = document.getElementById('authSection');
const pinInput = document.getElementById('pinInput');
const submitPinBtn = document.getElementById('submitPinBtn');
const disconnectBtn = document.getElementById('disconnectBtn');

function checkStatus() {
    chrome.runtime.sendMessage({ target: "dashboard", type: "PING" }, (response) => {
        if (chrome.runtime.lastError || !response) {
            statusDiv.innerText = "Dashboard Closed";
            statusDiv.style.color = "red";
            authSection.style.display = 'none';
            disconnectBtn.style.display = 'none';
            openBtn.style.display = 'block';
        } else {
            openBtn.style.display = 'none';
            disconnectBtn.style.display = response.connected ? 'block' : 'none';
            
            if (response.authState === "PIN_REQ") {
                statusDiv.innerText = "PIN REQUIRED";
                statusDiv.style.color = "orange";
                authSection.style.display = 'block';
                pinInput.placeholder = "Enter PIN";
            } else if (response.authState === "NEW_PIN_REQ") {
                statusDiv.innerText = "NEW PIN REQUIRED";
                statusDiv.style.color = "orange";
                authSection.style.display = 'block';
                pinInput.placeholder = "Create New PIN";
            } else if (response.authState === "AWAITING_FINGERPRINT") {
                statusDiv.innerText = "Waiting for Fingerprint";
                statusDiv.style.color = "#00ffff";
                authSection.style.display = 'none';
            } else {
                statusDiv.innerText = response.connected ? "Hardware Connected" : "Hardware Disconnected";
                statusDiv.style.color = response.connected ? "lime" : "orange";
                authSection.style.display = 'none';
            }
        }
    });
}

openBtn.onclick = () => {
    chrome.tabs.create({ url: "dashboard.html", pinned: true, active: false });
};

submitPinBtn.onclick = () => {
    chrome.runtime.sendMessage({ target: "dashboard", type: "SEND", payload: pinInput.value });
    pinInput.value = "";
};

disconnectBtn.onclick = () => {
    chrome.runtime.sendMessage({ target: "dashboard", type: "DISCONNECT" });
};

setInterval(checkStatus, 1000);
checkStatus();