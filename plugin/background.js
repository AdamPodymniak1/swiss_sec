chrome.runtime.onInstalled.addListener(() => {
    chrome.contextMenus.create({
        id: "get-esp32-password",
        title: "Autofill Saved Password",
        contexts: ["editable", "page"]
    });
    chrome.contextMenus.create({
        id: "generate-esp32-password",
        title: "Generate ESP32 Password & Save",
        contexts: ["editable", "page"]
    });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
    if (!tab || !tab.url) return;
    try {
        let url = new URL(tab.url);
        let domain = url.hostname || (url.protocol === "file:" ? "localfile" : null);
        if (!domain) return;

        let messageType = null;
        if (info.menuItemId === "get-esp32-password") {
            messageType = "GET_PASSWORD";
        } else if (info.menuItemId === "generate-esp32-password") {
            messageType = "AUTO_GENERATE";
        }

        if (messageType) {
            chrome.tabs.query({ url: chrome.runtime.getURL("dashboard.html") }, (tabs) => {
                if (tabs.length > 0) {
                    chrome.tabs.sendMessage(tabs[0].id, {
                        target: "dashboard",
                        type: messageType,
                        hostname: domain,
                        senderTabId: tab.id
                    });
                } else {
                    if (chrome.action.openPopup) {
                        chrome.action.openPopup().catch(() => {});
                    }
                }
            });
        }
    } catch(e) {}
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.target === "background" && message.type === "STATE_CHANGED") {
        if (message.authState === "AWAITING_FINGERPRINT") {
            chrome.action.setBadgeText({ text: "TOUCH" });
            chrome.action.setBadgeBackgroundColor({ color: "#00FFFF" });

            if (chrome.action.openPopup) {
                chrome.action.openPopup().catch(() => {});
            }
        } else {
            chrome.action.setBadgeText({ text: "" });
        }
    } else if (message.target === "dashboard") {
        if (sender && sender.tab) {
            message.senderTabId = sender.tab.id;
        }
        chrome.tabs.query({ url: chrome.runtime.getURL("dashboard.html") }, (tabs) => {
            if (tabs.length > 0) {
                chrome.tabs.sendMessage(tabs[0].id, message, (response) => {
                    if (chrome.runtime.lastError) {
                        sendResponse(null);
                    } else {
                        sendResponse(response);
                    }
                });
            } else {
                sendResponse(null);
            }
        });
        return true; 
    } else if (message.target === "content" && message.recipientTabId) {
        chrome.tabs.sendMessage(message.recipientTabId, message);
    }
});

function notifyActiveTab() {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs.length > 0 && tabs[0].url) {
            try {
                let url = new URL(tabs[0].url);
                let domain = url.hostname || (url.protocol === "file:" ? "localfile" : null);
                if (domain) {
                    chrome.runtime.sendMessage({
                        target: "dashboard",
                        type: "ACTIVE_SITE",
                        hostname: domain
                    }).catch(() => {});
                }
            } catch(e) {}
        }
    });
}

chrome.tabs.onActivated.addListener(notifyActiveTab);
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.active) {
        notifyActiveTab();
    }
});