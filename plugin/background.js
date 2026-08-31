chrome.runtime.onInstalled.addListener(() => {
    chrome.contextMenus.create({
        id: "generate-esp32-password",
        title: "Generate ESP32 Password & Save",
        contexts: ["editable", "page"]
    });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
    if (info.menuItemId === "generate-esp32-password" && tab && tab.url) {
        try {
            let url = new URL(tab.url);
            if (url.hostname) {
                chrome.tabs.query({ url: chrome.runtime.getURL("dashboard.html") }, (tabs) => {
                    if (tabs.length > 0) {
                        chrome.tabs.sendMessage(tabs[0].id, {
                            target: "dashboard",
                            type: "AUTO_GENERATE",
                            hostname: url.hostname,
                            senderTabId: tab.id
                        });
                    }
                });
            }
        } catch(e) {}
    }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.target === "dashboard") {
        if (sender && sender.tab) {
            message.senderTabId = sender.tab.id;
        }
        chrome.tabs.query({ url: chrome.runtime.getURL("dashboard.html") }, (tabs) => {
            if (tabs.length > 0) {
                chrome.tabs.sendMessage(tabs[0].id, message, sendResponse);
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
                if (url.hostname) {
                    chrome.runtime.sendMessage({
                        target: "dashboard",
                        type: "ACTIVE_SITE",
                        hostname: url.hostname
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