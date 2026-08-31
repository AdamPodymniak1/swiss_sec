chrome.runtime.sendMessage({
  target: "dashboard",
  type: "PAGE_LOADED",
  hostname: window.location.hostname,
  url: window.location.href
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "FILL_CREDENTIALS") {
    const passwordInput = document.querySelector('input[type="password"]');
    if (passwordInput && message.password) {
      passwordInput.value = message.password;
      passwordInput.dispatchEvent(new Event("input", { bubbles: true }));
      passwordInput.dispatchEvent(new Event("change", { bubbles: true }));
    }
  }
});