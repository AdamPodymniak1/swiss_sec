chrome.runtime.sendMessage({
  target: "dashboard",
  type: "PAGE_LOADED",
  hostname: window.location.hostname,
  url: window.location.href
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "FILL_CREDENTIALS" && message.password) {
    const passwordInputs = document.querySelectorAll('input[type="password"]:not([disabled])');
    passwordInputs.forEach((passwordInput) => {
      if (passwordInput.offsetWidth > 0 || passwordInput.offsetHeight > 0 || passwordInput.getClientRects().length > 0) {
        passwordInput.value = message.password;
        passwordInput.dispatchEvent(new Event("input", { bubbles: true }));
        passwordInput.dispatchEvent(new Event("change", { bubbles: true }));
        passwordInput.dispatchEvent(new Event("blur", { bubbles: true }));
      }
    });
  }
});