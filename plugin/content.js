chrome.runtime.sendMessage({
  target: "dashboard",
  type: "PAGE_LOADED",
  hostname: window.location.hostname,
  url: window.location.href
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "ASK_LOGIN_THEN_ACTION") {
    let userLogin = prompt(`ESP32 Hardware Vault\n\nEnter the login/username you use for ${message.domain}:`);
    if (userLogin !== null && userLogin.trim() !== "") {
      chrome.runtime.sendMessage({
        target: "dashboard",
        type: message.action,
        hostname: message.domain,
        login: userLogin.trim()
      });
    }
  }

  if (message.type === "FILL_CREDENTIALS" && message.password) {
    const passwordInputs = document.querySelectorAll('input[type="password"]:not([disabled])');
    passwordInputs.forEach((pw) => {
      if (pw.offsetWidth > 0 || pw.offsetHeight > 0 || pw.getClientRects().length > 0) {
        pw.value = message.password;
        pw.dispatchEvent(new Event("input", { bubbles: true }));
        pw.dispatchEvent(new Event("change", { bubbles: true }));
        pw.dispatchEvent(new Event("blur", { bubbles: true }));
      }
    });

    if (message.login) {
      const textInputs = document.querySelectorAll('input[type="text"]:not([disabled]), input[type="email"]:not([disabled])');
      textInputs.forEach((txt) => {
        if (txt.offsetWidth > 0 || txt.offsetHeight > 0) {
          let ident = (txt.name + txt.id).toLowerCase();
          if (ident.includes('user') || ident.includes('email') || ident.includes('login') || ident.includes('id') || textInputs.length === 1) {
             txt.value = message.login;
             txt.dispatchEvent(new Event("input", { bubbles: true }));
             txt.dispatchEvent(new Event("change", { bubbles: true }));
             txt.dispatchEvent(new Event("blur", { bubbles: true }));
          }
        }
      });
    }
  }
});