chrome.runtime.sendMessage({
  target: "dashboard",
  type: "PAGE_LOADED",
  hostname: window.location.hostname,
  url: window.location.href
});

document.addEventListener("focusin", (e) => {
  const target = e.target;
  if (target && target.tagName === "INPUT" && target.type === "password") {
    if (target.dataset.ssPrompted === "true") return;
    checkHardwareAndPrompt(target);
  }
});

function checkHardwareAndPrompt(passwordInput) {
  chrome.runtime.sendMessage({ target: "dashboard", type: "PING" }, (response) => {
    if (chrome.runtime.lastError || !response || !response.connected || response.authState !== "READY") {
      console.log("[SWISS SEC] Prompt blocked: Dashboard closed, hardware disconnected, or PIN required.");
      return;
    }

    const scope = passwordInput.closest("form") || document.body;
    const passwordInputs = scope.querySelectorAll('input[type="password"]');
    const textContent = scope.innerText.toLowerCase();
    
    const inputAttrs = (passwordInput.name + " " + passwordInput.id + " " + passwordInput.placeholder).toLowerCase();

    const isRegistration = passwordInputs.length > 1 || 
                           textContent.includes("confirm") || 
                           textContent.includes("new") || 
                           textContent.includes("register") || 
                           textContent.includes("sign up") ||
                           textContent.includes("create account") ||
                           inputAttrs.includes("new") ||
                           inputAttrs.includes("confirm");

    if (isRegistration) {
      injectRegistrationPrompt(passwordInput);
    }
  });
}

function injectRegistrationPrompt(targetInput) {
  if (document.getElementById("swiss-sec-reg-prompt")) return;

  targetInput.dataset.ssPrompted = "true";

  const promptDiv = document.createElement("div");
  promptDiv.id = "swiss-sec-reg-prompt";
  promptDiv.style.cssText = `
    position: absolute;
    background: #121212;
    color: #00ff00;
    border: 1px solid #444;
    padding: 10px;
    z-index: 2147483647;
    border-radius: 4px;
    font-family: monospace;
    box-shadow: 0 4px 8px rgba(0,0,0,0.5);
  `;
  
  promptDiv.innerHTML = `
    <div style="margin-bottom:8px; font-weight:bold;">Save & Generate Vault Password?</div>
    <button id="ss-btn-yes" style="background:#333; color:#fff; border:1px solid #555; padding:5px 10px; cursor:pointer;">Yes</button>
    <button id="ss-btn-no" style="background:#333; color:#fff; border:1px solid #555; padding:5px 10px; cursor:pointer; margin-left:5px;">No</button>
  `;
  
  const rect = targetInput.getBoundingClientRect();
  promptDiv.style.top = (window.scrollY + rect.bottom + 5) + "px";
  promptDiv.style.left = (window.scrollX + rect.left) + "px";
  document.body.appendChild(promptDiv);

  document.getElementById("ss-btn-yes").addEventListener("click", (e) => {
    e.preventDefault();
    chrome.runtime.sendMessage({
      target: "dashboard",
      type: "AUTO_GENERATE",
      hostname: window.location.hostname
    });
    promptDiv.remove();
  });

  document.getElementById("ss-btn-no").addEventListener("click", (e) => {
    e.preventDefault();
    promptDiv.remove();
  });
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "FILL_CREDENTIALS") {
    const passwordInputs = document.querySelectorAll('input[type="password"]');
    passwordInputs.forEach((passwordInput) => {
      passwordInput.value = message.password;
      passwordInput.dispatchEvent(new Event("input", { bubbles: true }));
      passwordInput.dispatchEvent(new Event("change", { bubbles: true }));
    });
  }
});