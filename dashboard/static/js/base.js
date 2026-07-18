(() => {
  const body = document.body;
  const toggle = document.getElementById("menu-toggle");
  const sidebar = document.getElementById("sidebar");
  const overlay = document.getElementById("loading-overlay");
  const loadingMessage = document.getElementById("loading-message");

  if (toggle) {
    toggle.addEventListener("click", () => body.classList.toggle("menu-open"));
    document.addEventListener("click", event => {
      if (window.innerWidth > 860 || !body.classList.contains("menu-open")) return;
      if (sidebar && !sidebar.contains(event.target) && !toggle.contains(event.target)) {
        body.classList.remove("menu-open");
      }
    });
  }

  function hideLoading() {
    if (!overlay) return;
    overlay.hidden = true;
    body.classList.remove("is-loading");
  }

  function showLoading(message = "Processing…") {
    if (!overlay) return;
    if (loadingMessage) loadingMessage.textContent = message;
    overlay.hidden = false;
    body.classList.add("is-loading");
  }

  document.querySelectorAll("form:not([data-no-loading])").forEach(form => {
    form.addEventListener("submit", event => {
      if (event.defaultPrevented || !form.checkValidity()) return;
      const submitter = event.submitter;
      const message = form.dataset.loadingText || submitter?.dataset.loadingText || "Processing request…";
      if (submitter) {
        submitter.disabled = true;
        submitter.classList.add("button-loading");
      }
      window.setTimeout(() => showLoading(message), 40);
    });
  });

  document.querySelectorAll(".toast").forEach((toast, index) => {
    const dismiss = () => {
      toast.classList.add("toast-out");
      window.setTimeout(() => toast.remove(), 220);
    };
    toast.querySelector("button")?.addEventListener("click", dismiss);
    window.setTimeout(dismiss, 5600 + index * 500);
  });

  window.addEventListener("pageshow", hideLoading);
  window.ShadowTrace = { showLoading, hideLoading };
})();
