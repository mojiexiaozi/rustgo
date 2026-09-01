(() => {
  "use strict";

  const form = document.getElementById("login-form");
  const status = document.getElementById("login-status");
  if (!form || !status) return;

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    status.textContent = "Signing in…";
    const formData = new FormData(form);
    const body = new URLSearchParams();
    body.set("username", String(formData.get("username") || ""));
    body.set("password", String(formData.get("password") || ""));
    try {
      const response = await fetch("/login", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        credentials: "same-origin",
        body,
      });
      if (!response.ok) throw new Error("sign in failed");
      window.location.assign("/");
    } catch (_) {
      status.textContent = "Sign in failed. Check the administrator credentials and try again.";
    }
  });
})();
