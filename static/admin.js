// Copy only the actual viewer link; native anchors remain the fallback.
if (
  window.isSecureContext &&
  typeof navigator.clipboard?.writeText === "function"
) {
  for (const group of document.querySelectorAll("[data-copy-link]")) {
    const link = group.querySelector("a[data-share-url]");
    const button = group.querySelector("button[data-copy-button]");
    const status = group.querySelector("[data-copy-status]");
    if (!link || !button || !status) continue;

    button.hidden = false;
    button.addEventListener("click", async () => {
      button.disabled = true;
      status.textContent = "Copying link…";
      try {
        await navigator.clipboard.writeText(link.href);
        status.textContent = "Link copied.";
      } catch {
        status.textContent =
          "Could not copy. Select the share link and copy it manually.";
      } finally {
        button.disabled = false;
      }
    });
  }
}
