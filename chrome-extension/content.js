// Content script for clawfeel.ai
// Syncs extension clawId into the page's localStorage so the simulator
// always recognizes the user, even if browser data was cleared.

(async () => {
  try {
    const data = await chrome.storage.local.get('clawId');
    if (data.clawId) {
      const existing = localStorage.getItem('clawfeel_browser_id');
      if (!existing || existing !== data.clawId) {
        localStorage.setItem('clawfeel_browser_id', data.clawId);
      }
    }
  } catch { /* extension context invalidated, ignore */ }
})();
