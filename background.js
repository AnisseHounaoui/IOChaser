chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "openToolTab") {
    chrome.tabs.create({ url: request.url, active: false });
  }
});
