// Unthrottled Background Timer Worker for AWSSecurity AI
// Runs in dedicated worker thread - NOT throttled by Chromium tab sleep or energy saver

let timer = null;

self.onmessage = function(e) {
  if (e.data === "start") {
    if (timer) clearInterval(timer);
    timer = setInterval(() => {
      self.postMessage({ type: "tick", timestamp: Date.now() });
    }, 2500);
  } else if (e.data === "stop") {
    if (timer) {
      clearInterval(timer);
      timer = null;
    }
  }
};
