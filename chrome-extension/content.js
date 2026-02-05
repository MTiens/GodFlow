// AuPen Request Capture - Content Script
// This script runs in the context of web pages to capture additional request details

// Override fetch to capture requests
const originalFetch = window.fetch;
window.fetch = function(...args) {
  const [url, options = {}] = args;
  
  // Send request details to background script
  chrome.runtime.sendMessage({
    action: 'captureFetch',
    data: {
      url: url,
      method: options.method || 'GET',
      headers: options.headers || {},
      body: options.body
    }
  });
  
  return originalFetch.apply(this, args);
};

// Override XMLHttpRequest to capture AJAX requests
const originalXHROpen = XMLHttpRequest.prototype.open;
const originalXHRSend = XMLHttpRequest.prototype.send;

XMLHttpRequest.prototype.open = function(method, url, ...args) {
  this._aupenMethod = method;
  this._aupenUrl = url;
  return originalXHROpen.apply(this, [method, url, ...args]);
};

XMLHttpRequest.prototype.send = function(data) {
  // Send request details to background script
  chrome.runtime.sendMessage({
    action: 'captureXHR',
    data: {
      url: this._aupenUrl,
      method: this._aupenMethod,
      body: data
    }
  });
  
  return originalXHRSend.apply(this, [data]);
};

// Capture form submissions
document.addEventListener('submit', function(event) {
  const form = event.target;
  const formData = new FormData(form);
  const data = Object.fromEntries(formData.entries());
  
  chrome.runtime.sendMessage({
    action: 'captureForm',
    data: {
      url: form.action || window.location.href,
      method: form.method || 'GET',
      data: data
    }
  });
});

console.log('🚀 AuPen Request Capture: Content script loaded');
