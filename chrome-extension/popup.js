// AuPen Request Capture - Popup Script
document.addEventListener('DOMContentLoaded', function() {
  const startBtn = document.getElementById('startBtn');
  const stopBtn = document.getElementById('stopBtn');
  const exportBtn = document.getElementById('exportBtn');
  const clearBtn = document.getElementById('clearBtn');
  const statusDiv = document.getElementById('status');
  const requestCountSpan = document.getElementById('requestCount');

  // Update UI based on current status
  updateStatus();

  // Event listeners
  startBtn.addEventListener('click', startCapture);
  stopBtn.addEventListener('click', stopCapture);
  exportBtn.addEventListener('click', exportRequests);
  clearBtn.addEventListener('click', clearRequests);

  function startCapture() {
    chrome.runtime.sendMessage({ action: 'startCapture' }, (response) => {
      if (response.success) {
        updateStatus();
        updateRequestCount();
      }
    });
  }

  function stopCapture() {
    chrome.runtime.sendMessage({ action: 'stopCapture' }, (response) => {
      if (response.success) {
        updateStatus();
      }
    });
  }

  function exportRequests() {
    chrome.runtime.sendMessage({ action: 'exportRequests' }, (response) => {
      if (response.success) {
        // Show success message
        const originalText = exportBtn.textContent;
        exportBtn.textContent = '✅ Exported!';
        exportBtn.disabled = true;
        
        setTimeout(() => {
          exportBtn.textContent = originalText;
          exportBtn.disabled = false;
        }, 2000);
      }
    });
  }

  function clearRequests() {
    if (confirm('Are you sure you want to clear all captured requests?')) {
      chrome.runtime.sendMessage({ action: 'clearRequests' }, (response) => {
        if (response.success) {
          updateRequestCount();
        }
      });
    }
  }

  function updateStatus() {
    chrome.runtime.sendMessage({ action: 'getStatus' }, (response) => {
      if (response.isCapturing) {
        statusDiv.textContent = 'Capturing...';
        statusDiv.className = 'status capturing';
        startBtn.disabled = true;
        stopBtn.disabled = false;
      } else {
        statusDiv.textContent = 'Stopped';
        statusDiv.className = 'status stopped';
        startBtn.disabled = false;
        stopBtn.disabled = true;
      }
    });
  }

  function updateRequestCount() {
    chrome.runtime.sendMessage({ action: 'getCapturedRequests' }, (response) => {
      requestCountSpan.textContent = response.requests.length;
    });
  }

  // Update request count every 2 seconds when capturing
  setInterval(() => {
    chrome.runtime.sendMessage({ action: 'getStatus' }, (response) => {
      if (response.isCapturing) {
        updateRequestCount();
      }
    });
  }, 2000);
});
