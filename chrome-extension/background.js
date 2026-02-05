// AuPen Request Capture - Background Script
let capturedRequests = [];
let isCapturing = false;
let requestCounter = 0;

// Listen for web requests
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (!isCapturing) return;
    
    // Capture request details
    const requestData = {
      id: ++requestCounter,
      method: details.method,
      url: details.url,
      timestamp: new Date().toISOString(),
      type: details.type,
      tabId: details.tabId,
      requestBody: details.requestBody
    };
    
    capturedRequests.push(requestData);
    console.log(`📡 Captured: ${requestData.method} ${requestData.url}`);
  },
  { urls: ["<all_urls>"] },
  ["requestBody"]
);

// Listen for response headers
chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (!isCapturing) return;
    
    // Find the corresponding request and add response info
    const request = capturedRequests.find(r => r.id === requestCounter);
    if (request) {
      request.responseHeaders = details.responseHeaders;
      request.statusCode = details.statusCode;
    }
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

// Handle messages from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  switch (request.action) {
    case 'startCapture':
      isCapturing = true;
      capturedRequests = [];
      requestCounter = 0;
      sendResponse({ success: true, message: 'Started capturing requests' });
      break;
      
    case 'stopCapture':
      isCapturing = false;
      sendResponse({ success: true, message: 'Stopped capturing requests' });
      break;
      
    case 'getCapturedRequests':
      sendResponse({ requests: capturedRequests });
      break;
      
    case 'exportRequests':
      exportRequests();
      sendResponse({ success: true, message: 'Requests exported' });
      break;
      
    case 'clearRequests':
      capturedRequests = [];
      requestCounter = 0;
      sendResponse({ success: true, message: 'Cleared all requests' });
      break;
      
    case 'getStatus':
      sendResponse({ 
        isCapturing, 
        requestCount: capturedRequests.length 
      });
      break;
  }
});

// Export requests as .txt files
function exportRequests() {
  if (capturedRequests.length === 0) {
    console.log('No requests to export');
    return;
  }
  
  capturedRequests.forEach((request, index) => {
    const requestText = formatRequestForAuPen(request);
    const filename = generateFilename(request, index + 1);
    
    // Create blob and download
    const blob = new Blob([requestText], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    
    chrome.downloads.download({
      url: url,
      filename: `aupen_requests/${filename}`,
      saveAs: false
    });
  });
}

function formatRequestForAuPen(request) {
  const lines = [];
  
  // Parse URL
  const url = new URL(request.url);
  
  // Request line
  lines.push(`${request.method} ${request.url} HTTP/1.1`);
  
  // Headers (simulated - we don't have access to request headers in webRequest)
  lines.push(`Host: ${url.host}`);
  lines.push(`User-Agent: Mozilla/5.0 (Chrome Extension)`);
  lines.push(`Accept: */*`);
  
  // Add response headers if available
  if (request.responseHeaders) {
    request.responseHeaders.forEach(header => {
      lines.push(`${header.name}: ${header.value}`);
    });
  }
  
  // Empty line before body
  lines.push('');
  
  // Body
  if (request.requestBody && request.requestBody.formData) {
    const formData = request.requestBody.formData;
    const bodyContent = Object.entries(formData)
      .map(([key, values]) => `${key}=${values.join(',')}`)
      .join('&');
    lines.push(bodyContent);
  } else if (request.requestBody && request.requestBody.raw) {
    const bodyContent = new TextDecoder().decode(
      new Uint8Array(request.requestBody.raw[0].bytes)
    );
    lines.push(bodyContent);
  }
  
  return lines.join('\n');
}

function generateFilename(request, index) {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const method = request.method.toLowerCase();
  const path = new URL(request.url).pathname.split('/').pop() || 'root';
  const sanitizedPath = path.replace(/[^\w\-_.]/g, '_').substring(0, 20);
  
  return `${index.toString().padStart(2, '0')}_${method}_${sanitizedPath}_${timestamp}.txt`;
}
