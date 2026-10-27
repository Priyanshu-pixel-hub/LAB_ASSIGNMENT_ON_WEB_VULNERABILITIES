/**
 * Client-Side Helper for Reflected XSS Lab Demonstration
 */

window.LAB_PAYLOADS = {
  '1': "<script>alert('Reflected XSS Detected!')</script>",
  '2': "<img src=x onerror=\"alert('Reflected XSS via img onerror')\">",
  '3': "Network Security Fundamentals 2026"
};

window.loadPayload = function(triggerEl, payloadId) {
  var searchInput = document.getElementById('searchInput');
  if (!searchInput) return;

  var payload = window.LAB_PAYLOADS[payloadId];
  if (!payload && triggerEl && triggerEl.getAttribute) {
    var id = triggerEl.getAttribute('data-payload-id');
    payload = window.LAB_PAYLOADS[id] || triggerEl.getAttribute('data-payload');
  }

  if (payload) {
    searchInput.value = payload;
    searchInput.focus();

    if (searchInput.form) {
      searchInput.form.submit();
    }
  }
};

window.clearPayload = function() {
  var searchInput = document.getElementById('searchInput');
  if (searchInput) {
    searchInput.value = '';
    searchInput.focus();
  }
};

// Global Event Delegation as an additional fallback
document.addEventListener('click', function(event) {
  var target = event.target;
  var chipBtn = target.closest ? target.closest('.btn-chip[data-payload], .btn-chip[data-payload-id]') : null;
  if (chipBtn) {
    var payloadId = chipBtn.getAttribute('data-payload-id');
    window.loadPayload(chipBtn, payloadId);
  } else if (target.closest && target.closest('#clearBtn')) {
    window.clearPayload();
  }
});
