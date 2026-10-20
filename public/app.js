/**
 * Mailboxer Client Application Controller
 *
 * Implements:
 * - 1-Click OAuth 2.0 popup handshakes (Google & Microsoft) with postMessage listener
 * - Guided Apple Mail App-Specific Password connection with auto-hyphenation
 * - Real-time account list rendering with permanent session badges
 * - Instant IMAP diagnostics and explicit user logout
 */

document.addEventListener('DOMContentLoaded', () => {
  const accountsContainer = document.getElementById('accounts-container');
  const btnRefresh = document.getElementById('btn-refresh-accounts');

  // OAuth Buttons
  const btnGoogle = document.getElementById('btn-connect-google');
  const btnMicrosoft = document.getElementById('btn-connect-microsoft');

  // Apple Form
  const formApple = document.getElementById('form-apple-login');
  const inputApplePass = document.getElementById('apple-password');
  const appleError = document.getElementById('apple-error');
  const btnSubmitApple = document.getElementById('btn-submit-apple');

  // Gmail Form
  const formGmail = document.getElementById('form-gmail-login');
  const inputGmailPass = document.getElementById('gmail-password');
  const gmailError = document.getElementById('gmail-error');
  const btnSubmitGmail = document.getElementById('btn-submit-gmail');

  // Outlook Form
  const formOutlook = document.getElementById('form-outlook-login');
  const inputOutlookPass = document.getElementById('outlook-password');
  const outlookError = document.getElementById('outlook-error');
  const btnSubmitOutlook = document.getElementById('btn-submit-outlook');

  // Custom Form
  const formCustom = document.getElementById('form-custom-login');
  const customError = document.getElementById('custom-error');
  const btnSubmitCustom = document.getElementById('btn-submit-custom');

  // Modal Settings
  const btnOpenSettings = document.getElementById('btn-oauth-settings');
  const modalSettings = document.getElementById('modal-oauth-settings');
  const btnCloseModal = document.getElementById('btn-close-modal');
  const btnCancelModal = document.getElementById('btn-cancel-modal');
  const formSettings = document.getElementById('form-oauth-settings');

  // --- 1. INITIAL LOAD ---
  loadAccounts();

  btnRefresh?.addEventListener('click', loadAccounts);

  // --- 2. OAUTH POPUP EVENT & STORAGE LISTENERS ---
  function handleOAuthResult(data) {
    if (data && data.type === 'MAILBOXER_OAUTH_RESULT') {
      if (data.success) {
        showToast('Account connected permanently! Credentials encrypted in local vault.', 'success');
        loadAccounts();
      } else {
        showToast(`Authentication failed: ${data.error || 'Unknown error'}`, 'error');
      }
    }
  }

  window.addEventListener('message', (event) => {
    handleOAuthResult(event.data);
  });

  // Cross-origin opener policy fallback via localStorage storage event
  window.addEventListener('storage', (event) => {
    if (event.key === 'mailboxer_oauth_result' && event.newValue) {
      try {
        const data = JSON.parse(event.newValue);
        handleOAuthResult(data);
      } catch {}
    }
  });

  // --- 3. GOOGLE OAUTH POPUP ---
  btnGoogle?.addEventListener('click', async () => {
    await triggerOAuthFlow('gmail', 'Google Mail');
  });

  // --- 4. MICROSOFT OAUTH POPUP ---
  btnMicrosoft?.addEventListener('click', async () => {
    await triggerOAuthFlow('outlook', 'Microsoft Outlook');
  });

  async function triggerOAuthFlow(provider, providerName) {
    const width = 600;
    const height = 700;
    const left = Math.max(0, Math.floor((window.screen.width - width) / 2));
    const top = Math.max(0, Math.floor((window.screen.height - height) / 2));

    // Open popup window synchronously within user-click gesture to avoid popup blockers
    const popup = window.open(
      'about:blank',
      `mailboxer_oauth_${provider}`,
      `toolbar=no, location=no, directories=no, status=no, menubar=no, scrollbars=yes, resizable=yes, copyhistory=no, width=${width}, height=${height}, top=${top}, left=${left}`
    );

    if (!popup || popup.closed || typeof popup.closed === 'undefined') {
      showToast('OAuth popup was blocked by your browser. Please allow popups for Mailboxer and try again.', 'warning');
      return;
    }

    try {
      popup.document.write(`<!DOCTYPE html><html><head><title>Connecting to ${providerName}...</title><style>body{background:#0f1115;color:#94a3b8;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;}</style></head><body><p>Connecting to ${providerName}...</p></body></html>`);
    } catch {}

    try {
      const res = await fetch(`/api/auth/${provider}/url`);
      const data = await res.json();

      if (!res.ok || !data.url) {
        if (popup && !popup.closed) popup.close();
        openSettingsModal();
        showToast(`Please enter your ${providerName} OAuth Client ID in Settings first.`, 'warning');
        return;
      }

      popup.location.href = data.url;
    } catch (err) {
      if (popup && !popup.closed) popup.close();
      showToast(`Error starting ${providerName} login: ${err.message}`, 'error');
    }
  }

  // --- 5. 4x4 INPUT AUTO-FORMATTER HELPER ---
  function attach4x4AutoFormatter(inputElement) {
    if (!inputElement) return;

    // Keydown handler: if cursor is right after a hyphen and user hits backspace, delete preceding character cleanly
    inputElement.addEventListener('keydown', (e) => {
      if (e.key === 'Backspace' && inputElement.selectionStart === inputElement.selectionEnd) {
        const pos = inputElement.selectionStart;
        if (pos > 0 && inputElement.value[pos - 1] === '-') {
          e.preventDefault();
          const val = inputElement.value;
          const newVal = val.slice(0, pos - 2) + val.slice(pos);
          let raw = newVal.replace(/[^a-zA-Z0-9]/g, '').toLowerCase().slice(0, 16);
          const parts = raw.match(/.{1,4}/g);
          inputElement.value = parts ? parts.join('-') : raw;
          const newPos = Math.max(0, pos - 2);
          inputElement.setSelectionRange(newPos, newPos);
        }
      }
    });

    // Paste handler: clean and auto-format pasted App Passwords (handling hyphens, spaces, em-dashes)
    inputElement.addEventListener('paste', (e) => {
      e.preventDefault();
      const pasted = (e.clipboardData || window.clipboardData)?.getData('text') || '';
      let raw = pasted.replace(/[^a-zA-Z0-9]/g, '').toLowerCase().slice(0, 16);
      const parts = raw.match(/.{1,4}/g);
      inputElement.value = parts ? parts.join('-') : raw;
    });

    // Auto-format 16-character password into xxxx-xxxx-xxxx-xxxx in lowercase
    inputElement.addEventListener('input', (e) => {
      let raw = e.target.value.replace(/[^a-zA-Z0-9]/g, '').toLowerCase();
      if (raw.length > 16) raw = raw.slice(0, 16);
      const parts = raw.match(/.{1,4}/g);
      const formatted = parts ? parts.join('-') : raw;
      if (e.target.value !== formatted) {
        e.target.value = formatted;
      }
    });
  }

  // Attach auto-formatters to Apple and Google App Password fields
  attach4x4AutoFormatter(inputApplePass);
  attach4x4AutoFormatter(inputGmailPass);

  // Toggle password visibility buttons
  document.querySelectorAll('.btn-toggle-visibility').forEach((btn) => {
    btn.addEventListener('click', () => {
      const input = btn.previousElementSibling;
      if (input && input.tagName === 'INPUT') {
        input.type = input.type === 'password' ? 'text' : 'password';
        btn.textContent = input.type === 'password' ? '👁' : '🔒';
      }
    });
  });

  // --- 5a. APPLE MAIL GUIDED FORM ---
  formApple?.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideError(appleError);
    setLoading(btnSubmitApple, true, 'Testing & Encrypting...');

    const email = document.getElementById('apple-email').value;
    const appPassword = inputApplePass.value;
    const label = document.getElementById('apple-label').value || 'Apple Mail';

    try {
      const res = await fetch('/api/accounts/apple', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, appPassword, label })
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || data.remediationAdvice || 'Failed to authenticate with Apple Mail');
      }

      showToast('Apple Mail connected successfully and encrypted in vault!', 'success');
      formApple.reset();
      loadAccounts();
    } catch (err) {
      showError(appleError, `Connection failed: ${err.message}`);
    } finally {
      setLoading(btnSubmitApple, false, 'Connect & Save to Vault');
    }
  });

  // --- 5b. GOOGLE MAIL GUIDED FORM ---
  formGmail?.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideError(gmailError);
    setLoading(btnSubmitGmail, true, 'Testing & Encrypting...');

    const email = document.getElementById('gmail-email').value;
    const appPassword = inputGmailPass.value;
    const label = document.getElementById('gmail-label').value || 'Google Mail';

    try {
      const res = await fetch('/api/accounts/gmail', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, appPassword, label })
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || data.remediationAdvice || 'Failed to authenticate with Google Mail');
      }

      showToast('Google Mail connected successfully and encrypted in vault!', 'success');
      formGmail.reset();
      loadAccounts();
    } catch (err) {
      showError(gmailError, `Connection failed: ${err.message}`);
    } finally {
      setLoading(btnSubmitGmail, false, 'Connect & Save to Vault');
    }
  });

  // --- 5c. MICROSOFT OUTLOOK GUIDED FORM ---
  formOutlook?.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideError(outlookError);
    setLoading(btnSubmitOutlook, true, 'Testing & Encrypting...');

    const email = document.getElementById('outlook-email').value;
    const password = inputOutlookPass.value;
    const label = document.getElementById('outlook-label').value || 'Microsoft Outlook';

    try {
      const res = await fetch('/api/accounts/outlook', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, label })
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || data.remediationAdvice || 'Failed to authenticate with Microsoft Outlook');
      }

      showToast('Microsoft Outlook connected successfully and encrypted in vault!', 'success');
      formOutlook.reset();
      loadAccounts();
    } catch (err) {
      showError(outlookError, `Connection failed: ${err.message}`);
    } finally {
      setLoading(btnSubmitOutlook, false, 'Connect & Save to Vault');
    }
  });

  // --- 6. CUSTOM IMAP FORM ---
  formCustom?.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideError(customError);
    setLoading(btnSubmitCustom, true, 'Testing Connection...');

    const email = document.getElementById('custom-email').value;
    const password = document.getElementById('custom-password').value;
    const host = document.getElementById('custom-imap-host').value;
    const port = parseInt(document.getElementById('custom-imap-port').value, 10);

    try {
      const res = await fetch('/api/accounts/custom', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          provider: 'custom',
          email,
          password,
          imap: { host, port, secure: true }
        })
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Connection failed');
      }

      showToast('Custom account connected and saved!', 'success');
      formCustom.reset();
      loadAccounts();
    } catch (err) {
      showError(customError, err.message);
    } finally {
      setLoading(btnSubmitCustom, false, 'Connect & Save to Vault');
    }
  });

  // --- 7. LOAD & RENDER ACCOUNTS ---
  async function loadAccounts() {
    try {
      const res = await fetch('/api/accounts');
      const data = await res.json();
      renderAccounts(data.accounts || []);
    } catch (err) {
      accountsContainer.innerHTML = `
        <div class="empty-state">
          <p style="color:#ef4444;">Failed to load accounts: ${err.message}</p>
        </div>
      `;
    }
  }

  function renderAccounts(accounts) {
    if (!accounts || accounts.length === 0) {
      accountsContainer.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-icon">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
              <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/>
              <polyline points="22,6 12,13 2,6"/>
            </svg>
          </div>
          <h3 class="empty-state-title">No Connected Inboxes Yet</h3>
          <p>Choose an option above to connect your Google, Apple Mail, or University Outlook accounts.</p>
        </div>
      `;
      return;
    }

    accountsContainer.innerHTML = accounts.map((acc) => {
      const avatarClass = `avatar-${acc.provider || 'custom'}`;
      const initials = (acc.provider || 'M').charAt(0).toUpperCase();
      const authBadge = acc.authType === 'oauth2' ? 'OAuth 2.0 (Permanent)' : 'Encrypted App Password';

      return `
        <div class="account-item-card" data-id="${acc.id}">
          <div class="account-info-left">
            <div class="account-avatar ${avatarClass}">${initials}</div>
            <div class="account-details">
              <h4>
                ${escapeHtml(acc.label || acc.email)}
                <span class="permanent-badge">🔒 Permanent Session</span>
              </h4>
              <div class="account-meta-line">
                <span>${escapeHtml(acc.email)}</span>
                <span>•</span>
                <span style="color:#94a3b8;">${authBadge}</span>
                ${acc.inboxStatus ? `<span>•</span><span style="color:#10b981;">📥 ${acc.inboxStatus.totalMessages} msgs (${acc.inboxStatus.unseen} unread)</span>` : ''}
              </div>
            </div>
          </div>
          <div class="account-actions">
            <button class="btn-test" data-id="${escapeHtml(acc.id)}">⚡ Test Connection</button>
            <button class="btn-logout" data-id="${escapeHtml(acc.id)}" data-email="${escapeHtml(acc.email)}">🚪 Log Out</button>
          </div>
        </div>
      `;
    }).join('');
  }

  // Event delegation on accountsContainer for connection tests and logouts
  accountsContainer?.addEventListener('click', async (e) => {
    const testBtn = e.target.closest('.btn-test');
    if (testBtn) {
      const id = testBtn.dataset.id;
      if (id) await window.testAccount(id, testBtn);
      return;
    }

    const logoutBtn = e.target.closest('.btn-logout');
    if (logoutBtn) {
      const id = logoutBtn.dataset.id;
      const email = logoutBtn.dataset.email;
      if (id) await window.logoutAccount(id, email);
      return;
    }
  });

  // --- 8. TEST & EXPLICIT LOGOUT HANDLERS ---
  window.testAccount = async (id, btn) => {
    const originalText = btn.textContent;
    btn.textContent = 'Testing...';
    btn.disabled = true;

    try {
      const res = await fetch(`/api/accounts/${id}/test`, { method: 'POST' });
      const data = await res.json();

      if (data.success) {
        showToast(`Connection verified! ${data.inboxStatus?.totalMessages || 0} messages found in INBOX.`, 'success');
        loadAccounts();
      } else {
        const errorMsg = (typeof data.error === 'object' && data.error !== null)
          ? (data.error.message || data.error.code || 'Server rejected connection')
          : (data.error || data.message || 'Server did not respond');
        const advice = data.remediationAdvice ? ` (${data.remediationAdvice})` : '';
        showToast(`Test failed: ${errorMsg}${advice}`, 'error');
      }
    } catch (err) {
      showToast(`Network error: ${err.message}`, 'error');
    } finally {
      btn.textContent = originalText;
      btn.disabled = false;
    }
  };

  window.logoutAccount = async (id, email) => {
    const confirmed = window.confirm(`Are you sure you want to log out of ${email}?\n\nThis will remove the credentials from your local encrypted vault.`);
    if (!confirmed) return;

    try {
      const res = await fetch(`/api/accounts/${id}`, { method: 'DELETE' });
      if (res.ok) {
        showToast(`Logged out of ${email}.`, 'success');
        loadAccounts();
      } else {
        showToast('Failed to log out.', 'error');
      }
    } catch (err) {
      showToast(`Error: ${err.message}`, 'error');
    }
  };

  // --- 9. MODAL & SETTINGS ---
  btnOpenSettings?.addEventListener('click', openSettingsModal);
  btnCloseModal?.addEventListener('click', closeSettingsModal);
  btnCancelModal?.addEventListener('click', closeSettingsModal);

  function openSettingsModal() {
    modalSettings.classList.remove('hidden');
  }

  function closeSettingsModal() {
    modalSettings.classList.add('hidden');
  }

  formSettings?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const googleId = document.getElementById('cfg-google-id').value;
    const googleSecret = document.getElementById('cfg-google-secret').value;
    const msId = document.getElementById('cfg-ms-id').value;
    const msSecret = document.getElementById('cfg-ms-secret').value;

    if (googleId) {
      await fetch('/api/oauth/credentials', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ provider: 'gmail', clientId: googleId, clientSecret: googleSecret })
      });
    }

    if (msId) {
      await fetch('/api/oauth/credentials', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ provider: 'outlook', clientId: msId, clientSecret: msSecret })
      });
    }

    showToast('OAuth settings saved!', 'success');
    closeSettingsModal();
  });

  // --- 10. UTILITIES ---
  function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    const bg = type === 'success' ? '#065f46' : type === 'error' ? '#991b1b' : type === 'warning' ? '#b45309' : '#1e293b';
    toast.style.cssText = `
      position: fixed;
      bottom: 24px;
      right: 24px;
      max-width: 450px;
      word-break: break-word;
      background: ${bg};
      color: #fff;
      padding: 12px 20px;
      border-radius: 8px;
      font-size: 14px;
      font-weight: 500;
      box-shadow: 0 10px 25px rgba(0,0,0,0.5);
      z-index: 9999;
      transition: all 0.3s;
      display: flex;
      align-items: center;
      gap: 10px;
    `;
    toast.textContent = message;
    document.body.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(10px)';
      setTimeout(() => toast.remove(), 300);
    }, 4000);
  }

  function showError(el, msg) {
    if (!el) return;
    el.textContent = msg;
    el.classList.remove('hidden');
  }

  function hideError(el) {
    if (!el) return;
    el.textContent = '';
    el.classList.add('hidden');
  }

  function setLoading(btn, isLoading, text) {
    if (!btn) return;
    const btnText = btn.querySelector('.btn-text');
    const spinner = btn.querySelector('.btn-spinner');
    if (btnText) btnText.textContent = text;
    if (spinner) {
      if (isLoading) spinner.classList.remove('hidden');
      else spinner.classList.add('hidden');
    }
    btn.disabled = isLoading;
  }

  // --- 11. TRIAGE FEED CONTROLLER ---
  let currentCategory = 'ALL';
  let currentSearchQuery = '';
  let searchDebounceTimer = null;

  const messagesContainer = document.getElementById('messages-container');
  const triageTabs = document.getElementById('triage-category-tabs');
  const searchInput = document.getElementById('triage-search-input');

  async function loadMessages() {
    if (!messagesContainer) return;
    try {
      let url = '/api/messages?limit=50';
      if (currentCategory && currentCategory !== 'ALL') {
        url += `&category=${encodeURIComponent(currentCategory)}`;
      }
      if (currentSearchQuery) {
        url += `&q=${encodeURIComponent(currentSearchQuery)}`;
      }

      const res = await fetch(url);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      renderMessages(data.messages || []);
    } catch (err) {
      messagesContainer.innerHTML = `
        <div class="empty-state">
          <p style="color:var(--text-dim);">Failed to load messages: ${escapeHtml(err.message)}</p>
        </div>
      `;
    }
  }

  function renderMessages(messages) {
    if (!messagesContainer) return;
    if (messages.length === 0) {
      messagesContainer.innerHTML = `
        <div class="empty-state" style="padding: 40px; text-align: center; color: var(--text-dim);">
          <p>No messages found in ${escapeHtml(currentCategory)}.</p>
        </div>
      `;
      return;
    }

    messagesContainer.innerHTML = messages.map(msg => {
      const cat = (msg.category || 'NORMAL').toUpperCase();
      const catClass = cat === 'VIP' ? 'card-vip' : (cat === 'UPDATE' ? 'card-update' : (cat === 'NOISE' ? 'card-noise' : ''));
      const badgeClass = cat === 'VIP' ? 'badge-vip' : (cat === 'UPDATE' ? 'badge-update' : (cat === 'NOISE' ? 'badge-noise' : 'badge-normal'));
      const badgeLabel = cat === 'VIP' ? '⭐ VIP / Urgent' : (cat === 'UPDATE' ? '📘 Coursework' : (cat === 'NOISE' ? '🔇 Muted Noise' : 'Normal'));

      const senderDisplay = msg.sender || msg.senderEmail || 'Sender';
      const subjectDisplay = msg.subject || '(No Subject)';
      const dateDisplay = msg.date ? new Date(msg.date).toLocaleDateString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : '';
      const snippetDisplay = msg.bodySnippet || '';

      return `
        <div class="message-card ${catClass}" id="msg-${escapeHtml(msg.id)}">
          <div class="message-header-row">
            <div class="message-sender-meta">
              <span class="badge-pill ${badgeClass}">${badgeLabel}</span>
              <span class="message-sender-name">${escapeHtml(senderDisplay)}</span>
            </div>
            <span class="message-date">${escapeHtml(dateDisplay)}</span>
          </div>
          <h4 class="message-subject">${escapeHtml(subjectDisplay)}</h4>
          ${snippetDisplay ? `<p class="message-snippet">${escapeHtml(snippetDisplay)}</p>` : ''}
          <div class="message-actions-row">
            ${!msg.isSeen ? `<button class="btn-mark-read" data-id="${escapeHtml(msg.id)}">Mark as Read</button>` : '<span style="font-size:12px;color:var(--text-dim);">✓ Read</span>'}
          </div>
        </div>
      `;
    }).join('');

    // Attach read handlers
    messagesContainer.querySelectorAll('.btn-mark-read').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        const id = e.target.getAttribute('data-id');
        if (!id) return;
        try {
          await fetch(`/api/messages/${encodeURIComponent(id)}/read`, { method: 'POST' });
          e.target.parentElement.innerHTML = '<span style="font-size:12px;color:var(--text-dim);">✓ Read</span>';
        } catch {}
      });
    });
  }

  // Triage category tab switching
  if (triageTabs) {
    triageTabs.querySelectorAll('.triage-tab').forEach(tab => {
      tab.addEventListener('click', () => {
        triageTabs.querySelectorAll('.triage-tab').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        currentCategory = tab.getAttribute('data-category') || 'ALL';
        loadMessages();
      });
    });
  }

  // Sub-20ms Search bar debounced input
  if (searchInput) {
    searchInput.addEventListener('input', (e) => {
      clearTimeout(searchDebounceTimer);
      searchDebounceTimer = setTimeout(() => {
        currentSearchQuery = e.target.value.trim();
        loadMessages();
      }, 150);
    });
  }

  // --- 12. REAL-TIME NOTIFICATIONS CONTROLLER ---
  const btnToggleWebPush = document.getElementById('btn-toggle-webpush');
  const webPushStatus = document.getElementById('webpush-status-text');
  const webPushBtnText = document.getElementById('webpush-btn-text');
  const ntfyTopicInput = document.getElementById('ntfy-topic-input');
  const btnSaveNtfy = document.getElementById('btn-save-ntfy');
  const btnTestAlert = document.getElementById('btn-test-alert');
  const alertTestStatus = document.getElementById('alert-test-status');

  // Load saved ntfy topic
  if (ntfyTopicInput) {
    const savedTopic = localStorage.getItem('mailboxer_ntfy_topic') || '';
    ntfyTopicInput.value = savedTopic;
  }

  btnSaveNtfy?.addEventListener('click', () => {
    const val = ntfyTopicInput?.value.trim() || '';
    localStorage.setItem('mailboxer_ntfy_topic', val);
    showToast(`ntfy.sh topic saved: ${val || '(cleared)'}`, 'success');
  });

  btnTestAlert?.addEventListener('click', async () => {
    if (alertTestStatus) alertTestStatus.textContent = 'Sending test notification to conduits...';
    try {
      const topic = ntfyTopicInput?.value.trim() || '';
      const res = await fetch('/api/notifications/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ topic })
      });
      const data = await res.json();
      if (res.ok) {
        if (alertTestStatus) alertTestStatus.textContent = '✓ Test alert dispatched successfully to active conduits!';
        showToast('VIP Test alert dispatched!', 'success');
      } else {
        if (alertTestStatus) alertTestStatus.textContent = `Alert failed: ${data.error || 'Unknown error'}`;
      }
    } catch (err) {
      if (alertTestStatus) alertTestStatus.textContent = `Network error: ${err.message}`;
    }
  });

  // Base64URL to Uint8Array helper for VAPID applicationServerKey
  function urlBase64ToUint8Array(base64String) {
    const padding = '='.repeat((4 - (base64String.length % 4)) % 4);
    const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
    const rawData = window.atob(base64);
    const outputArray = new Uint8Array(rawData.length);
    for (let i = 0; i < rawData.length; ++i) {
      outputArray[i] = rawData.charCodeAt(i);
    }
    return outputArray;
  }

  async function checkWebPushStatus() {
    if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
      if (webPushStatus) webPushStatus.textContent = 'Status: Web Push not supported in this browser';
      if (btnToggleWebPush) btnToggleWebPush.disabled = true;
      return;
    }

    try {
      const reg = await navigator.serviceWorker.register('/sw.js');
      const sub = await reg.pushManager.getSubscription();

      if (sub) {
        if (webPushStatus) webPushStatus.textContent = 'Status: Active (Listening for VIP push alerts)';
        if (webPushBtnText) webPushBtnText.textContent = 'Disable Web Push Notifications';
      } else {
        if (webPushStatus) webPushStatus.textContent = 'Status: Push not yet subscribed';
        if (webPushBtnText) webPushBtnText.textContent = 'Enable Web Push Notifications';
      }
    } catch (err) {
      if (webPushStatus) webPushStatus.textContent = `Status: Service worker inactive (${err.message})`;
    }
  }

  btnToggleWebPush?.addEventListener('click', async () => {
    try {
      const reg = await navigator.serviceWorker.ready;
      const existingSub = await reg.pushManager.getSubscription();

      if (existingSub) {
        await existingSub.unsubscribe();
        showToast('Web Push unsubscribed.', 'info');
        checkWebPushStatus();
        return;
      }

      // Fetch VAPID public key
      const keyRes = await fetch('/api/notifications/vapid-public-key');
      const keyData = await keyRes.json();
      if (!keyData.publicKey) throw new Error('Failed to retrieve VAPID public key from server');

      const convertedKey = urlBase64ToUint8Array(keyData.publicKey);
      const newSub = await reg.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: convertedKey
      });

      const subJson = newSub.toJSON();
      await fetch('/api/notifications/subscribe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(subJson)
      });

      showToast('Web Push enabled! Ready to receive VIP alerts.', 'success');
      checkWebPushStatus();
    } catch (err) {
      showToast(`Web Push subscription error: ${err.message}`, 'error');
    }
  });

  // Initial load of messages and push status
  loadMessages();
  checkWebPushStatus();
});
