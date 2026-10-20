/**
 * Mailboxer Desktop Client Application Controller
 *
 * Implements:
 * - 3-Pane Desktop Mailbox Workspace with responsive sidebar, message list, and reading pane
 * - Multi-Account Switching (All Inboxes, Apple, Gmail, Outlook, Custom IMAP)
 * - Smart Anti-Noise Triage (VIP / Urgent, Coursework & LMS, Muted Noise, All Mail)
 * - Sub-20ms instant FTS search & pagination backfill
 * - Full email reader view with sender avatars, recipient chips, relative timestamps, star, read/unread, and reply
 * - Permanent AES-256-GCM vault onboarding and background sync engine integration
 */

/**
 * Utility to escape HTML entities to prevent XSS and rendering errors
 */
function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

if (typeof window !== 'undefined') {
  window.escapeHtml = escapeHtml;
}
if (typeof globalThis !== 'undefined' && !globalThis.escapeHtml) {
  globalThis.escapeHtml = escapeHtml;
}

document.addEventListener('DOMContentLoaded', () => {
  // ==========================================
  // STATE MANAGEMENT
  // ==========================================
  let currentAccount = 'ALL';       // 'ALL' or specific accountId
  let currentCategory = 'ALL';      // 'ALL', 'VIP', 'UPDATE', 'NOISE', 'NORMAL'
  let currentSearchQuery = '';
  let filterUnreadOnly = false;
  let filterStarredOnly = false;
  let currentOffset = 0;
  const pageSize = 50;
  let totalAvailableMessages = 0;
  let allLoadedMessages = [];
  const currentMessagesMap = new Map();
  let activeReaderMessage = null;
  let searchDebounceTimer = null;
  let accountsList = [];

  // ==========================================
  // DOM ELEMENT REFERENCES
  // ==========================================
  // Sidebar Elements
  const btnSyncAll = document.getElementById('btn-sync-all');
  const syncStatusLabel = document.getElementById('sync-status-label');
  const btnSidebarAdd = document.getElementById('btn-sidebar-add-account');
  const navAllInboxes = document.getElementById('nav-all-inboxes');
  const sidebarAccountsList = document.getElementById('sidebar-accounts-list');
  const badgeAllInboxes = document.getElementById('badge-all-inboxes');
  const badgeVipInbox = document.getElementById('badge-vip-inbox');
  const badgeUpdateInbox = document.getElementById('badge-update-inbox');
  const badgeNoiseInbox = document.getElementById('badge-noise-inbox');
  const navFilterUnread = document.getElementById('nav-filter-unread');
  const navFilterStarred = document.getElementById('nav-filter-starred');
  const badgeFilterUnread = document.getElementById('badge-filter-unread');
  const btnOpenConduits = document.getElementById('btn-open-conduits');
  const btnOpenAccountsModal = document.getElementById('btn-open-accounts-modal');
  const btnOpenOAuthSettings = document.getElementById('btn-oauth-settings');

  // Message List Elements
  const searchInput = document.getElementById('triage-search-input');
  const btnClearSearch = document.getElementById('btn-clear-search');
  const activeViewHeading = document.getElementById('active-view-heading');
  const activeViewSubtitle = document.getElementById('active-view-subtitle');
  const btnMarkAllRead = document.getElementById('btn-mark-all-read');
  const btnFilterUnreadPill = document.getElementById('btn-filter-unread-pill');
  const messagesContainer = document.getElementById('messages-container');
  const triageTabs = document.getElementById('triage-category-tabs');
  const feedPaginationBar = document.getElementById('feed-pagination-bar');
  const btnLoadMore = document.getElementById('btn-load-more');
  const loadMoreText = document.getElementById('load-more-text');
  const loadMoreSpinner = document.getElementById('load-more-spinner');

  // Desktop Reader Pane Elements
  const desktopReaderPane = document.getElementById('desktop-reader-pane');
  const readerEmptyState = document.getElementById('reader-empty-state');
  const readerActiveWorkspace = document.getElementById('reader-active-workspace');
  const btnReaderBackMobile = document.getElementById('btn-reader-back-mobile');
  const readerViewCategoryBadge = document.getElementById('reader-view-category-badge');
  const readerViewAccountPill = document.getElementById('reader-view-account-pill');
  const btnReaderToggleStar = document.getElementById('btn-reader-toggle-star');
  const btnReaderActionRead = document.getElementById('btn-reader-action-read');
  const btnReaderReply = document.getElementById('btn-reader-reply');
  const btnReaderDelete = document.getElementById('btn-reader-delete');
  const readerViewSubject = document.getElementById('reader-view-subject');
  const readerSenderAvatar = document.getElementById('reader-sender-avatar');
  const readerViewSenderName = document.getElementById('reader-view-sender-name');
  const readerViewSenderEmail = document.getElementById('reader-view-sender-email');
  const readerViewRecipient = document.getElementById('reader-view-recipient');
  const readerViewTimestamp = document.getElementById('reader-view-timestamp');
  const readerViewBody = document.getElementById('reader-view-body');

  // Legacy / Modal Reader Elements (Maintained for mobile view & unit tests)
  const modalEmailReader = document.getElementById('modal-email-reader');
  const btnCloseReader = document.getElementById('btn-close-reader');
  const readerCategoryBadge = document.getElementById('reader-category-badge');
  const readerSubject = document.getElementById('reader-subject');
  const readerSender = document.getElementById('reader-sender');
  const readerRecipient = document.getElementById('reader-recipient');
  const readerTimestamp = document.getElementById('reader-timestamp');
  const readerBodyContent = document.getElementById('reader-body-content');
  const btnReaderToggleRead = document.getElementById('btn-reader-toggle-read');

  // Modals & Dialog Elements
  const modalAddAccount = document.getElementById('modal-add-account');
  const btnCloseAddModal = document.getElementById('btn-close-add-modal');
  const modalAccountsVault = document.getElementById('modal-accounts-vault');
  const btnCloseAccountsModal = document.getElementById('btn-close-accounts-modal');
  const accountsContainer = document.getElementById('accounts-container');
  const btnRefresh = document.getElementById('btn-refresh-accounts');
  const modalNotifications = document.getElementById('modal-notifications');
  const btnCloseNotificationsModal = document.getElementById('btn-close-notifications-modal');
  const modalSettings = document.getElementById('modal-oauth-settings');
  const btnCloseModal = document.getElementById('btn-close-modal');
  const btnCancelModal = document.getElementById('btn-cancel-modal');
  const formSettings = document.getElementById('form-oauth-settings');

  // Guided Provider Forms
  const formApple = document.getElementById('form-apple-login');
  const inputApplePass = document.getElementById('apple-password');
  const appleError = document.getElementById('apple-error');
  const btnSubmitApple = document.getElementById('btn-submit-apple');

  const formGmail = document.getElementById('form-gmail-login');
  const inputGmailPass = document.getElementById('gmail-password');
  const gmailError = document.getElementById('gmail-error');
  const btnSubmitGmail = document.getElementById('btn-submit-gmail');

  const formOutlook = document.getElementById('form-outlook-login');
  const inputOutlookPass = document.getElementById('outlook-password');
  const outlookError = document.getElementById('outlook-error');
  const btnSubmitOutlook = document.getElementById('btn-submit-outlook');

  const formCustom = document.getElementById('form-custom-login');
  const customError = document.getElementById('custom-error');
  const btnSubmitCustom = document.getElementById('btn-submit-custom');

  const btnGoogle = document.getElementById('btn-connect-google');
  const btnMicrosoft = document.getElementById('btn-connect-microsoft');

  // ==========================================
  // 1. INITIALIZATION & REFRESH LOGIC
  // ==========================================
  async function init() {
    await loadAccounts();
    await loadMailboxSummary();
    await loadMessages();
  }

  init();

  // Periodic Polling: Every 20 seconds stream fresh emails and refresh counts
  setInterval(() => {
    loadMailboxSummary();
    // Only refresh message feed if search is inactive
    if (!currentSearchQuery) {
      loadMessages({ silent: true });
    }
  }, 20000);

  // Manual Full Sync Trigger
  btnSyncAll?.addEventListener('click', triggerFullSync);
  btnRefresh?.addEventListener('click', triggerFullSync);

  async function triggerFullSync() {
    if (btnSyncAll) {
      btnSyncAll.style.transform = 'rotate(360deg)';
      btnSyncAll.style.transition = 'transform 0.8s ease';
    }
    if (syncStatusLabel) syncStatusLabel.textContent = 'Syncing...';
    if (btnRefresh) btnRefresh.innerText = 'Syncing...';

    try {
      await fetch('/api/sync?await=true', { method: 'POST' });
      showToast('All inboxes synchronized!', 'success');
    } catch {}

    await loadAccounts();
    await loadMailboxSummary();
    await loadMessages();

    if (btnSyncAll) {
      setTimeout(() => {
        btnSyncAll.style.transform = 'none';
        btnSyncAll.style.transition = 'none';
      }, 800);
    }
    if (syncStatusLabel) syncStatusLabel.textContent = 'Synced just now';
    if (btnRefresh) btnRefresh.innerText = 'Refresh Status';
  }

  // ==========================================
  // 2. ACCOUNT LIST & SIDEBAR SUB-LIST
  // ==========================================
  async function loadAccounts() {
    try {
      const res = await fetch('/api/accounts');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      accountsList = Array.isArray(data.accounts) ? data.accounts : [];
      renderAccounts(accountsList);
      renderSidebarAccounts(accountsList);

      // If user has zero accounts on first launch, open Add Account Modal automatically
      if (accountsList.length === 0 && modalAddAccount) {
        modalAddAccount.classList.remove('hidden');
      }
    } catch (err) {
      renderAccounts([]);
      renderSidebarAccounts([]);
    }
  }

  function renderSidebarAccounts(accounts) {
    if (!sidebarAccountsList) return;
    if (!Array.isArray(accounts) || accounts.length === 0) {
      sidebarAccountsList.innerHTML = '';
      return;
    }

    sidebarAccountsList.innerHTML = accounts.map(acc => {
      if (!acc) return '';
      const prov = (acc.provider || 'custom').toLowerCase();
      const iconClass = prov === 'apple' ? 'icon-apple' : (prov === 'gmail' || prov === 'google' ? 'icon-gmail' : (prov === 'outlook' ? 'icon-outlook' : 'icon-custom'));
      const initial = (prov[0] || 'M').toUpperCase();
      const email = acc.email || acc.label || 'Account';
      const unreadCount = acc.inboxStatus?.unseen || acc.unreadCount || 0;
      const isActive = currentAccount === acc.id;

      return `
        <button class="account-nav-row ${isActive ? 'active' : ''}" data-account-id="${escapeHtml(acc.id)}" title="${escapeHtml(email)}">
          <div class="acc-row-left">
            <span class="acc-provider-icon ${iconClass}">${initial}</span>
            <span class="acc-email-label">${escapeHtml(email)}</span>
          </div>
          ${unreadCount > 0 ? `<span class="nav-badge">${unreadCount}</span>` : ''}
        </button>
      `;
    }).join('');

    // Attach click events on sidebar account rows
    sidebarAccountsList.querySelectorAll('.account-nav-row').forEach(row => {
      row.addEventListener('click', () => {
        const accId = row.getAttribute('data-account-id');
        setActiveAccountFilter(accId);
      });
    });
  }

  function renderAccounts(accounts) {
    if (!accountsContainer) return;
    if (!Array.isArray(accounts) || accounts.length === 0) {
      accountsContainer.innerHTML = `
        <div class="empty-state">
          <p>No Connected Inboxes Yet</p>
          <p style="font-size:12px; margin-top:4px;">Connect Apple Mail, Google Mail, or Outlook above.</p>
        </div>
      `;
      return;
    }

    accountsContainer.innerHTML = accounts.map(acc => {
      if (!acc) return '';
      const prov = (acc.provider || 'custom').toLowerCase();
      const badgeText = prov === 'apple' ? 'Apple Mail' : (prov === 'gmail' || prov === 'google' ? 'Google Mail' : (prov === 'outlook' ? 'Microsoft Outlook' : 'Custom IMAP'));
      const avatarClass = prov === 'apple' ? 'avatar-apple' : (prov === 'gmail' || prov === 'google' ? 'avatar-gmail' : (prov === 'outlook' ? 'avatar-outlook' : 'avatar-custom'));
      const initial = (prov[0] || 'M').toUpperCase();
      const label = acc.label ? ` <span style="font-weight:400;color:var(--text-dim);">(${escapeHtml(acc.label)})</span>` : '';
      const unreadStatus = acc.inboxStatus ? `<span>•</span><span style="color:#10b981;">📥 ${escapeHtml(acc.inboxStatus.totalMessages)} msgs (${escapeHtml(acc.inboxStatus.unseen)} unread)</span>` : '';

      return `
        <div class="account-card" id="card-${escapeHtml(acc.id)}">
          <div class="account-card-left">
            <div class="account-avatar ${avatarClass}">${initial}</div>
            <div class="account-details">
              <div class="account-email">${escapeHtml(acc.email)}${label}</div>
              <div class="account-meta-line">
                <span class="provider-pill-small">${badgeText}</span>
                <span>•</span>
                <span style="color:#10b981;font-size:11px;">🔒 Permanent Session</span>
                ${unreadStatus}
              </div>
            </div>
          </div>
          <div class="account-actions">
            <button class="btn-test-conn" data-id="${escapeHtml(acc.id)}">Test Check</button>
            <button class="btn-logout" data-id="${escapeHtml(acc.id)}" data-email="${escapeHtml(acc.email)}">Disconnect</button>
          </div>
        </div>
      `;
    }).join('');

    // Attach account card action handlers if querySelectorAll is supported (in DOM environment)
    accountsContainer.querySelectorAll?.('.btn-test-conn')?.forEach(btn => {
      btn.addEventListener('click', async (e) => {
        const id = e.target.getAttribute('data-id');
        const orig = e.target.innerText;
        e.target.innerText = 'Checking...';
        try {
          const res = await fetch(`/api/accounts/${encodeURIComponent(id)}/test`, { method: 'POST' });
          const d = await res.json();
          if (res.ok && d.connected) {
            showToast(`Connection verified! Cipher: ${d.tls?.cipher || 'TLS'}`, 'success');
          } else {
            showToast(`Connection failed: ${d.error || 'Unknown error'}`, 'error');
          }
        } catch (err) {
          showToast(`Error: ${err.message}`, 'error');
        }
        e.target.innerText = orig;
      });
    });

    accountsContainer.querySelectorAll?.('.btn-logout')?.forEach(btn => {
      btn.addEventListener('click', async (e) => {
        const id = e.target.getAttribute('data-id');
        const email = e.target.getAttribute('data-email');
        if (!confirm(`Are you sure you want to disconnect ${email}?`)) return;
        try {
          const res = await fetch(`/api/accounts/${encodeURIComponent(id)}`, { method: 'DELETE' });
          if (res.ok) {
            showToast(`Logged out of ${email}.`, 'success');
            loadAccounts();
            loadMailboxSummary();
            loadMessages();
          } else {
            showToast('Failed to log out.', 'error');
          }
        } catch (err) {
          showToast(`Error: ${err.message}`, 'error');
        }
      });
    });
  }

  // ==========================================
  // 3. MAILBOX SUMMARY & COUNTERS
  // ==========================================
  async function loadMailboxSummary() {
    try {
      const res = await fetch('/api/mailbox/summary');
      if (!res.ok) return;
      const data = await res.json();

      if (badgeAllInboxes) badgeAllInboxes.textContent = data.totalUnread || 0;
      if (badgeVipInbox) badgeVipInbox.textContent = data.categories?.VIP?.unread || 0;
      if (badgeUpdateInbox) badgeUpdateInbox.textContent = data.categories?.UPDATE?.unread || 0;
      if (badgeNoiseInbox) badgeNoiseInbox.textContent = data.categories?.NOISE?.unread || 0;
      if (badgeFilterUnread) badgeFilterUnread.textContent = data.totalUnread || 0;

      if (data.lastSyncAt && syncStatusLabel) {
        const d = new Date(data.lastSyncAt);
        syncStatusLabel.textContent = `Synced ${d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`;
      }
    } catch {}
  }

  // ==========================================
  // 4. MESSAGES FEED CONTROLLER & PAGINATION
  // ==========================================
  async function loadMessages(options = {}) {
    const isAppend = Boolean(options.append);
    const isSilent = Boolean(options.silent);

    if (!isAppend) {
      currentOffset = 0;
      if (!isSilent && messagesContainer) {
        messagesContainer.innerHTML = `
          <div class="loading-state">
            <div class="spinner-inline"></div>
            <p>Loading messages...</p>
          </div>
        `;
      }
    }

    try {
      let url = `/api/messages?limit=${pageSize}&offset=${currentOffset}`;
      if (currentAccount && currentAccount !== 'ALL') {
        url += `&accountId=${encodeURIComponent(currentAccount)}`;
      }
      if (currentCategory && currentCategory !== 'ALL') {
        url += `&category=${encodeURIComponent(currentCategory)}`;
      }
      if (currentSearchQuery) {
        url += `&q=${encodeURIComponent(currentSearchQuery)}`;
      }
      if (filterUnreadOnly) {
        url += `&unread=true`;
      }
      if (filterStarredOnly) {
        url += `&starred=true`;
      }

      const res = await fetch(url);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();

      const newMessages = data.messages || [];
      totalAvailableMessages = data.total !== undefined ? data.total : newMessages.length;

      if (isAppend) {
        allLoadedMessages = [...allLoadedMessages, ...newMessages];
      } else {
        allLoadedMessages = newMessages;
        currentMessagesMap.clear();
      }

      for (const m of newMessages) {
        if (m?.id) currentMessagesMap.set(String(m.id), m);
      }

      renderMessages(allLoadedMessages);
      updateViewHeaders(data);
      updatePaginationControls();
    } catch (err) {
      if (!isAppend && messagesContainer) {
        messagesContainer.innerHTML = `
          <div class="empty-state">
            <p style="color:var(--text-dim);">Failed to load messages: ${escapeHtml(err.message)}</p>
          </div>
        `;
      }
    }
  }

  function updateViewHeaders(data) {
    if (activeViewHeading) {
      if (currentSearchQuery) {
        activeViewHeading.textContent = `Search: "${currentSearchQuery}"`;
      } else if (currentAccount !== 'ALL') {
        const found = accountsList.find(a => a.id === currentAccount);
        activeViewHeading.textContent = found ? found.email : 'Selected Account';
      } else if (currentCategory === 'VIP') {
        activeViewHeading.textContent = '⭐ VIP / Urgent';
      } else if (currentCategory === 'UPDATE') {
        activeViewHeading.textContent = '📘 Coursework & LMS';
      } else if (currentCategory === 'NOISE') {
        activeViewHeading.textContent = '🔇 Promotions & Noise';
      } else {
        activeViewHeading.textContent = 'All Inboxes';
      }
    }

    if (activeViewSubtitle) {
      const total = totalAvailableMessages || allLoadedMessages.length;
      const count = allLoadedMessages.length;
      if (filterUnreadOnly) {
        activeViewSubtitle.textContent = `${count} unread messages`;
      } else if (filterStarredOnly) {
        activeViewSubtitle.textContent = `${count} starred messages`;
      } else if (total > count) {
        activeViewSubtitle.textContent = `Showing ${count} of ${total} emails`;
      } else {
        activeViewSubtitle.textContent = `${count} messages`;
      }
    }
  }

  function updatePaginationControls() {
    if (!feedPaginationBar || !btnLoadMore) return;
    if (allLoadedMessages.length < totalAvailableMessages && !currentSearchQuery) {
      feedPaginationBar.classList.remove('hidden');
      if (loadMoreText) {
        loadMoreText.textContent = `Load Older Emails (${allLoadedMessages.length} of ${totalAvailableMessages})`;
      }
    } else {
      feedPaginationBar.classList.add('hidden');
    }
  }

  btnLoadMore?.addEventListener('click', async () => {
    if (loadMoreSpinner) loadMoreSpinner.classList.remove('hidden');
    currentOffset += pageSize;
    await loadMessages({ append: true });
    if (loadMoreSpinner) loadMoreSpinner.classList.add('hidden');
  });

  function renderMessages(messages) {
    if (!messagesContainer) return;

    if (!Array.isArray(messages) || messages.length === 0) {
      messagesContainer.innerHTML = `
        <div class="empty-state" style="padding: 48px 20px;">
          <p style="font-size:15px;font-weight:600;color:var(--text-muted);margin-bottom:4px;">No messages found</p>
          <p style="font-size:12px;color:var(--text-dim);">There are no emails matching the selected view or filter.</p>
        </div>
      `;
      return;
    }

    messagesContainer.innerHTML = messages.map(msg => {
      const cat = (msg.category || 'NORMAL').toUpperCase();
      const catClass = cat === 'VIP' ? 'card-vip' : (cat === 'UPDATE' ? 'card-update' : (cat === 'NOISE' ? 'card-noise' : ''));
      const badgeClass = cat === 'VIP' ? 'badge-vip' : (cat === 'UPDATE' ? 'badge-update' : (cat === 'NOISE' ? 'badge-noise' : 'badge-normal'));
      const badgeLabel = cat === 'VIP' ? '⭐ VIP' : (cat === 'UPDATE' ? '📘 LMS' : (cat === 'NOISE' ? '🔇 Noise' : 'Mail'));

      const isUnread = !msg.isSeen;
      const isStarred = Boolean(msg.isFlagged);
      const isSelected = activeReaderMessage && String(activeReaderMessage.id) === String(msg.id);

      const senderDisplay = msg.sender || msg.senderEmail || 'Sender';
      const subjectDisplay = msg.subject || '(No Subject)';
      const dateDisplay = formatRelativeDate(msg.date);
      const snippetDisplay = msg.bodySnippet || '';

      // Account pill if known
      const acc = accountsList.find(a => a.id === msg.accountId);
      const accLabel = acc ? (acc.provider === 'gmail' ? 'Gmail' : (acc.provider === 'apple' ? 'Apple' : (acc.provider === 'outlook' ? 'Outlook' : 'IMAP'))) : '';

      return `
        <div class="message-card ${catClass} ${isUnread ? 'is-unread' : ''} ${isSelected ? 'selected' : ''}" id="msg-${escapeHtml(msg.id)}">
          <div class="message-header-row">
            <div class="message-sender-meta">
              ${isUnread ? '<span class="unread-dot"></span>' : ''}
              <button class="btn-card-star ${isStarred ? 'starred' : ''}" data-id="${escapeHtml(msg.id)}" title="${isStarred ? 'Unstar' : 'Star'}">
                ${isStarred ? '★' : '☆'}
              </button>
              <span class="message-sender-name">${escapeHtml(senderDisplay)}</span>
            </div>
            <span class="message-date">${escapeHtml(dateDisplay)}</span>
          </div>

          <h4 class="message-subject">${escapeHtml(subjectDisplay)}</h4>
          ${snippetDisplay ? `<p class="message-snippet">${escapeHtml(snippetDisplay)}</p>` : ''}

          <div class="message-tags-row">
            <div class="card-badges-left">
              <span class="badge-pill ${badgeClass}">${badgeLabel}</span>
              ${accLabel ? `<span class="provider-pill-small">${escapeHtml(accLabel)}</span>` : ''}
            </div>
            <div class="message-actions-row">
              ${isUnread ? `<button class="btn-mark-read" data-id="${escapeHtml(msg.id)}">Mark Read</button>` : '<span style="font-size:11px;color:var(--text-dim);">✓ Read</span>'}
            </div>
          </div>
        </div>
      `;
    }).join('');

    // Attach card star handlers
    messagesContainer.querySelectorAll('.btn-card-star').forEach(starBtn => {
      starBtn.addEventListener('click', async (e) => {
        e.stopPropagation();
        const id = starBtn.getAttribute('data-id');
        await toggleMessageStar(id, starBtn);
      });
    });

    // Attach card read handlers
    messagesContainer.querySelectorAll('.btn-mark-read').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        e.stopPropagation();
        const id = btn.getAttribute('data-id');
        if (!id) return;
        await markMessageRead(id, btn.parentElement);
      });
    });
  }

  // Card click event delegation to open full email reader
  messagesContainer?.addEventListener('click', (e) => {
    if (e.target.closest('button')) return;
    const card = e.target.closest('.message-card');
    if (!card) return;
    const msgId = card.id.replace(/^msg-/, '');
    const msg = currentMessagesMap.get(msgId);
    if (msg) {
      openEmailReader(msg);
    }
  });

  // Date formatter: "10:45 AM" if today, "Yesterday", or "Oct 19"
  function formatRelativeDate(isoDateStr) {
    if (!isoDateStr) return '';
    try {
      const d = new Date(isoDateStr);
      if (Number.isNaN(d.getTime())) return '';
      const now = new Date();
      const isToday = d.toDateString() === now.toDateString();
      if (isToday) {
        return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      }
      const yesterday = new Date(now);
      yesterday.setDate(yesterday.getDate() - 1);
      if (d.toDateString() === yesterday.toDateString()) {
        return 'Yesterday';
      }
      return d.toLocaleDateString([], { month: 'short', day: 'numeric' });
    } catch {
      return '';
    }
  }

  // ==========================================
  // 5. EMAIL READER (INLINE DESKTOP & MODAL)
  // ==========================================
  function openEmailReader(msg) {
    if (!msg) return;
    activeReaderMessage = msg;

    // Highlight selected card in message feed
    messagesContainer?.querySelectorAll('.message-card').forEach(c => c.classList.remove('selected'));
    const activeCard = document.getElementById(`msg-${msg.id}`);
    if (activeCard) activeCard.classList.add('selected');

    const cat = (msg.category || 'NORMAL').toUpperCase();
    const badgeClass = cat === 'VIP' ? 'badge-vip' : (cat === 'UPDATE' ? 'badge-update' : (cat === 'NOISE' ? 'badge-noise' : 'badge-normal'));
    const badgeLabel = cat === 'VIP' ? '⭐ VIP / Urgent' : (cat === 'UPDATE' ? '📘 Coursework' : (cat === 'NOISE' ? '🔇 Muted Noise' : 'Normal'));

    // Sender details
    const senderDisplay = msg.sender || msg.senderEmail || 'Unknown Sender';
    const senderEmailDisplay = msg.senderEmail || '';
    const initial = (senderDisplay.replace(/[^a-zA-Z]/g, '')[0] || 'U').toUpperCase();

    // Recipient text
    let recipientText = 'me';
    if (Array.isArray(msg.recipients) && msg.recipients.length > 0) {
      recipientText = msg.recipients.join(', ');
    } else if (typeof msg.recipients === 'string' && msg.recipients.trim()) {
      try {
        const parsed = JSON.parse(msg.recipients);
        recipientText = Array.isArray(parsed) && parsed.length > 0 ? parsed.join(', ') : msg.recipients;
      } catch {
        recipientText = msg.recipients;
      }
    }

    // Formatted Date
    const fullDate = msg.date
      ? new Date(msg.date).toLocaleString(undefined, { dateStyle: 'full', timeStyle: 'short' })
      : 'Unknown Date';

    // Account pill
    const acc = accountsList.find(a => a.id === msg.accountId);
    const accLabel = acc ? (acc.email || acc.provider) : 'Inbox';

    // Body formatting
    const rawBody = msg.bodySnippet || msg.body || '(No message body content available)';
    const formattedBody = escapeHtml(rawBody)
      .replace(/(https?:\/\/[^\s]+)/g, '<a href="$1" target="_blank" rel="noopener">$1</a>')
      .replace(/\n/g, '<br>');

    // 1. Populate Desktop Reader Pane
    if (readerEmptyState) readerEmptyState.classList.add('hidden');
    if (readerActiveWorkspace) readerActiveWorkspace.classList.remove('hidden');

    if (readerViewCategoryBadge) {
      readerViewCategoryBadge.className = `badge-pill ${badgeClass}`;
      readerViewCategoryBadge.textContent = badgeLabel;
    }
    if (readerViewAccountPill) readerViewAccountPill.textContent = accLabel;
    if (readerViewSubject) readerViewSubject.textContent = msg.subject || '(No Subject)';
    if (readerSenderAvatar) readerSenderAvatar.textContent = initial;
    if (readerViewSenderName) readerViewSenderName.textContent = senderDisplay;
    if (readerViewSenderEmail) readerViewSenderEmail.textContent = senderEmailDisplay ? `<${senderEmailDisplay}>` : '';
    if (readerViewRecipient) readerViewRecipient.textContent = recipientText;
    if (readerViewTimestamp) readerViewTimestamp.textContent = fullDate;
    if (readerViewBody) readerViewBody.innerHTML = formattedBody;

    updateReaderReadButtons(msg.isSeen);
    updateReaderStarButton(Boolean(msg.isFlagged));

    // Wire mailto reply link
    if (btnReaderReply) {
      const replySubject = encodeURIComponent(`Re: ${msg.subject || ''}`);
      btnReaderReply.href = `mailto:${encodeURIComponent(senderEmailDisplay || senderDisplay)}?subject=${replySubject}`;
    }

    // 2. Populate Mobile / Modal Reader (for compatibility & narrow screens)
    if (readerCategoryBadge) {
      readerCategoryBadge.className = `badge-pill ${badgeClass}`;
      readerCategoryBadge.textContent = badgeLabel;
    }
    if (readerSubject) readerSubject.textContent = msg.subject || '(No Subject)';
    if (readerSender) readerSender.textContent = `${senderDisplay} ${senderEmailDisplay ? `<${senderEmailDisplay}>` : ''}`;
    if (readerRecipient) readerRecipient.textContent = recipientText;
    if (readerTimestamp) readerTimestamp.textContent = fullDate;
    if (readerBodyContent) readerBodyContent.innerHTML = formattedBody;

    // Mobile slide-in
    if (window.innerWidth < 900 && desktopReaderPane) {
      desktopReaderPane.classList.add('mobile-open');
    }

    // Automatically mark read on open if unread
    if (!msg.isSeen) {
      markMessageRead(msg.id);
    }
  }

  function updateReaderReadButtons(isSeen) {
    const text = isSeen ? 'Mark as Unread' : 'Mark as Read';
    if (btnReaderActionRead) btnReaderActionRead.textContent = text;
    if (btnReaderToggleRead) btnReaderToggleRead.textContent = text;
  }

  function updateReaderStarButton(isStarred) {
    if (btnReaderToggleStar) {
      btnReaderToggleStar.textContent = isStarred ? '★ Starred' : '☆ Star';
      btnReaderToggleStar.style.color = isStarred ? '#f59e0b' : 'var(--text-muted)';
    }
  }

  // Reader Top Actions
  btnReaderActionRead?.addEventListener('click', toggleActiveReaderReadState);
  btnReaderToggleRead?.addEventListener('click', toggleActiveReaderReadState);

  async function toggleActiveReaderReadState() {
    if (!activeReaderMessage) return;
    const isCurrentlySeen = activeReaderMessage.isSeen;
    const endpoint = isCurrentlySeen ? 'unread' : 'read';

    try {
      const res = await fetch(`/api/messages/${encodeURIComponent(activeReaderMessage.id)}/${endpoint}`, { method: 'POST' });
      if (res.ok) {
        activeReaderMessage.isSeen = !isCurrentlySeen;
        updateReaderReadButtons(activeReaderMessage.isSeen);
        updateCardSeenState(activeReaderMessage.id, activeReaderMessage.isSeen);
        loadMailboxSummary();
      }
    } catch {}
  }

  btnReaderToggleStar?.addEventListener('click', async () => {
    if (!activeReaderMessage) return;
    const isCurrentlyStarred = Boolean(activeReaderMessage.isFlagged);
    const endpoint = isCurrentlyStarred ? 'unstar' : 'star';

    try {
      const res = await fetch(`/api/messages/${encodeURIComponent(activeReaderMessage.id)}/${endpoint}`, { method: 'POST' });
      if (res.ok) {
        activeReaderMessage.isFlagged = !isCurrentlyStarred;
        updateReaderStarButton(activeReaderMessage.isFlagged);
        updateCardStarState(activeReaderMessage.id, activeReaderMessage.isFlagged);
      }
    } catch {}
  });

  btnReaderDelete?.addEventListener('click', async () => {
    if (!activeReaderMessage) return;
    if (!confirm('Are you sure you want to delete this message?')) return;
    const id = activeReaderMessage.id;
    try {
      const res = await fetch(`/api/messages/${encodeURIComponent(id)}`, { method: 'DELETE' });
      if (res.ok) {
        showToast('Message deleted', 'success');
        closeEmailReader();
        loadMessages();
        loadMailboxSummary();
      }
    } catch {}
  });

  btnReaderBackMobile?.addEventListener('click', () => {
    if (desktopReaderPane) desktopReaderPane.classList.remove('mobile-open');
  });

  function closeEmailReader() {
    activeReaderMessage = null;
    if (readerEmptyState) readerEmptyState.classList.remove('hidden');
    if (readerActiveWorkspace) readerActiveWorkspace.classList.add('hidden');
    if (modalEmailReader) modalEmailReader.classList.add('hidden');
    if (desktopReaderPane) desktopReaderPane.classList.remove('mobile-open');
    messagesContainer?.querySelectorAll('.message-card').forEach(c => c.classList.remove('selected'));
  }

  btnCloseReader?.addEventListener('click', closeEmailReader);
  modalEmailReader?.addEventListener('click', (e) => {
    if (e.target === modalEmailReader) closeEmailReader();
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      if (modalAddAccount && !modalAddAccount.classList.contains('hidden')) modalAddAccount.classList.add('hidden');
      if (modalAccountsVault && !modalAccountsVault.classList.contains('hidden')) modalAccountsVault.classList.add('hidden');
      if (modalNotifications && !modalNotifications.classList.contains('hidden')) modalNotifications.classList.add('hidden');
      if (modalSettings && !modalSettings.classList.contains('hidden')) modalSettings.classList.add('hidden');
      if (modalEmailReader && !modalEmailReader.classList.contains('hidden')) closeEmailReader();
      if (desktopReaderPane?.classList.contains('mobile-open')) desktopReaderPane.classList.remove('mobile-open');
    }
  });

  // State Updates on Message Cards
  async function markMessageRead(id, containerEl) {
    try {
      await fetch(`/api/messages/${encodeURIComponent(id)}/read`, { method: 'POST' });
      const msg = currentMessagesMap.get(String(id));
      if (msg) msg.isSeen = true;
      updateCardSeenState(id, true);
      loadMailboxSummary();
    } catch {}
  }

  function updateCardSeenState(msgId, isSeen) {
    const card = document.getElementById(`msg-${msgId}`);
    if (!card) return;

    if (isSeen) {
      card.classList.remove('is-unread');
      const dot = card.querySelector('.unread-dot');
      if (dot) dot.remove();
      const actionsRow = card.querySelector('.message-actions-row');
      if (actionsRow) actionsRow.innerHTML = '<span style="font-size:11px;color:var(--text-dim);">✓ Read</span>';
    } else {
      card.classList.add('is-unread');
      const actionsRow = card.querySelector('.message-actions-row');
      if (actionsRow) {
        actionsRow.innerHTML = `<button class="btn-mark-read" data-id="${escapeHtml(msgId)}">Mark Read</button>`;
        actionsRow.querySelector('.btn-mark-read')?.addEventListener('click', async (e) => {
          e.stopPropagation();
          await markMessageRead(msgId, actionsRow);
        });
      }
    }
  }

  async function toggleMessageStar(id, btnEl) {
    const msg = currentMessagesMap.get(String(id));
    if (!msg) return;
    const isCurrentlyStarred = Boolean(msg.isFlagged);
    const endpoint = isCurrentlyStarred ? 'unstar' : 'star';

    try {
      const res = await fetch(`/api/messages/${encodeURIComponent(id)}/${endpoint}`, { method: 'POST' });
      if (res.ok) {
        msg.isFlagged = !isCurrentlyStarred;
        updateCardStarState(id, msg.isFlagged);
        if (activeReaderMessage && String(activeReaderMessage.id) === String(id)) {
          activeReaderMessage.isFlagged = msg.isFlagged;
          updateReaderStarButton(msg.isFlagged);
        }
      }
    } catch {}
  }

  function updateCardStarState(msgId, isStarred) {
    const card = document.getElementById(`msg-${msgId}`);
    if (!card) return;
    const btn = card.querySelector('.btn-card-star');
    if (!btn) return;
    if (isStarred) {
      btn.classList.add('starred');
      btn.textContent = '★';
    } else {
      btn.classList.remove('starred');
      btn.textContent = '☆';
    }
  }

  // Mark all visible as read
  btnMarkAllRead?.addEventListener('click', async () => {
    const unread = allLoadedMessages.filter(m => !m.isSeen);
    if (unread.length === 0) {
      showToast('No unread messages visible.', 'info');
      return;
    }
    for (const m of unread) {
      markMessageRead(m.id);
    }
    showToast(`Marked ${unread.length} messages as read.`, 'success');
  });

  // ==========================================
  // 6. NAVIGATION & FILTER ACTIONS
  // ==========================================
  navAllInboxes?.addEventListener('click', () => {
    setActiveNav(navAllInboxes);
    currentAccount = 'ALL';
    currentCategory = 'ALL';
    filterUnreadOnly = false;
    filterStarredOnly = false;
    updateFilterButtonStates();
    loadMessages();
  });

  function setActiveAccountFilter(accountId) {
    currentAccount = accountId;
    currentCategory = 'ALL';
    filterUnreadOnly = false;
    filterStarredOnly = false;
    updateFilterButtonStates();

    // Update active highlight on nav
    document.querySelectorAll('.nav-item, .account-nav-row').forEach(el => el.classList.remove('active'));
    const row = sidebarAccountsList?.querySelector(`[data-account-id="${accountId}"]`);
    if (row) row.classList.add('active');

    loadMessages();
  }

  // Triage category tab buttons
  document.querySelectorAll('[data-category]').forEach(btn => {
    btn.addEventListener('click', () => {
      const cat = btn.getAttribute('data-category') || 'ALL';
      currentCategory = cat;
      filterUnreadOnly = false;
      filterStarredOnly = false;
      updateFilterButtonStates();

      document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
      btn.classList.add('active');

      loadMessages();
    });
  });

  // Filter Unread Only
  navFilterUnread?.addEventListener('click', () => {
    filterUnreadOnly = !filterUnreadOnly;
    filterStarredOnly = false;
    updateFilterButtonStates();
    loadMessages();
  });

  btnFilterUnreadPill?.addEventListener('click', () => {
    filterUnreadOnly = !filterUnreadOnly;
    filterStarredOnly = false;
    updateFilterButtonStates();
    loadMessages();
  });

  // Filter Starred Only
  navFilterStarred?.addEventListener('click', () => {
    filterStarredOnly = !filterStarredOnly;
    filterUnreadOnly = false;
    updateFilterButtonStates();
    loadMessages();
  });

  function updateFilterButtonStates() {
    if (btnFilterUnreadPill) {
      btnFilterUnreadPill.classList.toggle('active', filterUnreadOnly);
    }
    if (navFilterUnread) {
      navFilterUnread.classList.toggle('active', filterUnreadOnly);
    }
    if (navFilterStarred) {
      navFilterStarred.classList.toggle('active', filterStarredOnly);
    }
  }

  function setActiveNav(activeElement) {
    document.querySelectorAll('.nav-item, .account-nav-row').forEach(el => el.classList.remove('active'));
    activeElement.classList.add('active');
  }

  // Sub-20ms Search Input Debouncing
  if (searchInput) {
    searchInput.addEventListener('input', (e) => {
      clearTimeout(searchDebounceTimer);
      const val = e.target.value.trim();
      if (btnClearSearch) btnClearSearch.classList.toggle('hidden', !val);

      searchDebounceTimer = setTimeout(() => {
        currentSearchQuery = val;
        loadMessages();
      }, 150);
    });
  }

  btnClearSearch?.addEventListener('click', () => {
    if (searchInput) searchInput.value = '';
    btnClearSearch.classList.add('hidden');
    currentSearchQuery = '';
    loadMessages();
  });

  // ==========================================
  // 7. MODALS CONTROLLERS
  // ==========================================
  btnSidebarAdd?.addEventListener('click', () => {
    if (modalAddAccount) modalAddAccount.classList.remove('hidden');
  });

  btnCloseAddModal?.addEventListener('click', () => {
    if (modalAddAccount) modalAddAccount.classList.add('hidden');
  });

  btnOpenAccountsModal?.addEventListener('click', () => {
    if (modalAccountsVault) modalAccountsVault.classList.remove('hidden');
  });

  btnCloseAccountsModal?.addEventListener('click', () => {
    if (modalAccountsVault) modalAccountsVault.classList.add('hidden');
  });

  btnOpenConduits?.addEventListener('click', () => {
    if (modalNotifications) modalNotifications.classList.remove('hidden');
  });

  btnCloseNotificationsModal?.addEventListener('click', () => {
    if (modalNotifications) modalNotifications.classList.add('hidden');
  });

  btnOpenOAuthSettings?.addEventListener('click', () => {
    if (modalSettings) modalSettings.classList.remove('hidden');
  });

  btnCloseModal?.addEventListener('click', () => {
    if (modalSettings) modalSettings.classList.add('hidden');
  });

  btnCancelModal?.addEventListener('click', () => {
    if (modalSettings) modalSettings.classList.add('hidden');
  });

  // OAuth Settings Save
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
    if (modalSettings) modalSettings.classList.add('hidden');
  });

  // ==========================================
  // 8. GUIDED ONBOARDING & VAULT CONNECTIONS
  // ==========================================
  // Auto-hyphenate Apple password: xxxx-xxxx-xxxx-xxxx
  inputApplePass?.addEventListener('input', (e) => {
    let val = e.target.value.replace(/[^a-zA-Z0-9]/g, '').toLowerCase();
    if (val.length > 16) val = val.slice(0, 16);
    const parts = [];
    for (let i = 0; i < val.length; i += 4) {
      parts.push(val.slice(i, i + 4));
    }
    e.target.value = parts.join('-');
  });

  // Password visibility toggles
  document.querySelectorAll('.btn-toggle-visibility').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const input = e.target.parentElement.querySelector('input');
      if (input.type === 'password') {
        input.type = 'text';
        btn.textContent = '🔒';
      } else {
        input.type = 'password';
        btn.textContent = '👁';
      }
    });
  });

  // Form Submissions
  formApple?.addEventListener('submit', async (e) => {
    e.preventDefault();
    await submitAccountForm('/api/accounts/apple', {
      email: document.getElementById('apple-email').value.trim(),
      appPassword: inputApplePass.value.trim(),
      label: document.getElementById('apple-label').value.trim()
    }, btnSubmitApple, appleError);
  });

  formGmail?.addEventListener('submit', async (e) => {
    e.preventDefault();
    await submitAccountForm('/api/accounts/gmail', {
      email: document.getElementById('gmail-email').value.trim(),
      appPassword: inputGmailPass.value.trim(),
      label: document.getElementById('gmail-label').value.trim()
    }, btnSubmitGmail, gmailError);
  });

  formOutlook?.addEventListener('submit', async (e) => {
    e.preventDefault();
    await submitAccountForm('/api/accounts/outlook', {
      email: document.getElementById('outlook-email').value.trim(),
      password: inputOutlookPass.value.trim(),
      label: document.getElementById('outlook-label').value.trim()
    }, btnSubmitOutlook, outlookError);
  });

  formCustom?.addEventListener('submit', async (e) => {
    e.preventDefault();
    await submitAccountForm('/api/accounts/custom', {
      email: document.getElementById('custom-email').value.trim(),
      password: document.getElementById('custom-password').value.trim(),
      imap: {
        host: document.getElementById('custom-imap-host').value.trim(),
        port: Number(document.getElementById('custom-imap-port').value) || 993,
        secure: true
      }
    }, btnSubmitCustom, customError);
  });

  async function submitAccountForm(url, payload, btnEl, errEl) {
    hideError(errEl);
    setLoading(btnEl, true, 'Testing connection & saving to vault...');

    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || 'Connection failed');
      }

      showToast('Account connected! Background backfill started.', 'success');
      if (modalAddAccount) modalAddAccount.classList.add('hidden');
      await loadAccounts();
      await loadMailboxSummary();
      await loadMessages();
    } catch (err) {
      showError(errEl, err.message);
    } finally {
      setLoading(btnEl, false, 'Connect & Save to Vault');
    }
  }

  // OAuth 2.0 Flow Trigger
  btnGoogle?.addEventListener('click', () => triggerOAuthFlow('gmail', 'Google Mail'));
  btnMicrosoft?.addEventListener('click', () => triggerOAuthFlow('outlook', 'Microsoft Outlook'));

  async function triggerOAuthFlow(provider, providerName) {
    const width = 600;
    const height = 700;
    const left = Math.max(0, Math.floor((window.screen.width - width) / 2));
    const top = Math.max(0, Math.floor((window.screen.height - height) / 2));

    const popup = window.open(
      'about:blank',
      `mailboxer_oauth_${provider}`,
      `toolbar=no, location=no, directories=no, status=no, menubar=no, scrollbars=yes, resizable=yes, width=${width}, height=${height}, top=${top}, left=${left}`
    );

    try {
      const res = await fetch(`/api/auth/${provider}/url`);
      const data = await res.json();
      if (!res.ok || !data.url) {
        if (popup && !popup.closed) popup.close();
        if (modalSettings) modalSettings.classList.remove('hidden');
        showToast(`Please enter your ${providerName} OAuth Client ID in Settings first.`, 'warning');
        return;
      }
      popup.location.href = data.url;
    } catch (err) {
      if (popup && !popup.closed) popup.close();
      showToast(`Error starting ${providerName} login: ${err.message}`, 'error');
    }
  }

  window.addEventListener('message', (event) => {
    if (event.data?.type === 'MAILBOXER_OAUTH_RESULT') {
      if (event.data.success) {
        showToast('OAuth account connected successfully!', 'success');
        if (modalAddAccount) modalAddAccount.classList.add('hidden');
        loadAccounts();
        loadMailboxSummary();
        loadMessages();
      } else {
        showToast(`Authentication failed: ${event.data.error || 'Unknown error'}`, 'error');
      }
    }
  });

  // ==========================================
  // 9. VIP CONDUITS & NOTIFICATIONS
  // ==========================================
  const btnToggleWebPush = document.getElementById('btn-toggle-webpush');
  const webPushStatus = document.getElementById('webpush-status-text');
  const webPushBtnText = document.getElementById('webpush-btn-text');
  const ntfyTopicInput = document.getElementById('ntfy-topic-input');
  const btnSaveNtfy = document.getElementById('btn-save-ntfy');
  const btnTestAlert = document.getElementById('btn-test-alert');
  const alertTestStatus = document.getElementById('alert-test-status');

  if (ntfyTopicInput) {
    ntfyTopicInput.value = localStorage.getItem('mailboxer_ntfy_topic') || '';
  }

  btnSaveNtfy?.addEventListener('click', () => {
    const val = ntfyTopicInput?.value.trim() || '';
    localStorage.setItem('mailboxer_ntfy_topic', val);
    showToast(`ntfy.sh topic saved: ${val || '(cleared)'}`, 'success');
  });

  btnTestAlert?.addEventListener('click', async () => {
    if (alertTestStatus) alertTestStatus.textContent = 'Sending VIP test alert...';
    try {
      const topic = ntfyTopicInput?.value.trim() || '';
      const res = await fetch('/api/notifications/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ topic })
      });
      const d = await res.json();
      if (res.ok) {
        if (alertTestStatus) alertTestStatus.textContent = '✓ VIP alert dispatched successfully!';
        showToast('Test alert dispatched!', 'success');
      } else {
        if (alertTestStatus) alertTestStatus.textContent = `Alert failed: ${d.error || 'Unknown error'}`;
      }
    } catch (err) {
      if (alertTestStatus) alertTestStatus.textContent = `Error: ${err.message}`;
    }
  });

  // ==========================================
  // 10. UI UTILITIES & TOASTS
  // ==========================================
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
      font-size: 13.5px;
      font-weight: 500;
      box-shadow: 0 10px 25px rgba(0,0,0,0.5);
      z-index: 99999;
      transition: all 0.3s;
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
    if (spinner) spinner.classList.toggle('hidden', !isLoading);
    btn.disabled = isLoading;
  }

  // Export globally for browser and test environments
  if (typeof window !== 'undefined') {
    window.renderAccounts = renderAccounts;
    window.renderMessages = renderMessages;
    window.openEmailReader = openEmailReader;
  }
  if (typeof globalThis !== 'undefined') {
    globalThis.renderAccounts = renderAccounts;
    globalThis.renderMessages = renderMessages;
    globalThis.openEmailReader = openEmailReader;
  }
});