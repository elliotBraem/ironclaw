// IronClaw Web Gateway - Client

let token = '';
let eventSource = null;
let logEventSource = null;
let currentTab = 'chat';

// --- Auth ---

function authenticate() {
  token = document.getElementById('token-input').value.trim();
  if (!token) {
    document.getElementById('auth-error').textContent = 'Token required';
    return;
  }

  // Test the token against the health-ish endpoint (chat/threads requires auth)
  apiFetch('/api/chat/threads')
    .then(() => {
      document.getElementById('auth-screen').style.display = 'none';
      document.getElementById('app').style.display = 'flex';
      connectSSE();
      connectLogSSE();
      loadHistory();
      loadMemoryTree();
      loadJobs();
    })
    .catch(() => {
      document.getElementById('auth-error').textContent = 'Invalid token';
    });
}

document.getElementById('token-input').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') authenticate();
});

// --- API helper ---

function apiFetch(path, options) {
  const opts = options || {};
  opts.headers = opts.headers || {};
  opts.headers['Authorization'] = 'Bearer ' + token;
  if (opts.body && typeof opts.body === 'object') {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(opts.body);
  }
  return fetch(path, opts).then((res) => {
    if (!res.ok) throw new Error(res.status + ' ' + res.statusText);
    return res.json();
  });
}

// --- SSE ---

function connectSSE() {
  if (eventSource) eventSource.close();

  eventSource = new EventSource('/api/chat/events?token=' + encodeURIComponent(token));

  eventSource.onopen = () => {
    document.getElementById('sse-dot').classList.remove('disconnected');
    document.getElementById('sse-status').textContent = 'Connected';
  };

  eventSource.onerror = () => {
    document.getElementById('sse-dot').classList.add('disconnected');
    document.getElementById('sse-status').textContent = 'Reconnecting...';
  };

  eventSource.addEventListener('response', (e) => {
    const data = JSON.parse(e.data);
    addMessage('assistant', data.content);
    setStatus('');
    hideApproval();
  });

  eventSource.addEventListener('thinking', (e) => {
    const data = JSON.parse(e.data);
    setStatus(data.message, true);
  });

  eventSource.addEventListener('tool_started', (e) => {
    const data = JSON.parse(e.data);
    setStatus('Running tool: ' + data.name, true);
  });

  eventSource.addEventListener('tool_completed', (e) => {
    const data = JSON.parse(e.data);
    const icon = data.success ? '\u2713' : '\u2717';
    setStatus('Tool ' + data.name + ' ' + icon);
  });

  eventSource.addEventListener('stream_chunk', (e) => {
    const data = JSON.parse(e.data);
    appendToLastAssistant(data.content);
  });

  eventSource.addEventListener('status', (e) => {
    const data = JSON.parse(e.data);
    setStatus(data.message);
  });

  eventSource.addEventListener('approval_needed', (e) => {
    const data = JSON.parse(e.data);
    showApproval(data);
  });

  eventSource.addEventListener('error', (e) => {
    if (e.data) {
      const data = JSON.parse(e.data);
      addMessage('system', 'Error: ' + data.message);
    }
  });
}

// --- Chat ---

function sendMessage() {
  const input = document.getElementById('chat-input');
  const content = input.value.trim();
  if (!content) return;

  addMessage('user', content);
  input.value = '';
  autoResizeTextarea(input);
  setStatus('Sending...', true);

  apiFetch('/api/chat/send', {
    method: 'POST',
    body: { content },
  }).catch((err) => {
    addMessage('system', 'Failed to send: ' + err.message);
    setStatus('');
  });
}

function sendApproval(response) {
  apiFetch('/api/chat/send', {
    method: 'POST',
    body: { content: response },
  }).catch((err) => {
    addMessage('system', 'Failed to send approval: ' + err.message);
  });
  hideApproval();
}

function addMessage(role, content) {
  const container = document.getElementById('chat-messages');
  const div = document.createElement('div');
  div.className = 'message ' + role;
  div.textContent = content;
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
}

function appendToLastAssistant(chunk) {
  const container = document.getElementById('chat-messages');
  const messages = container.querySelectorAll('.message.assistant');
  if (messages.length > 0) {
    const last = messages[messages.length - 1];
    last.textContent += chunk;
    container.scrollTop = container.scrollHeight;
  } else {
    addMessage('assistant', chunk);
  }
}

function setStatus(text, spinning) {
  const el = document.getElementById('chat-status');
  if (!text) {
    el.innerHTML = '';
    return;
  }
  el.innerHTML = (spinning ? '<div class="spinner"></div>' : '') + escapeHtml(text);
}

function showApproval(data) {
  const banner = document.getElementById('approval-banner');
  const info = document.getElementById('approval-info');
  info.textContent = 'Tool "' + data.tool_name + '" requires approval: ' + data.description;
  banner.classList.add('visible');
}

function hideApproval() {
  document.getElementById('approval-banner').classList.remove('visible');
}

function loadHistory() {
  apiFetch('/api/chat/history').then((data) => {
    const container = document.getElementById('chat-messages');
    container.innerHTML = '';
    for (const turn of data.turns) {
      addMessage('user', turn.user_input);
      if (turn.response) {
        addMessage('assistant', turn.response);
      }
    }
  }).catch(() => {
    // No history or no active thread, that's fine
  });
}

// Chat input auto-resize and keyboard handling
const chatInput = document.getElementById('chat-input');
chatInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    sendMessage();
  }
});
chatInput.addEventListener('input', () => autoResizeTextarea(chatInput));

function autoResizeTextarea(el) {
  el.style.height = 'auto';
  el.style.height = Math.min(el.scrollHeight, 120) + 'px';
}

// --- Tabs ---

document.querySelectorAll('.tab-bar button[data-tab]').forEach((btn) => {
  btn.addEventListener('click', () => {
    const tab = btn.getAttribute('data-tab');
    switchTab(tab);
  });
});

function switchTab(tab) {
  currentTab = tab;
  document.querySelectorAll('.tab-bar button[data-tab]').forEach((b) => {
    b.classList.toggle('active', b.getAttribute('data-tab') === tab);
  });
  document.querySelectorAll('.tab-panel').forEach((p) => {
    p.classList.toggle('active', p.id === 'tab-' + tab);
  });

  if (tab === 'memory') loadMemoryTree();
  if (tab === 'jobs') loadJobs();
  if (tab === 'extensions') loadExtensions();
}

// --- Memory (filesystem tree) ---

let memorySearchTimeout = null;
// Tree state: nested nodes persisted across renders
// { name, path, is_dir, children: [] | null, expanded: bool, loaded: bool }
let memoryTreeState = null;

document.getElementById('memory-search').addEventListener('input', (e) => {
  clearTimeout(memorySearchTimeout);
  const query = e.target.value.trim();
  if (!query) {
    loadMemoryTree();
    return;
  }
  memorySearchTimeout = setTimeout(() => searchMemory(query), 300);
});

function loadMemoryTree() {
  // Only load top-level on first load (or refresh)
  apiFetch('/api/memory/list?path=').then((data) => {
    memoryTreeState = data.entries.map((e) => ({
      name: e.name,
      path: e.path,
      is_dir: e.is_dir,
      children: e.is_dir ? null : undefined,
      expanded: false,
      loaded: false,
    }));
    renderTree();
  }).catch(() => {});
}

function renderTree() {
  const container = document.getElementById('memory-tree');
  container.innerHTML = '';
  if (!memoryTreeState || memoryTreeState.length === 0) {
    container.innerHTML = '<div class="tree-item" style="color:var(--text-secondary)">No files in workspace</div>';
    return;
  }
  renderNodes(memoryTreeState, container, 0);
}

function renderNodes(nodes, container, depth) {
  for (const node of nodes) {
    const row = document.createElement('div');
    row.className = 'tree-row';
    row.style.paddingLeft = (depth * 16 + 8) + 'px';

    if (node.is_dir) {
      const arrow = document.createElement('span');
      arrow.className = 'expand-arrow' + (node.expanded ? ' expanded' : '');
      arrow.textContent = '\u25B6';
      arrow.addEventListener('click', (e) => {
        e.stopPropagation();
        toggleExpand(node);
      });
      row.appendChild(arrow);

      const label = document.createElement('span');
      label.className = 'tree-label dir';
      label.textContent = node.name;
      label.addEventListener('click', () => toggleExpand(node));
      row.appendChild(label);
    } else {
      const spacer = document.createElement('span');
      spacer.className = 'expand-arrow-spacer';
      row.appendChild(spacer);

      const label = document.createElement('span');
      label.className = 'tree-label file';
      label.textContent = node.name;
      label.addEventListener('click', () => readMemoryFile(node.path));
      row.appendChild(label);
    }

    container.appendChild(row);

    if (node.is_dir && node.expanded && node.children) {
      const childContainer = document.createElement('div');
      childContainer.className = 'tree-children';
      renderNodes(node.children, childContainer, depth + 1);
      container.appendChild(childContainer);
    }
  }
}

function toggleExpand(node) {
  if (node.expanded) {
    node.expanded = false;
    renderTree();
    return;
  }

  if (node.loaded) {
    node.expanded = true;
    renderTree();
    return;
  }

  // Lazy-load children
  apiFetch('/api/memory/list?path=' + encodeURIComponent(node.path)).then((data) => {
    node.children = data.entries.map((e) => ({
      name: e.name,
      path: e.path,
      is_dir: e.is_dir,
      children: e.is_dir ? null : undefined,
      expanded: false,
      loaded: false,
    }));
    node.loaded = true;
    node.expanded = true;
    renderTree();
  }).catch(() => {});
}

function readMemoryFile(path) {
  // Update breadcrumb
  document.getElementById('memory-breadcrumb').innerHTML = buildBreadcrumb(path);

  apiFetch('/api/memory/read?path=' + encodeURIComponent(path)).then((data) => {
    document.getElementById('memory-viewer').textContent = data.content;
  }).catch((err) => {
    document.getElementById('memory-viewer').innerHTML = '<div class="empty">Error: ' + escapeHtml(err.message) + '</div>';
  });
}

function buildBreadcrumb(path) {
  const parts = path.split('/');
  let html = '<a onclick="loadMemoryTree()">workspace</a>';
  let current = '';
  for (const part of parts) {
    current += (current ? '/' : '') + part;
    html += ' / <a onclick="readMemoryFile(\'' + escapeHtml(current) + '\')">' + escapeHtml(part) + '</a>';
  }
  return html;
}

function searchMemory(query) {
  apiFetch('/api/memory/search', {
    method: 'POST',
    body: { query, limit: 20 },
  }).then((data) => {
    const tree = document.getElementById('memory-tree');
    tree.innerHTML = '';
    if (data.results.length === 0) {
      tree.innerHTML = '<div class="tree-item" style="color:var(--text-secondary)">No results</div>';
      return;
    }
    for (const result of data.results) {
      const item = document.createElement('div');
      item.className = 'search-result';
      item.innerHTML = '<div class="path">' + escapeHtml(result.path) + '</div>'
        + '<div class="snippet">' + escapeHtml(result.content.substring(0, 120)) + '</div>';
      item.addEventListener('click', () => readMemoryFile(result.path));
      tree.appendChild(item);
    }
  }).catch(() => {});
}

// --- Logs ---

const LOG_MAX_ENTRIES = 2000;
let logsPaused = false;
let logBuffer = []; // buffer while paused

function connectLogSSE() {
  if (logEventSource) logEventSource.close();

  logEventSource = new EventSource('/api/logs/events?token=' + encodeURIComponent(token));

  logEventSource.addEventListener('log', (e) => {
    const entry = JSON.parse(e.data);
    if (logsPaused) {
      logBuffer.push(entry);
      return;
    }
    appendLogEntry(entry);
  });

  logEventSource.onerror = () => {
    // Silent reconnect
  };
}

function appendLogEntry(entry) {
  const output = document.getElementById('logs-output');

  // Level filter
  const levelFilter = document.getElementById('logs-level-filter').value;
  const targetFilter = document.getElementById('logs-target-filter').value.trim().toLowerCase();

  const div = document.createElement('div');
  div.className = 'log-entry level-' + entry.level;
  div.setAttribute('data-level', entry.level);
  div.setAttribute('data-target', entry.target);

  const ts = document.createElement('span');
  ts.className = 'log-ts';
  ts.textContent = entry.timestamp.substring(11, 23);
  div.appendChild(ts);

  const lvl = document.createElement('span');
  lvl.className = 'log-level';
  lvl.textContent = entry.level.padEnd(5);
  div.appendChild(lvl);

  const tgt = document.createElement('span');
  tgt.className = 'log-target';
  tgt.textContent = entry.target;
  div.appendChild(tgt);

  const msg = document.createElement('span');
  msg.className = 'log-msg';
  msg.textContent = entry.message;
  div.appendChild(msg);

  // Apply current filters as visibility
  const matchesLevel = levelFilter === 'all' || entry.level === levelFilter;
  const matchesTarget = !targetFilter || entry.target.toLowerCase().includes(targetFilter);
  if (!matchesLevel || !matchesTarget) {
    div.style.display = 'none';
  }

  output.appendChild(div);

  // Cap entries
  while (output.children.length > LOG_MAX_ENTRIES) {
    output.removeChild(output.firstChild);
  }

  // Auto-scroll
  if (document.getElementById('logs-autoscroll').checked) {
    output.scrollTop = output.scrollHeight;
  }
}

function toggleLogsPause() {
  logsPaused = !logsPaused;
  const btn = document.getElementById('logs-pause-btn');
  btn.textContent = logsPaused ? 'Resume' : 'Pause';

  if (!logsPaused) {
    // Flush buffer
    for (const entry of logBuffer) {
      appendLogEntry(entry);
    }
    logBuffer = [];
  }
}

function clearLogs() {
  document.getElementById('logs-output').innerHTML = '';
  logBuffer = [];
}

// Re-apply filters when level or target changes
document.getElementById('logs-level-filter').addEventListener('change', applyLogFilters);
document.getElementById('logs-target-filter').addEventListener('input', applyLogFilters);

function applyLogFilters() {
  const levelFilter = document.getElementById('logs-level-filter').value;
  const targetFilter = document.getElementById('logs-target-filter').value.trim().toLowerCase();
  const entries = document.querySelectorAll('#logs-output .log-entry');
  for (const el of entries) {
    const matchesLevel = levelFilter === 'all' || el.getAttribute('data-level') === levelFilter;
    const matchesTarget = !targetFilter || el.getAttribute('data-target').toLowerCase().includes(targetFilter);
    el.style.display = (matchesLevel && matchesTarget) ? '' : 'none';
  }
}

// --- Extensions ---

function loadExtensions() {
  const extList = document.getElementById('extensions-list');
  const toolsTbody = document.getElementById('tools-tbody');
  const toolsEmpty = document.getElementById('tools-empty');

  // Fetch both in parallel
  Promise.all([
    apiFetch('/api/extensions').catch(() => ({ extensions: [] })),
    apiFetch('/api/extensions/tools').catch(() => ({ tools: [] })),
  ]).then(([extData, toolData]) => {
    // Render extensions
    if (extData.extensions.length === 0) {
      extList.innerHTML = '<div class="empty-state">No extensions installed</div>';
    } else {
      extList.innerHTML = '';
      for (const ext of extData.extensions) {
        extList.appendChild(renderExtensionCard(ext));
      }
    }

    // Render tools
    if (toolData.tools.length === 0) {
      toolsTbody.innerHTML = '';
      toolsEmpty.style.display = 'block';
    } else {
      toolsEmpty.style.display = 'none';
      toolsTbody.innerHTML = toolData.tools.map((t) =>
        '<tr><td>' + escapeHtml(t.name) + '</td><td>' + escapeHtml(t.description) + '</td></tr>'
      ).join('');
    }
  });
}

function renderExtensionCard(ext) {
  const card = document.createElement('div');
  card.className = 'ext-card';

  const header = document.createElement('div');
  header.className = 'ext-header';

  const name = document.createElement('span');
  name.className = 'ext-name';
  name.textContent = ext.name;
  header.appendChild(name);

  const kind = document.createElement('span');
  kind.className = 'ext-kind kind-' + ext.kind;
  kind.textContent = ext.kind;
  header.appendChild(kind);

  const authDot = document.createElement('span');
  authDot.className = 'ext-auth-dot ' + (ext.authenticated ? 'authed' : 'unauthed');
  authDot.title = ext.authenticated ? 'Authenticated' : 'Not authenticated';
  header.appendChild(authDot);

  card.appendChild(header);

  if (ext.description) {
    const desc = document.createElement('div');
    desc.className = 'ext-desc';
    desc.textContent = ext.description;
    card.appendChild(desc);
  }

  if (ext.tools.length > 0) {
    const tools = document.createElement('div');
    tools.className = 'ext-tools';
    tools.textContent = 'Tools: ' + ext.tools.join(', ');
    card.appendChild(tools);
  }

  const actions = document.createElement('div');
  actions.className = 'ext-actions';

  if (!ext.active) {
    const activateBtn = document.createElement('button');
    activateBtn.className = 'btn-ext activate';
    activateBtn.textContent = 'Activate';
    activateBtn.addEventListener('click', () => activateExtension(ext.name));
    actions.appendChild(activateBtn);
  } else {
    const activeLabel = document.createElement('span');
    activeLabel.className = 'ext-active-label';
    activeLabel.textContent = 'Active';
    actions.appendChild(activeLabel);
  }

  const removeBtn = document.createElement('button');
  removeBtn.className = 'btn-ext remove';
  removeBtn.textContent = 'Remove';
  removeBtn.addEventListener('click', () => removeExtension(ext.name));
  actions.appendChild(removeBtn);

  card.appendChild(actions);
  return card;
}

function activateExtension(name) {
  apiFetch('/api/extensions/' + encodeURIComponent(name) + '/activate', { method: 'POST' })
    .then((res) => {
      if (!res.success) {
        addMessage('system', 'Activate failed: ' + res.message);
      }
      loadExtensions();
    })
    .catch((err) => addMessage('system', 'Activate failed: ' + err.message));
}

function removeExtension(name) {
  apiFetch('/api/extensions/' + encodeURIComponent(name) + '/remove', { method: 'POST' })
    .then((res) => {
      if (!res.success) {
        addMessage('system', 'Remove failed: ' + res.message);
      }
      loadExtensions();
    })
    .catch((err) => addMessage('system', 'Remove failed: ' + err.message));
}

// --- Jobs ---

function loadJobs() {
  Promise.all([
    apiFetch('/api/jobs/summary'),
    apiFetch('/api/jobs'),
  ]).then(([summary, jobList]) => {
    renderJobsSummary(summary);
    renderJobsList(jobList.jobs);
  }).catch(() => {});
}

function renderJobsSummary(s) {
  document.getElementById('jobs-summary').innerHTML = ''
    + summaryCard('Total', s.total, '')
    + summaryCard('In Progress', s.in_progress, 'active')
    + summaryCard('Completed', s.completed, 'completed')
    + summaryCard('Failed', s.failed, 'failed')
    + summaryCard('Stuck', s.stuck, 'stuck');
}

function summaryCard(label, count, cls) {
  return '<div class="summary-card ' + cls + '">'
    + '<div class="count">' + count + '</div>'
    + '<div class="label">' + label + '</div>'
    + '</div>';
}

function renderJobsList(jobs) {
  const tbody = document.getElementById('jobs-tbody');
  const empty = document.getElementById('jobs-empty');

  if (jobs.length === 0) {
    tbody.innerHTML = '';
    empty.style.display = 'block';
    return;
  }

  empty.style.display = 'none';
  tbody.innerHTML = jobs.map((job) => {
    const shortId = job.id.substring(0, 8);
    const stateClass = job.state.replace(' ', '_');
    const cancelBtn = (job.state === 'pending' || job.state === 'in_progress')
      ? '<button class="btn-cancel" onclick="cancelJob(\'' + job.id + '\')">Cancel</button>'
      : '';
    return '<tr>'
      + '<td title="' + escapeHtml(job.id) + '">' + shortId + '</td>'
      + '<td>' + escapeHtml(job.title) + '</td>'
      + '<td><span class="badge ' + stateClass + '">' + escapeHtml(job.state) + '</span></td>'
      + '<td>' + formatDate(job.created_at) + '</td>'
      + '<td>' + cancelBtn + '</td>'
      + '</tr>';
  }).join('');
}

function cancelJob(jobId) {
  apiFetch('/api/jobs/' + jobId + '/cancel', { method: 'POST' })
    .then(() => loadJobs())
    .catch((err) => {
      addMessage('system', 'Failed to cancel job: ' + err.message);
    });
}

// --- Utilities ---

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function formatDate(isoString) {
  if (!isoString) return '-';
  const d = new Date(isoString);
  return d.toLocaleString();
}
