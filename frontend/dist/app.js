const state = {
  bootstrap: null,
  busy: false,
};

function api() {
  const app = window.go?.main?.App;
  if (!app) {
    throw new Error('Wails API 尚未注入');
  }
  return app;
}

async function refresh() {
  state.bootstrap = await api().GetBootstrap();
  render();
}

function appendLogEntry(entry) {
  if (!state.bootstrap || !entry) return;
  const logs = Array.isArray(state.bootstrap.logs) ? state.bootstrap.logs : [];
  logs.push(entry);
  if (logs.length > 200) {
    logs.splice(0, logs.length - 200);
  }
  state.bootstrap.logs = logs;
  renderLogs(state.bootstrap);
}

function render() {
  const data = state.bootstrap;
  if (!data) return;

  renderSession(data);
  renderSelectors(data);
  renderServerList(data);
  renderRuleList(data);
  renderAssets(data);
  renderDNSWatch(data);
  renderLogs(data);
}

function renderSession(data) {
  const badge = document.getElementById('sessionBadge');
  const message = document.getElementById('sessionMessage');
  const hint = document.getElementById('selectionHint');
  const startBtn = document.getElementById('startBtn');
  const session = data.session;
  badge.textContent = session.message || '未启动';
  badge.className = 'session-badge ' + (session.running ? 'running' : session.missingAssets?.length ? 'error' : 'idle');
  if (startBtn) {
    startBtn.textContent = session.running ? '重新启动' : '启动';
  }
  message.textContent = session.running
    ? `${session.message}，启动时间 ${session.startedAt || '-'}。`
    : session.warnings?.length
      ? session.warnings.join('；')
      : '选择一个 SOCKS 服务器和一个规则集，然后启动。';
  hint.textContent = `服务器 ${data.config.selection.serverId || '未选'} / 规则 ${data.config.selection.ruleSetId || '未选'}`;
}

function renderSelectors(data) {
  const serverSelect = document.getElementById('serverSelect');
  const ruleSelect = document.getElementById('ruleSelect');
  serverSelect.innerHTML = ['<option value="">请选择服务器</option>']
    .concat(data.config.servers.map(server => `<option value="${server.id}" ${selected(server.id === data.config.selection.serverId)}>${escapeHtml(server.name)} (${escapeHtml(server.host)}:${server.port})</option>`))
    .join('');
  ruleSelect.innerHTML = ['<option value="">请选择规则集</option>']
    .concat(data.ruleSets.map(rule => `<option value="${rule.id}" ${selected(rule.id === data.config.selection.ruleSetId)}>${escapeHtml(ruleDisplayName(rule))}</option>`))
    .join('');
}

function renderServerList(data) {
  const list = document.getElementById('serverList');
  if (!data.config.servers.length) {
    list.innerHTML = '<div class="empty">还没有服务器配置。</div>';
    return;
  }
  list.innerHTML = data.config.servers.map(server => `
    <article class="list-item ${server.id === data.config.selection.serverId ? 'selected' : ''}">
      <div class="item-top">
        <strong>${escapeHtml(server.name)}</strong>
        <div class="button-row compact">
          <button class="ghost" data-action="edit-server" data-id="${server.id}">编辑</button>
          <button class="ghost" data-action="select-server" data-id="${server.id}">设为当前</button>
          <button class="danger" data-action="delete-server" data-id="${server.id}">删除</button>
        </div>
      </div>
      <div class="item-meta">
        <span class="tag">${escapeHtml(server.group || 'Default')}</span>
        <span>${escapeHtml(server.host)}:${server.port}</span>
        <span>SOCKS ${escapeHtml(server.version || '5')}</span>
      </div>
      <div class="muted">${escapeHtml(server.notes || '无备注')}</div>
    </article>
  `).join('');
}

function renderRuleList(data) {
  const list = document.getElementById('ruleList');
  if (!data.ruleSets.length) {
    list.innerHTML = '<div class="empty">还没有规则集。</div>';
    return;
  }
  list.innerHTML = data.ruleSets.map(rule => `
    <article class="list-item ${rule.id === data.config.selection.ruleSetId ? 'selected' : ''}">
      <div class="item-top">
        <strong>${escapeHtml(rule.name)}</strong>
        <div class="button-row compact">
          <button class="ghost" data-action="select-rule" data-id="${rule.id}">设为当前</button>
          <button class="ghost" data-action="edit-rule" data-id="${rule.id}">编辑</button>
          <button class="danger" data-action="delete-rule" data-id="${rule.id}">删除</button>
        </div>
      </div>
      <div class="item-meta">
        ${rule.tag ? `<span class="tag">${escapeHtml(rule.tag)}</span>` : ''}
        <span>${rule.include.length} 条包含</span>
        <span>${rule.exclude.length} 条绕过</span>
        <span>${(rule.domainRules || []).length} 条域名</span>
      </div>
      <div class="muted">${escapeHtml(rule.description || '无描述')}</div>
    </article>
  `).join('');
}

function renderAssets(data) {
  const list = document.getElementById('assetList');
  list.innerHTML = data.assets.map(asset => `
    <article class="asset-card ${asset.status}">
      <strong>${escapeHtml(asset.name)}</strong>
      <p>${escapeHtml(asset.message)}</p>
      <small>${escapeHtml(asset.path || '未找到')}</small>
    </article>
  `).join('');
}

function renderDNSWatch(data) {
  const watch = data.dnsWatch || {};
  const domains = Array.isArray(watch.domains) ? watch.domains : [];
  setValue('dnsWatchToggle', watch.enabled);

  const summary = watch.capturing ? '监听中' : (watch.enabled ? '已开启' : '未开启');
  setText('dnsWatchSummary', summary);
  setText('dnsWatchStatus', watch.message || '未开启 DNS Client ETW 抓取');
  setText('dnsWatchCount', `${domains.length} 条`);

  if (watch.channelEnabled === false && watch.enabled !== true) {
    setText('dnsWatchHint', 'DNS Client ETW 通道未开启，请先启用 Microsoft-Windows-DNS-Client/Operational。');
  } else if (watch.capturing) {
    setText('dnsWatchHint', '监听中：正在从 DNS Client ETW 事件实时提取 QueryName。');
  } else {
    setText('dnsWatchHint', '开启时会先检查 ETW 通道、服务状态，再执行 flushdns 后开始抓取。');
  }

  const list = document.getElementById('dnsWatchList');
  if (!domains.length) {
    list.innerHTML = '<div class="empty">暂无域名记录。</div>';
    return;
  }
  list.innerHTML = domains.slice().reverse().map(domain => `
    <article class="dns-domain-item">${escapeHtml(domain)}</article>
  `).join('');
}

function renderLogs(data) {
  const list = document.getElementById('logList');
  if (!data.logs.length) {
    list.innerHTML = '<div class="empty">暂无日志。</div>';
    return;
  }
  list.innerHTML = data.logs.slice().reverse().map(entry => `
    <article class="log-entry">
      <span>${escapeHtml(entry.time)}</span>
      <span class="level">${escapeHtml(entry.level)}</span>
      <span>${escapeHtml(entry.message)}</span>
    </article>
  `).join('');
}

function selected(value) {
  return value ? 'selected' : '';
}

function setValue(id, value) {
  const el = document.getElementById(id);
  if (!el) return;
  if (el.type === 'checkbox') {
    el.checked = Boolean(value);
  } else {
    el.value = value ?? '';
  }
}

function setText(id, text) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = text;
}

function setRuleSaveStatus(text = '') {
  setText('ruleSaveStatus', text);
}

function setBusy(active, text = '') {
  state.busy = Boolean(active);
  const overlay = document.getElementById('busyOverlay');
  const busyText = document.getElementById('busyText');

  if (busyText && text) {
    busyText.textContent = text;
  }
  if (overlay) {
    overlay.hidden = !state.busy;
  }
  document.body.classList.toggle('busy', state.busy);

  const controls = document.querySelectorAll('button, input, textarea, select');
  controls.forEach(control => {
    if (state.busy) {
      if (!control.dataset.busyPrevDisabled) {
        control.dataset.busyPrevDisabled = control.disabled ? '1' : '0';
      }
      control.disabled = true;
      return;
    }

    const prev = control.dataset.busyPrevDisabled;
    if (prev) {
      control.disabled = prev === '1';
      delete control.dataset.busyPrevDisabled;
    }
  });
}

async function withBusy(text, task) {
  if (state.busy) return;
  setBusy(true, text);
  try {
    await task();
  } catch (error) {
    console.error(error);
    alert(error?.message || String(error));
  } finally {
    setBusy(false);
  }
}

function updateDNSHints(proxy) {
  if (proxy?.filterDNS) {
    if (proxy?.dnsDomainOnly) {
      setText('processDnsHint', '进程 DNS 重定向已开启：处理 svchost 且命中“域名规则”的 DNS 请求。');
    } else if (proxy?.handleOnlyDns) {
      setText('processDnsHint', '进程 DNS 重定向已开启：仅命中规则进程会被重定向。');
    } else {
      setText('processDnsHint', '进程 DNS 重定向已开启：命中规则进程 + DNS Client(svchost) 会被重定向。');
    }
  } else {
    setText('processDnsHint', '进程 DNS 重定向未开启：命中规则的进程将使用系统 DNS。');
  }
}

function syncDNSClientDomainOnlyControl() {
  const dnsClientEl = document.getElementById('proxyDnsOnly');
  const domainOnlyEl = document.getElementById('proxyDnsDomainOnly');
  if (!dnsClientEl || !domainOnlyEl) return;

  const dnsClientEnabled = Boolean(dnsClientEl.checked);
  domainOnlyEl.disabled = !dnsClientEnabled;
  if (!dnsClientEnabled) {
    domainOnlyEl.checked = false;
  }
}

function defaultRuleProxy() {
  const source = state.bootstrap?.config?.proxy || {};
  return {
    filterTCP: source.filterTCP ?? true,
    filterUDP: source.filterUDP ?? true,
    filterDNS: source.filterDNS ?? true,
    handleOnlyDns: source.handleOnlyDns ?? false,
    dnsProxy: source.dnsProxy ?? false,
    dnsDomainOnly: source.dnsDomainOnly ?? false,
    filterLoopback: source.filterLoopback ?? false,
    filterIntranet: source.filterIntranet ?? true,
    filterParent: source.filterParent ?? false,
    filterICMP: source.filterICMP ?? false,
    remoteDns: source.remoteDns || '1.1.1.1:53',
    icmpDelay: Number(source.icmpDelay ?? 10),
  };
}

function proxyFromForm() {
  const dnsClientEnabled = document.getElementById('proxyDnsOnly').checked;
  const dnsClientDomainOnlyEnabled = dnsClientEnabled && document.getElementById('proxyDnsDomainOnly').checked;
  return {
    filterTCP: document.getElementById('proxyFilterTCP').checked,
    filterUDP: document.getElementById('proxyFilterUDP').checked,
    filterDNS: document.getElementById('proxyFilterDNS').checked,
    handleOnlyDns: !dnsClientEnabled,
    dnsProxy: document.getElementById('proxyDnsThrough').checked,
    dnsDomainOnly: dnsClientDomainOnlyEnabled,
    filterLoopback: document.getElementById('proxyFilterLoopback').checked,
    filterIntranet: document.getElementById('proxyFilterIntranet').checked,
    filterParent: document.getElementById('proxyFilterParent').checked,
    filterICMP: document.getElementById('proxyFilterICMP').checked,
    remoteDns: document.getElementById('proxyRemoteDns').value,
    icmpDelay: Number(document.getElementById('proxyICMPDelay').value || 0),
  };
}

function setRuleProxyForm(proxy) {
  const source = proxy || defaultRuleProxy();
  setValue('proxyRemoteDns', source.remoteDns ?? '1.1.1.1:53');
  setValue('proxyICMPDelay', source.icmpDelay ?? 10);
  setValue('proxyFilterTCP', source.filterTCP);
  setValue('proxyFilterUDP', source.filterUDP);
  setValue('proxyFilterDNS', source.filterDNS);
  setValue('proxyDnsOnly', !source.handleOnlyDns);
  setValue('proxyDnsThrough', source.dnsProxy);
  setValue('proxyDnsDomainOnly', source.dnsDomainOnly);
  setValue('proxyFilterLoopback', source.filterLoopback);
  setValue('proxyFilterIntranet', source.filterIntranet);
  setValue('proxyFilterParent', source.filterParent);
  setValue('proxyFilterICMP', source.filterICMP);
  syncDNSClientDomainOnlyControl();
  updateDNSHints(proxyFromForm());
}

function serverFromForm() {
  return {
    id: document.getElementById('serverId').value,
    name: document.getElementById('serverName').value,
    host: document.getElementById('serverHost').value,
    port: Number(document.getElementById('serverPort').value || 0),
    username: document.getElementById('serverUser').value,
    password: document.getElementById('serverPass').value,
    group: document.getElementById('serverGroup').value,
    version: document.getElementById('serverVersion').value || '5',
    notes: document.getElementById('serverNotes').value,
    remoteHost: '',
  };
}

function ruleFromForm() {
  const id = document.getElementById('ruleId').value;
  const existing = id ? findRule(id) : null;
  return {
    id,
    name: document.getElementById('ruleName').value,
    description: document.getElementById('ruleDescription').value,
    include: lines(document.getElementById('ruleInclude').value),
    exclude: lines(document.getElementById('ruleExclude').value),
    domainRules: lines(document.getElementById('ruleDomains').value),
    proxy: proxyFromForm(),
    sourcePath: existing?.sourcePath || 'custom',
  };
}

function lines(value) {
  return value.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
}

function mergeUniqueLines(existingText, incomingLines) {
  const merged = [];
  const seen = new Set();
  for (const line of lines(existingText).concat(incomingLines || [])) {
    const normalized = String(line || '').trim();
    if (!normalized || seen.has(normalized)) continue;
    seen.add(normalized);
    merged.push(normalized);
  }
  return merged.join('\n');
}

function appendDnsWatchDomain(domain) {
  if (!state.bootstrap || !domain) return;
  const watch = state.bootstrap.dnsWatch || {};
  const list = Array.isArray(watch.domains) ? watch.domains.slice() : [];
  const normalized = String(domain || '').trim().toLowerCase();
  if (!normalized || list.includes(normalized)) {
    return;
  }
  list.push(normalized);
  if (list.length > 200) {
    list.splice(0, list.length - 200);
  }
  state.bootstrap.dnsWatch = { ...watch, domains: list };
  renderDNSWatch(state.bootstrap);
}

async function scanIncludeRulesFromFolder() {
  const imported = await api().ScanRuleIncludeExecutables();
  if (!Array.isArray(imported) || imported.length === 0) {
    return;
  }

  const includeEl = document.getElementById('ruleInclude');
  includeEl.value = mergeUniqueLines(includeEl.value, imported);
  alert(`已导入 ${imported.length} 条可执行文件规则。`);
}

function resetServerForm() {
  ['serverId','serverName','serverHost','serverPort','serverUser','serverPass','serverGroup','serverNotes'].forEach(id => setValue(id, ''));
  setValue('serverVersion', '5');
}

function resetRuleForm() {
  ['ruleId','ruleName','ruleDescription','ruleInclude','ruleExclude','ruleDomains'].forEach(id => setValue(id, ''));
  setRuleProxyForm(defaultRuleProxy());
  setRuleSaveStatus('');
}

function findServer(id) {
  return state.bootstrap?.config?.servers?.find(server => server.id === id);
}

function findRule(id) {
  return state.bootstrap?.ruleSets?.find(rule => rule.id === id);
}

function fillRuleForm(rule) {
  if (!rule) return;
  setValue('ruleId', rule.id);
  setValue('ruleName', rule.name);
  setValue('ruleDescription', rule.description || '');
  setValue('ruleInclude', (rule.include || []).join('\n'));
  setValue('ruleExclude', (rule.exclude || []).join('\n'));
  setValue('ruleDomains', (rule.domainRules || []).join('\n'));
  setRuleProxyForm(rule.proxy || defaultRuleProxy());
}

function ruleDisplayName(rule) {
  if (rule?.tag) {
    return `[${rule.tag}] ${rule.name}`;
  }
  return rule?.name || '';
}

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;');
}

async function saveSelection(partial) {
  if (state.busy) return;
  const selection = { ...state.bootstrap.config.selection, ...partial };
  state.bootstrap = await api().SaveSelection(selection);
  render();
}

async function handleAction(event) {
  if (state.busy) return;
  const button = event.target.closest('button[data-action]');
  if (!button) return;
  const id = button.dataset.id;
  const action = button.dataset.action;

  if (action === 'edit-server') {
    const server = findServer(id);
    if (!server) return;
    setValue('serverId', server.id);
    setValue('serverName', server.name);
    setValue('serverHost', server.host);
    setValue('serverPort', server.port);
    setValue('serverUser', server.username);
    setValue('serverPass', server.password);
    setValue('serverGroup', server.group);
    setValue('serverVersion', server.version || '5');
    setValue('serverNotes', server.notes || '');
  }

  if (action === 'select-server') {
    await saveSelection({ serverId: id });
  }

  if (action === 'delete-server' && confirm('删除这个服务器配置？')) {
    state.bootstrap = await api().DeleteServer(id);
    render();
  }

  if (action === 'edit-rule') {
    const rule = findRule(id);
    if (!rule) return;
    fillRuleForm(rule);
    setRuleSaveStatus('');
  }

  if (action === 'select-rule') {
    await saveSelection({ ruleSetId: id });
    setRuleSaveStatus('');
  }

  if (action === 'delete-rule' && confirm('删除这个规则集？')) {
    state.bootstrap = await api().DeleteRuleSet(id);
    render();
  }
}

async function main() {
  setBusy(false);
  document.body.addEventListener('click', handleAction);
  document.getElementById('serverSelect').addEventListener('change', event => saveSelection({ serverId: event.target.value }));
  document.getElementById('ruleSelect').addEventListener('change', event => saveSelection({ ruleSetId: event.target.value }));

  const refreshHintPreview = () => {
    syncDNSClientDomainOnlyControl();
    updateDNSHints(proxyFromForm());
  };
  document.getElementById('proxyFilterDNS').addEventListener('change', refreshHintPreview);
  document.getElementById('proxyDnsOnly').addEventListener('change', refreshHintPreview);
  document.getElementById('proxyDnsDomainOnly').addEventListener('change', refreshHintPreview);

  document.getElementById('serverForm').addEventListener('submit', async event => {
    event.preventDefault();
    await withBusy('正在保存服务器...', async () => {
      state.bootstrap = await api().UpsertServer(serverFromForm());
      resetServerForm();
      render();
    });
  });
  document.getElementById('ruleForm').addEventListener('submit', async event => {
    event.preventDefault();
    const proxy = proxyFromForm();
    if (!proxy.filterTCP && !proxy.filterUDP && !proxy.filterDNS) {
      alert('请在当前规则集中至少启用一种拦截（TCP / UDP / DNS），否则启动后不会接管流量。');
      return;
    }
    await withBusy('正在保存规则集...', async () => {
      state.bootstrap = await api().UpsertRuleSet(ruleFromForm());
      const selectedRuleID = state.bootstrap?.config?.selection?.ruleSetId;
      const savedRule = selectedRuleID ? findRule(selectedRuleID) : null;
      if (savedRule) {
        fillRuleForm(savedRule);
      }
      setRuleSaveStatus('规则集已保存');
      render();
    });
  });
  document.getElementById('scanRuleIncludeBtn').addEventListener('click', async () => {
    await withBusy('正在扫描目录...', scanIncludeRulesFromFolder);
  });

  document.getElementById('startBtn').addEventListener('click', async () => {
    const running = Boolean(state.bootstrap?.session?.running);
    const actionText = running ? '正在重新启动强制代理...' : '正在启动强制代理...';
    await withBusy(actionText, async () => {
      state.bootstrap = await api().StartSession();
      render();
    });
  });
  document.getElementById('stopBtn').addEventListener('click', async () => {
    await withBusy('正在停止强制代理...', async () => {
      state.bootstrap = await api().StopSession();
      render();
    });
  });
  document.getElementById('newServerBtn').addEventListener('click', resetServerForm);
  document.getElementById('newRuleBtn').addEventListener('click', () => {
    resetRuleForm();
    setRuleSaveStatus('');
  });
  document.getElementById('resetServerBtn').addEventListener('click', resetServerForm);
  document.getElementById('resetRuleBtn').addEventListener('click', () => {
    resetRuleForm();
    setRuleSaveStatus('');
  });
  document.getElementById('openRuntimeBtn').addEventListener('click', () => api().OpenRuntimeDir());
  document.getElementById('openDataBtn').addEventListener('click', () => api().OpenDataDir());
  document.getElementById('dnsWatchToggle').addEventListener('change', async event => {
    const enabled = Boolean(event.target.checked);
    const text = enabled ? '正在开启 DNS Client ETW 抓取...' : '正在关闭 DNS Client ETW 抓取...';
    await withBusy(text, async () => {
      let status = null;
      try {
        status = await api().SetDNSCaptureEnabled(enabled);
      } catch (error) {
        alert(error?.message || String(error));
        status = await api().GetDNSCaptureState();
      }
      if (state.bootstrap) {
        state.bootstrap.dnsWatch = status;
        renderDNSWatch(state.bootstrap);
      }
    });
  });

  if (window.runtime?.EventsOn) {
    window.runtime.EventsOn('netch:log', entry => {
      appendLogEntry(entry);
    });
    window.runtime.EventsOn('netch:dns-query', domain => {
      appendDnsWatchDomain(domain);
    });
  }

  await refresh();
  resetRuleForm();
}

main().catch(error => {
  setBusy(false);
  console.error(error);
  alert(error.message || String(error));
});





