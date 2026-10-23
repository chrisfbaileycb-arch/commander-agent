// Agent Commander HUD. All data is rendered through textContent; nothing from the API is parsed as HTML.
(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const POLL_MS = 2500;

  let key = '';
  try {
    key = sessionStorage.getItem('commander_key') || '';
  } catch {
    /* storage unavailable: the key lives in memory only */
  }
  let timer = null;
  let inflight = false;

  function el(tag, props, ...kids) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(props || {})) {
      if (k === 'class') node.className = v;
      else if (k === 'text') node.textContent = v;
      else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
      else node.setAttribute(k, v);
    }
    for (const kid of kids) if (kid) node.append(kid);
    return node;
  }

  async function api(path, init) {
    const res = await fetch(path, {
      ...init,
      headers: { authorization: 'Bearer ' + key, 'content-type': 'application/json' },
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw Object.assign(new Error(body.message || res.statusText), { status: res.status });
    return body;
  }

  function setLink(state, text) {
    const link = $('link');
    link.className = 'link ' + state;
    link.textContent = text;
  }

  function renderTiles(m) {
    $('t-agents').textContent = String(m.activeAgents);
    const c = m.missions;
    $('t-missions').textContent = `${c.active} active · ${c.paused} paused · ${c.quarantined} quarantined · ${c.completed} done`;
    $('t-burn').textContent = String(m.spend.creditsLastMinute);
    $('t-spend').textContent = `cr/min · ${m.spend.creditsLastHour}/h · balance ${m.spend.balance} · ${m.spend.tokensSaved} tokens pruned`;
    $('t-err').textContent = String(m.errorVelocity.perMinute);
    $('t-err-sub').textContent = `errors/min · ${m.errorVelocity.last10Min} in last 10 min`;
    $('t-appr').textContent = String(m.stagedApprovals);
    $('tile-appr').classList.toggle('alert', m.stagedApprovals > 0);
  }

  async function decide(id, decision, note) {
    try {
      await api('/v1/operator/approvals/' + encodeURIComponent(id) + '/decision', {
        method: 'POST',
        body: JSON.stringify({ decision, note: note || undefined }),
      });
    } catch (err) {
      setLink('fault', 'DECISION FAILED: ' + err.message);
    }
    refresh();
  }

  function approvalCard(a) {
    const noteInput = el('input', { type: 'text', maxlength: '400', placeholder: 'Redirect note', 'aria-label': 'Redirect note' });
    const note = el(
      'div',
      { class: 'note' },
      noteInput,
      el('button', { class: 'btn-warn', type: 'button', text: 'Send redirect', onclick: () => decide(a.id, 'redirect', noteInput.value) }),
    );
    return el(
      'article',
      { class: 'card pending' },
      el(
        'div',
        { class: 'head' },
        el('span', { class: 'badge s-pending', text: a.kind === 'quarantine' ? 'QUARANTINE' : 'STAGED' }),
        el('span', { class: 'title', text: `${a.mission || ''} · ${a.step || ''}` }),
      ),
      el('div', { class: 'label', text: 'Attempted' }),
      el('pre', { text: a.incident }),
      el('div', { class: 'label', text: 'Reason' }),
      el('pre', { text: a.reason }),
      el(
        'div',
        { class: 'actions' },
        el('button', { class: 'btn-ok', type: 'button', text: 'Authorize', onclick: () => decide(a.id, 'authorize') }),
        el('button', { class: 'btn-warn', type: 'button', text: 'Redirect', onclick: () => { note.classList.toggle('open'); noteInput.focus(); } }),
        el('button', { class: 'btn-bad', type: 'button', text: 'Kill', onclick: () => decide(a.id, 'kill') }),
      ),
      note,
    );
  }

  function missionCard(m) {
    const ladder = el('div', { class: 'ladder' });
    for (const s of m.steps) {
      const tries = s.attempts.length ? ` ×${s.attempts.length}` : '';
      ladder.append(el('span', { class: 'chip s-' + s.status, text: `${s.index + 1}. ${s.title} · ${s.status}${tries}` }));
    }
    return el(
      'article',
      { class: 'card' },
      el(
        'div',
        { class: 'head' },
        el('span', { class: 'badge s-' + m.status, text: m.status.toUpperCase() }),
        el('span', { class: 'title', text: m.title }),
        el('span', { class: 'sm', text: m.id }),
      ),
      ladder,
    );
  }

  // Rebuild only when the content changed, so a half-typed redirect note survives the poll.
  function fill(container, items, build, emptyText, sig) {
    if (container.dataset.sig === sig) return;
    container.dataset.sig = sig;
    container.replaceChildren();
    if (!items.length) container.append(el('p', { class: 'empty', text: emptyText }));
    else for (const it of items) container.append(build(it));
  }

  function render(o) {
    renderTiles(o.metrics);
    fill($('approvals'), o.approvals, approvalCard, 'Nothing staged.', o.approvals.map((a) => a.id).join(','));
    fill($('missions'), o.missions, missionCard, 'No missions.', JSON.stringify(o.missions));
    const audit = $('audit');
    audit.replaceChildren();
    for (const r of o.audit) {
      audit.append(el('li', {}, el('span', { class: 't', text: r.type }), document.createTextNode(`  #${r.seq}  ${r.ts}  ${JSON.stringify(r.data)}`)));
    }
  }

  async function refresh() {
    if (!key || inflight) return;
    inflight = true;
    try {
      render(await api('/v1/operator/overview'));
      setLink('live', 'LIVE');
    } catch (err) {
      if (err.status === 401 || err.status === 403) {
        stop();
        setLink('fault', 'KEY REJECTED');
      } else setLink('fault', 'LINK FAULT');
    } finally {
      inflight = false;
    }
  }

  function start() {
    stop();
    refresh();
    timer = setInterval(() => {
      if (!document.hidden) refresh();
    }, POLL_MS);
  }
  function stop() {
    if (timer) clearInterval(timer);
    timer = null;
  }

  $('connect').addEventListener('submit', (e) => {
    e.preventDefault();
    key = $('key').value.trim();
    $('key').value = '';
    try {
      sessionStorage.setItem('commander_key', key);
    } catch {
      /* ignore */
    }
    start();
  });

  if (key) start();
})();
