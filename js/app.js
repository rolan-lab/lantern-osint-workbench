'use strict';
/* Lantern — bootstrap. */
(function boot() {
  App.load();
  // Persist the starter case immediately so its id (and the user's first edits) survive a restart.
  try { if (!localStorage.getItem(STORE_KEY)) App.saveNow(); } catch { /* storage unavailable */ }
  App.applyTheme();
  App.renderChrome();

  $('#caseSelect').addEventListener('change', (e) => App.switchCase(e.target.value));
  $('#newCaseBtn').addEventListener('click', () => App.createCase());
  $('#modeBadge').addEventListener('click', () => App.toggleActive());
  $('#themeBtn').addEventListener('click', () => App.cycleTheme());
  $('#quickForm').addEventListener('submit', (e) => {
    e.preventDefault();
    const v = $('#quickInput').value.trim();
    if (!v) return;
    App.go('pivot', { q: v });
    $('#quickInput').select();
  });
  const closeNav = () => { $('#sidebar').classList.remove('open'); $('#scrim').classList.remove('open'); };
  $('#navToggle').addEventListener('click', () => { $('#sidebar').classList.toggle('open'); $('#scrim').classList.toggle('open'); });
  $('#scrim').addEventListener('click', closeNav);

  document.addEventListener('keydown', (e) => {
    if (e.key === '/' && !e.ctrlKey && !e.metaKey && !e.target.closest('input,textarea,select,[contenteditable]') && !$('.modal-backdrop')) {
      e.preventDefault(); $('#quickInput').focus(); $('#quickInput').select();
    }
  });

  const clock = () => { const s = fmtUTC(nowISO()); $('#utcClock').textContent = `${s.slice(0, 10)} ${s.slice(11, 19)} UTC`; };
  clock(); setInterval(clock, 1000);

  window.addEventListener('hashchange', () => App.onHash());
  window.addEventListener('beforeunload', () => App.saveNow());
  window.addEventListener('storage', (e) => {
    if (e.key !== STORE_KEY || !e.newValue) return;
    try { App.state = migrate(JSON.parse(e.newValue)); App.renderChrome(); App.refresh(); toast('Synced changes from another tab'); } catch { /* ignore */ }
  });

  App.onHash();
})();
