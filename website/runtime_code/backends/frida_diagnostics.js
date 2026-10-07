// Loaded before the Java bridge so bridge initialization can be diagnosed too.
const runtimeDebug = (() => {
  let stopped = false, ready = false, mainPending = 0, mainProbe = 'disabled';
  const active = new Map();
  function emit(data) { if (!stopped) { try { send({runtime_diagnostic: data}); } catch (_) {} } }
  function mark(stage) { emit({kind: 'checkpoint', stage}); }
  const timer = setInterval(() => {
    emit({kind: 'heartbeat', ready, main_pending_ms: mainPending ? Date.now() - mainPending : 0,
      main_probe: mainProbe, active_hooks: Array.from(active.values()).slice(0, 16)});
    if (ready && mainProbe === 'enabled' && !mainPending) {
      mainPending = Date.now();
      // One outstanding callback at most. Never wait synchronously for the app.
      try { Java.scheduleOnMainThread(() => { mainPending = 0; }); }
      catch (error) { mainProbe = 'failed'; mainPending = 0; emit({kind: 'error', error: 'Main-thread probe: ' + error}); }
    }
  }, 2000);
  mark('agent.bootstrap.enter');
  return {
    mark,
    ready(java) { ready = true; mainProbe = java ? 'enabled' : 'disabled'; emit({kind: 'ready'}); },
    enter(name) {
      const id = Process.getCurrentThreadId();
      const previous = active.get(id);
      active.set(id, {thread: id, hook: name, entered_ms: Date.now()});
      return {id, previous};
    },
    leave(token) { if (token.previous) active.set(token.id, token.previous); else active.delete(token.id); },
    stop() { emit({kind: 'stopped'}); stopped = true; clearInterval(timer); }
  };
})();
