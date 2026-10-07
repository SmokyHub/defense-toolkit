"""Opt-in diagnostics independent of Frida RPC, SQLite and the event consumer."""
from collections import deque
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import wraps
import html
from importlib import metadata as package_metadata
import json
from pathlib import Path
import queue
import platform
import sys
import threading
import time
import traceback
import uuid


_active = None


@contextmanager
def phase(name):
    monitor = _active
    token = monitor.begin(name) if monitor else None
    try:
        yield
    except BaseException as error:
        if monitor:
            # Callers may recover (e.g. probing a server before starting it).
            monitor.record('host.operation_error', stage=name, error=str(error))
        raise
    finally:
        if monitor:
            monitor.end(token)


def operation(name):
    def decorate(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            with phase(name):
                return fn(*args, **kwargs)
        return wrapped
    return decorate


def target(pid, payload):
    # Frida callbacks must not wait for disk, the report lock or a target RPC.
    monitor = _active
    if monitor:
        try:
            monitor.inbox.put_nowait((pid, payload))
        except queue.Full:
            monitor.dropped += 1
            if isinstance(payload,dict) and payload.get('kind') in ('heartbeat','ready','detached','error','stopped'):
                # Drop an old checkpoint so lifecycle/heartbeat state survives a
                # large hook-install burst. Never block the Frida callback.
                try:monitor.inbox.get_nowait();monitor.inbox.put_nowait((pid,payload))
                except (queue.Empty,queue.Full):pass


class Diagnostics:
    def __init__(self, root, metadata, threshold=10, interval=1):
        self.root = Path(root).resolve() / ('debug-' + datetime.now().strftime('%Y%m%d-%H%M%S-') + uuid.uuid4().hex[:6])
        self.root.mkdir(parents=True)
        self.report = self.root / 'report.html'
        self.lock = threading.RLock()
        self.inbox = queue.Queue(maxsize=512)
        self.dropped = 0
        self.history = deque(maxlen=100)
        self.phases = {}
        self.targets = {}
        self.metadata = metadata
        self.metadata.update({'host': platform.platform(), 'python': sys.version.split()[0]})
        self.metadata['packages'] = {}
        for name in ('frida', 'frida-tools'):
            try:self.metadata['packages'][name] = package_metadata.version(name)
            except package_metadata.PackageNotFoundError:self.metadata['packages'][name] = 'not installed'
        self.incidents = deque(maxlen=20)
        self.threshold = threshold
        self.interval = interval
        self.finished = threading.Event()
        self.last_warning = None
        self.failure = None
        self.outcome = None
        self.stream = (self.root / 'checkpoints.jsonl').open('a', encoding='utf-8')
        self.thread = threading.Thread(target=self._watch, name='runtime-diagnostics', daemon=True)

    def start(self):
        global _active
        _active = self
        self.record('debug.started', **self.metadata)
        self.render()
        print(f'[debug] Open {self.report.as_uri()} — updates every 2 seconds', file=sys.stderr, flush=True)
        self.thread.start()
        return self

    def open_browser(self):
        import webbrowser
        threading.Thread(target=webbrowser.open, args=(self.report.as_uri(),), daemon=True).start()

    def record(self, kind, **data):
        with self.lock:
            row = {'time': datetime.now(timezone.utc).isoformat(), 'kind': kind, **data}
            self.history.append(row)
            self.stream.write(json.dumps(row) + '\n')
            self.stream.flush()
            if kind in ('host.begin', 'target.checkpoint', 'target.error', 'target.detached', 'watchdog.warning'):
                label = data.get('stage') or data.get('summary') or data.get('error', '')
                if kind == 'target.detached':
                    label = f'PID {data["pid"]}: {label}'
                    if (data.get('crash') or {}).get('summary'):
                        label += '; crash: ' + data['crash']['summary'][:512]
                print(f'[debug] {kind}: {label}', file=sys.stderr, flush=True)
            if kind in ('host.error', 'target.error'):
                self.failure = data

    def begin(self, name):
        token = uuid.uuid4().hex
        with self.lock:
            self.phases[token] = {'stage': name, 'since': time.monotonic(), 'thread': threading.get_ident()}
            self.record('host.begin', stage=name)
        return token

    def end(self, token):
        with self.lock:
            stage = self.phases.pop(token, None)
            if stage:
                self.record('host.end', stage=stage['stage'], elapsed=round(time.monotonic()-stage['since'], 3))

    def consume(self, now=None):
        now = time.monotonic() if now is None else now
        for _ in range(512):
            try:
                pid, data = self.inbox.get_nowait()
            except queue.Empty:
                break
            with self.lock:
                if data.get('kind') == 'checkpoint' and data.get('stage') == 'agent.bootstrap.enter':
                    self.targets.pop(str(pid), None)
                state = self.targets.setdefault(str(pid), {'since': now, 'ready': False})
                kind = data.get('kind')
                if kind == 'checkpoint':
                    state['checkpoint'] = str(data.get('stage', 'unknown'))[:512]
                    if state['checkpoint'].startswith('java.'):
                        state['java_checkpoint'] = state['checkpoint']
                    state['checkpoint_time'] = now
                    self.record('target.checkpoint', pid=pid, stage=state['checkpoint'])
                elif kind == 'heartbeat':
                    state['heartbeat'] = now
                    if data.get('ready') is True:state['ready']=True
                    state['main_pending_ms'] = data.get('main_pending_ms', 0)
                    state['main_probe'] = data.get('main_probe', 'disabled')
                    state['active_hooks'] = data.get('active_hooks', [])
                elif kind == 'ready':
                    state['ready'] = True
                    state['heartbeat'] = now
                    self.record('target.ready', pid=pid)
                elif kind in ('error', 'detached', 'stopped'):
                    state[kind] = str(data.get('error', kind))[:4096]
                    extra = {}
                    if kind == 'detached':
                        state['crash'] = data.get('crash') or {}
                        extra['crash'] = state['crash']
                    self.record('target.' + kind, pid=pid, error=state[kind], **extra)

    def assess(self, now=None):
        now = time.monotonic() if now is None else now
        with self.lock:
            for pid, target_state in self.targets.items():
                if target_state.get('error'):
                    return 'AGENT_ERROR', f'PID {pid}: instrumentation reported an error: {target_state["error"]}'
                if target_state.get('detached') or target_state.get('stopped'):
                    continue
                checkpoint = target_state.get('checkpoint', 'no target checkpoint received')
                if not target_state['ready'] and now-target_state['since'] > self.threshold:
                    java = target_state.get('java_checkpoint', 'none')
                    return 'TARGET_STARTUP_STALLED', f'PID {pid}: instrumentation is not ready. Last Java checkpoint: {java}. Last target checkpoint: {checkpoint}'
                heartbeat = target_state.get('heartbeat')
                if target_state['ready'] and heartbeat is not None and now-heartbeat > self.threshold:
                    return 'AGENT_HEARTBEAT_MISSING', f'PID {pid}: no JavaScript heartbeat for {int(now-heartbeat)}s. The agent thread or transport may be blocked. Last checkpoint: {checkpoint}'
                if target_state.get('main_pending_ms', 0) > self.threshold*1000:
                    return 'ANDROID_MAIN_THREAD_STALLED', f'PID {pid}: JavaScript responds, but the Android main-thread probe has not returned for {int(target_state["main_pending_ms"]/1000)}s.'
            waiting = [v for v in self.phases.values() if now-v['since'] > self.threshold]
            if waiting:
                stage = max(waiting, key=lambda v:v['since'])
                return 'HOST_CALL_STALLED', f'Host waiting in {stage["stage"]} for {int(now-stage["since"])}s.'
            if self.failure:
                return 'ERROR_RECORDED', 'An error was recorded; inspect the last checkpoints below.'
            if self.targets and all(v.get('detached') or v.get('stopped') for v in self.targets.values()):
                if any(not v.get('stopped') for v in self.targets.values()):
                    reasons = []
                    for pid, state in list(self.targets.items())[:8]:
                        if state.get('detached'):
                            detail = f'PID {pid}: {state["detached"][:512]}'
                            if state.get('crash', {}).get('summary'):
                                detail += '; crash: ' + state['crash']['summary'][:512]
                            reasons.append(detail)
                    return 'TARGET_DISCONNECTED', 'No instrumented target remains connected. ' + ' | '.join(reasons)
                return 'STOPPED', 'The instrumented agents reported shutdown.'
            if self.targets and all(v['ready'] or v.get('detached') or v.get('stopped') for v in self.targets.values()):
                return 'RESPONDING', 'Instrumentation checkpoints are responding. This does not prove that every app thread is healthy.'
            return 'STARTING', 'Waiting for instrumentation readiness; host and target checkpoints appear below.'

    def render(self):
        with self.lock:
            code, summary = self.assess()
            if self.outcome and self.incidents:
                code, summary = self.incidents[-1]['code'], self.incidents[-1]['summary']
            snapshot = {'code': code, 'summary': summary, 'outcome': self.outcome, 'metadata': self.metadata,
                        'targets': self.targets, 'host_phases': list(self.phases.values()),
                        'dropped_diagnostics': self.dropped, 'incidents': list(self.incidents), 'recent_checkpoints': list(self.history)}
            guidance = {
                'HOST_CALL_STALLED': 'The named host operation has not returned. Check host-threads.txt for its Python call stack; a timeout cannot prove that target-side work stopped.',
                'TARGET_STARTUP_STALLED': 'Use the last target checkpoint: java.bridge.begin points to bridge initialization; java.perform.waiting means its callback has not entered; java.hook.install names the hook being installed. A checkpoint before a call does not prove that call is the root cause.',
                'AGENT_HEARTBEAT_MISSING': 'The agent event loop or transport stopped responding. Check active_hooks in the last heartbeat and the host stages. Missing heartbeats alone do not prove a deadlock.',
                'ANDROID_MAIN_THREAD_STALLED': 'The agent event loop is alive, but the scheduled Android main-thread callback has not run. Check active_hooks for callbacks still in flight. Normal long-running main-thread work can also trigger this warning.',
                'AGENT_ERROR': 'The agent returned an error. Its stack is retained in the checkpoint log and target state.',
                'TARGET_DISCONNECTED': 'process-terminated records process exit; connection-terminated records transport loss. Neither reason alone establishes why it happened. Any crash details Frida supplied are shown below; otherwise check the saved Logcat without the App only filter.',
            }.get(code, 'Keep this page open while reproducing the freeze. Diagnostics are opt-in and add timing overhead.')
            now = time.monotonic()
            target_rows = []
            crash_reports = []
            for pid, state in self.targets.items():
                heartbeat = f'{now-state["heartbeat"]:.1f}s ago' if 'heartbeat' in state else 'not received'
                hooks = ', '.join(str(hook.get('hook', '?')) for hook in state.get('active_hooks', [])) or 'none observed'
                cells = [pid, state.get('java_checkpoint', 'not used or not reached'), state.get('checkpoint', 'none'),
                         heartbeat, f'{state.get("main_pending_ms", 0)/1000:.1f}s ({state.get("main_probe", "not started")})', hooks,
                         state.get('detached', 'connected' if not state.get('stopped') else 'agent stopped'),
                         state.get('crash', {}).get('summary') or ('not supplied by Frida' if state.get('detached') else 'none received')]
                target_rows.append('<tr>' + ''.join('<td>'+html.escape(str(value))+'</td>' for value in cells) + '</tr>')
                crash = state.get('crash', {})
                if crash:
                    report = crash.get('report') or 'Frida supplied no crash report text.'
                    if crash.get('report_truncated'):report += '\n[Report truncated to 65,536 characters.]'
                    crash_reports.append('<details><summary>Frida crash report for PID '+html.escape(pid)+'</summary><pre>'+html.escape(report)+'</pre></details>')
            target_table = '<table><tr><th>PID</th><th>Last Java checkpoint</th><th>Last overall checkpoint</th><th>Agent heartbeat</th><th>Main-thread probe pending</th><th>Last observed callbacks</th><th>Detach reason</th><th>Crash summary</th></tr>' + ''.join(target_rows) + '</table>' if target_rows else '<p>No agent checkpoint has arrived yet. See host operations below.</p>'
            target_table += ''.join(crash_reports)
            host_rows = ''.join(f'<li>{html.escape(value["stage"])} — {now-value["since"]:.1f}s</li>' for value in self.phases.values())
            checkpoint_rows = ''.join('<tr><td>'+html.escape(row['time'])+'</td><td>'+html.escape(row['kind'])+'</td><td>'+html.escape(str(row.get('stage') or row.get('summary') or row.get('error', '')))+'</td></tr>' for row in list(self.history)[-25:])
            self._replace('status.json', json.dumps(snapshot, indent=2))
            refresh = '' if self.outcome else '<meta http-equiv="refresh" content="2">'
            body = f'''<!doctype html><meta charset="utf-8">{refresh}<title>Runtime Code diagnostics</title>
<style>body{{font:16px system-ui;max-width:1200px;margin:3em auto;padding:0 1em;background:#101820;color:#e8eef4}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#1d2935;padding:1em}}a{{color:#8bd3ff}}table{{width:100%;border-collapse:collapse;table-layout:fixed}}td,th{{text-align:left;padding:.6em;border:1px solid #405060;overflow-wrap:anywhere;font-size:13px}}summary{{cursor:pointer;padding:1em 0}}</style>
<h1>{html.escape(code)}</h1><p>{html.escape(summary)}</p>
<p>{html.escape(guidance)}</p>
<p>Updated {datetime.now(timezone.utc).isoformat()}. Session: {html.escape(self.outcome or 'active')}.</p>
<p>A checkpoint identifies the last observed boundary, not a proven deadlock location. The watchdog uses no Frida RPC or SQLite. It does not unblock or kill the app.</p>
<h2>Target status</h2>{target_table}
<h2>Host operations in progress</h2><ul>{host_rows or '<li>None</li>'}</ul>
<h2>Recent checkpoints</h2><table><tr><th>Time (UTC)</th><th>Kind</th><th>Stage or message</th></tr>{checkpoint_rows}</table>
<p><a href="checkpoints.jsonl">Checkpoint log</a> · <a href="host-threads.txt">Host thread stacks (created on a stall)</a> · <a href="status.json">Status JSON</a></p>
<details><summary>Full diagnostic data</summary><pre>{html.escape(json.dumps(snapshot, indent=2))}</pre></details>'''
            self._replace('report.html', body)

    def _replace(self, name, text):
        path = self.root / name
        temporary = path.with_suffix(path.suffix + '.tmp')
        temporary.write_text(text, encoding='utf-8')
        temporary.replace(path)

    def tick(self):
        self.consume()
        code, summary = self.assess()
        if code not in ('STARTING', 'RESPONDING', 'STOPPED') and code != self.last_warning:
            self.last_warning = code
            with self.lock:self.incidents.append({'code': code, 'summary': summary})
            self.record('watchdog.warning', code=code, summary=summary)
            stacks = []
            for thread_id, frame in sys._current_frames().items():
                stacks.append(f'\nThread {thread_id}\n' + ''.join(traceback.format_stack(frame)))
            self._replace('host-threads.txt', ''.join(stacks))
        elif code in ('STARTING', 'RESPONDING', 'STOPPED'):
            self.last_warning = None
        self.render()

    def _watch(self):
        while not self.finished.wait(self.interval):
            try:
                self.tick()
            except Exception as error:
                print(f'[debug] Report update failed: {error}', file=sys.stderr, flush=True)

    def close(self, outcome='finished'):
        global _active
        if _active is self:
            _active = None
        self.finished.set()
        self.thread.join(timeout=2)
        with self.lock:
            self.consume()
            self.outcome = outcome
            self.record('debug.finished', outcome=outcome)
            self.render()
            self.stream.close()
