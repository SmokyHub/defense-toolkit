"""SQLite provenance and immutable content storage. Only owned bytes enter this layer."""
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import threading
import time
import uuid
import fcntl
import tempfile
import shutil
from contextlib import contextmanager

from .model import Limits


def identity():
    return uuid.uuid4().hex


def encoded(value):
    text = json.dumps(value, ensure_ascii=True, separators=(',', ':'))
    if len(text) > 65536:
        raise ValueError('Observation metadata exceeds 64 KiB')
    return text


@contextmanager
def export_directory(directory):
    target=Path(directory).absolute()
    target.parent.mkdir(parents=True,exist_ok=True)
    if target.exists() or target.is_symlink():raise FileExistsError(str(target))
    stage=Path(tempfile.mkdtemp(prefix='.runtime-export-',dir=target.parent))
    try:
        yield stage
        if target.exists() or target.is_symlink():raise FileExistsError(str(target))
        stage.rename(target)
    finally:
        if stage.exists():shutil.rmtree(stage)


class Store:
    def __init__(self, directory):
        self.root = Path(directory).resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.blobs = self.root / 'blobs'
        self.pending = self.root / 'pending'
        for path in (self.blobs, self.pending):
            if path.is_symlink():
                raise ValueError('Managed artifact directories cannot be symlinks')
            path.mkdir(exist_ok=True, mode=0o700)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(self.root / 'runs.sqlite3', check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA foreign_keys=ON')
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.executescript('''
          CREATE TABLE IF NOT EXISTS runs(id TEXT PRIMARY KEY, app TEXT, device TEXT,
            started_ns INTEGER, ended_ns INTEGER, state TEXT, pack TEXT, coverage TEXT);
          CREATE TABLE IF NOT EXISTS workspace_checkpoints(run_id TEXT PRIMARY KEY REFERENCES runs,
            sequence INTEGER NOT NULL, time_ns INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS processes(id TEXT PRIMARY KEY, run_id TEXT REFERENCES runs,
            pid INTEGER, name TEXT, started_ns INTEGER, ended_ns INTEGER, state TEXT, coverage TEXT);
          CREATE TABLE IF NOT EXISTS observations(id TEXT PRIMARY KEY, run_id TEXT REFERENCES runs,
            process_id TEXT REFERENCES processes, sequence INTEGER, agent_sequence INTEGER,
            kind TEXT, time_ns INTEGER, data TEXT);
          CREATE INDEX IF NOT EXISTS timeline ON observations(run_id,sequence);
          CREATE TABLE IF NOT EXISTS blobs(hash TEXT PRIMARY KEY, size INTEGER);
          CREATE TABLE IF NOT EXISTS snapshots(id TEXT PRIMARY KEY, run_id TEXT REFERENCES runs,
            process_id TEXT REFERENCES processes, observation_id TEXT REFERENCES observations,
            logical_id TEXT, transfer_id TEXT, token TEXT, kind TEXT, status TEXT,
            expected_size INTEGER, expected_hash TEXT, hash TEXT REFERENCES blobs,
            received INTEGER, time_ns INTEGER, metadata TEXT,
            UNIQUE(process_id,transfer_id));
          CREATE TABLE IF NOT EXISTS analyses(id TEXT PRIMARY KEY, snapshot_id TEXT REFERENCES snapshots,
            handler TEXT, started_ns INTEGER, ended_ns INTEGER, state TEXT, result TEXT);
          CREATE TABLE IF NOT EXISTS findings(id TEXT PRIMARY KEY, analysis_id TEXT REFERENCES analyses,
            snapshot_id TEXT REFERENCES snapshots, data TEXT);
          CREATE TABLE IF NOT EXISTS commands(id TEXT PRIMARY KEY, run_id TEXT REFERENCES runs,
            created_ns INTEGER, state TEXT, request TEXT, result TEXT);
          CREATE TABLE IF NOT EXISTS relationships(id TEXT PRIMARY KEY, run_id TEXT REFERENCES runs,
            source_snapshot TEXT REFERENCES snapshots, target_snapshot TEXT REFERENCES snapshots,
            kind TEXT, basis TEXT, observation_id TEXT REFERENCES observations,
            UNIQUE(source_snapshot,target_snapshot,kind));
        ''')

    def rows(self, sql, parameters=()):
        with self.lock:
            return [dict(r) for r in self.db.execute(sql, parameters)]

    def one(self, sql, parameters=()):
        rows = self.rows(sql, parameters)
        if len(rows) != 1:
            raise ValueError('Record not found or ambiguous')
        return rows[0]

    def create_run(self, app, device, pack, coverage):
        run = identity()
        with self.lock, self.db:
            self.db.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)',
                            (run, app, device, time.time_ns(), None, 'starting', encoded(pack.json()), encoded(coverage)))
        return run

    def add_process(self, run, pid, name, coverage):
        process = identity()
        with self.lock, self.db:
            self.db.execute('INSERT INTO processes VALUES(?,?,?,?,?,?,?,?)',
                            (process, run, pid, name, time.time_ns(), None, 'instrumenting', encoded(coverage)))
        return process

    def state(self, table, item, state, ended=False):
        if table not in ('runs', 'processes'):
            raise ValueError('Invalid lifecycle table')
        with self.lock, self.db:
            self.db.execute(f'UPDATE {table} SET state=?, ended_ns=? WHERE id=?',
                            (state, time.time_ns() if ended else None, item))

    def observe(self, run, process, kind, data, agent_sequence=None):
        raw = encoded(data)
        observation = identity()
        with self.lock, self.db:
            if process and self.one('SELECT run_id FROM processes WHERE id=?', (process,))['run_id'] != run:
                raise ValueError('Process belongs to another Run')
            seq = self.db.execute('SELECT COALESCE(MAX(sequence),0)+1 FROM observations WHERE run_id=?', (run,)).fetchone()[0]
            self.db.execute('INSERT INTO observations VALUES(?,?,?,?,?,?,?,?)',
                            (observation, run, process, seq, agent_sequence, kind, time.time_ns(), raw))
        return observation

    def limits(self, run):
        return Limits.parse(json.loads(self.one('SELECT pack FROM runs WHERE id=?', (run,))['pack'])['limits'])

    def begin(self, run, process, data, sequence=None, *, analyst_import=False):
        limits = self.limits(run)
        size = data.get('size')
        digest = data.get('sha256')
        if analyst_import and (process is not None or data.get('token')!='analyst-import'):
            raise ValueError('Static imports cannot impersonate process captures')
        if type(size) is not int or not 0 <= size <= (64*1024*1024 if analyst_import else limits.capture_bytes):
            raise ValueError('Capture exceeds declared size limit')
        if not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest):
            raise ValueError('Invalid expected SHA-256')
        if not isinstance(data.get('transfer'), str) or len(data['transfer']) > 128:
            raise ValueError('Invalid transfer identity')
        pack = json.loads(self.one('SELECT pack FROM runs WHERE id=?', (run,))['pack'])
        if not analyst_import and data.get('token') not in {t['name'] for t in pack['tokens']}:
            raise ValueError('Capture references an undeclared token')
        with self.lock:
            count=self.db.execute('SELECT COUNT(*) FROM snapshots WHERE run_id=?',(run,)).fetchone()[0]
            if count >= limits.events:
                raise ValueError('Capture event budget exhausted')
            reserved = self.db.execute("SELECT COALESCE(SUM(expected_size),0) FROM snapshots WHERE status='pending'").fetchone()[0]
            if reserved + size > limits.pending_bytes:
                raise ValueError('Pending transfer byte budget exhausted')
            snapshot = identity()
            path = self.pending / snapshot
            with path.open('xb'):
                pass
            try:
                with self.db:
                    obs = self.observe(run, process, 'capture.begin', data, sequence)
                    self.db.execute('INSERT INTO snapshots VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                        (snapshot, run, process, obs, str(data.get('logical_id', snapshot)), data['transfer'], data['token'],
                         str(data.get('kind', 'unknown')), 'pending', size, digest, None, 0, time.time_ns(), encoded(data)))
            except Exception:
                path.unlink(missing_ok=True)
                raise
            return snapshot

    def transfer(self, process, transfer):
        return self.one('SELECT * FROM snapshots WHERE process_id IS ? AND transfer_id=?', (process, transfer))

    def import_static(self,run,data,metadata):
        transfer=identity()
        snapshot=self.begin(run,None,{**metadata,'token':'analyst-import','kind':'static_dex','transfer':transfer,
            'size':len(data),'sha256':hashlib.sha256(data).hexdigest(),'profile':'analyst-static-import-v1',
            'pack':json.loads(self.one('SELECT pack FROM runs WHERE id=?',(run,))['pack'])['id']},analyst_import=True)
        try:
            for offset in range(0,len(data),256*1024):self.chunk(None,transfer,offset,data[offset:offset+256*1024])
            self.finish(None,transfer)
        except Exception:
            if self.one('SELECT status FROM snapshots WHERE id=?',(snapshot,))['status']=='pending':self.finish(None,transfer,'static_import_interrupted')
            raise
        return snapshot

    def chunk(self, process, transfer, offset, data):
        if not isinstance(data, bytes) or len(data) > 256 * 1024:
            raise ValueError('Invalid binary chunk')
        with self.lock:
            row = self.transfer(process, transfer)
            if row['status'] != 'pending' or offset != row['received'] or offset + len(data) > row['expected_size']:
                raise ValueError('Out-of-order, excessive, or closed transfer')
            with (self.pending / row['id']).open('ab') as stream:
                stream.write(data)
            with self.db:
                self.db.execute('UPDATE snapshots SET received=? WHERE id=?', (offset + len(data), row['id']))

    def finish(self, process, transfer, interrupted=None):
        with self.lock:
            row = self.transfer(process, transfer)
            if row['status'] != 'pending':
                raise ValueError('Transfer is already finalized')
            path = self.pending / row['id']
            data = path.read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            status = 'captured' if not interrupted and len(data) == row['expected_size'] and digest == row['expected_hash'] else 'partial'
            reason = interrupted or ('verified_transfer' if status == 'captured' else 'size_or_integrity_mismatch')
            limits = self.limits(row['run_id'])
            used = self.db.execute('SELECT COALESCE(SUM(size),0) FROM blobs').fetchone()[0]
            exists = bool(self.rows('SELECT hash FROM blobs WHERE hash=?', (digest,)))
            if not exists and used + len(data) > limits.retained_bytes:
                status, reason, digest = 'failed', 'retained_byte_budget_exhausted', None
            if digest is not None:
                target = self.blobs / digest
                with path.open('rb') as stream:
                    os.fsync(stream.fileno())
                try:
                    os.link(path, target)
                except FileExistsError:
                    if target.is_symlink() or hashlib.sha256(target.read_bytes()).hexdigest() != digest:
                        raise ValueError('Managed blob integrity failure')
                with self.db:
                    self.db.execute('INSERT OR IGNORE INTO blobs VALUES(?,?)', (digest, len(data)))
            metadata = {**json.loads(row['metadata']), 'transfer_outcome': reason}
            with self.db:
                self.db.execute('UPDATE snapshots SET status=?,hash=?,metadata=?,received=? WHERE id=?',
                                (status, digest, encoded(metadata), len(data), row['id']))
            path.unlink(missing_ok=True)
            self.observe(row['run_id'], process, 'capture.end', {'snapshot': row['id'], 'status': status, 'reason': reason,
                         'bytes': len(data), 'sha256': digest, 'transfer': transfer})
            return row['id']

    def expire(self, run, reason=None):
        for row in self.rows("SELECT * FROM snapshots WHERE run_id=? AND status='pending'", (run,)):
            if reason or time.time_ns() - row['time_ns'] > self.limits(run).transfer_seconds * 10**9:
                self.finish(row['process_id'], row['transfer_id'], reason or 'transfer_timeout')

    def read(self, snapshot):
        row = self.one('SELECT * FROM snapshots WHERE id=?', (snapshot,))
        if not row['hash']:
            raise ValueError(f"Snapshot has no published bytes ({row['status']})")
        path = self.blobs / row['hash']
        if path.is_symlink():
            raise ValueError('Managed blob is a symlink')
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != row['hash'] or len(data) != row['received']:
            raise ValueError('Stored evidence failed integrity verification')
        return row, data

    def export(self, snapshot, directory):
        row, data = self.read(snapshot)
        # User supplies a destination directory; all filenames are collector-generated.
        with export_directory(directory) as target:
            (target / 'snapshot.bin').write_bytes(data)
            (target / 'manifest.json').write_text(json.dumps(row, indent=2) + '\n')
        return str(directory)

    def lease(self,run):
        if not re.fullmatch('[0-9a-f]{32}',run):raise ValueError('Invalid Run identity')
        file=(self.root/(run+'.lock')).open('a')
        try:fcntl.flock(file,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            file.close();raise ValueError('Run has an active collector; recovery is refused')
        return file

    def close(self):
        self.db.close()
