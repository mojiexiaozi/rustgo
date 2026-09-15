"""Move one static identity into approval management, preserving its key and tunnels."""
import argparse
import base64
import hashlib
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import time
import tomllib
import urllib.request
import uuid

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('name')
p.add_argument('--apply', action='store_true')
a = p.parse_args()
config_path = Path('/etc/rustgo/server.toml')
identity_path = Path('/var/lib/rustgo/rustgo-enrollment.db')
managed_path = Path('/var/lib/rustgo/rustgo-managed-tunnels.db')
original = config_path.read_text()
config_stat = config_path.stat()
config = tomllib.loads(original)
matches = [c for c in config.get('clients', []) if c['name'] == a.name]
assert len(matches) == 1, 'Expected one static client'
client = matches[0]
assert set(client) <= {'name', 'public_key', 'enabled'}, 'Unsupported static client fields'
key = client['public_key']
assert key.startswith('ed25519:')
fingerprint = hashlib.sha256(base64.b64decode(key[8:], validate=True)).hexdigest()
old_identity = 'static:sha256:' + fingerprint
new_id = str(uuid.uuid4())
new_identity = 'dynamic:' + new_id
blocks = list(re.finditer(r'^\[\[clients\]\][^\n]*\n.*?(?=^\[|\Z)', original, re.M | re.S))
blocks = [m for m in blocks if tomllib.loads(m.group())['clients'][0]['name'] == a.name]
assert len(blocks) == 1, 'Cannot isolate client configuration block'
block = blocks[0]
updated = original[:block.start()] + original[block.end():]
expected = dict(config)
expected['clients'] = [c for c in config['clients'] if c['name'] != a.name]
assert tomllib.loads(updated) == expected

def inspect():
    with sqlite3.connect(identity_path) as db:
        assert not db.execute('SELECT 1 FROM dynamic_clients WHERE normalized_id=? OR public_key=?', (a.name.lower(), key)).fetchall(), 'Dynamic identity collision'
    with sqlite3.connect(managed_path) as db:
        rows = db.execute('SELECT identity, revision, configuration FROM managed_snapshots WHERE name=?', (a.name,)).fetchall()
        assert all(r[0] == old_identity for r in rows), 'Unexpected tunnel ownership'
        return rows

before = inspect()
print('Migration:', a.name, '; tunnel revisions:', [r[1] for r in before], '; current key retained')
if not a.apply:
    print('Dry run passed; use --apply to migrate')
    raise SystemExit(0)

backup = Path('/var/backups/rustgo') / ('static-migration-' + time.strftime('%Y%m%d-%H%M%S'))
backup.mkdir(parents=True, mode=0o700)
subprocess.run(['systemctl', 'stop', 'rustgos'], check=True)
backed_up = False
try:
    # Re-read after stopping to avoid racing management updates.
    assert config_path.read_text() == original, 'Configuration changed during preparation'
    before = inspect()
    shutil.copy2(config_path, backup / config_path.name)
    for path in (identity_path, managed_path):
        with sqlite3.connect(path) as src, sqlite3.connect(backup / path.name) as dst:
            src.backup(dst)
    backed_up = True
    now = int(time.time())
    with sqlite3.connect(identity_path) as db:
        db.execute('INSERT INTO dynamic_clients (internal_id,display_id,normalized_id,public_key,enabled,revision,created_at,updated_at) VALUES (?,?,?,?,?,1,?,?)', (new_id,a.name,a.name.lower(),key,int(client.get('enabled', True)),now,now))
        db.execute('INSERT INTO enrollment_audit (event,target_id,created_at) VALUES (?,?,?)', ('static_identity_migrated',new_id,now))
    with sqlite3.connect(managed_path) as db:
        db.execute('UPDATE managed_snapshots SET identity=? WHERE identity=?', (new_identity,old_identity))
        after = db.execute('SELECT identity, revision, configuration FROM managed_snapshots WHERE name=?', (a.name,)).fetchall()
        assert [(r[1],r[2]) for r in after] == [(r[1],r[2]) for r in before], 'Tunnel configuration changed'
    candidate = config_path.with_suffix('.migration.tmp')
    shutil.copy2(config_path, candidate)
    candidate.write_text(updated)
    os.chown(candidate, config_stat.st_uid, config_stat.st_gid)
    os.replace(candidate, config_path)
    subprocess.run(['/opt/rustgo/bin/rustgos', '-c', str(config_path), 'check'], check=True)
    subprocess.run(['systemctl', 'start', 'rustgos'], check=True)
    for _ in range(30):
        try:
            with urllib.request.urlopen('http://127.0.0.1:8143/healthz', timeout=2) as response:
                if response.status == 200:
                    break
        except Exception:
            time.sleep(1)
    else:
        raise RuntimeError('Service health check failed')
except Exception:
    subprocess.run(['systemctl', 'stop', 'rustgos'], check=True)
    if backed_up:
        shutil.copy2(backup / config_path.name, config_path)
        os.chown(config_path, config_stat.st_uid, config_stat.st_gid)
        for path in (identity_path, managed_path):
            with sqlite3.connect(backup / path.name) as src, sqlite3.connect(path) as dst:
                src.backup(dst)
    subprocess.run(['systemctl', 'start', 'rustgos'], check=True)
    raise
print('Migration complete; service healthy; backup:', backup)
