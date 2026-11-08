#!/usr/bin/env python3
"""Regression checks for upgrade preservation and real release preflight."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
INSTALLER = REPO / 'install.sh'


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='xui-delivery-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ['program', 'candidate/bin', 'data', 'commands', 'work']:
            (self.root / name).mkdir(parents=True)
        (self.root / 'program/x-ui').write_text('old panel\n')
        (self.root / 'program/certificate.pem').write_text('relative certificate\n')
        (self.root / 'data/x-ui.db').write_bytes(b'original database bytes')
        (self.root / 'menu').write_text('old management script\n')
        (self.root / 'unit').write_text('old unit\n')
        (self.root / 'running').touch()
        (self.root / 'enabled').touch()
        (self.root / 'candidate/x-ui').write_text('''#!/bin/bash
if [[ "$1" == check ]]; then
    printf '%s|%s|%s\\n' "$PWD" "$XUI_BIN_FOLDER" "$*" >> "$FIXTURE/check.log"
    [[ ! -f "$FIXTURE/reject" ]]
else
    echo 'new panel'
fi
''')
        (self.root / 'candidate/x-ui').chmod(0o755)
        (self.root / 'candidate/x-ui.sh').write_text('new management script\n')
        (self.root / 'candidate/x-ui.service').write_text('new unit\n')
        (self.root / 'commands/systemctl').write_text('''#!/bin/bash
printf '%s\\n' "$*" >> "$FIXTURE/service.log"
case "$1" in
  is-active) [[ -f "$FIXTURE/running" ]] ;;
  is-enabled) [[ -f "$FIXTURE/enabled" ]] ;;
  stop) rm -f "$FIXTURE/running" ;;
  enable) touch "$FIXTURE/enabled" ;;
  disable) rm -f "$FIXTURE/enabled" ;;
  start)
    if [[ -f "$FIXTURE/fail-start" ]] && grep -q 'new panel' "$FIXTURE/program/x-ui"; then
      printf 'partially migrated database' > "$FIXTURE/data/x-ui.db"
      exit 1
    fi
    touch "$FIXTURE/running" ;;
  daemon-reload) exit 0 ;;
  *) exit 1 ;;
esac
''')
        (self.root / 'commands/systemctl').chmod(0o755)

    def run_shell(self, body):
        setup = f'''source {shlex.quote(str(INSTALLER))}
INSTALL_DIR="$FIXTURE/program"
DB_PATH="$FIXTURE/data/x-ui.db"
MENU_PATH="$FIXTURE/menu"
UNIT_PATH="$FIXTURE/unit"
WORK_DIR="$FIXTURE/work"
trap 'finish $?' EXIT
verify_started() {{ systemctl is-active --quiet x-ui; }}
'''
        env = dict(os.environ, FIXTURE=str(self.root), PATH=str(self.root / 'commands') + ':' + os.environ['PATH'])
        return subprocess.run(['bash', '-c', setup + body], env=env, text=True, capture_output=True)

    def test_preflight_failure_leaves_running_installation_untouched(self):
        (self.root / 'reject').touch()
        result = self.run_shell('preflight "$FIXTURE/candidate"\napply_installation "$FIXTURE/candidate"\n')
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.root / 'program/x-ui').read_text(), 'old panel\n')
        self.assertEqual((self.root / 'data/x-ui.db').read_bytes(), b'original database bytes')
        self.assertTrue((self.root / 'running').exists())
        self.assertFalse((self.root / 'service.log').exists())
        self.assertIn(str(self.root / 'program') + '|' + str(self.root / 'candidate/bin'), (self.root / 'check.log').read_text())

    def test_success_keeps_database_and_relative_certificates(self):
        result = self.run_shell('preflight "$FIXTURE/candidate"\napply_installation "$FIXTURE/candidate"\n')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('new panel', (self.root / 'program/x-ui').read_text())
        self.assertEqual((self.root / 'data/x-ui.db').read_bytes(), b'original database bytes')
        self.assertEqual((self.root / 'program/certificate.pem').read_text(), 'relative certificate\n')
        self.assertEqual((self.root / 'menu').read_text(), 'new management script\n')
        self.assertEqual((self.root / 'unit').read_text(), 'old unit\n')
        self.assertTrue((self.root / 'running').exists())
        backups = list(self.root.glob('program.backup.*'))
        self.assertEqual(len(backups), 1)
        self.assertEqual((backups[0] / 'program/x-ui').read_text(), 'old panel\n')
        self.assertEqual(backups[0].stat().st_mode & 0o777, 0o700)

    def test_failed_start_restores_program_database_and_service(self):
        (self.root / 'fail-start').touch()
        result = self.run_shell('apply_installation "$FIXTURE/candidate"\n')
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.root / 'program/x-ui').read_text(), 'old panel\n')
        self.assertEqual((self.root / 'data/x-ui.db').read_bytes(), b'original database bytes')
        self.assertEqual((self.root / 'menu').read_text(), 'old management script\n')
        self.assertEqual((self.root / 'unit').read_text(), 'old unit\n')
        self.assertTrue((self.root / 'running').exists())
        self.assertTrue((self.root / 'enabled').exists())
        self.assertIn('Previous program, database and service state restored', result.stderr)

    def test_failed_start_preserves_previously_stopped_state(self):
        (self.root / 'running').unlink()
        (self.root / 'enabled').unlink()
        (self.root / 'fail-start').touch()
        result = self.run_shell('apply_installation "$FIXTURE/candidate"\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'running').exists())
        self.assertFalse((self.root / 'enabled').exists())

    def test_rejects_bad_checksum_before_extraction(self):
        (self.root / 'package.tar.gz').write_bytes(b'corrupt')
        (self.root / 'SHA256SUMS').write_text('0' * 64 + '  package.tar.gz\n')
        result = self.run_shell('verify_asset "$FIXTURE/package.tar.gz" "$FIXTURE/SHA256SUMS"\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('checksum mismatch', result.stderr)

    def test_rejects_unlisted_asset(self):
        (self.root / 'package.tar.gz').write_bytes(b'content')
        (self.root / 'SHA256SUMS').write_text('0' * 64 + '  another.tar.gz\n')
        result = self.run_shell('verify_asset "$FIXTURE/package.tar.gz" "$FIXTURE/SHA256SUMS"\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('checksum is missing', result.stderr)

    def test_unsafe_tar_members_never_escape_staging(self):
        for kind in ['parent', 'absolute', 'symlink', 'hardlink', 'duplicate']:
            with self.subTest(kind=kind):
                archive = self.root / 'unsafe.tar.gz'
                with tarfile.open(archive, 'w:gz') as tar:
                    item = tarfile.TarInfo('x-ui/file')
                    if kind == 'parent': item.name = 'x-ui/../../escaped'
                    elif kind == 'absolute': item.name = str(self.root / 'escaped')
                    elif kind == 'symlink': item.type = tarfile.SYMTYPE; item.linkname = '../escaped'
                    elif kind == 'hardlink': item.type = tarfile.LNKTYPE; item.linkname = '../escaped'
                    tar.addfile(item, io.BytesIO())
                    if kind == 'duplicate': tar.addfile(item, io.BytesIO())
                result = self.run_shell('extract_package "$FIXTURE/unsafe.tar.gz" "$FIXTURE/work"\n')
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse((self.root / 'escaped').exists())
                (self.root / 'work').mkdir(exist_ok=True)

    def test_invalid_tag_fails_even_inside_command_substitution(self):
        result = self.run_shell('tag=$(release_tag "2.4.3;touch injected")\necho "should not continue"\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('should not continue', result.stdout)

    @unittest.skipUnless(os.environ.get('XUI_RELEASE_ARCHIVE'), 'requires the actual release archive')
    def test_real_archive_database_preflight(self):
        archive = Path(os.environ['XUI_RELEASE_ARCHIVE']).resolve()
        unpack = self.root / 'real'
        unpack.mkdir()
        result = self.run_shell('extract_package ' + shlex.quote(str(archive)) + ' ' + shlex.quote(str(unpack)) + '\n')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        package = unpack / 'x-ui'
        binary = package / 'x-ui'
        dbdir = self.root / 'real-db'
        dbdir.mkdir()
        env = dict(os.environ, XUI_DB_FOLDER=str(dbdir), XUI_BIN_FOLDER=str(package / 'bin'), XRAY_LOCATION_ASSET=str(package / 'bin'))
        subprocess.run([str(binary), 'setting', '-username', 'audit', '-password', 'audit-only'], cwd=package, env=env, check=True, capture_output=True)
        database = dbdir / 'x-ui.db'
        before = hashlib.sha256(database.read_bytes()).hexdigest()
        check = subprocess.run([str(binary), 'check', '-db', str(database)], cwd=package, env=env, text=True, capture_output=True)
        self.assertEqual(check.returncode, 0, check.stdout + check.stderr)
        self.assertEqual(hashlib.sha256(database.read_bytes()).hexdigest(), before)
        with sqlite3.connect(database) as db:
            db.execute('INSERT INTO inbounds (user_id,enable,listen,port,protocol,settings,stream_settings,tag) VALUES (?,?,?,?,?,?,?,?)',
                       (1,1,'127.0.0.1',19991,'vless',json.dumps({'decryption':'none','clients':[{'id':'5b956135-f9b1-4aeb-9741-fb541beec69a','email':'audit'}]}),json.dumps({'network':'h2','security':'none'}),'removed-h2'))
        before = hashlib.sha256(database.read_bytes()).hexdigest()
        check = subprocess.run([str(binary), 'check', '-db', str(database)], cwd=package, env=env, text=True, capture_output=True)
        self.assertNotEqual(check.returncode, 0, check.stdout + check.stderr)
        self.assertEqual(hashlib.sha256(database.read_bytes()).hexdigest(), before)
        self.assertIn('removed-h2', check.stdout + check.stderr)


class PublisherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='xui-publisher-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        sys.path.insert(0, str(REPO / 'scripts'))
        self.addCleanup(lambda: sys.path.remove(str(REPO / 'scripts')))
        spec = importlib.util.spec_from_file_location('release_publisher_test', REPO / 'scripts/publish-release.py')
        self.publisher = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.publisher)
        for name in self.publisher.asset_names() - {'SHA256SUMS'}:
            (self.root / name).write_bytes(b'fixture artifact\n')
        (self.root / 'release-manifest.json').write_text(json.dumps({
            'repository': '9holy/3x-ui', 'commit': 'a' * 40, 'tag': 'v2.4.3'}))
        (self.root / 'SHA256SUMS').write_text(''.join(
            hashlib.sha256(path.read_bytes()).hexdigest() + '  ' + path.name + '\n'
            for path in sorted(self.root.iterdir())))

    def test_missing_or_modified_asset_prevents_publication(self):
        (self.root / 'install.sh').write_bytes(b'tampered')
        with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
            self.publisher.verify_local(self.root)
        (self.root / 'install.sh').unlink()
        with self.assertRaisesRegex(ValueError, 'fourteen'):
            self.publisher.verify_local(self.root)

    def test_wrong_source_commit_prevents_remote_writes(self):
        with patch.object(self.publisher.subprocess, 'run') as write:
            with self.assertRaisesRegex(ValueError, 'different source commit'):
                self.publisher.publish(self.root, '9holy/3x-ui', 'b' * 40)
            write.assert_not_called()

    def test_existing_tag_cannot_be_moved(self):
        with patch.object(self.publisher, 'tag_commit', return_value='b' * 40), \
                patch.object(self.publisher.subprocess, 'run') as write:
            with self.assertRaisesRegex(ValueError, 'refusing to move'):
                self.publisher.publish(self.root, '9holy/3x-ui', 'a' * 40)
            write.assert_not_called()

    def test_existing_public_release_cannot_be_overwritten(self):
        with patch.object(self.publisher, 'tag_commit', return_value='a' * 40), \
                patch.object(self.publisher, 'optional_api', return_value={'draft': False}), \
                patch.object(self.publisher.subprocess, 'run') as write:
            with self.assertRaisesRegex(ValueError, 'already published'):
                self.publisher.publish(self.root, '9holy/3x-ui', 'a' * 40)
            write.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=2)
