#!/usr/bin/env python3
"""Regression checks for upgrade preservation and real release preflight."""
import hashlib
import importlib.util
import io
import json
import copy
from contextlib import redirect_stdout
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


class DraftReleaseAPI:
    """GitHub contract fixture: drafts are listed, but the tag endpoint is 404."""
    repo = '9holy/3x-ui'
    tag = 'v2.4.3'

    def __init__(self, releases=()):
        self.releases = copy.deepcopy(list(releases))
        self.tag_sha = None
        self.requests = []
        self.writes = []
        self.events = []
        self.uploads = []
        self.downloads = []
        self.remote_bytes = {}
        self.corrupt_name = None
        self.after_upload = lambda release: None
        self.after_download = lambda: None
        self.before_release_read = lambda release: None

    @staticmethod
    def draft(release_id=438401707, commit='a' * 40):
        return {'id': release_id, 'tag_name': 'v2.4.3', 'target_commitish': commit,
                'draft': True, 'prerelease': False, 'body': 'stale draft notes', 'assets': []}

    def optional_api(self, path):
        self.requests.append(path)
        if '/releases/tags/' in path:
            return None
        if path == f'repos/{self.repo}/git/ref/tags/{self.tag}':
            return {'object': {'type': 'commit', 'sha': self.tag_sha}} if self.tag_sha else None
        raise AssertionError('unexpected optional API request: ' + path)

    def gh_json(self, arguments, payload=None):
        path = next(a for a in arguments if a.startswith(('repos/', 'https://uploads.github.com/')))
        self.requests.append(path)
        if '/releases/tags/' in path:
            raise subprocess.CalledProcessError(1, ['gh'] + arguments, stderr='HTTP 404: Not Found')
        if path.startswith(f'repos/{self.repo}/releases?per_page=100&page='):
            page = int(path.rsplit('=', 1)[1])
            return copy.deepcopy(self.releases[(page - 1) * 100:page * 100])
        if path.startswith(f'https://uploads.github.com/repos/{self.repo}/releases/'):
            assert arguments[1:3] == ['--method', 'POST']
            release_id = int(path.split('/releases/', 1)[1].split('/', 1)[0])
            release = next(r for r in self.releases if r['id'] == release_id)
            file = Path(arguments[arguments.index('--input') + 1])
            assert path.endswith('?name=' + file.name)
            assert 'Content-Type: application/octet-stream' in arguments
            assert f'Content-Length: {file.stat().st_size}' in arguments
            self.writes.append(('upload', release_id, file.name))
            self.uploads.append((release_id, file.name))
            if any(a['name'] == file.name for a in release['assets']):
                raise subprocess.CalledProcessError(1, ['gh'] + arguments, stderr='HTTP 422: asset already exists')
            asset_id = len(self.remote_bytes) + 1000
            self.remote_bytes[asset_id] = file.read_bytes()
            asset = {'id': asset_id, 'name': file.name, 'state': 'uploaded',
                     'size': file.stat().st_size, 'download_count': 0}
            release['assets'].append(asset)
            if len(self.uploads) == 14:
                self.after_upload(release)
            return copy.deepcopy(asset)
        if path.startswith(f'repos/{self.repo}/releases/'):
            release_id = int(path.rsplit('/', 1)[1])
            release = next(r for r in self.releases if r['id'] == release_id)
            if payload is None:
                self.before_release_read(release)
            if payload is not None:
                assert arguments[1:3] == ['--method', 'PATCH']
                self.writes.append(('patch', release_id, copy.deepcopy(payload)))
                if payload.get('draft') is False:
                    self.events.append(('publish', release_id))
                    self.tag_sha = release['target_commitish']
                release.update(payload)
            return copy.deepcopy(release)
        raise AssertionError('unexpected JSON API request: ' + path)

    def run(self, arguments, **kwargs):
        if arguments[:3] == ['gh', 'release', 'create']:
            self.writes.append(('create', arguments[3]))
            release = self.draft()
            release['target_commitish'] = arguments[arguments.index('--target') + 1]
            release['body'] = Path(arguments[arguments.index('--notes-file') + 1]).read_text()
            self.releases.append(release)
        elif arguments[:4] == ['gh', 'api', '--method', 'DELETE']:
            asset_id = int(arguments[-1].rsplit('/', 1)[1])
            self.writes.append(('delete', asset_id))
            release = next(r for r in self.releases if any(a['id'] == asset_id for a in r['assets']))
            release['assets'] = [a for a in release['assets'] if a['id'] != asset_id]
        elif arguments[:4] == ['gh', 'api', '-H', 'Accept: application/octet-stream']:
            asset_id = int(arguments[-1].rsplit('/', 1)[1])
            asset = next(a for r in self.releases for a in r['assets'] if a['id'] == asset_id)
            data = self.remote_bytes[asset_id]
            if asset['name'] == self.corrupt_name:
                data = bytes([data[0] ^ 1]) + data[1:]
            kwargs['stdout'].write(data)
            asset['download_count'] += 1
            self.downloads.append(asset['name'])
            self.events.append(('download', asset['name']))
            self.after_download()
        else:
            raise AssertionError('unexpected gh command: ' + repr(arguments))
        return subprocess.CompletedProcess(arguments, 0)


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
        release = DraftReleaseAPI.draft()
        release['draft'] = False
        api = DraftReleaseAPI([release])
        with self.assertRaisesRegex(ValueError, 'already published'):
            self.publish_with_api(api)
        self.assertEqual(api.writes, [])

    def publish_with_api(self, api):
        with patch.object(self.publisher, 'optional_api', side_effect=api.optional_api), \
                patch.object(self.publisher, 'gh_json', side_effect=api.gh_json), \
                patch.object(self.publisher.subprocess, 'run', side_effect=api.run), \
                redirect_stdout(io.StringIO()):
            self.publisher.publish(self.root, api.repo, 'a' * 40)

    def assert_published_after_all_bytes(self, api, release_id=438401707):
        self.assertCountEqual(api.downloads, self.publisher.asset_names())
        self.assertEqual(len(api.downloads), 14)
        self.assertEqual({upload_id for upload_id, name in api.uploads}, {release_id})
        self.assertEqual(api.events[-1], ('publish', release_id))
        self.assertEqual(len(api.events), 15)
        self.assertFalse(any('/releases/tags/' in path for path in api.requests))
        self.assertEqual(api.writes[-1], ('patch', release_id,
                         {'draft': False, 'prerelease': False, 'make_latest': 'true'}))
        release = next(r for r in api.releases if r['id'] == release_id)
        self.assertFalse(release['draft'])
        self.assertFalse(release['prerelease'])
        self.assertEqual(api.tag_sha, 'a' * 40)

    def test_draft_tag_endpoint_404_does_not_block_complete_publication(self):
        api = DraftReleaseAPI()
        self.publish_with_api(api)
        self.assertEqual([w for w in api.writes if w[0] == 'create'], [('create', api.tag)])
        self.assert_published_after_all_bytes(api)

    def test_same_source_draft_on_second_page_is_reused_and_notes_refreshed(self):
        unrelated = [dict(DraftReleaseAPI.draft(i), tag_name=f'v1.0.{i}') for i in range(100)]
        api = DraftReleaseAPI(unrelated + [DraftReleaseAPI.draft()])
        # Reproduce an interrupted publisher with all fourteen files uploaded.
        # Resuming replaces only these asset IDs in the already selected draft.
        for index, path in enumerate(sorted(self.root.iterdir())):
            asset_id = 1000 + index
            api.remote_bytes[asset_id] = path.read_bytes()
            api.releases[-1]['assets'].append({'id': asset_id, 'name': path.name,
                'state': 'uploaded', 'size': path.stat().st_size, 'download_count': 0})
        self.publish_with_api(api)
        self.assertFalse(any(w[0] == 'create' for w in api.writes))
        self.assertIn(f'repos/{api.repo}/releases?per_page=100&page=2', api.requests)
        self.assertEqual(len(api.releases), 101)
        self.assertIn('`' + 'a' * 40 + '`', api.releases[-1]['body'])
        self.assertNotIn('stale draft notes', api.releases[-1]['body'])
        self.assertCountEqual([w[1] for w in api.writes if w[0] == 'delete'], range(1000, 1014))
        self.assert_published_after_all_bytes(api)

    def test_foreign_source_draft_prevents_all_remote_writes(self):
        api = DraftReleaseAPI([DraftReleaseAPI.draft(commit='b' * 40)])
        with self.assertRaisesRegex(ValueError, 'another source commit'):
            self.publish_with_api(api)
        self.assertEqual(api.writes, [])

    def test_duplicate_draft_on_later_page_prevents_all_remote_writes(self):
        unrelated = [dict(DraftReleaseAPI.draft(i), tag_name=f'v1.0.{i}') for i in range(99)]
        api = DraftReleaseAPI([DraftReleaseAPI.draft()] + unrelated + [DraftReleaseAPI.draft(999)])
        with self.assertRaisesRegex(ValueError, 'duplicate releases'):
            self.publish_with_api(api)
        self.assertEqual(api.writes, [])

    def test_corrupt_remote_bytes_leave_release_draft(self):
        api = DraftReleaseAPI([DraftReleaseAPI.draft()])
        api.corrupt_name = 'install.sh'
        with self.assertRaisesRegex(ValueError, 'remote checksum mismatch'):
            self.publish_with_api(api)
        self.assertTrue(api.releases[0]['draft'])
        self.assertFalse(any(e[0] == 'publish' for e in api.events))

    def test_incomplete_or_unexpected_remote_assets_never_publish(self):
        for defect in ['missing', 'extra', 'duplicate', 'size', 'state']:
            with self.subTest(defect=defect):
                api = DraftReleaseAPI([DraftReleaseAPI.draft()])
                def damage(release):
                    if defect == 'missing': release['assets'].pop()
                    elif defect == 'extra': release['assets'].append(dict(release['assets'][0], name='unexpected.txt'))
                    elif defect == 'duplicate': release['assets'].append(dict(release['assets'][0]))
                    elif defect == 'size': release['assets'][0]['size'] += 1
                    elif defect == 'state': release['assets'][0]['state'] = 'starter'
                api.after_upload = damage
                with self.assertRaisesRegex(ValueError, 'remote draft|incomplete remote upload'):
                    self.publish_with_api(api)
                self.assertTrue(api.releases[0]['draft'])
                self.assertFalse(any(e[0] == 'publish' for e in api.events))

    def test_draft_identity_change_during_download_prevents_publication(self):
        api = DraftReleaseAPI([DraftReleaseAPI.draft()])
        def replace_draft():
            if len(api.downloads) == 14:
                api.releases[0]['id'] += 1
        api.after_download = replace_draft
        with self.assertRaisesRegex(ValueError, 'identity changed'):
            self.publish_with_api(api)
        self.assertFalse(any(e[0] == 'publish' for e in api.events))

    def test_draft_changed_before_upload_prevents_asset_writes(self):
        for change, message in [('published', 'already published'), ('source', 'another source commit')]:
            with self.subTest(change=change):
                api = DraftReleaseAPI([DraftReleaseAPI.draft()])
                def change_after_notes(release):
                    if any(w[0] == 'patch' for w in api.writes):
                        if change == 'published': release['draft'] = False
                        else: release['target_commitish'] = 'b' * 40
                api.before_release_read = change_after_notes
                with self.assertRaisesRegex(ValueError, message):
                    self.publish_with_api(api)
                self.assertFalse(any(w[0] in ['upload', 'delete'] for w in api.writes))

    def test_new_duplicate_draft_is_never_selected_for_upload(self):
        api = DraftReleaseAPI([DraftReleaseAPI.draft()])
        foreign = DraftReleaseAPI.draft(999, 'b' * 40)
        def add_duplicate_after_notes(release):
            if len(api.releases) == 1 and any(w[0] == 'patch' for w in api.writes):
                api.releases.insert(0, copy.deepcopy(foreign))
        api.before_release_read = add_duplicate_after_notes
        with self.assertRaisesRegex(ValueError, 'duplicate releases'):
            self.publish_with_api(api)
        self.assertEqual(api.releases[0], foreign)
        self.assertEqual({upload_id for upload_id, name in api.uploads}, {438401707})
        self.assertFalse(any(e[0] == 'publish' for e in api.events))

    def test_tag_moved_during_download_prevents_publication(self):
        api = DraftReleaseAPI([DraftReleaseAPI.draft()])
        def move_tag():
            if len(api.downloads) == 14:
                api.tag_sha = 'b' * 40
        api.after_download = move_tag
        with self.assertRaisesRegex(ValueError, 'refusing to move'):
            self.publish_with_api(api)
        self.assertFalse(any(e[0] == 'publish' for e in api.events))

    def test_api_patch_sends_structured_json_payload(self):
        payload = {'draft': False, 'body': 'source commit\n`literal notes`'}
        with patch.object(self.publisher.subprocess, 'check_output', return_value='{}') as command:
            self.publisher.gh_json(['api', '--method', 'PATCH', 'repos/9holy/3x-ui/releases/7'], payload)
        arguments, options = command.call_args
        self.assertEqual(arguments[0], ['gh', 'api', '--method', 'PATCH',
                         'repos/9holy/3x-ui/releases/7', '-H', 'Content-Type: application/json', '--input', '-'])
        self.assertEqual(json.loads(options['input']), payload)


if __name__ == '__main__':
    unittest.main(verbosity=2)
