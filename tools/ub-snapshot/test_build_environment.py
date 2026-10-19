"""Environment discovery regressions. Query results are mocked, no compiler/install/network calls."""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import types
import unittest
import uuid
from unittest.mock import patch

DIRECTORY = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('build_offline_discovery', DIRECTORY / 'build_offline.py')
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.repo = DIRECTORY.parents[1]
        self.path = self.repo / ('.ub-env-unit-' + uuid.uuid4().hex[:12])
        self.path.mkdir(mode=0o755)
        self.root_patch = patch.object(b, 'ROOT', self.path)
        self.root_patch.start()
        self.home_patch = patch.object(Path, 'home', return_value=self.path / 'home')
        self.home_patch.start()
        self.calls, self.versions = [], {}

    def tearDown(self):
        self.home_patch.stop()
        self.root_patch.stop()
        assert self.path.resolve().is_relative_to(self.repo.resolve())
        shutil.rmtree(self.path)

    def toolchain(self, name, version='1.95.0', library='lib'):
        prefix = self.path / 'toolchains' / name / 'prefix'
        binary = prefix / 'bin'
        standard = prefix / library / 'rustlib/aarch64-unknown-linux-gnu/lib'
        binary.mkdir(parents=True)
        standard.mkdir(parents=True)
        (standard / 'libstd-fixture.rlib').write_bytes(b'fixture')
        header = bytearray(64)
        header[:4] = b'\x7fELF'
        header[18:20] = (183).to_bytes(2, 'little')
        for tool in ('rustc', 'cargo'):
            (binary / tool).write_bytes(header)
            (binary / tool).chmod(0o700)
        self.versions[str(binary.resolve())] = version
        return binary

    def runner(self, command, **kwargs):
        self.calls.append(command)
        directory = str(Path(command[0]).parent)
        version = self.versions[directory]
        text = ('rustc ' + version + '\nhost: aarch64-unknown-linux-gnu\nrelease: ' + version + '\n'
                if Path(command[0]).name == 'rustc' else 'cargo ' + version + ' (fixture)\n')
        return types.SimpleNamespace(returncode=0, stdout=text, stderr='')

    def discover(self, environment=None, which=None):
        return b.discover_rust(environment or {}, which=which or (lambda name: None), runner=self.runner)

    def test_missing_old_pointer_still_finds_private_compiler(self):
        binary = self.toolchain('different-layout')
        selected, warnings = self.discover()
        self.assertEqual(selected['rustc'], str((binary / 'rustc').resolve()))
        self.assertTrue(any('pointer' in item for item in warnings))
        self.assertEqual(len(self.calls), 2)

    def test_installed_version_is_not_hardcoded_to_199(self):
        self.toolchain('installed', '1.90.0')
        selected, _ = self.discover()
        self.assertEqual(selected['version'], '1.90.0')

    def test_highest_existing_stable_version_is_selected(self):
        self.toolchain('old', '1.90.0')
        self.toolchain('new', '1.99.0')
        selected, _ = self.discover()
        self.assertEqual(selected['version'], '1.99.0')

    def test_explicit_toolchain_override_is_respected(self):
        selected_bin = self.toolchain('chosen', '1.90.0')
        self.toolchain('other', '1.99.0')
        selected, _ = self.discover({'AENV_RUST_BIN_DIR': str(selected_bin)})
        self.assertEqual(selected['version'], '1.90.0')
        self.assertEqual(len(self.calls), 2)

    def test_broken_explicit_override_is_reported_not_silently_replaced(self):
        self.toolchain('valid')
        selected, warnings = self.discover({'AENV_RUST_BIN_DIR': str(self.path / 'missing')})
        self.assertIsNone(selected)
        self.assertIn('override', warnings[0])
        self.assertEqual(self.calls, [])

    def test_rustup_hardlink_proxy_is_not_executed(self):
        binary = self.toolchain('proxy')
        os.link(binary / 'rustc', binary / 'rustup')
        selected, warnings = self.discover()
        self.assertIsNone(selected)
        self.assertTrue(any('rustup proxy' in item['reason'] for item in warnings if 'candidate' in item))
        self.assertEqual(self.calls, [])

    def test_unpacked_or_incomplete_compiler_is_not_executed(self):
        binary = self.toolchain('incomplete')
        (binary.parent / 'lib/rustlib/aarch64-unknown-linux-gnu/lib/libstd-fixture.rlib').unlink()
        selected, _ = self.discover()
        self.assertIsNone(selected)
        self.assertEqual(self.calls, [])

    def test_lib64_sysroot_is_supported(self):
        self.toolchain('rpm-layout', library='lib64')
        selected, _ = self.discover()
        self.assertIn('lib64', selected['standard_library'])

    def test_non_elf_wrapper_is_rejected_before_query(self):
        binary = self.toolchain('wrapper')
        (binary / 'rustc').write_text('#!/bin/sh\nrustup update\n')
        selected, _ = self.discover()
        self.assertIsNone(selected)
        self.assertEqual(self.calls, [])

    def test_path_real_compiler_can_be_discovered(self):
        binary = self.toolchain('path-visible')
        selected, _ = self.discover(which=lambda name: str(binary / name))
        self.assertEqual(selected['bin'], str(binary.resolve()))

    def test_failed_probe_does_not_trigger_installer_or_other_command(self):
        self.toolchain('broken')
        def fail(command, **kwargs):
            self.calls.append(command)
            raise subprocess.TimeoutExpired(command, 15)
        selected, _ = b.discover_rust({}, which=lambda name: None, runner=fail)
        self.assertIsNone(selected)
        self.assertTrue(all(Path(command[0]).name == 'rustc' for command in self.calls))

    def test_missing_vendor_pointer_discovers_existing_matching_vendor(self):
        vendor = self.path / 'offline/vendor-ae9c626-existing'
        vendor.mkdir(parents=True)
        (vendor / 'agentenv-vendor-manifest.json').write_text(json.dumps({'lock_sha256': b.LOCK_SHA}))
        selected, warnings = b.discover_vendor({})
        self.assertEqual(selected, vendor)
        self.assertTrue(any('pointer' in item for item in warnings))

    def test_mismatched_vendor_is_not_accepted(self):
        vendor = self.path / 'offline/vendor-ae9c626-wrong'
        vendor.mkdir(parents=True)
        (vendor / 'agentenv-vendor-manifest.json').write_text(json.dumps({'lock_sha256': 'wrong'}))
        selected, warnings = b.discover_vendor({})
        self.assertIsNone(selected)
        self.assertTrue(any('another Cargo.lock' in item['reason'] for item in warnings if 'candidate' in item))

    def test_known_scan_excludes_unpack_and_cache_trees(self):
        visible = self.toolchain('real')
        hidden = self.path / 'toolchains/unpack/hidden/bin'
        hidden.mkdir(parents=True)
        (hidden / 'rustc').write_text('do not execute')
        paths = list(b.bounded_directories([self.path / 'toolchains']))
        self.assertIn(visible, paths)
        self.assertNotIn(hidden, paths)

    def old_cache_fixture(self, payload=b'locked archive'):
        source = self.path / 'src/modified'
        source.mkdir(parents=True)
        digest = hashlib.sha256(payload).hexdigest()
        (source / 'Cargo.lock').write_text(
            '[[package]]\nname = "cast"\nversion = "0.3.0"\n'
            'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
            'checksum = "' + digest + '"\n')
        old = self.path / 'toolchains/agentenv-rust-1.99.0/cargo/registry/cache/old-registry'
        old.mkdir(parents=True)
        archive = old / 'cast-0.3.0.crate'
        archive.write_bytes(payload)
        cache = self.path / 'builds/agentenv-ub-build-v2'
        dest = cache / 'cargo/registry/cache/current-registry'
        dest.mkdir(parents=True)
        return source, archive, cache, dest / archive.name

    def test_original_cargo_cache_is_discovered_and_copied_by_lock_checksum(self):
        source, old, cache, target = self.old_cache_fixture()
        before = old.read_bytes()
        locations = b.existing_inputs()
        result = b.reuse_crate_archives(source, cache, locations)
        self.assertEqual(target.read_bytes(), before)
        self.assertEqual(old.read_bytes(), before)
        self.assertFalse(os.path.samefile(old, target))
        self.assertEqual(result['archives_copied'], 1)
        self.assertEqual(len(locations['cargo_homes']), 1)

    def test_wrong_checksum_is_not_reused(self):
        source, old, cache, target = self.old_cache_fixture()
        old.write_bytes(b'corrupt')
        result = b.reuse_crate_archives(source, cache, b.existing_inputs())
        self.assertFalse(target.exists())
        self.assertEqual(result['invalid_archives_skipped'], 1)

    def test_existing_new_cache_file_is_never_overwritten(self):
        source, old, cache, target = self.old_cache_fixture()
        target.write_bytes(b'already here')
        result = b.reuse_crate_archives(source, cache, b.existing_inputs())
        self.assertEqual(target.read_bytes(), b'already here')
        self.assertEqual(result['archives_copied'], 0)

    def test_nonlocked_archive_is_not_imported(self):
        source, old, cache, target = self.old_cache_fixture()
        (old.parent / 'other-9.0.0.crate').write_bytes(b'extra')
        b.reuse_crate_archives(source, cache, b.existing_inputs())
        self.assertFalse((target.parent / 'other-9.0.0.crate').exists())

    def test_old_config_and_credentials_are_not_imported(self):
        source, old, cache, target = self.old_cache_fixture()
        home = old.parents[3]
        (home / 'credentials.toml').write_text('secret fixture')
        (home / 'config.toml').write_text('untrusted fixture')
        b.reuse_crate_archives(source, cache, b.existing_inputs())
        self.assertTrue(target.exists())
        self.assertFalse((cache / 'cargo/credentials.toml').exists())
        self.assertFalse((cache / 'cargo/config.toml').exists())

    def test_no_registry_slot_does_not_invent_a_mirror_or_namespace(self):
        source, old, cache, target = self.old_cache_fixture()
        target.parent.rmdir()
        result = b.reuse_crate_archives(source, cache, b.existing_inputs())
        self.assertEqual(result['destination_slots'], 0)
        self.assertEqual(result['archives_copied'], 0)

    def test_old_report_can_locate_vendor_outside_offline_directory(self):
        vendor = self.path / 'deps/original-vendor'
        vendor.mkdir(parents=True)
        (vendor / 'agentenv-vendor-manifest.json').write_text(json.dumps({'lock_sha256': b.LOCK_SHA}))
        report = self.path / 'relay/reports/node-a-build-20261015T063406Z-wAjyMg'
        report.mkdir(parents=True)
        (report / 'cargo-offline.toml').write_text('directory = ' + json.dumps(str(vendor)))
        selected, _ = b.discover_vendor({})
        self.assertEqual(selected, vendor)

    def test_old_cache_write_failure_never_publishes_partial_crate(self):
        source, old, cache, target = self.old_cache_fixture()
        with patch.object(b.shutil, 'copyfileobj', side_effect=OSError('disk full')):
            b.reuse_crate_archives(source, cache, b.existing_inputs())
        self.assertFalse(target.exists())
        self.assertEqual(list(target.parent.iterdir()), [])

    @unittest.skipIf(os.name == 'nt', 'Creating symlinks requires special Windows privilege')
    def test_symlink_archive_is_not_imported(self):
        source, old, cache, target = self.old_cache_fixture()
        outside = self.path / 'payload'
        old.rename(outside)
        old.symlink_to(outside)
        result = b.reuse_crate_archives(source, cache, b.existing_inputs())
        self.assertFalse(target.exists())
        self.assertEqual(result['archives_copied'], 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
