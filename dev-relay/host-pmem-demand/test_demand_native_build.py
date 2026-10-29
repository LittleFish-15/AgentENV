import importlib.util
from pathlib import Path
import unittest
from unittest import mock

import demand_native_build as builder


class BuildGuards(unittest.TestCase):
    def test_root_is_rejected_before_any_workspace_creation(self):
        with mock.patch.object(builder.platform,'system',return_value='Linux'), \
             mock.patch.object(builder.platform,'machine',return_value='aarch64'), \
             mock.patch.object(builder.os,'getuid',return_value=0,create=True), \
             mock.patch.object(builder.os,'geteuid',return_value=0,create=True), \
             mock.patch.object(Path,'mkdir') as mkdir:
            with self.assertRaisesRegex(RuntimeError,'Ordinary'):builder.build(Path('.'))
            mkdir.assert_not_called()

    def test_capabilities_are_rejected_before_build(self):
        status='CapInh:\t0\nCapPrm:\t0\nCapEff:\t1\nCapAmb:\t0\n'
        with mock.patch.object(builder.platform,'system',return_value='Linux'), \
             mock.patch.object(builder.platform,'machine',return_value='aarch64'), \
             mock.patch.object(builder.os,'getuid',return_value=1204,create=True), \
             mock.patch.object(builder.os,'geteuid',return_value=1204,create=True), \
             mock.patch.object(builder.os,'getgid',return_value=1205,create=True), \
             mock.patch.object(builder.os,'getegid',return_value=1205,create=True), \
             mock.patch.object(Path,'read_text',return_value=status), \
             mock.patch.object(Path,'mkdir') as mkdir:
            with self.assertRaisesRegex(RuntimeError,'capabilities'):builder.build(Path('.'))
            mkdir.assert_not_called()

    def test_existing_full_workload_defers_build(self):
        status='CapInh:\t0\nCapPrm:\t0\nCapEff:\t0\nCapAmb:\t0\n'
        with mock.patch.object(builder.platform,'system',return_value='Linux'), \
             mock.patch.object(builder.platform,'machine',return_value='aarch64'), \
             mock.patch.object(builder.os,'getuid',return_value=1204,create=True), \
             mock.patch.object(builder.os,'geteuid',return_value=1204,create=True), \
             mock.patch.object(builder.os,'getgid',return_value=1205,create=True), \
             mock.patch.object(builder.os,'getegid',return_value=1205,create=True), \
             mock.patch.object(Path,'read_text',return_value=status), \
             mock.patch.object(Path,'glob',return_value=[Path('ublkb0')]), \
             mock.patch.object(Path,'mkdir') as mkdir:
            with self.assertRaisesRegex(RuntimeError,'BUILD_DEFERRED_ACTIVE_UBLK'):builder.build(Path('.'))
            mkdir.assert_not_called()


if __name__=='__main__':unittest.main()
