"""Real tar/hash round trips with only Linux owner/open flags modeled on Windows."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import contextlib
import uuid
import types
import unittest
from unittest import mock

spec=importlib.util.spec_from_file_location('snapshot_archive',Path(__file__).with_name('lazy_four_snapshots.py'))
s=importlib.util.module_from_spec(spec);spec.loader.exec_module(s)


@contextlib.contextmanager
def test_directory():
    parent=Path(__file__).resolve().parent/'t'
    parent.mkdir(exist_ok=True)
    root=parent/uuid.uuid4().hex
    root.mkdir()
    try:
        yield str(root)
    finally:
        assert root.resolve(strict=True).parent==parent.resolve(strict=True)
        for path in sorted(root.rglob('*'),key=lambda p:len(p.parts),reverse=True):
            assert path.resolve().is_relative_to(root.resolve()) and not path.is_symlink()
            if path.is_dir():path.rmdir()
            else:path.unlink()
        root.rmdir()


class ArchiveTests(unittest.TestCase):
    def fixture(self,base):
        repo=base/'repository';repo.mkdir()
        layers=[]
        for raw in (b'root-one'*512,b'captured-tail'*512,b'ordinary-memory'*512):
            digest=hashlib.sha256(raw).hexdigest();layer={'digest':'sha256:'+digest,'size':len(raw)}
            path=repo/s.layer_name(layer);path.parent.mkdir(exist_ok=True);path.write_bytes(raw);layers.append(layer)
        selected=[]
        for index in range(4):
            sid=str(index)*36
            record={'id':sid,'resources':{'cpu_count':2,'memory_mib':4096},'committed':{
                'runtime_versions':{'tools_drive_version':'0.1.1'},'memory_layers':[layers[2]],
                'rootfs_layers':[{'Managed':x} for x in layers[:2]]}}
            path=repo/'catalog/records'/(sid+'.json');path.parent.mkdir(parents=True,exist_ok=True)
            path.write_text(json.dumps(record))
            directory=repo/'snapshots'/sid;directory.mkdir(parents=True)
            (directory/'commit').write_bytes(b'committed');(directory/'vm_state.bin').write_bytes(b'model-vm-state')
            (directory/'firecracker-manifest.json').write_text(json.dumps({'memory':{'virtualSize':4096*1024**2}}))
            selected.append({'original':{'template_id':sid,'catalog_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
                                         'resources':record['resources']},'case':{'instance_id':str(index),'replay_sha256':'a'*64}})
        selection=base/'selection.private.json';selection.write_text(json.dumps({'selected':selected}))
        history=base/'history.json';history.write_text('{}')
        return repo,selection,history

    def run_case(self,corrupt=False):
        with test_directory() as name:
            base=Path(name).resolve();repo,selection,history=self.fixture(base)
            def opened(path,limit=8*1024**3):
                path=s.safe(path);stream=path.open('rb');m=os.fstat(stream.fileno())
                s.need(0<m.st_size<=limit,'Modeled Linux input budget');return stream,m
            mkdir=Path.mkdir
            def inherited_mkdir(path,mode=0o777,parents=False,exist_ok=False):
                # Windows test ACL inheritance only; production keeps0700.
                return mkdir(path,mode=0o777,parents=parents,exist_ok=exist_ok)
            with mock.patch.multiple(s,ROOT=base,opened=opened),mock.patch.object(s.shutil,'disk_usage',lambda _:types.SimpleNamespace(free=100*1024**3)), \
                 mock.patch.object(Path,'mkdir',inherited_mkdir):
                archive=base/'snapshots.tar';manifest=s.pack(repo,selection,history,archive)
                original=archive.read_bytes()
                if corrupt:
                    changed=original.replace(b'captured-tail',b'captured-FAIL',1)
                    self.assertNotEqual(original,changed);archive.write_bytes(changed)
                    with self.assertRaisesRegex(RuntimeError,'checksum differs'):
                        s.receive(archive,hashlib.sha256(changed).hexdigest(),base/'received')
                    self.assertFalse((base/'received/manifest.json').exists())
                else:
                    received=s.receive(archive,hashlib.sha256(original).hexdigest(),base/'received')
                    self.assertEqual(received,manifest)
                    self.assertEqual(len([n for n in manifest['files'] if n.startswith('managed-layers/')]),3)
                    for n in manifest['files']:
                        path=base/'received'/n
                        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),manifest['files'][n]['sha256'])
                    with self.assertRaisesRegex(RuntimeError,'Existing received snapshot'):
                        s.receive(archive,hashlib.sha256(original).hexdigest(),base/'received')

    def test_complete_archive_roundtrip_deduplicates_and_preserves_existing_destination(self):
        self.run_case()

    def test_corrupted_capture_tail_never_publishes_received_manifest(self):
        self.run_case(True)


if __name__=='__main__':unittest.main()
