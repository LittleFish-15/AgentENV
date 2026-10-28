from dataclasses import asdict
import copy,hashlib,json,types,unittest
from pathlib import Path
from unittest import mock
from aenv_ub_provider import host_pmem_rootfs as r, raw, stored


class RootfsPlanTests(unittest.TestCase):
    def config(self):
        base=Path(Path(__file__).anchor)
        source={'objectId':'image','generation':'gen','bytes':4*1024**2,
                'sha256':'sha256:'+'a'*64,'socket':'/owned/raw.sock'}
        sock=str(base/'lower.sock')
        replica=stored.Replica(sock,'aenv_'+'c'*32,'d'*32,'sha256:'+'e'*64,4096,stored.ALIGN)
        return {'version':1,'workDir':str(base/'private/run'),'source':source,'ownerUid':1204,
                'ownerPid':10,'ownerStartTicks':'20','publication':{'version':1,'ownerId':'b'*32,
                'mode':'pmem','readers':['peer'],'replicas':[raw.shape(source,'aenv_'+'f'*32)]},
                'releaseReceipt':str(base/'public/release.json'),'kernelRelease':'kernel',
                'moduleSrcversion':'C2BBB64D75C618180ABA3A6','files':[{'name':'lower.commit','replica':asdict(replica)}],
                'brokerSocket':sock,'brokerGid':1205,'runtimeIndex':str(base/'public/index.json'),'payloadResponses':2}

    def test_plan_does_not_create_mount_worker_or_sdk(self):
        with mock.patch.object(r,'MountedSession',side_effect=AssertionError('must not mount')):
            result=r.plan(self.config())
        self.assertEqual(result['logicalFileBytes'],4096);self.assertFalse(result['SDKAllocationIncluded'])

    def test_rejects_path_escape_duplicate_and_fallback(self):
        for change in ('path','duplicate','fallback','wrong_socket','too_large'):
            c=self.config()
            if change=='path':c['files'][0]['name']='../lower'
            elif change=='duplicate':c['files']*=2
            elif change=='fallback':c['files'][0]['replica']['allowRepositoryFallback']=True
            elif change=='wrong_socket':c['brokerSocket']=str(Path(Path(__file__).anchor)/'other.sock')
            else:c['source']['bytes']=1
            with self.subTest(change=change),self.assertRaises(ValueError):r.plan(c)

    def test_index_and_response_bounds_are_part_of_config_digest(self):
        c=self.config();before=r.plan(c)['configSha256']
        c['payloadResponses']=1
        self.assertNotEqual(before,r.plan(c)['configSha256'])
        c['payloadResponses']=9
        with self.assertRaises(ValueError):r.plan(c)

    def test_runtime_index_cannot_reuse_release_receipt(self):
        c=self.config();c['runtimeIndex']=c['releaseReceipt']
        with self.assertRaises(ValueError):r.plan(c)

    def test_first_index_publication_never_overwrites_a_racing_writer(self):
        import contextlib,stat
        info=types.SimpleNamespace(st_uid=0,st_mode=stat.S_IFDIR|0o755,st_dev=1,st_ino=2)
        stream=mock.MagicMock();stream.__enter__.return_value=stream
        with contextlib.ExitStack() as stack:
            for name,value in [('stat',mock.Mock(return_value=info)),('exists',mock.Mock(return_value=False)),
                               ('is_symlink',mock.Mock(return_value=False)),('resolve',lambda p,**kw:p)]:
                stack.enter_context(mock.patch.object(r.Path,name,value))
            for name,value in [('open',mock.Mock(return_value=7)),('fdopen',mock.Mock(return_value=stream)),
                               ('fchmod',mock.Mock()),('fsync',mock.Mock()),('close',mock.Mock()),('O_NOFOLLOW',0)]:
                stack.enter_context(mock.patch.object(r.os,name,value,create=True))
            link=stack.enter_context(mock.patch.object(r.os,'link',side_effect=FileExistsError('race')))
            replace=stack.enter_context(mock.patch.object(r.os,'replace'))
            with self.assertRaises(FileExistsError):r.write_index(Path('/public/index'),{'state':'ready'})
            link.assert_called_once();replace.assert_not_called()


if __name__=='__main__':unittest.main()
