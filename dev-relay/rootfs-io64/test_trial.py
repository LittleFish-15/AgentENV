"""Portable control tests. systemd, proc and root ownership are simulated.

File replacement/restoration uses real files and hardlinks in a private test
directory. These tests do not claim Linux service or Guest execution.
"""
import contextlib, hashlib, importlib.util, io, json, os, re, socket, stat, types, unittest, uuid
from pathlib import Path
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('trial_packet',HERE.parent/'cow4_original_io64_once.py')
PACKET=importlib.util.module_from_spec(spec);spec.loader.exec_module(PACKET)


def require(ok,why):
    if not ok:raise RuntimeError(why)


class TrialTests(unittest.TestCase):
    def setUp(self):
        self.context=contextlib.ExitStack()
        if os.name=='nt':
            original=Path.__str__
            self.context.enter_context(patch.object(Path,'__str__',lambda p:original(p).replace('\\','/')))
        self.addCleanup(self.context.close)

    def test_original_config_delta_and_duplicate_rejection(self):
        raw=b'[ublk]\ndaemon_binary_path = "/base/bin/uvm-ublk-daemon"\n'
        ns={'require':require,'BASE':Path('/base'),'re':re,'json':json}
        exec((HERE/'root_binary.py').read_text(encoding='utf-8'),ns)
        value=ns['io64_config'](raw,Path('/work/observer/daemon'))
        self.assertEqual(value,b'[ublk]\ndaemon_binary_path = "/work/observer/daemon"\n[ublk.overlaybd]\nrootfs_max_io_kib = 64\n')
        for extra in [b'rootfs_max_io_kib = 256\n',b'[ublk.overlaybd]\n',b'daemon_binary_path = "ambiguous"\n']:
            with self.assertRaises(RuntimeError):ns['io64_config'](raw+extra,Path('/candidate'))

    def test_effective_kernel_limits_must_match_both_fields(self):
        ns={'require':require,'Path':Path,'stat':stat,'re':re,'os':os}
        exec((HERE/'root_binary.py').read_text(encoding='utf-8'),ns)
        values={'max_hw_sectors_kb':64,'max_sectors_kb':64,'logical_block_size':512,'physical_block_size':512,'read_ahead_kb':128}
        def read(p,*a,**k):return '240:3' if p.name=='dev' else str(values[p.name])
        with patch.object(Path,'resolve',lambda p,**k:p),patch.object(Path,'stat',lambda p,**k:types.SimpleNamespace(st_mode=stat.S_IFBLK,st_rdev=3)),patch.object(Path,'read_text',read),patch.object(os,'major',lambda n:240,create=True),patch.object(os,'minor',lambda n:3,create=True):
            self.assertEqual(ns['io64_device_limit']('/dev/ublkb3',64)['expected_kib'],64)
            with self.assertRaises(RuntimeError):ns['io64_device_limit']('/dev/ublkb3',256)
            values['max_sectors_kb']=32
            with self.assertRaises(RuntimeError):ns['io64_device_limit']('/dev/ublkb3',64)
            with self.assertRaises(RuntimeError):ns['io64_device_limit']('/dev/nvme0n1',64)

    def lifecycle(self,fault=None):
        # Fixed target hash pins are replaced only inside this local fixture.
        directory=Path.cwd()/'outputs/rootfs-io64-original-20261022/lifecycle-tests'/uuid.uuid4().hex
        directory.mkdir(parents=True)
        # Keep diagnostic files; avoid changing Windows ACLs through mkdtemp(0700).
        with contextlib.nullcontext(str(directory)) as d:
            root=Path(d);base=root/'base';work=root/'work'
            for p in (base/'bin',base/'config',work/'observer',root/'r'):p.mkdir(parents=True,exist_ok=True)
            installed=base/'bin/server';installed.write_bytes(b'original server fixture')
            os.chmod(installed,0o755)
            backup=work/'server.original';os.link(installed,backup)
            server=work/'observer/server-rootfs-io64';server.write_bytes(b'candidate server fixture')
            daemon=work/'observer/uvm-ublk-daemon-observe';daemon.write_bytes(b'candidate daemon fixture')
            daemon.with_suffix('.access-spec').write_bytes(b'fixture spec')
            raw=('[ublk]\ndaemon_binary_path = '+json.dumps(str(base/'bin/uvm-ublk-daemon'),ensure_ascii=False)+'\n').encode()
            config=base/'config/runtime.toml';config.write_bytes(raw)
            sha=lambda b:hashlib.sha256(b).hexdigest()
            run='a'*32;endpoint=root/'r'/('c4-'+run[:12]+'.sock')
            state={'pid':'10','restarts':0,'read_count':0};sent=[]
            class Sock:
                def settimeout(self,n):pass
                def connect(self,p):pass
                def close(self):pass
            fake_sock=Sock()
            ns={'UNIT':'fixture-original.service','ROOT':root,'BASE':base,'require':require,'identity':lambda p:(1,'ticks'+str(p))}
            code=PACKET.ROOT_SOURCE.replace('f2a1abe6542c3230bfe3cd81b884cf080dc4a3b2f2c371b40092940c686d01bd',sha(raw))
            exec(code,ns)
            ns['IO64_SERVER_SHA']=sha(server.read_bytes());ns['IO64_DAEMON_SHA']=sha(daemon.read_bytes())
            meta=installed.stat();cmeta=config.stat()
            plan={'run_id':run,'work':str(work),'core_commit':'fixture-core','candidate':str(daemon),'candidate_sha256':ns['IO64_DAEMON_SHA'],
                  'server_candidate':str(server),'server_sha256':ns['IO64_SERVER_SHA'],'original_server_backup':str(backup),
                  'original_server_sha256':sha(installed.read_bytes()),'original_server_metadata':ns['io64_meta'](installed),
                  'original_config_base64':__import__('base64').b64encode(raw).decode(),'original_config_sha256':sha(raw),
                  'original_config_metadata':{'uid':cmeta.st_uid,'gid':cmeta.st_gid,'mode':stat.S_IMODE(cmeta.st_mode)},
                  'original_identity':[10,'ticks10'],'boot_id':'fixture-boot','endpoint':str(endpoint),'spec_sha256':sha(b'fixture spec')}
            new=ns['io64_config'](raw,daemon);plan['new_config_sha256']=sha(new)
            def unit():return {'MainPID':state['pid'],'ticks':'ticks'+state['pid'],'ActiveState':'active'}
            def api(p):
                if p=='/health':return 204,None
                return (200,[{'sandboxID':'still-running'}]) if fault=='remaining_guest' and state['read_count']>=2 else (200,[])
            ns.update(unit_state=unit,assert_unit=lambda s:None,other_units=lambda:{'other':'unchanged'},
                      scoped_read=lambda p,limit=65536:p.read_bytes(),api_get=api,check_peer=lambda p,s:None)
            def send(sock,value):
                sent.append(value)
                if value['op']=='ready':config.write_bytes(new)
            def recv(sock):
                state['read_count']+=1
                if state['read_count']==1:return {'op':'activate'}
                if fault=='unknown_binary':installed.write_bytes(b'unknown later mutation')
                return {'op':'restore'}
            ns.update(wire_send=send,wire_recv=recv)
            def restart(command,**kw):
                self.assertEqual(command,['/usr/bin/systemctl','restart','fixture-original.service'])
                state['restarts']+=1;state['pid']=str(10+state['restarts'])
                return types.SimpleNamespace(returncode=0)
            real_stat=Path.stat;real_read=Path.read_text;real_lstat=Path.lstat
            def path_stat(p,*a,**kw):
                if str(p).replace('\\','/').startswith('/proc/') and p.name=='exe':return real_stat(installed)
                return real_stat(p,*a,**kw)
            def path_read(p,*a,**kw):
                if p.name=='boot_id':return 'fixture-boot'
                return real_read(p,*a,**kw)
            def path_lstat(p,*a,**kw):
                if p==endpoint:return types.SimpleNamespace(st_mode=stat.S_IFSOCK|0o600,st_uid=1204)
                return real_lstat(p,*a,**kw)
            if fault=='candidate_tampered':server.write_bytes(b'wrong candidate')
            with patch.object(Path,'stat',path_stat),patch.object(Path,'read_text',path_read),patch.object(Path,'lstat',path_lstat),patch.object(os,'geteuid',lambda:0,create=True),patch.object(os,'uname',lambda:types.SimpleNamespace(nodename='server1'),create=True),patch.object(os,'O_NOFOLLOW',0,create=True),patch.object(os,'fchown',lambda *a:None,create=True),patch.object(os,'fchmod',lambda *a:None,create=True),patch.object(socket,'socket',lambda *a:fake_sock),patch.object(socket,'AF_UNIX',1,create=True),patch.object(ns['subprocess'],'run',restart),contextlib.redirect_stdout(io.StringIO()) as printed:
                ns['root_session'](plan)
            report=json.JSONDecoder().raw_decode(printed.getvalue().split('BEGIN_RETURN_REPORT\n')[-1])[0]
            if fault=='candidate_tampered':
                self.assertEqual(state['restarts'],0);self.assertEqual(config.read_bytes(),raw)
                self.assertEqual(installed.read_bytes(),b'original server fixture')
            elif fault=='remaining_guest':
                self.assertEqual(state['restarts'],1,report)
                self.assertIn('restoration_error',report)
                self.assertEqual(installed.read_bytes(),b'candidate server fixture')
                self.assertEqual(config.read_bytes(),new)
                self.assertEqual(backup.read_bytes(),b'original server fixture')
            elif fault=='unknown_binary':
                self.assertEqual(state['restarts'],1,report);self.assertIn('restoration_error',report)
                self.assertEqual(installed.read_bytes(),b'unknown later mutation')
                self.assertEqual(backup.read_bytes(),b'original server fixture')
                self.assertNotIn('original_server_bytes_and_metadata_restored',report)
            else:
                self.assertEqual(state['restarts'],2,report);self.assertEqual(config.read_bytes(),raw)
                self.assertEqual(installed.read_bytes(),b'original server fixture')
                self.assertEqual(installed.stat().st_ino,meta.st_ino)
                self.assertTrue(report['original_server_bytes_and_metadata_restored'])
                self.assertTrue(report['original_configuration_restored'])
                self.assertEqual(report['status'],'COW4_ROOT_SESSION_RESTORED')
                self.assertNotIn('rootfs64_memory256_verified',report)

    def test_actual_file_replacement_and_exact_inode_restore(self):self.lifecycle()
    def test_tampered_candidate_stops_before_activation(self):self.lifecycle('candidate_tampered')
    def test_unknown_later_binary_is_preserved_not_overwritten(self):self.lifecycle('unknown_binary')
    def test_remaining_guest_prevents_restore_restart(self):self.lifecycle('remaining_guest')

    def test_packet_preserves_baseline_observation_modules(self):
        # Modules below were used by the prior global-cache experiment.
        self.assertEqual(PACKET.PATCH_SHA,'c553d631d18a01ce5511dec12e50a1a58817c92181d20f1443f17561f87a67ce')
        self.assertIn('self.global_cold(\'idle_control\')',__import__('inspect').getsource(PACKET.GlobalFourRun.run))
        self.assertIn('self.global_cold(\'replay\')',__import__('inspect').getsource(PACKET.GlobalFourRun.run))
        self.assertIn('original_server_bytes_and_metadata_restored',__import__('inspect').getsource(PACKET.main))
        self.assertIn('rootfs64_memory256_verified',__import__('inspect').getsource(PACKET.main))


if __name__=='__main__':unittest.main(verbosity=2)
