"""Install under the verified jwk deployment instead of an existing foreign path."""
import ast
from pathlib import Path
H=Path(__file__).resolve().parent
s=(H/'Y_install_scripts019.py').read_text(encoding='utf-8')
s=s.replace("DEST=P('/home/jwk/scripts')","DEST=BASE/'scripts'").replace("receipt=BASE/'script-install019'","receipt=BASE/'script-install020'").replace('.install019.tmp','.install020.tmp').replace('INSTALL_X_EQUIVALENT_MANUAL_TEST_KIT','INSTALL_X_EQUIVALENT_MANUAL_TEST_KIT020').replace('cd /home/jwk/scripts && bash run.sh','cd /home/jwk/aenv-y-clean-20261111/scripts && bash run.sh')
s=s.replace("    assert os.getuid()", "    assert os.getuid()")
needle=" result={'action':"
# Existing source uses one-space indents; add useful diagnostics to final receipt.
idx=s.index(needle)
s=s[:idx]+''' legacy=P('/home/jwk/scripts');legacy_info={'exists':legacy.exists(),'symlink':legacy.is_symlink()}
 if legacy.exists() or legacy.is_symlink():
  st=legacy.lstat();legacy_info.update(uid=st.st_uid,gid=st.st_gid,mode=oct(stat.S_IMODE(st.st_mode)),resolved=str(legacy.resolve()))
'''+s[idx:]
s=s.replace("\n result['sdk']=", "\n result['existingHomeScriptsPath']=legacy_info\n result['sdk']=",1)
ast.parse(s,feature_version=(3,11));(H/'Y_install_scripts020.py').write_bytes(s.encode())
doc=(H/'README-scripts019.md').read_text(encoding='utf-8').replace('/home/jwk/scripts','/home/jwk/aenv-y-clean-20261111/scripts')
(H/'README-scripts020.md').write_bytes(doc.encode())
print('Scripts020 uses verified deployment-owned directory; legacy /home/jwk/scripts remains untouched')
