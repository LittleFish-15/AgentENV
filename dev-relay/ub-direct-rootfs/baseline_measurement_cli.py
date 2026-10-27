"""Create only missing per-deployment CLI configuration from the live baseline.

The existing Runtime key is reused locally, never returned in receipts. No
server configuration, binary, service or user-global CLI config is changed.
"""
import json,os,re,stat,tomllib

def baseline_endpoint(environment):
    value=environment.get(b'API_ADDR',b'').decode('ascii')
    match=re.fullmatch(r'127\.0\.0\.1:(180[0-9]{2})',value)
    if match is None:raise RuntimeError('Live original Runtime must declare a retained loopback API_ADDR')
    return int(match[1])

def baseline_cli_config(base,api,read):
    def directory(path):
        if not path.exists() and not path.is_symlink():
            path.mkdir(mode=0o700);os.chown(path,1204,1205)
        meta=path.stat()
        if path.resolve(strict=True)!=path or not stat.S_ISDIR(meta.st_mode) or meta.st_uid!=1204 or meta.st_mode&0o022:
            raise RuntimeError('Baseline CLI directory identity differs: '+str(path))
    api.stable()
    for relative in ('cli','cli/config','cli/config/aenv','cli/cache','cli/tmp'):directory(base/relative)
    path=base/'cli/config/aenv/credentials'
    expected={'url':'http://127.0.0.1:'+str(api.port),'api_key':api.key}
    if path.exists() or path.is_symlink():
        # Existing equivalent configuration is retained byte for byte.
        actual=tomllib.loads(read(path).decode())
        if actual!=expected:raise RuntimeError('Existing baseline CLI endpoint/authentication differs; preserved')
        created=False
    else:
        raw=('url = '+json.dumps(expected['url'])+'\napi_key = '+json.dumps(expected['api_key'])+'\n').encode()
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:
            stream.write(raw);stream.flush();os.fchown(stream.fileno(),1204,1205);os.fchmod(stream.fileno(),0o600);os.fsync(stream.fileno())
        created=True
    if tomllib.loads(read(path).decode())!=expected:raise RuntimeError('Baseline CLI configuration verification failed')
    api.stable()
    return {'status':'BASELINE_MEASUREMENT_CLI_READY','createdCredentials':created,
            'existingRuntimeAuthenticationReused':True,'credentialValueReturned':False,'serverConfigurationChanged':False}
