"""Same shell, delay and editor normalization as the recorded reference."""
import json, shlex

def need(ok, message):
    if not ok: raise RuntimeError(message)

def normalize_action(action):
    """Independent implementation of the reviewed rendered-editor convention."""
    try:words=shlex.split(action)
    except ValueError:return action
    if words[:2]!=['str_replace_editor','str_replace']:return action
    try:positions=[words.index(flag)+1 for flag in ('--old_str','--new_str')];values=[words[i] for i in positions]
    except (ValueError,IndexError):return action
    def trim(value):
        if value.startswith('\r\n'):value=value[2:]
        elif value.startswith('\n'):value=value[1:]
        if value.endswith('\r\n'):value=value[:-2]
        elif value.endswith('\n'):value=value[:-1]
        return value
    values=list(map(trim,values))
    if not values[0]:return action
    for i,v in zip(positions,values):words[i]=v
    return shlex.join(words)

def steps_from(raw):
    data=json.loads(raw);rows=[];terminal=None
    for item in data['trajectory']:
        if not isinstance(item,dict) or not isinstance(item.get('action'),str) or not item['action'].strip():continue
        action=item['action'].strip()
        if action.lower() in ('submit','finish','done'):terminal=action;break
        delay=item.get('delay_time',0)
        need(type(delay) in (int,float) and 0<=delay<3600,'Invalid trajectory delay')
        rows.append({'action':normalize_action(action),'delay':float(delay)})
    need(rows,'Empty executable trajectory');return rows,terminal

def shell_command(action,marker):
    inner="set +o pipefail; export PAGER=cat; export MANPAGER=cat; export GIT_PAGER=cat; export LESS=-FRX; cd -- / || exit 125; "+action
    return 'set +e; /agentenv/bin/busybox timeout -s TERM -k 5 300 /bin/bash -l -c '+shlex.quote(inner)+"; code=$?; printf '\\n"+marker+" %s\\n' \"$code\"; exit 0"
