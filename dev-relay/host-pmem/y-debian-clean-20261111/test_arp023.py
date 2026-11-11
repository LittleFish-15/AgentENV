import ast,json,pathlib,unittest
H=pathlib.Path(__file__).resolve().parent
tree=ast.parse((H/'Y_neigh023.py').read_text(encoding='utf-8'))
function=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name=='arp_stats')
CODE=compile(ast.Module(body=[function],type_ignores=[]),'<arp-counter-reader>','exec')
def parse(raw):
 scope={'read':lambda *a:raw};exec(CODE,scope);return scope['arp_stats']()
class ArpTests(unittest.TestCase):
 def test_entries_not_summed_across_cpus(self):
  d=parse('entries allocs table_fulls\n00000003 00000010 00000001\n00000003 00000020 00000002\n')
  self.assertEqual(d['entries'],3);self.assertEqual(d['counters'],{'allocs':48,'table_fulls':3})
 def test_actual_readonly_snapshot_matches_netlink(self):
  d=json.loads((H/'collected-private/y-debian-neighbor-readonly-20261111-022-node-y/stdout.log').read_text(encoding='utf-8'))
  result=parse(d['host']['arpStats']['text'])
  expected=d['host']['neighborTables']['thresholdRows'][0]
  for name in ('table_fulls','forced_gc_runs','res_failed'):self.assertEqual(result['counters'][name],expected[name])
 def test_missing_stats_explicit(self):self.assertEqual(parse(None),{'available':False})
if __name__=='__main__':unittest.main()
