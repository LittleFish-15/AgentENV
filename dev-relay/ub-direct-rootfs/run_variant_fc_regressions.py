from pathlib import Path
p=Path(__file__).with_name('run_resourcefix_regressions.py');s=p.read_text()
s=s.replace("'full_comparison_admission_deletefix.py':'resourcefix_admission.py'","'full_comparison_admission_deletefix.py':'variant_fc_admission.py'")
s=s.replace("'actual_comparison_cohort_deletefix.py':'resourcefix_cohort.py'","'actual_comparison_cohort_deletefix.py':'layoutfix_cohort.py'")
s=s.replace("'deletefix_comparison_aggregation_body.py':'resourcefix_aggregation_body.py'","'deletefix_comparison_aggregation_body.py':'variant_fc_aggregation_body.py',\n         'deletefix_local_comparison_body.py':'variant_fc_comparison_body.py'")
needle="replay_tests=load('resourcefix_replay_tests','test_native_group_replay.py')"
extra="""original_fixture=m.aggregate_tests.inputs
def pinned_fc_fixture():
    nodes,pair,allocation=original_fixture()
    for node,variants in nodes.items():
        for variant,data in variants.items():
            pin=m.admission.FC_BUILDS[variant]
            data['receipt']['context'].update(firecrackerSha256=pin['sha256'],firecrackerBytes=pin['bytes'])
    return nodes,pair,allocation
m.aggregate_tests.inputs=pinned_fc_fixture
"""
s=s.replace(needle,extra+needle)
exec(compile(s,str(p),'exec'),{'__name__':'__main__','__file__':str(p)})
