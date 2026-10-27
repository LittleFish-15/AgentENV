from pathlib import Path
p=Path(__file__).with_name('run_resourcefix_regressions.py')
s=p.read_text().replace("'actual_comparison_cohort_deletefix.py':'resourcefix_cohort.py'","'actual_comparison_cohort_deletefix.py':'layoutfix_cohort.py'")
s=s.replace("'deletefix_comparison_aggregation_body.py':'resourcefix_aggregation_body.py'","'deletefix_comparison_aggregation_body.py':'layoutfix_aggregation_body.py',\n         'deletefix_local_comparison_body.py':'layoutfix_comparison_body.py'")
exec(compile(s,str(p),'exec'),{'__name__':'__main__','__file__':str(p)})
