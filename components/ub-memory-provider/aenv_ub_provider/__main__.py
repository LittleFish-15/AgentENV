import json
import sys
from .service import main

try:
    raise SystemExit(main())
except Exception as error:
    print(json.dumps({'state': 'stopped', 'errorType': type(error).__name__, 'reason': str(error)[:1000]}), file=sys.stderr)
    raise SystemExit(1)
