"""The check logic must import without boto3 or psycopg, so it can run in a browser
(Pyodide) or any other place with only the standard library. See ADR 0006."""

import subprocess
import sys

PURE = ["findings", "inventory", "health", "maintenance", "compat", "upgrade", "drill"]


def test_check_modules_do_not_import_aws_or_database_drivers():
    code = (
        "import sys\n"
        "sys.modules['boto3'] = None\n"
        "sys.modules['botocore'] = None\n"
        "sys.modules['psycopg'] = None\n"
        + "".join(f"import rdsops.{m}\n" for m in PURE)
        + "from rdsops.compat import load_matrix\n"
        "assert load_matrix()\n"
    )
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
