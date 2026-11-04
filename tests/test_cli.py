import json

from conftest import make_instance

from rdsops.cli import main


def test_json_output_and_exit_code(rds, capsys):
    make_instance(rds, StorageEncrypted=False)
    code = main(["inventory", "--instance", "egdb-lab", "--region", "us-east-1", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert code == 2
    assert out["instance"]["identifier"] == "egdb-lab"
    assert {"code": "INV001", "severity": "FAIL"}.items() <= next(
        f for f in out["findings"] if f["code"] == "INV001"
    ).items()


def test_text_output_lists_every_check(rds, capsys):
    make_instance(rds)
    main(["inventory", "--instance", "egdb-lab", "--region", "us-east-1"])
    text = capsys.readouterr().out
    assert "egdb-lab  postgres 17.7" in text
    for n in range(1, 10):
        assert f"INV00{n}" in text
