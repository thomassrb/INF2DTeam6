import os
import tempfile
import importlib

def test_storage_utils_roundtrip_json_csv_txt(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        monkeypatch.setenv("MOBYPARK_DATA_DIR", tmp)

        from MobyPark.api import storage_utils as su
        importlib.reload(su)

        # JSON gedeelte
        su.save_data("test.json", {"a": 1})
        assert su.load_data("test.json") == {"a": 1}

        # CSV
        rows = [["c1","c2"], ["v1","v2"]]
        su.save_data("test.csv", rows)
        assert su.load_data("test.csv") == rows

        # TXT
        su.save_data("test.txt", ["line1","line2"])
        assert [s.strip() for s in su.load_data("test.txt")] == ["line1","line2"]