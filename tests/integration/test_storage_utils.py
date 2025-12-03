import os
import tempfile
import importlib
import pytest

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

def test_load_nonexistent_file(monkeypatch, tmp_path):
    monkeypatch.setenv("MOBYPARK_DATA_DIR", str(tmp_path))
    
    from MobyPark.api import storage_utils as su
    importlib.reload(su)
    
    # Testen met een niet bestaande json file
    result = su.load_data("ikbestaniet.json")
    assert result == {}, "Expected empty dictionary for non-existent JSON file"
    
    # Testen met een niet bestaande CSV file
    result = su.load_data("ikbestaniet.csv")
    assert result == [], "Expected empty list for non-existent CSV file"
    
    # Testen met een niet bestaande TXT file
    result = su.load_data("ikbestaniet.txt")
    assert result == [], "Expected empty list for non-existent TXT file"