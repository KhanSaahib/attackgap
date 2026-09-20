from attackgap.inventory import entry_matches, is_visible, load_inventory
import json
from pathlib import Path

FIXTURE = Path(__file__).parent / "fixtures" / "inventory.json"


def test_entry_matches_exact_product_service_category():
    entry = {"product": "windows", "service": "sysmon", "categories": ["process_creation"]}
    assert entry_matches({"product": "windows", "service": "sysmon", "category": "process_creation"}, entry)
    assert not entry_matches({"product": "linux", "service": "sysmon", "category": "process_creation"}, entry)


def test_entry_matches_case_insensitively():
    entry = {"product": "Windows", "service": "Sysmon", "categories": ["Process_Creation"]}
    assert entry_matches(
        {"product": "windows", "service": "sysmon", "category": "process_creation"},
        entry,
    )


def test_entry_matches_category_not_in_list():
    entry = {"product": "windows", "categories": ["process_creation"]}
    assert not entry_matches({"product": "windows", "category": "dns"}, entry)


def test_entry_matches_wildcard_category():
    entry = {"service": "cloudtrail", "categories": ["*"]}
    assert entry_matches({"service": "cloudtrail", "category": "anything"}, entry)


def test_is_visible_empty_logsource_is_never_visible():
    assert not is_visible({}, [{"product": "windows", "categories": ["*"]}])


def test_load_inventory_defaults():
    data = load_inventory(FIXTURE)
    assert "sources" in data and "data_sources" in data
    assert data["sources"][0]["product"] == "windows"


def test_load_inventory_rejects_unsafe_catch_all_source(tmp_path):
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps({"sources": [{}]}), encoding="utf-8")
    try:
        load_inventory(path)
    except ValueError as exc:
        assert "must define" in str(exc)
    else:
        raise AssertionError("expected invalid inventory to be rejected")
