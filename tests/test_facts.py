from tradecraft.memory.facts import FactStore


def test_merge_port_creates_new_record():
    store = FactStore()
    store.merge_port("examplepaint.com.br", 80, {"state": "open", "service": "http"})
    assert "examplepaint.com.br:80" in store.render()
    assert "state=open" in store.render()
    assert "service=http" in store.render()


def test_second_call_adds_fields_without_duplicating_record():
    store = FactStore()
    store.merge_port("examplepaint.com.br", 80, {"state": "open", "service": "http"})
    store.merge_port("examplepaint.com.br", 80, {"version": "nginx 1.24.0"})

    rendered = store.render()
    assert rendered.count("examplepaint.com.br:80") == 1
    assert "version=nginx 1.24.0" in rendered
    assert "service=http" in rendered  # earlier field still present


def test_repeated_field_is_last_write_wins():
    store = FactStore()
    store.merge_port("10.0.0.5", 22, {"version": "OpenSSH 8.0"})
    store.merge_port("10.0.0.5", 22, {"version": "OpenSSH 9.2"})

    rendered = store.render()
    assert "OpenSSH 9.2" in rendered
    assert "OpenSSH 8.0" not in rendered


def test_different_ports_get_separate_records():
    store = FactStore()
    store.merge_port("10.0.0.5", 22, {"service": "ssh"})
    store.merge_port("10.0.0.5", 80, {"service": "http"})

    rendered = store.render()
    assert "10.0.0.5:22" in rendered
    assert "10.0.0.5:80" in rendered


def test_empty_store_renders_placeholder():
    assert FactStore().render() == "(no facts recorded yet)"


def test_merge_many_skips_entries_missing_host_or_port():
    store = FactStore()
    store.merge_many([{"host": "10.0.0.5", "service": "ssh"}, {"port": 80, "service": "http"}])
    assert store.render() == "(no facts recorded yet)"


def test_blank_or_none_values_are_not_merged():
    store = FactStore()
    store.merge_port("10.0.0.5", 22, {"version": None, "service": ""})
    assert store.render() == "10.0.0.5:22"


def test_evidence_field_accumulates_instead_of_overwriting():
    """Regression for a real run: httpx_probe and trufflehog both touched
    the same (host, port); trufflehog's evidence pointer silently
    overwrote httpx_probe's even though the record's other fields
    (http_title, web_servers) were still httpx_probe's, so dereferencing
    "evidence" returned an unrelated empty secret scan."""
    store = FactStore()
    store.merge_port("example.app", 443, {"http_title": "Notebooks", "evidence": "httpx_probe:example.app"})
    store.merge_port("example.app", 443, {"evidence": "trufflehog:example.app"})

    record = dict(store.sorted_records())[("example.app", 443)]
    assert record["http_title"] == "Notebooks"
    assert record["evidence"] == "httpx_probe:example.app,trufflehog:example.app"


def test_evidence_field_does_not_duplicate_the_same_pointer():
    store = FactStore()
    store.merge_port("10.0.0.5", 443, {"evidence": "nmap_scan:10.0.0.5"})
    store.merge_port("10.0.0.5", 443, {"evidence": "nmap_scan:10.0.0.5"})

    record = dict(store.sorted_records())[("10.0.0.5", 443)]
    assert record["evidence"] == "nmap_scan:10.0.0.5"
