import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from tradecraft.execution.run_dir import (
    create_initial_manifest,
    create_run_dir,
    finalize_manifest,
    generate_run_id,
    get_tradecraft_home,
    get_target_dir,
    load_facts_json,
    load_seed_context,
    read_manifest,
    resolve_run_dir,
    save_facts_json,
    update_latest_symlink,
    write_manifest,
)
from tradecraft.memory.facts import FactStore


class TestRunDir(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.home = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_get_tradecraft_home_default_and_env(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            home = get_tradecraft_home()
            self.assertEqual(home, Path.home() / ".tradecraft")

        with mock.patch.dict(os.environ, {"TRADECRAFT_HOME": str(self.home)}):
            home = get_tradecraft_home()
            self.assertEqual(home, self.home)

    def test_generate_run_id_format_and_sorts_chronologically(self):
        dt1 = datetime(2026, 11, 1, 14, 32, 0, tzinfo=timezone.utc)
        dt2 = datetime(2026, 11, 1, 14, 32, 1, tzinfo=timezone.utc)
        rid1 = generate_run_id(dt1)
        rid2 = generate_run_id(dt2)

        self.assertTrue(rid1.startswith("20261101T143200Z_"))
        self.assertTrue(rid2.startswith("20261101T143201Z_"))
        self.assertEqual(len(rid1), len("20261101T143200Z_") + 6)
        self.assertLess(rid1, rid2)

    def test_get_target_dir_sanitizes_target(self):
        target_dir = get_target_dir("https://example.com:443/", tradecraft_home=self.home)
        self.assertEqual(target_dir, self.home / "targets" / "example.com_443")

        with self.assertRaises(ValueError):
            get_target_dir("../malicious", tradecraft_home=self.home)

    def test_create_run_dir_creates_hierarchy_and_evidence(self):
        rid, run_dir = create_run_dir("example.com", run_id="run_123", tradecraft_home=self.home)
        self.assertEqual(rid, "run_123")
        self.assertEqual(run_dir, self.home / "targets" / "example.com" / "runs" / "run_123")
        self.assertTrue(run_dir.is_dir())
        self.assertTrue((run_dir / "evidence").is_dir())

    def test_update_latest_symlink_and_resolve(self):
        target = "target.local"
        target_dir = get_target_dir(target, self.home)

        # Before any runs, resolve_run_dir with 'latest' raises FileNotFoundError
        with self.assertRaises(FileNotFoundError):
            resolve_run_dir(target, "latest", self.home)

        # Run 1
        rid1, dir1 = create_run_dir(target, run_id="20261101T100000Z_000001", tradecraft_home=self.home)
        update_latest_symlink(target_dir, rid1)

        resolved_id, resolved_dir = resolve_run_dir(target, "latest", self.home)
        self.assertEqual(resolved_id, rid1)
        self.assertEqual(resolved_dir, dir1)

        # Run 2
        rid2, dir2 = create_run_dir(target, run_id="20261101T110000Z_000002", tradecraft_home=self.home)
        update_latest_symlink(target_dir, rid2)

        resolved_id, resolved_dir = resolve_run_dir(target, "latest", self.home)
        self.assertEqual(resolved_id, rid2)
        self.assertEqual(resolved_dir, dir2)

        # Direct run_id lookup
        lookup_id, lookup_dir = resolve_run_dir(target, rid1, self.home)
        self.assertEqual(lookup_id, rid1)
        self.assertEqual(lookup_dir, dir1)

        with self.assertRaises(FileNotFoundError):
            resolve_run_dir(target, "nonexistent_run", self.home)

    def test_manifest_lifecycle(self):
        rid, run_dir = create_run_dir("example.com", run_id="run_abc", tradecraft_home=self.home)
        init_m = create_initial_manifest(
            run_dir=run_dir,
            run_id=rid,
            target="example.com",
            model="test-model",
            max_turns=5,
            mode="fresh",
            started_at="2026-11-01T12:00:00Z",
        )
        self.assertEqual(init_m["ended_at"], None)
        self.assertEqual(init_m["turns_used"], 0)
        self.assertEqual(init_m["findings_count"], 0)

        read_m = read_manifest(run_dir)
        self.assertEqual(read_m["run_id"], "run_abc")
        self.assertEqual(read_m["started_at"], "2026-11-01T12:00:00Z")

        final_m = finalize_manifest(
            run_dir=run_dir,
            turns_used=4,
            findings_count=2,
            ended_at="2026-11-01T12:05:00Z",
        )
        self.assertEqual(final_m["ended_at"], "2026-11-01T12:05:00Z")
        self.assertEqual(final_m["turns_used"], 4)
        self.assertEqual(final_m["findings_count"], 2)

    def test_manifest_records_provenance(self):
        # Without this, a run directory on disk gives no way to tell
        # afterwards whether a destructive tool was available for that
        # specific run, or which --tools/--profile selection produced its
        # effective tool set.
        rid, run_dir = create_run_dir("example.com", run_id="run_prov", tradecraft_home=self.home)
        init_m = create_initial_manifest(
            run_dir=run_dir,
            run_id=rid,
            target="example.com",
            model="test-model",
            max_turns=0,
            mode="fresh",
            profile="web",
            tool_ids=["nmap_scan", "httpx_probe"],
            allow_destructive=True,
            guidance="Focus on the login flow.",
        )
        self.assertEqual(init_m["profile"], "web")
        self.assertEqual(init_m["tool_ids"], ["nmap_scan", "httpx_probe"])
        self.assertEqual(init_m["allow_destructive"], True)
        self.assertEqual(init_m["guidance"], "Focus on the login flow.")

        read_m = read_manifest(run_dir)
        self.assertEqual(read_m["profile"], "web")
        self.assertEqual(read_m["tool_ids"], ["nmap_scan", "httpx_probe"])
        self.assertEqual(read_m["allow_destructive"], True)
        self.assertEqual(read_m["guidance"], "Focus on the login flow.")

    def test_manifest_provenance_defaults_are_backward_compatible(self):
        # Callers that don't pass the new fields (e.g. older call sites,
        # or run_engagement with tool_ids=None meaning "unrestricted")
        # get explicit, honest defaults, not a KeyError on read later.
        rid, run_dir = create_run_dir("example.com", run_id="run_prov_default", tradecraft_home=self.home)
        init_m = create_initial_manifest(
            run_dir=run_dir, run_id=rid, target="example.com", model="test-model", max_turns=0,
        )
        self.assertIsNone(init_m["profile"])
        self.assertIsNone(init_m["tool_ids"])
        self.assertEqual(init_m["allow_destructive"], False)
        self.assertIsNone(init_m["guidance"])

    def test_save_and_load_facts_json(self):
        rid, run_dir = create_run_dir("example.com", run_id="run_facts", tradecraft_home=self.home)
        facts = FactStore()
        facts.merge_port("example.com", 80, {"service": "http"})
        facts.merge_port("example.com", 443, {"service": "https", "tls": "TLSv1.3"})

        facts_path = save_facts_json(run_dir, facts)
        self.assertTrue(facts_path.is_file())

        loaded = load_facts_json(run_dir)
        records = dict(loaded.sorted_records())
        self.assertIn(("example.com", 80), records)
        self.assertIn(("example.com", 443), records)
        self.assertEqual(records[("example.com", 443)]["tls"], "TLSv1.3")

    def test_load_seed_context_success_and_mismatch(self):
        target = "target.local"
        rid, run_dir = create_run_dir(target, run_id="seed_run", tradecraft_home=self.home)
        target_dir = get_target_dir(target, self.home)

        create_initial_manifest(run_dir, rid, target, "model", 0)
        finalize_manifest(run_dir, turns_used=10, findings_count=1, ended_at="2026-11-01T10:30:00Z")

        facts = FactStore()
        facts.merge_port("target.local", 22, {"service": "ssh"})
        save_facts_json(run_dir, facts)

        (run_dir / "log.txt").write_text("FINDING: port 22 open SSH\n", encoding="utf-8")
        update_latest_symlink(target_dir, rid)

        # Seed from latest
        seed_id, seed_prompt = load_seed_context(target, "latest", tradecraft_home=self.home)
        self.assertEqual(seed_id, "seed_run")
        self.assertIn("--- Known from a prior engagement (run seed_run, ended 2026-11-01T10:30:00Z) ---", seed_prompt)
        self.assertIn("target.local:22 -- service=ssh", seed_prompt)
        self.assertIn("FINDING: port 22 open SSH", seed_prompt)

        # Attempting to seed a different target from seed_run by ID raises ValueError
        with self.assertRaises(ValueError) as ctx:
            load_seed_context("other.target", "seed_run", tradecraft_home=self.home)
        self.assertIn("does not match current target", str(ctx.exception))
