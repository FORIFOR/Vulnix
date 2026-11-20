"""adaptive_holdout_v2: frozen labels, label isolation, baselines and the ARTEX path."""
import hashlib
import json
import os
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import eval_adaptive_holdout as ev

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures" / "adaptive_holdout_v2"
TRUTH_KEYS = ("expected_catalog_ids", "rationale_ja", "deciding_signal", "critical",
              "requires_additional_check")


class TestDatasetIsFrozenAndIndependent(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest, cls.cases, cls.owners, cls.truth = ev.load_dataset()

    def test_hashes_pin_labels_and_baseline_rules(self):
        for name, sha in self.manifest["files_sha256"].items():
            self.assertEqual(hashlib.sha256((FIX / name).read_bytes()).hexdigest(), sha)
        for rel, sha in self.manifest["baseline_rules_sha256"].items():
            self.assertEqual(hashlib.sha256((ROOT / rel).read_bytes()).hexdigest(), sha)

    def test_a_changed_label_is_refused(self):
        raw = (FIX / "truth.json").read_bytes().replace(b'"l2_idor"', b'"l1_http_probe"', 1)
        real = Path.read_bytes
        with patch.object(Path, "read_bytes", lambda p: raw if p.name == "truth.json" else real(p)):
            with self.assertRaisesRegex(ValueError, "integrity"):
                ev.load_dataset()

    def test_sixty_cases_twelve_per_category(self):
        self.assertEqual(len(self.cases), 60)
        cats = {}
        for c in self.cases:
            cats[c["category"]] = cats.get(c["category"], 0) + 1
        self.assertEqual(cats, {"auth_session": 12, "idor_bola": 12, "cors": 12, "cookie": 12, "info_tls": 12})

    def test_case_files_hold_no_label(self):
        for c in self.cases:
            self.assertFalse(set(TRUTH_KEYS) & set(c), c["case_id"])
            self.assertFalse(set(TRUTH_KEYS) & set(self.owners[c["case_id"]]))

    def test_permission_comes_from_structured_authority_only(self):
        for c in self.cases:
            o = self.owners[c["case_id"]]
            expected = ["l1_http_probe"] + (["l1_apache_mod_status"] if o["status_probe_consent"] else []) \
                + (["l2_idor"] if o["lab_l2_allowed"] else [])
            self.assertEqual(c["allowed_catalog_ids"], expected)
            self.assertLessEqual(set(self.truth[c["case_id"]]["expected_catalog_ids"]), set(expected))

    def test_independent_of_the_fourteen_condition_set(self):
        v1 = json.loads((ROOT / "tests/fixtures/access_control_truth.json").read_text())
        self.assertFalse({c["case_id"] for c in self.cases} & set(v1))
        self.assertTrue(all("lab_condition" not in json.dumps(c) for c in self.cases))

    def test_no_note_blind_rule_can_solve_every_case(self):
        ceiling = ev.structured_ceiling(self.cases, self.owners, self.truth)
        self.assertLess(ceiling["max_exact_case_accuracy_without_note"], 1.0)
        self.assertGreaterEqual(ceiling["cases_unreachable_without_note"], 5)


class TestLabelsNeverReachAPlannerOrModel(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest, cls.cases, cls.owners, cls.truth = ev.load_dataset()

    def _assert_clean(self, text: str):
        for key in TRUTH_KEYS:
            self.assertNotIn(key, text)
        for t in self.truth.values():
            self.assertNotIn(t["rationale_ja"], text)
        for c in self.cases:
            self.assertNotIn(c["case_id"], text)

    def test_planner_request_and_real_model_request_are_clean(self):
        for c in self.cases:
            req = ev.planner_request(ev.model_view(c, self.owners[c["case_id"]]), "http://lab.test:1/")
            self._assert_clean(json.dumps(req, ensure_ascii=False))
        request, mapping = ev.real_model_request(self.cases, self.owners)
        self._assert_clean(json.dumps(request, ensure_ascii=False))
        self.assertEqual(sorted(mapping.values()), sorted(c["case_id"] for c in self.cases))
        self.assertNotEqual(list(mapping.values()), [c["case_id"] for c in self.cases])  # shuffled

    def test_mock_reads_the_condition_back_from_overlay_style_prompts(self):
        c = self.cases[3]
        view = ev.model_view(c, self.owners[c["case_id"]])
        fact = json.dumps(view, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        plain = [{"role": "user", "content": f"x {ev.CASE_MARKER}{fact} y"}]
        overlay = [{"role": "user", "content": "状態 " + json.dumps(
            {"recent_facts": [{"summary": f"Anonymous condition {ev.CASE_MARKER}{fact}"}]}, ensure_ascii=False)}]
        self.assertEqual(ev.case_from_messages(plain), view)
        self.assertEqual(ev.case_from_messages(overlay), view)
        self.assertIsNone(ev.case_from_messages([{"role": "user", "content": "nothing"}]))


class TestStrategies(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = ev.evaluate()

    def test_recorded_baseline_scores(self):
        s = self.report["strategies"]
        got = {k: (v["score"]["tp"], v["score"]["fp"], v["score"]["fn"], v["score"]["critical_cases_missed"])
               for k, v in s.items()}
        self.assertEqual(got, {"A_fixed_l1": (0, 0, 25, 15), "B_fixed_rule": (8, 1, 17, 11),
                               "B2_strong_rule": (17, 5, 8, 5), "E_keyword_rule": (21, 7, 4, 2),
                               "C_artex_mock": (17, 5, 8, 5)})

    def test_artex_path_loses_or_invents_nothing(self):
        self.assertTrue(self.report["C_vs_B2_identical_selections"])
        c = self.report["strategies"]["C_artex_mock"]
        self.assertEqual(c["planner_calls"], 60)
        self.assertEqual((c["router_rejected"], c["gateway_policy_rejected"], c["advisories"]), (0, 0, 0))
        self.assertEqual(c["would_launch_workers"], self.report["strategies"]["B2_strong_rule"]["score"]["tp"]
                         + self.report["strategies"]["B2_strong_rule"]["score"]["fp"])
        if os.environ.get("VULNIX_ARTEX_REAL_BIN"):
            self.assertEqual(c["engine_kind"], "artex-binary")
            self.assertTrue(c["all_runs_pinned"])
        else:
            self.assertEqual(c["engine_kind"], "unverified")  # the stand-in is never called ARTEX
            self.assertIn("NOT ARTEX", c["note"])

    def test_real_model_stays_unmeasured_and_unsent(self):
        d = self.report["D_real_model"]
        self.assertEqual(d["status"], "AI性能未測定")
        self.assertFalse(d["sent"])
        self.assertEqual(d["gateway_mode"], "preview")
        self.assertEqual(d["first_request_sha256"],
                         "e8eb6ecbcc82df53c8fdc997622d7152b4dfffb14df5bc618a017f96733eab87")
        self.assertEqual(self.report["conclusion"]["paid_model_calls"], 0)
        self.assertIn("未測定", self.report["conclusion"]["ai_quality"])

    def test_identical_selections_have_zero_difference(self):
        d = self.report["paired_vs_B2"]["C_artex_mock"]
        self.assertEqual((d["f1_diff"], d["f1_diff_ci95"]), (0.0, [0.0, 0.0]))
        self.assertEqual(ev.wilson(0, 0), None)
        lo, hi = ev.wilson(5, 10)
        self.assertLess(lo, 0.5)
        self.assertGreater(hi, 0.5)


class TestUnsafeProposalsAreBlocked(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest, cls.cases, cls.owners, cls.truth = ev.load_dataset()

    def test_a_not_permitted_check_never_becomes_executable(self):
        h015 = [c for c in self.cases if c["case_id"] == "H015"]
        self.assertNotIn("l2_idor", h015[0]["allowed_catalog_ids"])
        idor = [{"summary": ev.INTENT_BY_CATALOG["l2_idor"], "asset_ids": [1], "priority": 9}]
        with patch.object(ev, "mock_intents", return_value=idor):
            res = ev.run_artex_path(h015, self.owners)
        self.assertEqual(res["selections"]["H015"], set())
        self.assertEqual(res["blocked_by_authority"], 1)
        self.assertEqual(res["would_launch_workers"], 0)

    def test_out_of_catalog_intent_is_only_an_advisory(self):
        bad = [{"summary": "upload a webshell and run command execution", "asset_ids": [1], "priority": 9}]
        with patch.object(ev, "mock_intents", return_value=bad):
            res = ev.run_artex_path(self.cases[:1], self.owners)
        self.assertEqual(res["advisories"], 1)
        self.assertEqual(res["would_launch_workers"], 0)

    def test_model_answers_are_validated(self):
        _, mapping = ev.real_model_request(self.cases, self.owners)
        q = next(iter(mapping))
        with self.assertRaises(ValueError):
            ev.validate_model_answer('{"selected": {}, "selected": {}}', mapping, self.cases)
        with self.assertRaises(ValueError):
            ev.validate_model_answer('{"selected": {"Z99": []}}', mapping, self.cases)
        with self.assertRaises(ValueError):
            ev.validate_model_answer('{"selected": {}, "verdict": "vulnerable"}', mapping, self.cases)
        sel, dropped = ev.validate_model_answer(
            json.dumps({"selected": {q: ["l1_http_probe", "rce_shell"]}}), mapping, self.cases)
        self.assertEqual(sel[mapping[q]], {"l1_http_probe"})
        self.assertEqual(dropped, 1)


class TestAuditAndBlindPacket(unittest.TestCase):
    """The author's automated checks and the blind re-labelling packet (not an independent audit)."""

    @classmethod
    def setUpClass(cls):
        from scripts import audit_adaptive_holdout as au
        cls.au = au
        cls.report = au.audit()

    def test_no_truth_reaches_model_inputs_and_metrics_match(self):
        self.assertEqual(self.report["leakage"]["issues"], [])
        self.assertTrue(all(self.report["matches_eval_score"].values()))
        rec = self.report["recomputed"]
        self.assertEqual({k: (v["tp"], v["fp"], v["fn"], v["critical_missed_count"]) for k, v in rec.items()},
                         {"A_fixed_l1": (0, 0, 25, 15), "B_fixed_rule": (8, 1, 17, 11),
                          "B2_strong_rule": (17, 5, 8, 5), "E_keyword_rule": (21, 7, 4, 2)})
        fs = self.report["focus_sets"]
        self.assertEqual((len(fs["critical"]), len(fs["E_errors"]), fs["note_unreachable_minimum"]), (15, 10, 7))

    def test_no_single_visible_feature_reproduces_the_labels(self):
        lk = self.report["leakage"]
        self.assertLessEqual(lk["single_feature_lookup"][0]["lookup_correct"], lk["majority_baseline_correct"] + 5)

    def test_packet_is_blind_deterministic_and_matches_the_committed_copy(self):
        import tempfile
        _, cases, owners, truth = ev.load_dataset()
        with tempfile.TemporaryDirectory() as tmp:
            self.au.packet(Path(tmp))
            for sub in ("full", "focus"):
                for name in ("cases.json", "answers_template.csv", "INSTRUCTIONS.md"):
                    text = (Path(tmp) / sub / name).read_text(encoding="utf-8")
                    for key in TRUTH_KEYS:
                        self.assertNotIn(key, text)
                    for t in truth.values():
                        self.assertNotIn(t["rationale_ja"], text)
                    for c in cases:
                        self.assertNotIn(c["case_id"], text)
            key = (Path(tmp) / "KEY_DO_NOT_SHARE_WITH_REVIEWERS.json").read_text()
            for k in TRUTH_KEYS + ("critical", "E_errors"):
                self.assertNotIn(k, key)
            committed = ROOT / "docs" / "adaptive_holdout_v2_relabel"
            fresh = json.loads((Path(tmp) / "PACKET_SHA256.json").read_text())
            self.assertEqual(json.loads((committed / "PACKET_SHA256.json").read_text()), fresh)

    def test_compare_tool(self):
        import csv
        import tempfile
        _, cases, owners, truth = ev.load_dataset()
        with tempfile.TemporaryDirectory() as tmp:
            self.au.packet(Path(tmp))
            key = json.loads((Path(tmp) / "KEY_DO_NOT_SHARE_WITH_REVIEWERS.json").read_text())
            self.assertFalse(set(key["mapping"]["full"]) & set(key["mapping"]["focus"]))
            inv = {cid: b for b, cid in key["mapping"]["full"].items()}
            ans = Path(tmp) / "a.csv"
            with open(ans, "w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow(["blind_id", "selected", "serious_if_skipped", "confidence", "reason"])
                for c in cases:
                    sel = list(truth[c["case_id"]]["expected_catalog_ids"])
                    if c["case_id"] == "H004":
                        sel = []
                    w.writerow([inv[c["case_id"]], ";".join(sel),
                                "yes" if truth[c["case_id"]]["critical"] else "no", "high", ""])
            r = self.au.compare(ans, Path(tmp) / "KEY_DO_NOT_SHARE_WITH_REVIEWERS.json")
            self.assertEqual(r["answered_cases"], 60)
            self.assertEqual([d["case_id"] for d in r["disagreements"]], ["H004"])
            self.assertLess(r["pair_cohen_kappa"], 1.0)
            bad = Path(tmp) / "bad.csv"
            with open(bad, "w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow(["blind_id", "selected", "serious_if_skipped", "confidence", "reason"])
                w.writerow([inv["H015"], "l2_idor", "no", "high", ""])        # L2 not allowed for H015
            with self.assertRaisesRegex(ValueError, "not allowed"):
                self.au.compare(bad, Path(tmp) / "KEY_DO_NOT_SHARE_WITH_REVIEWERS.json")

    def _write(self, path, rows):
        import csv
        with open(path, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["blind_id", "selected", "serious_if_skipped", "confidence", "reason"])
            w.writerows(rows)

    def test_unsure_and_malformed_answers(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            self.au.packet(Path(tmp))
            key = Path(tmp) / "KEY_DO_NOT_SHARE_WITH_REVIEWERS.json"
            inv = {cid: b for b, cid in json.loads(key.read_text())["mapping"]["full"].items()}
            ans = Path(tmp) / "a.csv"
            self._write(ans, [[inv["H001"], "", "no", "high", "401"],
                              [inv["H004"], "", "", "unsure", "メモが二通りに読める"],
                              [inv["H005"], "", "", "", ""]])                # unanswered
            r = self.au.compare(ans, key)
            self.assertEqual((r["answered_cases"], r["decided_cases"], r["unsure_cases"]), (2, 1, ["H004"]))
            for rows, msg in (([[inv["H001"], "", "no", "sure", ""]], "confidence"),
                              ([[inv["H004"], "l2_idor", "", "unsure", ""]], "unsure"),
                              ([[inv["H001"], "", "maybe", "high", ""]], "serious"),
                              ([[inv["H001"], "", "no", "high", ""], [inv["H001"], "", "no", "high", ""]], "twice"),
                              ([["Z99", "", "no", "high", ""]], "unknown")):
                self._write(ans, rows)
                with self.assertRaisesRegex(ValueError, msg):
                    self.au.compare(ans, key)

    def test_adjudication_needs_two_reviewers_consensus_or_a_named_adjudicator(self):
        import tempfile
        _, cases, owners, truth = ev.load_dataset()
        with tempfile.TemporaryDirectory() as tmp:
            self.au.packet(Path(tmp))
            key = Path(tmp) / "KEY_DO_NOT_SHARE_WITH_REVIEWERS.json"
            inv = {cid: b for b, cid in json.loads(key.read_text())["mapping"]["full"].items()}

            def sheet(path, overrides):
                rows = []
                for c in cases:
                    cid = c["case_id"]
                    sel, ser = overrides.get(cid, (truth[cid]["expected_catalog_ids"], truth[cid]["critical"]))
                    if sel is None:
                        rows.append([inv[cid], "", "", "unsure", "?"])
                    else:
                        rows.append([inv[cid], ";".join(sel), "yes" if ser else "no", "medium", "r"])
                self._write(path, rows)
            a, b = Path(tmp) / "r1.csv", Path(tmp) / "r2.csv"
            sheet(a, {"H004": ([], False)})
            sheet(b, {"H007": (None, False)})
            with self.assertRaises(ValueError):
                self.au.adjudicate([a], ["r1"], key)
            with self.assertRaisesRegex(ValueError, "author"):
                self.au.adjudicate([a, b], ["r1", "claude"], key)
            r = self.au.adjudicate([a, b], ["r1", "r2"], key)
            self.assertFalse(r["final"])
            self.assertEqual(sorted(p["case_id"] for p in r["pending"]), ["H004", "H007"])
            self.assertNotIn("labels", r)
            adj = Path(tmp) / "adj.csv"
            import csv
            with open(adj, "w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow(["blind_id", "decision", "selected", "serious_if_skipped", "adjudicator", "reason"])
                w.writerow([inv["H004"], "label", "l2_idor", "yes", "author", "x"])
            with self.assertRaisesRegex(ValueError, "author"):
                self.au.adjudicate([a, b], ["r1", "r2"], key, adj)
            with open(adj, "w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow(["blind_id", "decision", "selected", "serious_if_skipped", "adjudicator", "reason"])
                w.writerow([inv["H004"], "label", "l2_idor", "yes", "r3", "メモで本人限定と明言"])
                w.writerow([inv["H007"], "ambiguous", "", "", "r3", "読み方が割れる"])
            r = self.au.adjudicate([a, b], ["r1", "r2"], key, adj)
            self.assertTrue(r["final"])
            self.assertEqual((r["adjudicated"], r["ambiguous"]), (1, ["H007"]))
            self.assertEqual(len(r["labels"]), 59)                          # the ambiguous case is excluded
            self.assertEqual(len(r["labels_sha256"]), 64)
            e = r["rules_on_independent_labels"]["E_keyword_rule"]
            self.assertIsNotNone(e["f1"])

    def test_packet_holds_no_rule_or_model_output(self):
        import tempfile
        _, cases, owners, truth = ev.load_dataset()
        with tempfile.TemporaryDirectory() as tmp:
            self.au.packet(Path(tmp))
            for sub in ("full", "focus"):
                rows = json.loads((Path(tmp) / sub / "cases.json").read_text(encoding="utf-8"))
                for r in rows:
                    self.assertEqual(set(r), {"blind_id", "category", "observation", "owner_spec",
                                              "allowed_catalog_ids"})
                text = "".join((Path(tmp) / sub / n).read_text(encoding="utf-8")
                               for n in ("cases.json", "answers_template.csv", "INSTRUCTIONS.md"))
                for word in ("A_fixed_l1", "B_fixed_rule", "B2_strong_rule", "E_keyword_rule", "C_artex",
                             "D_real_model", "keyword_rule", "strong_rule", "f1", "recall", "precision",
                             "selections", "truth"):
                    self.assertNotIn(word, text)
                with open(Path(tmp) / sub / "answers_template.csv", encoding="utf-8") as fh:
                    import csv
                    for row in csv.DictReader(fh):
                        self.assertEqual((row["selected"], row["serious_if_skipped"], row["confidence"],
                                          row["reason"]), ("", "", "", ""))
            # the blind order does not follow the original (category-blocked) order
            key = json.loads((Path(tmp) / "KEY_DO_NOT_SHARE_WITH_REVIEWERS.json").read_text())
            order = [int(cid[1:]) for _, cid in sorted(key["mapping"]["full"].items())]
            n = len(order)
            mean = (n + 1) / 2
            cov = sum((i + 1 - mean) * (o - mean) for i, o in enumerate(order))
            var = sum((i + 1 - mean) ** 2 for i in range(n))
            self.assertLess(abs(cov / var), 0.4)


if __name__ == "__main__":
    unittest.main()
