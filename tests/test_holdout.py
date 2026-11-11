"""Scoring-v3 holdout: development-case registry, deterministic strata, reviewer CSV, and metrics
from manual labels only. Fixtures are small synthetic parquet tables; expected values hand-worked."""

from __future__ import annotations

import csv
import json
import random
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from firmable.accounts.rollup import ACCOUNTS_SCHEMA
from firmable.attribution.asn import AsnInfo
from firmable.evaluation.holdout import (BLIND_COLUMNS, CSV_COLUMNS, MANUAL_COLUMNS, STRATA, DevInputs,
                                         DevRegistry, build_holdout, discover_dev_inputs, holdout_metrics,
                                         escape_cell, norm_name, read_holdout, wilson, with_attribution_version)

SECRET_NTLM = "corp-secret-ntlm.example"
N_ACTIONABLE = 2100
INJECTION_NAME = '=HYPERLINK("http://x.example")'


def _acct(aid, name, segment="enterprise", rank=None, eligibility="eligible", actionable=False,
          ownership="medium", flags=(), signals=("S01",)):
    row = {f: None for f in ACCOUNTS_SCHEMA.names}
    row.update(account_id=aid, account_name=name, segment=segment, rank=rank, eligibility=eligibility,
               actionable=actionable, ownership_confidence=ownership, review_flags=list(flags),
               signal_ids=list(signals), top_signals=list(signals), details=["detail"], countries=["AU"],
               account_kind="domain" if aid.startswith("dom:") else "org", best_tier="A1",
               eligibility_reasons=[], ownership_reasons=["record_names_account"], explanation=[],
               actionable_blockers=[] if actionable else ["ownership_low"], n_services=2, n_ips=1,
               opportunity_priority=40.0, priority_percentile=95.5, priority_band="Medium",
               evidence_quality_band="high", legacy_rank=7, legacy_score=12.5, named_public_services=1,
               third_party_domains=0, network_operators=1, subscriber_rdns_services=0, ownership_services=2,
               named_rdns_services=0)
    return row


def _population():
    rows, rank = [], 0
    for i in range(N_ACTIONABLE):
        rank += 1
        if i % 10 == 5:  # an eligible, non-actionable account between actionable ones
            rows.append(_acct(f"org:between {i:05d}", f"Between {i:05d}", rank=rank, ownership="low"))
            rank += 1
        name = INJECTION_NAME if i == 1 else f"Acct {i:05d}"
        rows.append(_acct(f"org:acct {i:05d}", name, rank=rank, actionable=True))
    for i in range(60):
        rank += 1
        rows.append(_acct(f"org:low {i:03d}", f"Low {i:03d}", rank=rank, ownership="low"))
    for i in range(40):
        rank += 1
        rows.append(_acct(f"org:flagged {i:03d}", f"Flagged {i:03d}", rank=rank, flags=["subscriber_reverse_dns"]))
    for i in range(50):
        rank += 1
        rows.append(_acct(f"dom:techonly{i:03d}.example", f"techonly{i:03d}.example", rank=rank, signals=("S16",)))
    rows.append(_acct("dom:nosignal.example", "nosignal.example", rank=rank + 1, signals=()))
    for i in range(5):
        rows.append(_acct(f"org:pool {i}", f"Customer pool {i}", eligibility="excluded", ownership="low"))
    for i in range(20):
        rows.append(_acct(f"net:isp{i:02d}", f"ISP {i:02d}", segment="network_provider", rank=i + 1, actionable=True))
    return rows


def _write(path: Path, rows: list[dict], schema: pa.Schema | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    pq.write_table(pa.Table.from_pylist(rows, schema=schema), path)


@pytest.fixture()
def lake(tmp_path):
    acc_dir, att_dir = tmp_path / "accounts", tmp_path / "attribution"
    accounts = _population()
    _write(acc_dir / "accounts.parquet", accounts, ACCOUNTS_SCHEMA)
    ids = [a["account_id"] for a in accounts]
    k = {a: n for n, a in enumerate(ids)}  # service / observation ids never embed account ids
    _write(acc_dir / "account_signals.parquet",
           [{"account_id": a, "signal_id": "S01", "n_services": 2, "n_counted_services": 1, "n_ips": 1} for a in ids])
    _write(acc_dir / "account_evidence.parquet",
           [{"account_id": a, "service_id": f"svc-{j}-{k[a]}", "observation_id": f"obs-{j}-{k[a]}", "ip": "192.0.2.1",
             "port": 443, "sni": None, "counted": j == 0, "family": "exposure", "signal_id": "S01"}
            for a in ids for j in range(2)])
    _write(att_dir / "service_attribution.parquet",
           [{"service_id": f"svc-{j}-{k[a]}", "account_id": a, "org": "Example Org", "isp": "Example ISP",
             "reasons": ["org_is_business"]} for a in ids for j in range(2)])
    ev = []
    for a in ids:
        own = a.split(":", 1)[1].split(" ")[0].replace(".example", "") + ".example"
        ev += [{"service_id": f"svc-0-{k[a]}", "source": "cert_cn", "reg_domain": own, "outcome": "accepted"},
               {"service_id": f"svc-0-{k[a]}", "source": "sni", "reg_domain": "tenant.example", "outcome": "accepted"},
               {"service_id": f"svc-1-{k[a]}", "source": "ntlm", "reg_domain": SECRET_NTLM, "outcome": "accepted"}]
    _write(att_dir / "evidence.parquet", ev)
    _write(tmp_path / "services.parquet",
           [{"service_id": f"svc-{j}-{k[a]}", "asn": "AS64500"} for a in ids for j in range(2)])
    return {"accounts": acc_dir, "attribution": att_dir, "services": tmp_path / "services.parquet",
            "asn": {64500: AsnInfo("isp", None, ())}, "tmp": tmp_path}


def _dev_inputs(tmp: Path, with_v3: Path | None = None) -> DevInputs:
    review = tmp / "review.csv"
    with review.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["case_id", "account_id", "account_name", "suggested_qualified"])
        w.writeheader()
        for i in range(100, 200):  # outreach positions ~41-200 region and beyond
            w.writerow({"case_id": i, "account_id": f"org:acct {i:05d}", "account_name": f"Acct {i:05d}",
                        "suggested_qualified": "yes"})
        w.writerow({"case_id": "svc:x", "account_id": "", "account_name": ""})  # service case: no account
    inspect = tmp / "inspect.json"
    # a renamed id from an older attribution build: matched by name only
    inspect.write_text(json.dumps([{"account_id": "org:old id for acct 00500", "account_name": "ACCT 00500"}]))
    return DevInputs(review_csvs=[review], inspect_jsons=[inspect], v3_dirs=[with_v3] if with_v3 else [],
                     dev_files=[tmp / "2026-11-07-dev-attribution-v5.json"])  # absent: optional


def _build(lake, out: Path, seed=20261112, dev=None, **kw):
    return build_holdout(lake["accounts"], lake["attribution"], lake["services"], lake["asn"],
                         dev or _dev_inputs(lake["tmp"]), out, snapshot="2026-11-07", seed=seed, **kw)


def _rows(path: Path) -> list[dict]:
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


# ----------------------------------------------------------------------------- registry
def test_norm_name_folds_case_accents_punctuation_and_legal_suffixes():
    assert norm_name("Telefónica  Chile, S.A.") == norm_name("TELEFONICA chile s a") == "telefonica chile"
    assert norm_name("Acme Corp") == norm_name("ACME Inc.") == "acme"
    assert norm_name("Ørsted Wind Power") == norm_name("ORSTED wind-power") == "orsted wind power"
    assert norm_name("Łódź Uczelnia") == "lodz uczelnia"
    assert norm_name("มหาวิทยาลัย") == "มหาวิทยาลัย"      # Thai vowel signs are kept, not stripped
    assert norm_name(None) == ""


def test_registry_matches_by_id_then_by_name():
    reg = DevRegistry()
    reg.add("review_set", "org:acme corp", "Acme Corp")
    reg.add("dev_file:x", None, "Beta GmbH")
    assert reg.match("org:acme corp", "Acme Corp") == ("review_set",)
    assert reg.match("org:acme corporation", "ACME CORP") == ("review_set@name",)  # id changed, name kept
    assert reg.match("org:beta gmbh", "Beta GmbH") == ("dev_file:x@name",)
    assert reg.match("org:gamma", "Gamma") == ()
    reg.add("review_set", "org:ibm", "IBM")       # short names match by id only, never by name
    assert reg.match("org:ibm", "IBM") == ("review_set",)
    assert reg.match("org:ibm research", "IBM Ltd") == ()
    assert reg.counts() == {"dev_file:x": {"ids": 0, "names": 1}, "review_set": {"ids": 2, "names": 2}}


def test_attribution_version_override_swaps_only_that_path_component():
    p = Path("/w/lake/accounts/scoring=v3/attribution=v5/normalizer=v1/snapshot=S")
    assert with_attribution_version(p, 4) == Path("/w/lake/accounts/scoring=v3/attribution=v4/normalizer=v1/snapshot=S")
    with pytest.raises(ValueError):
        with_attribution_version(Path("/w/lake/services/snapshot=S"), 4)


def test_discover_dev_inputs_follows_version_tags(tmp_path):
    lake, ev = tmp_path / "lake", tmp_path / "eval"
    for scoring, att, norm in ((2, 4, 1), (3, 4, 1), (3, 5, 2)):
        d = lake / "accounts" / f"scoring=v{scoring}" / f"attribution=v{att}" / f"normalizer=v{norm}" / "snapshot=S"
        d.mkdir(parents=True)
        (d / "accounts.parquet").write_bytes(b"")
    ev.mkdir()
    for name in ("S-review.csv", "S-review.attr-v3.csv", "S-inspect-enterprise.json",
                 "S-ranking-compare-detail.json", "S-dev-attribution-v5.json", "S-holdout-v3.csv"):
        (ev / name).write_text("")
    d = discover_dev_inputs(lake, ev, "S", tmp_path / "no-docs", scoring_version=3, legacy_scoring_version=2)
    assert [p.parent.parent.name for p in d.v3_dirs] == ["attribution=v4", "attribution=v5"]
    assert [p.parent.parent.name for p in d.legacy_dirs] == ["attribution=v4"]
    assert [p.name for p in d.review_csvs] == ["S-review.attr-v3.csv", "S-review.csv"]  # never the holdout
    assert [p.name for p in d.dev_files] == ["S-dev-attribution-v5.json"]
    assert d.doc_paths == [tmp_path / "no-docs"]       # absent docs are recorded, not skipped
    reg_inputs = __import__("firmable.evaluation.holdout", fromlist=["x"]).load_dev_registry(
        type(d)(doc_paths=d.doc_paths)).inputs
    assert reg_inputs == [{"source": "doc_reference", "path": str(tmp_path / "no-docs"), "present": False, "rows": 0}]


# ----------------------------------------------------------------------------- holdout CSV
def test_same_seed_gives_byte_identical_csvs_and_another_seed_does_not(lake):
    a, b, c = (lake["tmp"] / n for n in ("a.csv", "b.csv", "c.csv"))
    _build(lake, a)
    _build(lake, b)
    _build(lake, c, seed=7)
    assert a.read_bytes() == b.read_bytes()
    assert Path(str(a)[:-4] + ".blind.csv").read_bytes() == Path(str(b)[:-4] + ".blind.csv").read_bytes()
    assert a.read_bytes() != c.read_bytes()


def test_input_row_order_does_not_change_the_csv(lake):
    a, b = lake["tmp"] / "a.csv", lake["tmp"] / "b.csv"
    _build(lake, a)
    acc = lake["accounts"] / "accounts.parquet"
    t = pq.read_table(acc)
    order = list(range(t.num_rows))
    random.Random(3).shuffle(order)
    pq.write_table(t.take(order), acc)
    _build(lake, b)
    assert a.read_bytes() == b.read_bytes()


def test_refuses_to_overwrite_unless_asked(lake):
    out = lake["tmp"] / "h.csv"
    _build(lake, out)
    with pytest.raises(FileExistsError):
        _build(lake, out)
    _build(lake, out, overwrite=True)


def test_a_stale_blind_file_blocks_a_run_even_without_blind_output(lake):
    out = lake["tmp"] / "h.csv"
    blind = lake["tmp"] / "h.blind.csv"
    _build(lake, out)
    out.unlink()
    with pytest.raises(FileExistsError, match="blind"):
        _build(lake, out, blind=False)
    _build(lake, out, blind=False, overwrite=True)
    assert out.exists() and not blind.exists()   # the stale blind file is removed, never left beside new cases


def test_out_path_inside_a_git_repository_is_refused(lake):
    repo = lake["tmp"] / "repo"
    (repo / ".git").mkdir(parents=True)
    with pytest.raises(ValueError, match="Git"):
        _build(lake, repo / "eval" / "h.csv")


def test_escape_cell_neutralises_spreadsheet_formulas():
    for v in ("=1+1", "+1", "-2", "@SUM(A1)", "\tx", "\rx"):
        assert escape_cell(v) == "'" + v
    assert escape_cell("Acme") == "Acme" and escape_cell("") == ""


def test_strata_sizes_frames_and_top_enterprise(lake):
    out = lake["tmp"] / "h.csv"
    m = _build(lake, out)
    s = m["strata"]
    assert {k: v["drawn"] for k, v in s.items()} == {st.name: st.size for st in STRATA}
    assert s["top_enterprise"]["frame_n"] == 40 and s["rank_41_200"]["frame_n"] == 160
    assert s["rank_401_2000"]["frame_n"] == 1600
    assert s["network_provider/top5"]["frame_n"] == 5 and s["network_provider/random"]["frame_n"] == 15
    assert s["low_confidence_review/review_flag"]["frame_n"] == 40
    assert s["technographic_only"]["frame_n"] == 50   # S16 required: the signal-free account is not in it
    # ownership_low frame: 60 low + 210 "between" accounts (also low, not actionable)
    assert s["low_confidence_review/ownership_low"]["frame_n"] == 270
    rows = _rows(out)
    assert len(rows) == m["cases"] == m["unique_accounts"] == len({r["account_id"] for r in rows})
    assert m["stratum_memberships"] == sum(len(r["strata"].split(";")) for r in rows)
    top = sorted((r for r in rows if "top_enterprise" in r["strata"].split(";")),
                 key=lambda r: int(r["system_outreach_position"]))
    assert [int(r["system_outreach_position"]) for r in top] == list(range(1, 41))
    assert top[0]["account_id"] == "org:acct 00000"
    # outreach position skips non-actionable accounts: acct 00006 has rank 8 but position 7
    pos7 = next(r for r in top if r["system_outreach_position"] == "7")
    assert pos7["account_id"] == "org:acct 00006" and pos7["system_rank"] == "8"
    # the review order is shuffled, not grouped by rank
    assert [r["case_id"] for r in rows] == [f"H{i:03d}" for i in range(1, len(rows) + 1)]
    assert [r["account_id"] for r in rows[:40]] != [r["account_id"] for r in top]


def test_dev_cases_never_enter_random_strata_and_name_matches_count(lake):
    out = lake["tmp"] / "h.csv"
    m = _build(lake, out)
    non_dev = {s.name for s in STRATA if s.mode == "non_dev"}
    rows = _rows(out)
    for r in rows:
        if set(r["strata"].split(";")) & non_dev:
            assert r["dev_case"] == "no", r
    assert all(v["drawn_dev"] == 0 for k, v in m["strata"].items() if k in non_dev)
    reg = json.loads(Path(str(out)[:-4] + ".dev-registry.json").read_text())
    assert reg["counts_by_source"]["review_set"] == {"ids": 100, "names": 100}
    assert reg["current_build_accounts_by_source"] == {"inspect_worksheet@name": 1, "review_set": 100}
    assert {i["source"]: i["present"] for i in reg["inputs"]}["dev_file:attribution-v5"] is False


def test_rank_41_200_is_filled_from_dev_cases_when_its_frame_was_development_data(lake):
    out = lake["tmp"] / "h.csv"
    m = _build(lake, out, dev=_dev_inputs(lake["tmp"], with_v3=lake["accounts"]))
    s = m["strata"]["rank_41_200"]
    assert s["frame_non_dev_n"] == 0 and s["drawn"] == 25 and s["drawn_dev"] == 25
    rows = [r for r in _rows(out) if "rank_41_200" in r["strata"]]
    assert len(rows) == 25 and all(r["dev_case"] == "yes" and "v3_actionable_top400" in r["dev_sources"] for r in rows)
    # every excluded and pool-label account is development data
    assert m["current_build_accounts_marked_dev"] >= 400 + 5


def test_columns_carry_no_model_or_heuristic_judgement_no_ntlm_and_blank_labels(lake):
    out = lake["tmp"] / "h.csv"
    _build(lake, out)
    data = out.read_bytes().decode()
    blind = Path(str(out)[:-4] + ".blind.csv")
    rows = _rows(out)
    assert tuple(rows[0]) == CSV_COLUMNS
    assert not [c for c in CSV_COLUMNS if c.startswith("suggested") or "verdict" in c]
    assert SECRET_NTLM not in data and SECRET_NTLM not in blind.read_text()
    for col in ("details", "sample_services", "attribution_reasons", "sample_naming_domains",
                "sample_third_party_domains"):
        assert all(SECRET_NTLM not in r[col] for r in rows), col
    assert all(r[c] == "" for r in rows for c in MANUAL_COLUMNS)
    b = _rows(blind)
    assert tuple(b[0]) == BLIND_COLUMNS
    hidden = ("strata", "dev_case", "dev_sources", "segment", "best_tier", "account_kind", "account_id",
              "attribution_reasons", "app_path", "inspect_command")
    assert not [c for c in BLIND_COLUMNS if c.startswith("system_") or c in hidden]
    assert [r["case_id"] for r in b] == [r["case_id"] for r in rows]
    assert [r["account_ref"] for r in b] == [r["account_ref"] for r in rows]
    text = blind.read_text()
    assert not [p for p in ("org:", "dom:", "net:") if p in text]
    assert "account_name" in BLIND_COLUMNS and "evidence_command" in BLIND_COLUMNS
    inj = next(r for r in rows if r["account_id"] == "org:acct 00001")
    assert inj["account_name"] == "'" + INJECTION_NAME
    assert next(x for x in b if x["case_id"] == inj["case_id"])["account_name"] == "'" + INJECTION_NAME
    r = next(r for r in rows if r["account_id"] == "org:acct 00000")
    assert r["app_path"] == "/accounts/org:acct%2000000"
    assert r["evidence_command"] == "uv run firmable evidence obs-0-0"
    assert "--account 'org:acct 00000'" in r["inspect_command"]
    assert r["sample_naming_domains"] == "acct.example(1)"
    assert r["sample_third_party_domains"] == "tenant.example(1)"
    assert r["openasn_category"] == "isp" and r["asn"] == "AS64500"
    assert r["system_actionable"] == "yes" and r["signal_services"] == "S01 svc=2 counted=1 ips=1"


# ----------------------------------------------------------------------------- metrics
def _case(cid, strata, dev, segment="enterprise", pos="", actionable="yes", signals="S01", **labels):
    r = {"case_id": cid, "strata": strata, "dev_case": dev, "account_id": f"org:{cid}", "segment": segment,
         "system_actionable": actionable, "system_outreach_position": pos, "signal_ids": signals}
    for c in ("entity_type", "qualified", "attribution_correct", "evidence_supported"):
        r[f"manual_{c}"] = labels.get(c, "")
    r["manual_reviewer"], r["manual_notes"] = labels.get("reviewer", ""), ""
    return r


ROWS = [
    _case("H1", "top_enterprise", "yes", pos=1, qualified="yes", entity_type="enterprise",
          attribution_correct="yes", evidence_supported="yes"),
    _case("H2", "top_enterprise", "yes", pos=2, qualified="no"),
    _case("H3", "top_enterprise", "no", pos=25, qualified="unclear"),       # unclear counts as a negative
    _case("H4", "top_enterprise", "yes", pos=30),                           # unlabeled
    _case("H5", "random_eligible", "no", actionable="no", signals="S16", qualified="no",
          attribution_correct="unclear", evidence_supported="yes"),
    _case("H6", "network_provider/top5", "yes", segment="network_provider", entity_type="network_provider",
          qualified="no"),
    _case("H7", "network_provider/random", "no", segment="network_provider", entity_type="enterprise",
          attribution_correct="yes"),
]


def test_wilson_interval_values():
    assert wilson(0, 0) is None
    assert wilson(8, 10) == (0.4902, 0.9433)
    assert wilson(0, 10) == (0.0, 0.2775)
    assert wilson(10, 10) == (0.7225, 1.0)
    assert wilson(1, 3) == (0.0615, 0.7923)


def test_metrics_with_no_labels_report_zero_denominators_and_no_rates():
    m = holdout_metrics([{**r, **{c: "" for c in MANUAL_COLUMNS}} for r in ROWS])
    assert m["cases"] == 7 and m["cases_labeled"] == 0
    p = m["precision_at_k"]["40"]["census"]
    assert p == {"num": 0, "den": 0, "unlabeled": 4, "cases": 4, "rate": None, "wilson95": None,
                 "note": "no labels in this subgroup"}
    assert m["attribution_correct"]["overall"]["held_out"]["den"] == 0
    assert "no labels" in " ".join(m["notes"])


def test_precision_at_k_is_a_census_flagged_as_contaminated_never_a_clean_headline():
    pk = holdout_metrics(ROWS)["precision_at_k"]
    assert pk["contamination"] == "3 of 4 top_enterprise cases are development data"
    # top 20 = H1 (yes), H2 (no)
    assert pk["20"]["census"] == {"num": 1, "den": 2, "unlabeled": 0, "cases": 2, "rate": 0.5,
                                  "wilson95": list(wilson(1, 2))}
    assert pk["20"]["dev_cases"] == 2 and pk["20"]["clean"] is None and pk["20"]["clean_reason"]
    assert not {"all", "held_out", "dev"} & set(pk["20"])
    # top 40 = H1 yes, H2 no, H3 unclear (negative), H4 unlabeled
    c40 = pk["40"]["census"]
    assert (c40["num"], c40["den"], c40["unlabeled"], c40["wilson95"]) == (1, 3, 1, [0.0615, 0.7923])
    only_dev = holdout_metrics([r for r in ROWS if r["case_id"] != "H3"])["precision_at_k"]
    assert only_dev["contamination"] == "top_enterprise is entirely development data"


def test_metrics_math_on_hand_labeled_cases():
    m = holdout_metrics(ROWS)
    att = m["attribution_correct"]
    assert (att["overall"]["all"]["num"], att["overall"]["all"]["den"]) == (2, 3)   # H5 unclear = negative
    assert (att["overall"]["held_out"]["num"], att["overall"]["held_out"]["den"]) == (1, 2)
    assert (att["by_stratum"]["network_provider"]["all"]["num"], att["by_stratum"]["network_provider"]["all"]["den"]) == (1, 1)
    assert att["by_stratum"]["network_provider/top5"]["all"]["unlabeled"] == 1
    ev = m["evidence_supported"]["overall"]["all"]
    assert (ev["num"], ev["den"]) == (2, 2)
    agree = m["entity_type_agreement"]
    assert (agree["by_segment"]["enterprise"]["all"]["num"], agree["by_segment"]["enterprise"]["all"]["den"]) == (1, 1)
    np_ = agree["by_segment"]["network_provider"]["all"]
    assert (np_["num"], np_["den"]) == (1, 2)
    assert set(agree["by_stratum"]) == {"network_provider", "network_provider/random", "network_provider/top5"}
    assert agree["by_stratum"]["network_provider/random"]["all"]["num"] == 0
    q = m["qualified"]
    assert (q["by_actionable"]["actionable"]["all"]["num"], q["by_actionable"]["actionable"]["all"]["den"]) == (1, 3)
    assert (q["by_actionable"]["not_actionable"]["all"]["num"], q["by_actionable"]["not_actionable"]["all"]["den"]) == (0, 1)
    assert q["by_signal_group"]["technographic_only"]["all"]["den"] == 1
    assert q["by_signal_group"]["exposure"]["all"]["den"] == 3
    assert q["by_stratum"]["random_eligible"]["held_out"]["den"] == 1
    # qualified is an enterprise question: network-provider strata report entity agreement instead
    assert set(q["by_stratum"]) == {"top_enterprise", "random_eligible"}


def _write_csv(path: Path, rows: list[dict], encoding: str = "utf-8") -> Path:
    cols = list(rows[0])
    with path.open("w", newline="", encoding=encoding) as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)
    return path


FULL = [{**{c: "" for c in CSV_COLUMNS}, **r, "account_ref": f"ref{r['case_id']}"} for r in ROWS]


def test_reader_refuses_suggested_columns_model_reviewers_and_bad_values(tmp_path):
    ok = read_holdout(_write_csv(tmp_path / "ok.csv", FULL))
    assert holdout_metrics(ok)["cases_labeled"] == 6
    with pytest.raises(ValueError, match="suggest"):
        read_holdout(_write_csv(tmp_path / "s.csv", [{**r, "suggested_qualified": "yes"} for r in FULL]))
    for who in ("Claude", "GPT-4o", "claude-opus", "Gemini 2", "Llama", "an AI", "the model"):
        with pytest.raises(ValueError, match="model"):
            read_holdout(_write_csv(tmp_path / "m.csv", [{**r, "manual_reviewer": who} for r in FULL]))
    for who in ("Jane Modelo", "Agent Smith", "Alana", "Kai"):   # whole words only
        read_holdout(_write_csv(tmp_path / "h.csv", [{**r, "manual_reviewer": who} for r in FULL]))
    with pytest.raises(ValueError, match="not in"):
        read_holdout(_write_csv(tmp_path / "v.csv", [{**r, "manual_qualified": "maybe"} for r in FULL]))
    with pytest.raises(ValueError, match="dev_case"):
        read_holdout(_write_csv(tmp_path / "d.csv", [{**r, "dev_case": "maybe"} for r in FULL]))
    with pytest.raises(ValueError, match="duplicate case_id"):
        read_holdout(_write_csv(tmp_path / "dup.csv", FULL + FULL[:1]))
    bad = tmp_path / "latin1.csv"
    _write_csv(bad, [{**r, "manual_notes": "café"} for r in FULL], encoding="latin-1")
    with pytest.raises(ValueError, match="latin1.csv.*UTF-8"):
        read_holdout(bad)
    bom = _write_csv(tmp_path / "bom.csv", FULL, encoding="utf-8-sig")   # Excel's UTF-8 export
    assert len(read_holdout(bom)) == 7


def test_labels_from_a_blind_csv_join_strictly_by_case_id(tmp_path):
    unlabeled = [{**r, **{c: "" for c in MANUAL_COLUMNS}} for r in FULL]
    key = _write_csv(tmp_path / "key.csv", unlabeled)
    blind_rows = [{c: r[c] for c in BLIND_COLUMNS} for r in reversed(FULL)]
    blind = _write_csv(tmp_path / "blind.csv", blind_rows)
    rows = read_holdout(key, labels=blind)
    assert holdout_metrics(rows)["precision_at_k"] == holdout_metrics(ROWS)["precision_at_k"]
    with pytest.raises(ValueError, match="one file"):
        read_holdout(_write_csv(tmp_path / "both.csv", FULL), labels=blind)
    with pytest.raises(ValueError, match="dupblind.csv.*duplicate case_id"):
        read_holdout(key, labels=_write_csv(tmp_path / "dupblind.csv", blind_rows + blind_rows[:1]))
    with pytest.raises(ValueError, match="different cases"):
        read_holdout(key, labels=_write_csv(tmp_path / "short.csv", blind_rows[1:]))
    swapped = [{**r, "account_ref": "other"} if r["case_id"] == "H1" else r for r in blind_rows]
    with pytest.raises(ValueError, match="H1.*account_ref"):
        read_holdout(key, labels=_write_csv(tmp_path / "swapped.csv", swapped))
