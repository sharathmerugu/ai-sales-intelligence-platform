# Signals implementation (Phase 3, M1)

Status: built and verified on 2026-11-09 against sealed snapshot `2026-11-07`.
Signals v1 covers **S01, S03, S04, S05, S06, S16**. The contract is
`docs/phase3-plan.md` ("Contract: signal_hits").

## 1. What exists

| File | Holds |
|---|---|
| `src/firmable/signals/registry.py` | `Signal` dataclass, `SIGNALS` (six entries), `SIGNALS_VERSION = 1`, `FACT_PLACEHOLDERS`. Each entry has a SQL predicate, `detail`, `match_basis`, `sub_flags` and `evidence_json` expressions, and the observed-fact template, inferred risk and hypothesis (wording per `research-findings.md` §3) |
| `src/firmable/signals/build.py` | `build_signal_hits(services_parquet, out_parquet, snapshot_id=None, memory_limit='4GB', threads=4, temp_directory=None)`, `signal_hits_sql(source_sql)`, `evaluate(con, relation)`, `signal_hits_path(pipe, snapshot_id)` |
| `src/firmable/signals/reconcile.py` | Verification tool: rebuilds the research `svc` from the legacy slim Parquet and attributes every count delta to a cause (§4) |
| `tests/test_signals.py` | 26 tests: contract schema, provenance, atomic publish, snapshot filter, NULL lists, per-signal positives and catalog counterexamples, registry wording |

Output path:
`~/firmable-work/lake/signal_hits/signals=v1/normalizer=v1/snapshot=2026-11-07/signal_hits.parquet`
(1,836,092 rows, 190 MB, sorted by `signal_id, service_id`).

### How it runs

One DuckDB query over the services Parquet (`hive_partitioning = false`):

1. Project the 31 columns the rules need and add NULL-safe helpers
   (`p_l`, `t_l`, `module_l`, `tags_l`, `vers_l`, `pkeys`, `cdn`,
   `foreign_answer`, `s01_proto`).
2. Evaluate all six predicates per row as `coalesce(pred, false) AS hit_Sxx`
   and materialize only the rows with any hit.
3. `UNION ALL` one branch per signal that emits the contract columns.
4. `COPY` to `signal_hits.parquet.tmp`, then publish with `os.replace`.

The layer only reads `services`. One row per (signal_id, service_id) is
guaranteed by construction, because each branch reads each service row once.

### Commands

```bash
uv run pytest tests/test_signals.py                      # 26 tests, ~4.5 s
uv run python -c "
from pathlib import Path; from firmable.signals import build_signal_hits
w = Path.home() / 'firmable-work/lake'
print(build_signal_hits(
    w / 'services/services=v1/normalizer=v1/snapshot=2026-11-07/services.parquet',
    w / 'signal_hits/signals=v1/normalizer=v1/snapshot=2026-11-07/signal_hits.parquet',
    snapshot_id='2026-11-07', memory_limit='4GB', threads=4))"
uv run python -m firmable.signals.reconcile --snapshot 2026-11-07   # §4 table, ~21 s
```

There is no CLI subcommand yet (`cli.py` is outside this module's ownership).
`signal_hits_path(pipe, snapshot_id)` gives the canonical path for one.

## 2. Rules: research port and v1 changes

Each research predicate (`sql/exploration.sql` l.412-480) was ported with the
v1 column mapping. These details were kept from the research:

- `NOT is_cdn` on S01, S03, S04, S05 and S06. S16 allows CDN rows.
- `transport = 'tcp'` on S01.
- Exact list membership on `ssl_versions`, because `-TLSv1` means
  *disabled*.
- Only `rsa` keys under 2048 bits are weak. `dsa` with 256 or 384 bits is
  ECDSA.
- RDP is excluded from the self-signed criterion, which requires an HTTP
  status.
- DB-module-only hits are excluded when the banner starts with `HTTP/`.
- Every list predicate is coalesced, so NULL `tags` and NULL `ssl_versions`
  behave like `[]`.

These are the v1 changes. Each one has a test, and each one's full-data
effect is measured in §4.

| Signal | Change | Why | Effect |
|---|---|---|---|
| S01 | Also fires when `protocol_json` holds a `cisco_anyconnect` or `sonicwall` object, or a `fortinet` object whose `model` starts with `FG` or `FWF` (FortiGate / FortiWiFi) | v1 keeps these parsed device objects. A model string is a device fingerprint, not a port guess. FortiManager (`FMG`), FortiAnalyzer (`FAZ`), FortiClient EMS (`FCT`) and other non-gateway models are left out | +183 (all FortiGate with no product string). The AnyConnect and SonicWall keys add 0 on this snapshot |
| S01, S05 | A title-only match is ignored when the title contains `coming soon` | Parked pages are named after a host (`sslvpn.<domain> - Coming Soon`, `jenkins.<domain> - Coming Soon`) | S01 −47, S05 −23 |
| S03 | A module-only hit (`rdp`, `telnet`, `x11`, `rlogin`, `nomachine`) needs `NOT foreign_answer`: the banner does not start with `HTTP/` or `SSH-`, and the product does not name another service (`nginx`, `apache`, `iis`, `openresty`, `tengine`, `socks`, `ssh`, `http`, `ftpd`, `smtpd`, `imapd`, `pop3`, `nntpd`, `lpd`, `TLS`, `stockfish`, `vnc`) | CLAUDE.md: a module name says which probe ran, not what answered. Product hits (`Remote Desktop Protocol`, `VNC`, `telnetd`, ...) are unaffected, so a VNC server that answers the `rethinkdb` probe still counts as S03 VNC | −1,096 (638 HTTP, 317 SSH, 86 SOCKS, 55 other daemons) |
| S04 | The same `foreign_answer` guard on the DB-module clause, which already excluded HTTP in the research | Same reason. Examples: `rethinkdb`/`mysql`/`riak` probes answered by OpenSSH, SOCKS4 rejects, VNC | −68 |
| S04 | `protocol_json` keys `redis`, `mysql`, `mysqlx`, `mongodb`, `influxdb`, `mssql_ssrp` count as protocol evidence | New v1 evidence | +0 on this snapshot: every such row already matched. They raise `match_basis` to `protocol` where the product is missing |
| S04 | The `database` tag on a generic web-server product (`nginx`, `openresty`, `tengine`, `lighttpd`, `caddy`, `apache`, `IIS`, `HTTPAPI`) is not counted | Catalog counterexample: nginx 404 fronts carried the tag | 0 on v1 services. No such row exists after the fingerprint-soup and empty-banner filters |
| S05 | Word boundaries on `consul`, `unifi` and `ipmi` | The research `consul` matched inside a word ("Consulting", "Consultants", "Consulta") on 734 of 744 hits; only 10 are HashiCorp Consul. `unifi` matched "Unified Messaging" / "Unified Services Router" (100). `ipmi` matched "KIPMittelweg" / "EquipMinistry" (2) | −835 |
| S05 | `Bitwarden Web vault` gets the label `Bitwarden`, not `HashiCorp Vault` | Label accuracy only | 0 |

Not changed, but noted:

- **S06 `self_signed_http`** stays as researched: the `self-signed` tag
  plus an HTTP status, with RDP excluded. It is the second-largest S06
  flag (79,628).
- **S16** keeps every `http_waf` value, including ones that are not
  security vendors (`ASP.NET Generic`, `Open-Resty Lua Nginx`, `LiteSpeed`,
  `Squarespace`, `CacheWall (Varnish)`). The `detail` label shows which
  one it is, so scoring can weight vendors.

### Output semantics

- `match_basis` is the strongest clause that matched. For S01:
  `product` > `protocol` (`protocol_json` object) > `title`. For S03 and S04:
  `product` > `protocol` (module whose answer is not foreign, or a
  `protocol_json` object) > `tag`. For S05: `product` > `title` > `tag`.
  S06 is always `tls`. S16 is `waf` when `http_waf` is set, else `product`.
- `detail` is a priority-ordered label. Labels are tried on the product,
  then on the protocol object or module, then on the title. The fallback
  is the raw product, title or a generic label. For S06 the label names
  the most severe flag: SSLv2/v3 > expired > weak RSA > legacy TLS >
  weak signature > self-signed.
- `sub_flags` for S06 are in a fixed order: `cert_expired, legacy_tls,
  ssl_v2_v3, weak_rsa_key, weak_signature, self_signed_http`. S16 has
  `waf` and/or `appliance`. The other signals have `[]`.
- `evidence_json` holds only the matched field values. The FortiGate
  serial number is **not** copied; only `fortinet_model` is. NTLM fields
  are never copied (sensitive, behind human review).
- `observed_fact_template` uses only `FACT_PLACEHOLDERS`. That is checked by
  a test, and so is the absence of forbidden claims ("vulnerable to",
  "unauthenticated", "breached", "intends to", ...). Every hypothesis uses
  "may".

## 3. Full-data run (snapshot 2026-11-07)

Input: services v1, 5,233,493 rows. Settings: `memory_limit='4GB'`,
`threads=4`, on a 16 GB laptop while another agent ran DuckDB at the same
time. Measured with `/usr/bin/time -l`:

| Measure | Value |
|---|---|
| wall time (`build_signal_hits`) | **9.5 s** (9.7 s process) |
| peak RSS | 3.84 GB |
| output rows | 1,836,092 |

| Signal | Services | Distinct IPs | `match_basis` split |
|---|---|---|---|
| S01 | 26,847 | 24,055 | product 19,957 · title 6,705 · protocol 185 |
| S03 | 24,983 | 24,007 | product 21,140 · protocol 3,843 |
| S04 | 9,863 | 8,972 | product 7,610 · protocol 2,150 · tag 103 |
| S05 | 34,822 | 32,109 | product 17,434 · title 17,290 · tag 98 |
| S06 | 217,167 | 200,459 | tls 217,167 |
| S16 | 1,522,410 | 638,314 | waf 1,444,657 · product 77,753 (1,215,228 rows are CDN) |

**Top 8 `detail` per signal:**

| Signal | detail (services) |
|---|---|
| S01 | SonicWall 6,991 · Citrix NetScaler 4,583 · FortiGate 3,948 · DrayTek 3,245 · SSL VPN portal (unbranded) 2,006 · Check Point 1,733 · Palo Alto GlobalProtect 1,259 · F5 BIG-IP 867 |
| S03 | RDP 13,087 · Telnet 5,413 · VNC 5,328 · WinRM 500 · ScreenConnect 400 · X11 109 · TeamViewer 70 · rlogin 51 |
| S04 | MinIO 2,476 · MySQL 1,607 · ClickHouse 1,416 · SQL Server Browser 1,229 · MS-SQL 736 · MariaDB 675 · Redis 570 · PostgreSQL 383 |
| S05 | WHM/cPanel 6,751 · MikroTik RouterOS 6,186 · UniFi 4,390 · Kubernetes 4,048 · Plesk 2,689 · MinIO Console 2,336 · Control Web Panel 1,188 · GitLab 1,155 |
| S06 | TLS 1.0/1.1 accepted 92,462 · Self-signed certificate 54,010 · Expired certificate 51,968 · SHA-1/MD5 signature 8,077 · SSLv2/SSLv3 accepted 6,457 · RSA key < 2048 bits 4,193 |
| S16 | Cloudflare 496,376 · Imperva Incapsula 419,002 · Amazon CloudFront 226,029 · AWS ELB 112,927 · Akamai 93,810 · F5 BIG-IP 43,331 · SonicWall 27,464 · Squarespace 24,966 |

**S06 sub-flags** (v1 / research catalog Q6.3):

| Sub-flag | v1 | Research | Delta | From NULL-org | From recovered rows |
|---|---|---|---|---|---|
| cert_expired | 54,003 | 53,985 | +18 | +13 | +5 |
| legacy_tls | 112,952 | 112,841 | +111 | +24 | +87 |
| ssl_v2_v3 | 6,457 | 6,456 | +1 | 0 | +1 |
| weak_rsa_key | 9,614 | 9,614 | 0 | 0 | 0 |
| weak_signature | 17,026 | 17,023 | +3 | +2 | +1 |
| self_signed_http | 79,628 | not published | — | | |

## 4. Reconciliation with the research prevalence table

`python -m firmable.signals.reconcile` rebuilds the research `svc` from
`~/firmable-work/legacy/full_slim_v2.parquet` (eligible rows; latest `ts`
per `(ip, port, transport, raw SNI)`). It then runs the research predicates
verbatim on that table and on v1 `services`, and joins the results on the
service key. With NULL-org rows set aside, the research rebuild reproduces
the published "Services" column **exactly** for all six signals.

| Signal | Research published | NULL org kept | Recovered rows | Whitespace-only banner | SNI case merge | Research rule on v1 | v1 rule added | v1 rule removed | **v1** |
|---|---|---|---|---|---|---|---|---|---|
| S01 | 26,700 | +7 | +4 | 0 | 0 | 26,711 | +183 | −47 | **26,847** |
| S03 | 26,114 | 0 | 0 | −35 | 0 | 26,079 | 0 | −1,096 | **24,983** |
| S04 | 9,930 | +1 | 0 | 0 | 0 | 9,931 | 0 | −68 | **9,863** |
| S05 | 35,678 | +2 | 0 | 0 | 0 | 35,680 | 0 | −858 | **34,822** |
| S06 | 217,036 | +39 | +92 | 0 | 0 | 217,167 | 0 | 0 | **217,167** |
| S16 | 1,522,317 | +40 | +57 | 0 | −4 | 1,522,410 | 0 | 0 | **1,522,410** |

The causes:

- **NULL org kept (+89 in total).** The research `svc` was built with an
  inner `JOIN org_profile USING (org)`. That join silently dropped every
  service whose `org` is NULL (1,162 raw rows). v1 services has no such
  join. The rebuild matches the published numbers exactly once these
  rows are excluded.
- **Recovered rows (+153).** Every key that v1 has and the research lacks
  is a `unicode_repaired` row. These are the 451 lines the research parser
  dropped (`PHASE3_HANDOFF.md` §6).
- **Whitespace-only banner (−35, S03).** All 35 are `telnet` services whose
  banner contains only whitespace. The v1 empty-banner rule strips all
  whitespace; the research `trim` stripped only spaces. These are part of
  the documented 54 eligible-row difference.
- **SNI case merge (−4, S16).** The research partitioned on the raw
  `scan_hostname`, so `Webclusters.<domain>` and `webclusters.<domain>` on
  the same IPv6 were two services. v1 lower-cases SNI, so they are one.
- **v1 rule changes.** See §2. The removals break down as follows:
  - S01: parked titles −47.
  - S03: −1,096 in total. HTTP answer −638, SSH answer −317, product
    names another service −141 (86 of them SOCKS).
  - S04: −68 in total. Product names another service −35, SSH −33.
  - S05: −858 in total. Keyword inside a word −835, parked −23.

Reconcile wall time: 20.6 s (4 GB, 4 threads).

## 5. Spot checks (3 pseudo-random hits per signal; IPs masked to /24)

Sample: `ORDER BY hash(service_id || 'm1-spot')`.

| Signal | Hit | Verdict |
|---|---|---|
| S01 | x.x.x.x:443 SonicWall, title "Login", cert CN `192.168.168.168` | Correct. The CN is the vendor default, an attribution concern for M2 |
| S01 | x.x.x.x:10443 `Fortinet FortiGate-60F`, `fortinet_model` FGT60F | Correct |
| S01 | x.x.x.x:444 no product, title "FortiGate", CN `FortiGate` | Correct (title basis) |
| S03 | x.x.x.x:3389 `Remote Desktop Protocol` 10.0.26100 | Correct |
| S03 | x.x.x.x:23023 telnet module, no product | Plausible (protocol basis; non-standard port) |
| S03 | x.x.x.x:23 telnet module, no product | Plausible |
| S04 | x.x.x.x:3306 MySQL 8.4.9 (`mysql` object, database tag) | Correct |
| S04 | x.x.x.x:3306 MariaDB 10.1.48 | Correct |
| S04 | x.x.x.x:1434/udp SQL Server Browser (`mssql_ssrp`) | Correct. It reveals SQL instances; it is not itself a SQL port (catalog false-positive note) |
| S05 | x.x.x.x:443 HP iLO | Correct |
| S05 | x.x.x.x:80 title "RouterOS router configuration page" | Correct |
| S05 | x.x.x.x:443 GitLab Self-Managed | Correct |
| S06 | x.x.x.x:443 product `AWS ELB`, expired 2023 cert + TLS 1.0/1.1 | Correct as observed. The endpoint is a cloud load balancer, so attribution decides ownership |
| S06 | x.x.x.x:443 "Cisco Systems Login", self-signed | Correct. Device-management self-signed certificates are the catalog's known false-positive class |
| S06 | x.x.x.x:5006 self-signed, `ssl_versions` empty | Correct for the self-signed flag |
| S16 | x.x.x.x:80 CloudFront | Correct (CDN allowed) |
| S16 | x.x.x.x:80 CloudFront error page | Correct |
| S16 | x.x.x.x:2086 Cloudflare | Correct |

The first S05 sample, taken before the word-boundary change, returned
x.x.x.x with a small consultancy's website title. That led to
the §2 S05 change.

## 6. Known limitations

- **Residual decoy products.** About two dozen rows carry
  `Sophos SSL VPN User Portal` with unrelated titles ("pgAdmin 4",
  "WordPress Setup", "VMware Aria Operations"). These are single-product
  mislabels that the fingerprint-soup filter does not catch. S01 counts
  them.
- **Research product lists kept as is.** `barracuda` includes spam
  filters and the Barracuda Embedded Web Server on Honeywell NetAXS
  access panels. `juniper` includes the Junos Web Device Manager. DrayTek
  and Zyxel are SOHO routers (catalog false-positive class). Scoring
  should weight `detail`.
- **The `foreign_answer` regex is a deny-list.** Some module-only S04 hits
  answered by unrelated devices remain, e.g. `riak` answered by a MikroTik
  bandwidth-test server or a Roku SoundBridge (2 rows). A protocol-level
  allow-list would be stricter, but it needs banner parsers per protocol.
- **Fortinet models.** Only `FG*` and `FWF*` count as gateways. `F2K`
  (5 rows) may be a FortiGate 2000-series and is excluded conservatively.
- **S16 includes non-security `http_waf` values** (see §2).
- **No `cisco_anyconnect` / `sonicwall` gain on this snapshot.** Every such
  row already matched by product or title. The clause is kept for future
  snapshots.
- **One snapshot.** No signal implies change over time. Templates state
  only what the scanner recorded at `observed_at`.
- **Tests are synthetic.** No real-data regression fixture exists for
  S04 (see `PHASE3_HANDOFF.md` §13). Full-data validation is the
  reconciliation above.
