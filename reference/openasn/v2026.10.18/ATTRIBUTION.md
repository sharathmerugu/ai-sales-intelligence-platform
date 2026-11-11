# Attribution

OpenASN's canonical artifacts are compiled exclusively from sources whose
exact redistributed data carries explicit redistribution rights, plus one
class of input: uncopyrightable facts that OpenASN's own code recomputes from
a primary source whose terms require nothing beyond attribution (the IP→ASN
backbone, below). This file ships inside every release. Full license texts as
fetched and pinned: `data/licenses/` in the repository; the build fails if any
upstream license text changes (SHA-256 pinning).

## RouteViews — the IP→ASN backbone (CC BY 4.0)

[![RouteViews](https://assets.routeviews.org/logos/png/transparent-background/routeviews-powered-by-black_transparent_SMALL.png)](https://www.routeviews.org/)

This product utilizes data provided by RouteViews (www.routeviews.org). Use of
this data is subject to the CC BY 4.0 license.

With contributions from network operators and volunteers all over the world,
RouteViews collects BGP data by direct peering at Internet Exchange Points
(IXPs) or multi-hop peering. Data are archived and made publicly available for
download at archive.routeviews.org, lg.routeviews.org, and api.routeviews.org.

- Website: https://www.routeviews.org/
- Terms: https://www.routeviews.org/routeviews/licenses/ (pinned in
  `data/licenses/routeviews.txt`)
- License: Creative Commons Attribution 4.0 International,
  https://creativecommons.org/licenses/by/4.0/
- Citation DOI: 10.7264/1y7v-2d90
- Logo: https://www.routeviews.org/routeviews/logos/
- What OpenASN takes from it: every night, one BGP RIB dump from each of ten
  RouteViews collectors. OpenASN's own code (`tools/rib2origin` in
  openasn-pipeline, MIT) recomputes from them a table of address range →
  origin ASN, and only that table enters the artifacts. No RouteViews file,
  AS path, peer or timestamp is redistributed. Changes: OpenASN keeps an
  origin only when at least two distinct peer ASes see it, drops bogon
  prefixes and origins, flattens nested prefixes by longest match, and merges
  adjacent ranges; the exact rules are in DECISIONS.md, "D-SRC-2 (backbone)".
- RouteViews does not endorse OpenASN, and OpenASN's classifications are not
  RouteViews data.

## Sources requiring attribution (MIT)

### X4BNet / lists_vpn — VPN & datacenter range overlays, ASN curation seeds
- https://github.com/X4BNet/lists_vpn
- License: MIT — per the project README, the license covers "the scripts,
  automation, and the list itself (source files and generated output)".
- Copyright (c) 2024 X4B (Mathew Heard)
- What OpenASN takes: only X4B's own work. That is its hand-curated ASN lists
  (`input/*/ASN.txt`, expanded against the backbone below) and its manual
  netblocks (`input/*/ips/Manual.txt`), used to keep the matching ranges of
  X4B's published lists. X4B's generated lists also merge third-party feeds
  (Apple iCloud Private Relay egress, Mullvad, Private Internet Access,
  Proton VPN). Those feeds are not X4B's to license, so OpenASN strips them
  and does not republish them. They are Tier B (see below). Decision:
  DECISIONS.md D-SRC-3.

### brianhama / bad-asn-list — curated hosting/cloud/colo ASN list
- https://github.com/brianhama/bad-asn-list
- License: MIT
- Copyright (c) 2025 Brian Hamachek

## Public-domain sources (credited with thanks; attribution not required)

### ipverse / as-metadata — ASN categories, roles
- https://github.com/ipverse/as-metadata
- License: CC0 1.0
- Its `description` field (organization names) is NOT in these artifacts.
  Those strings are bulk RIR WHOIS records, which the registries do not
  allow to be republished in bulk (DECISIONS.md D-SRC-2, org names). Clients
  may fetch them locally through the `ipverse_org_names` recipe in
  `fetch-manifest.json`.
- Its country codes are NOT in these artifacts either. ipverse sources them
  from the RIRs' registry records (DECISIONS.md D-SRC-2, country). Clients
  may fetch them locally through the `ipverse_as_country` recipe.

### Wikidata — organization names and countries (`openasn-orgs.bin`, the `org` and `country` columns)
- https://www.wikidata.org/wiki/Property:P3797 ("autonomous system number"),
  with P17 ("country") and P159 ("headquarters location") of the same items
- License: CC0 1.0 ("All structured data from the main, Property, Lexeme,
  and EntitySchema namespaces is available under the Creative Commons CC0
  License", https://www.wikidata.org/wiki/Wikidata:Copyright)
- Only statements that do not rest solely on registry or aggregator
  references are used. Item labels and countries are taken as published. Thank you to
  the Wikidata community.

### ipverse / as-ip-blocks — per-ASN announced prefixes
- https://github.com/ipverse/as-ip-blocks
- License: CC0 1.0

## OpenASN's own layer

- `data/overrides/` (curated ASN classifications, corrections,
  organization names and countries): released under CC0 1.0 — public domain, forever.
- Compiled artifacts (`openasn-ipv4.bin`, `openasn-ipv6.bin`,
  `asn-categories.csv`): CC0 1.0.
- The organization-name sidecar `openasn-orgs.bin`, and the portable
  representations of the same core specified in EXPORT_FORMATS.md
  (`openasn.sqlite.gz`, `openasn.csv.gz`, `openasn.mmdb`): CC0 1.0. They are
  projections of the artifacts above, compiled from the same build and the
  same sources, so every notice in this file applies to them unchanged. This
  text is embedded verbatim in the SQLite metadata and in the MMDB
  description, so an export carries its attribution even when separated from
  the release.
- Pipeline code: MIT (see LICENSE-CODE).

## Former sources

- **sapics / ip-location-db (`origin-asn`, PDDL v1.0)** was the IP→ASN backbone
  of every release built before the RouteViews switchover (DECISIONS.md,
  "D-SRC-2 (backbone)"). It was retired because it is itself compiled from
  RouteViews and RIPE RIS BGP archives and from RIR delegated statistics, and
  README "Legal design" rule 1 excludes aggregators. Thank you to sapics for
  years of a well-kept public table. Its pinned terms stay in
  `data/licenses/sapics-origin-asn.txt` as the receipt for those releases.

## Not in these artifacts, by design

Tier B sources (Apple iCloud Private Relay egress, the Tor Project bulk
exit list, cloud provider ranges, first-party VPN provider lists, the
WHOIS-derived organization names and registry country codes in ipverse
as-metadata, ...) are
fetched by OpenASN *clients* directly from the original authorities at
runtime, per `fetch-manifest.json`. They are never republished in these
releases — either because their terms don't grant third-party
redistribution, or because they change too fast for a nightly artifact to
be honest. This boundary is deliberate and load-bearing; see README
("Legal design") before moving anything across it.
