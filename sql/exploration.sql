-- =============================================================================
-- Firmable scan dataset — cybersecurity buying-signal research queries
-- =============================================================================
-- Engine: DuckDB v2.0.0 (CLI).  Research only — no scoring, no UI.
--
-- HOW TO RUN (from repo root; the work DB and Parquet live OUTSIDE the repo):
--
--   duckdb ~/firmable-work/research.duckdb \
--     -c "SET VARIABLE sample  = 'sample.jsonl';" \
--     -c "SET VARIABLE dist    = 'distributed_sample.jsonl';" \
--     -c "SET VARIABLE dataset = '$HOME/Downloads/firmable_dataset';" \
--     -c "SET VARIABLE slim    = '$HOME/firmable-work/full_slim.parquet';" \
--     -c ".read sql/exploration.sql"
--
--   To run against a sample instead of the 137 GB file, point `dataset` at
--   sample.jsonl / distributed_sample.jsonl (and `slim` at another Parquet path).
--
-- MEMORY / SAFETY
--   * The dataset is streamed by read_json; nothing is loaded wholesale into RAM.
--     memory_limit caps DuckDB; observed full pass: ~2 min, 12-core laptop, <6 GB.
--   * maximum_object_size must stay modest (32 MB). DuckDB allocates read buffers
--     per thread sized by it; 500 MB x N threads caused OOM even on a 300 MB file.
--   * Largest record seen in samples: 2.1 MB. 451 of 16,988,823 lines fail to
--     parse (invalid surrogate escapes); ignore_errors=true turns them into
--     all-NULL rows which §2 drops (ts IS NULL).
--   * The slim Parquet keeps selected fields only (no full banners, HTML,
--     favicons or CVE text) — it is a derived index, not a copy of the data.
--
-- DUCKDB 2.0 GOTCHAS (each one bit this research)
--   * Operator precedence: `json->'a' IS NOT NULL` parses as json->('a' IS NOT NULL).
--     Always parenthesise: `(json->'a') IS NOT NULL`, or use json_extract_string().
--   * Lambdas: `lambda x: expr`. The old `x -> expr` form is rejected.
--   * NULL propagation: list_contains(NULL, 'x') is NULL, so `NOT is_honeypot`
--     silently drops every untagged record (20% of data). Wrap flags in coalesce().
--   * QUALIFY cannot be combined with GROUP BY ALL — nest the aggregate.
-- =============================================================================

SET memory_limit = '8GB';
SET threads = 8;
SET preserve_insertion_order = false;


-- =============================================================================
-- §1  RAW SAMPLE INSPECTION (sample.jsonl = first 5,000 lines of the dataset;
--     distributed_sample.jsonl = 250 byte offsets x 8 consecutive lines)
-- =============================================================================

CREATE OR REPLACE TABLE raw_samples AS
SELECT 'sample' AS src, row_number() OVER () AS rn, json
FROM read_ndjson_objects(getvariable('sample'), maximum_object_size = 33554432, ignore_errors = true)
UNION ALL
SELECT 'dist', row_number() OVER (), json
FROM read_ndjson_objects(getvariable('dist'), maximum_object_size = 33554432, ignore_errors = true);

-- Q1.1  record counts, time span, distinct IPs/orgs per sample
SELECT src, count(*) AS records,
       min(json_extract_string(json, '$.timestamp')) AS ts_min,
       max(json_extract_string(json, '$.timestamp')) AS ts_max,
       count(DISTINCT json_extract_string(json, '$.ip_str')) AS ips,
       count(DISTINCT json_extract_string(json, '$.org'))    AS orgs
FROM raw_samples GROUP BY src;

-- Q1.2  top-level key presence
SELECT src, k AS top_level_key, count(*) AS records
FROM (SELECT src, unnest(json_keys(json)) AS k FROM raw_samples)
GROUP BY ALL ORDER BY src, records DESC;

-- Q1.3  nested path inventory with JSON types (array indexes collapsed to [*]).
--       vulns and data are stripped first: vulns is a CVE-keyed map averaging
--       ~52 CVEs (p99 367) and makes json_tree explode (>10 min); data is the raw banner.
CREATE OR REPLACE TABLE raw_paths AS
SELECT o.src, regexp_replace(j.fullkey, '\[[0-9]+\]', '[*]', 'g') AS path, j.type,
       count(*) AS occurrences, count(DISTINCT o.rn) AS records
FROM raw_samples o, json_tree(json_merge_patch(o.json, '{"vulns":null,"data":null}')) j
GROUP BY ALL;

SELECT path, string_agg(DISTINCT type, '|') AS types,
       coalesce(sum(records) FILTER (WHERE src = 'sample'), 0) AS sample_records,
       coalesce(sum(records) FILTER (WHERE src = 'dist'), 0)   AS dist_records
FROM raw_paths
WHERE NOT regexp_matches(path, '\.(ssl\.cert\.extensions|ssl\.chain_sha256|http\.components\.|isakmp\.vendor_ids|tcp|udp)')
GROUP BY path HAVING sum(records) >= 5 ORDER BY path;

-- Q1.4  structure of one CVE entry inside vulns
SELECT k AS vuln_field, count(*) AS n
FROM (SELECT unnest(json_keys(e.value)) AS k
      FROM raw_samples, json_each(json, '$.vulns') e)
GROUP BY 1 ORDER BY 2 DESC;

-- Q1.5  scanner module is the PROBE that ran, not a detection.
--       e.g. module 'remcos-pro-rat' frequently returns an nginx 400 page.
SELECT json_extract_string(json, '$._shodan.module') AS module,
       json_extract_string(json, '$.product')        AS product,
       left(regexp_replace(json_extract_string(json, '$.data'), '\s+', ' ', 'g'), 70) AS banner_head
FROM raw_samples
WHERE json_extract_string(json, '$._shodan.module') LIKE '%rat%'
  AND trim(json_extract_string(json, '$.data')) <> ''
LIMIT 10;


-- =============================================================================
-- §2  STREAMING SLIM PROJECTION OF THE FULL DATASET  (one parse per record)
--     typed read_json(columns=...) is ~50x cheaper than many json_extract()
--     calls on read_ndjson_objects (which re-parse every 2 MB document per call).
-- =============================================================================

COPY (
SELECT
  ip_str AS ip, ipv6, port, transport, "timestamp"::TIMESTAMP AS ts, org, isp, asn,
  location.country_code AS cc, _shodan.module AS module, _shodan.options.hostname AS scan_hostname,
  product, version, os, devicetype, tags, hostnames, domains, cpe23,
  cloud.provider AS cloud_provider, cloud.service AS cloud_service,
  length(trim(data)) AS banner_len, left(data, 160) AS banner_head,
  http.status AS http_status, left(http.title, 200) AS http_title, http.server AS http_server,
  http.host AS http_host, http.waf AS http_waf, http.favicon.hash AS favicon_hash,
  http.securitytxt IS NOT NULL AS has_securitytxt,
  json_extract_string(http.headers, '$."strict-transport-security"') IS NOT NULL AS has_hsts,
  json_extract_string(http.headers, '$."content-security-policy"') IS NOT NULL   AS has_csp,
  json_extract_string(http.headers, '$."x-powered-by"')    AS x_powered_by,
  json_extract_string(http.headers, '$."www-authenticate"') AS www_authenticate,
  ssl IS NOT NULL AS has_ssl, ssl.versions AS ssl_versions,
  ssl.cert.expired AS cert_expired,
  try_strptime(ssl.cert.expires, '%Y%m%d%H%M%SZ') AS cert_expires,
  try_strptime(ssl.cert.issued,  '%Y%m%d%H%M%SZ') AS cert_issued,
  json_extract_string(ssl.cert.subject, '$.CN') AS cert_subject_cn,
  json_extract_string(ssl.cert.subject, '$.O')  AS cert_subject_o,
  json_extract_string(ssl.cert.issuer,  '$.CN') AS cert_issuer_cn,
  json_extract_string(ssl.cert.issuer,  '$.O')  AS cert_issuer_o,
  ssl.cert.sig_alg AS cert_sig_alg, ssl.cert.pubkey.type AS cert_key_type, ssl.cert.pubkey.bits AS cert_key_bits,
  ssl.cert.fingerprint.sha256 AS cert_sha256,
  json_extract_string(ssl.trust, '$.browser.mozilla') AS cert_trust_mozilla,
  ssl.jarm AS jarm, ssh.hassh AS ssh_hassh,
  ntlm.dns_domain_name AS ntlm_dns_domain, ntlm.netbios_domain_name AS ntlm_netbios_domain,
  ntlm.fqdn AS ntlm_fqdn, ntlm.os_build AS ntlm_os_build,
  json_keys(vulns) AS vuln_ids,
  contains(vulns::VARCHAR, '"kev":true')                    AS any_kev,
  contains(vulns::VARCHAR, '"ransomware_campaign":"Known"') AS any_ransomware_known,
  regexp_extract_all(vulns::VARCHAR, '"cvss":([0-9.]+)', 1) AS cvss_list,
  contains(vulns::VARCHAR, '"verified":true')               AS any_verified
FROM read_json(getvariable('dataset'), format = 'newline_delimited',
  maximum_object_size = 33554432, ignore_errors = true,
  columns = {
    ip_str:'VARCHAR', ipv6:'VARCHAR', port:'INTEGER', transport:'VARCHAR', "timestamp":'VARCHAR',
    org:'VARCHAR', isp:'VARCHAR', asn:'VARCHAR', location:'STRUCT(country_code VARCHAR)',
    _shodan:'STRUCT(module VARCHAR, options STRUCT(hostname VARCHAR))',
    product:'VARCHAR', version:'VARCHAR', os:'VARCHAR', devicetype:'VARCHAR',
    tags:'VARCHAR[]', hostnames:'VARCHAR[]', domains:'VARCHAR[]', cpe23:'VARCHAR[]',
    cloud:'STRUCT(provider VARCHAR, service VARCHAR)', data:'VARCHAR',
    http:'STRUCT(status INTEGER, title VARCHAR, server VARCHAR, host VARCHAR, waf VARCHAR, favicon STRUCT(hash BIGINT), securitytxt VARCHAR, headers JSON)',
    ssl:'STRUCT(versions VARCHAR[], jarm VARCHAR, trust JSON, cert STRUCT(expired BOOLEAN, expires VARCHAR, issued VARCHAR, subject JSON, issuer JSON, sig_alg VARCHAR, pubkey STRUCT(type VARCHAR, bits INTEGER), fingerprint STRUCT(sha256 VARCHAR)))',
    ssh:'STRUCT(hassh VARCHAR)',
    ntlm:'STRUCT(dns_domain_name VARCHAR, netbios_domain_name VARCHAR, fqdn VARCHAR, os_build VARCHAR)',
    vulns:'JSON'
  })
) TO (getvariable('slim')) (FORMAT parquet, COMPRESSION zstd, ROW_GROUP_SIZE 200000);

CREATE OR REPLACE VIEW slim AS SELECT * FROM read_parquet(getvariable('slim'));


-- =============================================================================
-- §3  POPULATION PROFILE
-- =============================================================================

-- Q3.1  headline volumes
SELECT count(*) AS rows_incl_parse_failures, count_if(ts IS NULL) AS parse_failures,
       min(ts) AS ts_min, max(ts) AS ts_max,
       count(DISTINCT ip) AS ipv4s, count(DISTINCT ipv6) AS ipv6s,
       count(DISTINCT org) AS orgs, count(DISTINCT isp) AS isps, count(DISTINCT asn) AS asns,
       count(DISTINCT (ip, port, transport)) AS ip_port_keys
FROM slim;

-- Q3.2  field coverage (% of records)
SELECT round(100 * count_if(org IS NULL) / count(*), 3)                    AS org_null_pct,
       round(100 * count_if(ip IS NULL) / count(*), 2)                     AS ipv6_only_pct,
       round(100 * count_if(len(hostnames) > 0) / count(*), 1)             AS has_hostname_pct,
       round(100 * count_if(coalesce(banner_len, 0) = 0) / count(*), 1)   AS empty_banner_pct,
       round(100 * count_if(product IS NOT NULL) / count(*), 1)            AS product_pct,
       round(100 * count_if(version IS NOT NULL) / count(*), 1)            AS version_pct,
       round(100 * count_if(os IS NOT NULL) / count(*), 1)                 AS os_pct,
       round(100 * count_if(len(tags) > 0) / count(*), 1)                  AS tagged_pct,
       round(100 * count_if(has_ssl) / count(*), 1)                        AS ssl_pct,
       round(100 * count_if(http_status IS NOT NULL) / count(*), 1)        AS http_pct,
       round(100 * count_if(len(cpe23) > 0) / count(*), 1)                 AS cpe_pct,
       round(100 * count_if(len(vuln_ids) > 0) / count(*), 2)              AS vulns_pct,
       round(100 * count_if(cloud_provider IS NOT NULL) / count(*), 1)     AS cloud_pct,
       round(100 * count_if(scan_hostname IS NOT NULL) / count(*), 2)      AS sni_scan_pct,
       count(ntlm_dns_domain)                                              AS ntlm_records
FROM slim WHERE ts IS NOT NULL;

-- Q3.3  distributions
SELECT t AS tag, count(*) AS n, round(100 * count(*) / (SELECT count(*) FROM slim), 3) AS pct
FROM (SELECT unnest(tags) AS t FROM slim) GROUP BY 1 ORDER BY 2 DESC;

SELECT module, count(*) AS n, round(100 * count_if(coalesce(banner_len, 0) = 0) / count(*), 1) AS empty_pct
FROM slim GROUP BY 1 ORDER BY 2 DESC LIMIT 60;

SELECT port, transport, count(*) AS n, round(100 * count_if(coalesce(banner_len, 0) = 0) / count(*), 1) AS empty_pct,
       count(DISTINCT org) AS orgs, mode(module) AS top_module
FROM slim GROUP BY ALL ORDER BY n DESC LIMIT 60;

SELECT org, count(*) AS n, round(100 * count(*) / (SELECT count(*) FROM slim), 2) AS pct,
       round(100 * count_if(coalesce(banner_len, 0) = 0) / count(*), 1) AS empty_pct,
       count(DISTINCT ip) AS ips, mode(isp) AS isp
FROM slim GROUP BY 1 ORDER BY 2 DESC LIMIT 60;

SELECT product, count(*) AS n, count(DISTINCT org) AS orgs, count(DISTINCT ip) AS ips,
       count_if(list_contains(tags, 'honeypot')) AS honeypot_tagged, mode(port) AS top_port
FROM slim WHERE product IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT 300;

SELECT time_bucket(INTERVAL 15 MINUTE, ts) AS bucket, count(*) AS n FROM slim GROUP BY 1 ORDER BY 1;

-- Q3.4  TLS + HTTP hygiene population stats
SELECT count(*) AS tls_records, count_if(cert_expired) AS expired,
       count_if(list_contains(ssl_versions, 'TLSv1'))   AS tls10_enabled,
       count_if(list_contains(ssl_versions, 'TLSv1.1')) AS tls11_enabled,
       count_if(list_contains(ssl_versions, 'SSLv3'))   AS sslv3_enabled,
       count_if(len(ssl_versions) = 0)                  AS versions_not_enumerated,
       count_if(cert_key_type = 'rsa' AND cert_key_bits < 2048) AS rsa_lt_2048,
       count_if(regexp_matches(lower(coalesce(cert_sig_alg, '')), 'sha1|md5')) AS sha1_md5_sig,
       count_if(cert_trust_mozilla IS NULL) AS trust_not_evaluated
FROM slim WHERE has_ssl;
-- NB: list entries prefixed '-' (e.g. '-TLSv1') mean NOT supported. Exact match only.
-- NB: pubkey.type is 'dsa' for ECDSA keys in this feed; do not read it as DSA.

SELECT count(*) AS http_records, count_if(http_waf IS NOT NULL) AS waf_fingerprinted,
       count_if(has_hsts) AS hsts, count_if(has_csp) AS csp, count_if(has_securitytxt) AS securitytxt
FROM slim WHERE http_status IS NOT NULL;

-- Q3.5  vulns block: inferred, not verified
SELECT count(*) AS records_with_vulns, round(avg(len(vuln_ids)), 1) AS mean_cves,
       quantile_cont(len(vuln_ids), 0.5) AS p50_cves, quantile_cont(len(vuln_ids), 0.99) AS p99_cves,
       count_if(any_kev) AS any_kev, count_if(any_ransomware_known) AS ransomware_known,
       count_if(any_verified) AS any_verified_cve, count_if(any_kev AND version IS NULL) AS kev_without_version
FROM slim WHERE len(vuln_ids) > 0;

-- Q3.6  repeated observations. Keying on (ip,port,transport) alone is wrong:
--       the scanner re-probes the same CDN IP once per SNI hostname.
WITH g AS (
  SELECT ip, port, transport, coalesce(scan_hostname, '') AS sni, count(*) AS n,
         count(DISTINCT coalesce(product, '-'))    AS products,
         count(DISTINCT coalesce(version, '-'))    AS versions,
         count(DISTINCT coalesce(http_title, '-')) AS titles,
         count(DISTINCT coalesce(cert_sha256, '-')) AS certs,
         count(DISTINCT coalesce(http_status, -1)) AS statuses,
         epoch(max(ts)) - epoch(min(ts)) AS span_s
  FROM slim WHERE ip IS NOT NULL AND ts IS NOT NULL GROUP BY ALL HAVING count(*) > 1)
SELECT count(*) AS repeated_keys, sum(n) AS obs, max(n) AS max_obs_per_key,
       quantile_cont(span_s / 60, [0.5, 0.9, 0.99]) AS span_minutes_p50_p90_p99,
       count_if(products > 1) AS product_changed, count_if(versions > 1) AS version_changed,
       count_if(titles > 1) AS title_changed, count_if(certs > 1) AS cert_changed,
       count_if(statuses > 1) AS status_changed
FROM g;


-- =============================================================================
-- §4  ENRICHMENT: NOISE FLAGS + ATTRIBUTION FEATURES
-- =============================================================================

CREATE OR REPLACE MACRO norm_org(o) AS
  trim(regexp_replace(regexp_replace(regexp_replace(lower(coalesce(o, '')), '[.,"''()]', ' ', 'g'),
       '\b(inc|incorporated|llc|l l c|ltd|limited|corp|corporation|co|company|gmbh|ag|sa|sas|s a|bv|b v|plc|pte|pty|llp|lp|kk|srl|spa|ab|oy|as|nv)\b',
       ' ', 'g'), '\s+', ' ', 'g'));

-- Name heuristic for infrastructure orgs (cloud, CDN, hosting, SaaS platform, ISP/telco).
-- Deliberately broad and still incomplete (misses e.g. BIGLOBE, Asahi Net, "IP pools").
-- Production should replace it with a curated ASN/org classification.
CREATE OR REPLACE MACRO is_provider_org(o) AS regexp_matches(lower(coalesce(o, '')),
  '(cloud|hosting|\bhost|data ?cent|datacenter|server|vps|colo|telecom|telekom|communications|network|internet|broadband|cable|mobile|wireless|\bisp\b|online|fiber|fibre|amazon|google|microsoft|akamai|incapsula|imperva|cloudflare|fastly|alibaba|aliyun|tencent|huawei|ovh|hetzner|digitalocean|linode|vultr|scaleway|contabo|oracle|leaseweb|fly\.io|zscaler|verizon|at&t|comcast|charter|spectrum|cogent|level 3|lumen|ntt|kddi|softbank|china (mobile|unicom|telecom)|chinanet|reliance jio|bharti|vodafone|orange|telefonica|telstra|vnpt|viettel|so-net|sony network|korea telecom|chunghwa|meteverse|aceville|^ace$|internet rimon|ionos|godaddy|squarespace|salesforce|bitly|egnyte|servicenow|cdn|ddos|edgecast|stackpath|limelight|rackspace|equinix|choopa|constant company|m247|psychz|quadranet|end user organization|ip pools|dynamic pools|static ip|customer-|private customer)');

-- Hostname looks like provider/ISP reverse DNS rather than a customer name.
CREATE OR REPLACE MACRO is_ptr_like(h) AS
  regexp_matches(lower(h), '(\d{1,3}[-._x]){3}\d{1,3}')
  OR regexp_matches(lower(h), '(^|[.-])(ip|host|static|dynamic|dyn|dhcp|pool|cust|customer|client|dsl|adsl|xdsl|ppp|pppoe|cpe|bb|broadband|ftth|fiber|res|user|mobile|nat|gw)[-.]?\d');

-- Hostnames that never identify a buying organisation: non-public TLDs, vendor
-- default certificate names, consumer dynamic-DNS services.
CREATE OR REPLACE MACRO is_non_company_name(h) AS
  regexp_matches(lower(h), '\.(local|lan|internal|localdomain|home|arpa|adsl|corp|intranet|invalid|test|example)$|^localhost')
  OR regexp_matches(lower(h), '(^|\.)(draytek\.com|fortinet\.com|fortigate|sonicwall\.com|ubnt\.com|ui\.com|mikrotik\.com|synology\.me|myqnapcloud\.com|tplinkdns\.com|asuscomm\.com|dyndns\.\w+|no-ip\.\w+|ddns\.net|duckdns\.org|hopto\.org|zapto\.org|freeddns\.org|myfritz\.net|kubernetes|traefik\.default|cloudflaressl\.com)$');

-- Approximate registrable domain (no Public Suffix List; common 2-level ccTLD suffixes only).
CREATE OR REPLACE MACRO reg_domain(h) AS
  regexp_extract(lower(rtrim(h, '.')),
    '([a-z0-9-]+\.((co|com|net|org|gov|edu|ac|or|ne|go|ad|gr|lg|ed|nhs|ltd|plc|sch|mil|nic)\.)?[a-z]{2,})$', 1);

-- Per-IP port spread (CDN / Google ranges answer on hundreds of ports).
CREATE OR REPLACE TABLE ip_ports AS
SELECT ip, count(DISTINCT (port, transport)) AS n_ports, count(*) AS n_obs
FROM slim WHERE ip IS NOT NULL GROUP BY ip;

CREATE OR REPLACE TABLE obs AS
SELECT row_number() OVER () AS obs_id, s.*,
  coalesce(s.banner_len, 0) = 0                                   AS is_empty,
  coalesce(list_contains(s.tags, 'honeypot'), false)              AS is_honeypot,
  -- "fingerprint soup": ~147 KB decoy page that matches 14-20 unrelated CPEs
  coalesce(len(s.cpe23) >= 8 AND list_contains(s.cpe23, 'cpe:2.3:a:adobe:coldfusion')
           AND list_contains(s.cpe23, 'cpe:2.3:a:wordpress:wordpress'), false) AS is_fp_soup,
  coalesce(list_contains(s.tags, 'cdn'), false)                   AS is_cdn,
  coalesce(p.n_ports, 1)                                          AS ip_n_ports,
  is_provider_org(s.org)                                          AS org_is_provider,
  is_provider_org(s.isp)                                          AS isp_is_provider,
  norm_org(s.org)                                                 AS org_key
FROM slim s LEFT JOIN ip_ports p USING (ip)
WHERE s.ts IS NOT NULL;

-- Q4.1  noise accounting
SELECT count(*) AS obs, count_if(is_empty) AS empty_banner, count_if(is_honeypot) AS honeypot,
       count_if(is_fp_soup) AS fingerprint_soup, count_if(is_fp_soup AND NOT is_honeypot) AS soup_not_honeypot_tagged,
       count_if(NOT is_empty AND NOT is_honeypot AND NOT is_fp_soup) AS eligible
FROM obs;

CREATE OR REPLACE VIEW eligible AS
SELECT * FROM obs WHERE NOT is_empty AND NOT is_honeypot AND NOT is_fp_soup;

-- Long-form domain evidence, one row per (observation, source, candidate name).
CREATE OR REPLACE TABLE domain_evidence AS
WITH c AS (
  SELECT obs_id, ip, org, 'hostname' AS src, unnest(hostnames) AS name FROM eligible
  UNION ALL SELECT obs_id, ip, org, 'sni_scan',  scan_hostname   FROM eligible WHERE scan_hostname IS NOT NULL
  UNION ALL SELECT obs_id, ip, org, 'http_host', http_host       FROM eligible WHERE regexp_matches(coalesce(http_host, ''), '[a-z]')
  UNION ALL SELECT obs_id, ip, org, 'cert_cn',   ltrim(cert_subject_cn, '*.') FROM eligible WHERE cert_subject_cn LIKE '%.%'
  UNION ALL SELECT obs_id, ip, org, 'ntlm',      ntlm_dns_domain FROM eligible WHERE ntlm_dns_domain LIKE '%.%')
SELECT obs_id, ip, org, src, lower(name) AS name, reg_domain(name) AS domain
FROM c
WHERE name IS NOT NULL AND NOT is_ptr_like(name) AND NOT is_non_company_name(name)
  AND reg_domain(name) IS NOT NULL AND reg_domain(name) <> '';

-- Infrastructure domains, data-driven: a registrable domain seen on >= 1,000
-- distinct IPs is a provider/platform namespace (googleusercontent.com,
-- ocn.ne.jp, myshopify.com, ...). This also drops large self-hosting brands
-- (amazon.com, cisco.com) — acceptable, they are vendors not prospects.
CREATE OR REPLACE TABLE infra_domains AS
SELECT domain, count(DISTINCT ip) AS ips, count(DISTINCT org) AS orgs
FROM (SELECT DISTINCT ip, org, unnest(list_transform(hostnames, lambda h: reg_domain(h))) AS domain FROM obs WHERE ip IS NOT NULL)
WHERE domain IS NOT NULL
GROUP BY 1 HAVING count(DISTINCT ip) >= 1000;

CREATE OR REPLACE TABLE obs_domains AS
SELECT obs_id,
       list_distinct(list(domain)) AS customer_domains,
       list_distinct(list(src))    AS domain_sources
FROM domain_evidence d
WHERE NOT EXISTS (SELECT 1 FROM infra_domains i WHERE i.domain = d.domain)
GROUP BY obs_id;

-- Org profile: platform = name heuristic OR multi-tenant (>100 distinct customer
-- domains) OR mostly CDN/cloud-tagged. Thresholds are first guesses, not tuned.
CREATE OR REPLACE TABLE org_profile AS
WITH od AS (
  SELECT e.org, count(DISTINCT u.d) AS n_dom
  FROM eligible e JOIN obs_domains o USING (obs_id), unnest(o.customer_domains) u(d)
  GROUP BY e.org)
SELECT x.org, x.org_key, x.n_obs, x.n_ips, x.cdn_cloud_share, coalesce(od.n_dom, 0) AS n_customer_domains,
       (is_provider_org(x.org) OR coalesce(od.n_dom, 0) > 100 OR x.cdn_cloud_share > 0.5) AS is_platform
FROM (SELECT org, any_value(org_key) AS org_key, count(*) AS n_obs, count(DISTINCT ip) AS n_ips,
             avg(CASE WHEN list_has_any(coalesce(tags, []), ['cdn', 'cloud']) THEN 1 ELSE 0 END) AS cdn_cloud_share
      FROM obs GROUP BY org) x
LEFT JOIN od USING (org);


-- =============================================================================
-- §5  SERVICE-LEVEL BASE TABLE + ATTRIBUTION TIER
--     one row per (ip, port, transport, SNI) — latest eligible observation
-- =============================================================================

CREATE OR REPLACE TABLE svc AS
SELECT e.*, coalesce(d.customer_domains, []) AS customer_domains, coalesce(d.domain_sources, []) AS domain_sources,
       p.is_platform,
       CASE WHEN NOT p.is_platform AND e.org IS DISTINCT FROM e.isp AND e.isp_is_provider THEN 'A2'
            WHEN NOT p.is_platform THEN 'A1'
            WHEN len(d.customer_domains) > 0 THEN 'B'
            ELSE 'C' END AS attribution_tier,
       lower(coalesce(e.product, '')) AS p_l, lower(coalesce(e.http_title, '')) AS t_l
FROM eligible e
LEFT JOIN obs_domains d USING (obs_id)
JOIN org_profile p USING (org)
QUALIFY row_number() OVER (PARTITION BY coalesce(e.ip, e.ipv6), e.port, e.transport, coalesce(e.scan_hostname, '') ORDER BY e.ts DESC) = 1;

-- Q5.1  attribution tiers over signal-eligible services
--   A1 = org is not an infrastructure provider (direct allocation)
--   A2 = non-provider org registered on a sub-allocation/BYOIP inside a provider's ISP
--   B  = provider/platform IP but the record names a customer domain
--   C  = provider/platform IP, nothing customer-specific -> unattributable
SELECT attribution_tier, count(*) AS services, round(100 * count(*) / sum(count(*)) OVER (), 1) AS pct,
       count(DISTINCT ip) AS ips, count(DISTINCT org) AS orgs
FROM svc GROUP BY 1 ORDER BY 1;

-- Q5.2  evidence-source coverage among signal-eligible services
SELECT src, count(DISTINCT obs_id) AS observations, count(DISTINCT domain) AS domains
FROM domain_evidence d WHERE NOT EXISTS (SELECT 1 FROM infra_domains i WHERE i.domain = d.domain)
GROUP BY 1 ORDER BY 2 DESC;

-- Q5.3  top non-platform orgs (precision check of the provider heuristic)
SELECT org, mode(isp) AS isp, count(*) AS services, count(DISTINCT ip) AS ips
FROM svc WHERE attribution_tier IN ('A1', 'A2') GROUP BY org ORDER BY services DESC LIMIT 60;

-- Q5.4  multi-tenant platforms that the name heuristic missed
SELECT org, n_customer_domains, n_ips FROM org_profile
WHERE NOT is_provider_org(org) AND n_customer_domains > 100 ORDER BY n_customer_domains DESC LIMIT 30;

-- Q5.5  org != isp patterns (BYOIP / reassignment)
SELECT org, isp, count(*) AS n, count_if(is_empty) AS empty_banner
FROM obs WHERE org IS DISTINCT FROM isp AND NOT org_is_provider AND isp_is_provider
GROUP BY ALL ORDER BY n DESC LIMIT 40;


-- =============================================================================
-- §6  SIGNAL DETECTION  (facts observed by the scanner; risk is an inference)
-- =============================================================================

CREATE OR REPLACE TABLE signal_hits AS
-- S01  identified remote-access gateway / SSL-VPN / firewall web portal (TCP)
SELECT 'S01' AS sid, * FROM svc WHERE transport = 'tcp' AND NOT is_cdn AND (
     regexp_matches(p_l, 'fortigate|fortinet|sonicwall|check ?point|connectra|cisco asa|cisco vpn|adaptive security|netscaler|citrix|globalprotect|pan-os|palo alto|pulse secure|ivanti connect|juniper|sophos|zyxel|barracuda|watchguard|fireware|stormshield|securepoint|openvpn|draytek')
  OR regexp_matches(t_l, 'globalprotect|fortigate|ssl ?vpn|vpn portal|netscaler|citrix gateway|pulse secure|ivanti connect|fireware|anyconnect|sonicwall|big-ip logout|sophos|access server client portal'))
UNION ALL
-- S02  IPsec/IKE responder — VPN presence only (very common, low value alone)
SELECT 'S02', * FROM svc WHERE module IN ('ike', 'ike-nat-t')
UNION ALL
-- S03  interactive remote administration protocol reachable
SELECT 'S03', * FROM svc WHERE NOT is_cdn AND (module IN ('rdp', 'telnet', 'x11', 'rlogin', 'nomachine')
  OR regexp_matches(p_l, 'remote desktop|vnc|winrm|screenconnect|teamviewer|telnetd'))
UNION ALL
-- S04  database / object store reachable (product identified)
SELECT 'S04', * FROM svc WHERE NOT is_cdn AND (
     regexp_matches(p_l, 'mysql|mariadb|postgresql|ms-sql|sql server|mongodb|redis|elastic|clickhouse|couchdb|cassandra|influxdb|memcached|minio|riak|rethinkdb')
  OR (module IN ('mysql','ms-sql','mongodb','redis','postgresql','clickhouse-native','riak','rethinkdb','oracle-tns','couchdb','memcached') AND NOT banner_head LIKE 'HTTP/%')
  OR coalesce(list_contains(tags, 'database'), false))
UNION ALL
-- S05  infrastructure / DevOps / hosting management plane reachable
SELECT 'S05', * FROM svc WHERE NOT is_cdn AND (regexp_matches(p_l || ' ' || t_l,
  '\bilo\b|idrac|ipmi|cisco ios http|winbox|kubernetes|portainer|docker|jenkins|gitlab|grafana|kibana|prometheus|airflow|argo cd|rancher|consul|\bvault\b|cpanel|\bwhm\b|plesk|webmin|control web panel|cyberpanel|phpmyadmin|keycloak|minio console|sonarqube|openstack|vcenter|esxi|proxmox|unifi|routeros')
  OR coalesce(list_contains(tags, 'devops'), false))
UNION ALL
-- S06  TLS hygiene defect on a non-CDN endpoint (sub-flags kept in columns below)
SELECT 'S06', * FROM svc WHERE has_ssl AND NOT is_cdn AND (
     cert_expired
  OR list_has_any(ssl_versions, ['TLSv1', 'TLSv1.1', 'SSLv3', 'SSLv2'])
  OR (cert_key_type = 'rsa' AND cert_key_bits < 2048)
  OR regexp_matches(lower(coalesce(cert_sig_alg, '')), 'sha1|md5')
  OR (coalesce(list_contains(tags, 'self-signed'), false) AND module NOT IN ('rdp') AND http_status IS NOT NULL))
UNION ALL
-- S07  end-of-life product / OS (scanner tag)
SELECT 'S07', * FROM svc WHERE list_has_any(coalesce(tags, []), ['eol-product', 'eol-os'])
UNION ALL
-- S08  version-inferred CVE carrying a CISA-KEV flag — UNVERIFIED, product+version required
SELECT 'S08', * FROM svc WHERE any_kev AND product IS NOT NULL AND version IS NOT NULL
UNION ALL
-- S09  public web app on owned space: no WAF/CDN fingerprint, no HSTS, not a block page
SELECT 'S09', * FROM svc WHERE http_status = 200 AND http_title IS NOT NULL AND NOT is_cdn AND http_waf IS NULL AND NOT has_hsts
  AND attribution_tier IN ('A1', 'A2')
  AND NOT regexp_matches(t_l, 'request rejected|rejected request|forbidden|access denied|blocked|^40\d|^50\d')
  AND NOT regexp_matches(p_l, 'bigip|netscaler|fortiweb|imperva|cloudflare|akamai')
UNION ALL
-- S10  NTLM challenge discloses internal AD domain / host name
SELECT 'S10', * FROM svc WHERE ntlm_dns_domain IS NOT NULL
UNION ALL
-- S11  OT / ICS / medical / IoT / camera exposure (protocol answer or device product, never CDN)
SELECT 'S11', * FROM svc WHERE NOT is_cdn AND (
     list_has_any(coalesce(tags, []), ['ics', 'medical'])
  OR (module IN ('modbus','dnp3','iec-104','ethernetip','s7','bacnet','fox','melsec-q-tcp','omron-tcp','pcworx','proconos','general-electric-srtp','dicom','matrikon-opc','codesys','lsv2')
      AND NOT banner_head LIKE 'HTTP/%' AND NOT regexp_matches(p_l, 'nginx|apache|iis|openresty|socks|ssh'))
  OR regexp_matches(p_l, 'hikvision|dahua|avtech|trendnet|cp plus|truvision|reolink|siemens|schneider|rockwell|niagara|crestron|axis'))
UNION ALL
-- S12  compromise / offensive-tooling indicators (scanner tags)
SELECT 'S12', * FROM svc WHERE list_has_any(coalesce(tags, []), ['compromised', 'c2', 'malware', 'doublepulsar'])
UNION ALL
-- S13  open directory listing
SELECT 'S13', * FROM svc WHERE NOT is_cdn AND coalesce(list_contains(tags, 'open-dir'), false)
UNION ALL
-- S14  self-hosted email / collaboration server
SELECT 'S14', * FROM svc WHERE regexp_matches(p_l || ' ' || t_l, 'outlook web app|exchange|lotus domino|groupwise|zimbra|mdaemon|mailenable|kerio') OR t_l = 'outlook'
UNION ALL
-- S15  self-hosted AI / LLM / agent / automation tooling
SELECT 'S15', * FROM svc WHERE list_has_any(coalesce(tags, []), ['ai', 'mcp'])
  OR regexp_matches(p_l || ' ' || t_l, 'litellm|ollama|comfyui|mcp server|n8n|open webui|langflow|flowise|vllm|jupyter|dify|librechat')
UNION ALL
-- S16  security-vendor technographics (WAF fingerprint or security appliance product)
SELECT 'S16', * FROM svc WHERE http_waf IS NOT NULL
  OR regexp_matches(p_l, 'fortigate|sonicwall|check ?point|zscaler|netscaler|bigip|barracuda|sophos|palo alto|juniper|watchguard')
UNION ALL
-- S17  security.txt published (positive maturity indicator)
SELECT 'S17', * FROM svc WHERE has_securitytxt;

-- Q6.1  signal prevalence by attribution tier
SELECT sid, count(*) AS services, count(DISTINCT ip) AS ips,
       count(*) FILTER (WHERE attribution_tier IN ('A1', 'A2')) AS owned_services,
       count(DISTINCT org) FILTER (WHERE attribution_tier IN ('A1', 'A2')) AS owned_orgs,
       count(*) FILTER (WHERE attribution_tier = 'B') AS tier_b_services,
       count(DISTINCT customer_domains[1]) FILTER (WHERE attribution_tier = 'B') AS tier_b_domains,
       count(*) FILTER (WHERE attribution_tier = 'C') AS tier_c_services
FROM signal_hits GROUP BY 1 ORDER BY 1;

-- Q6.2  what actually fires each rule (QA — look here before trusting a count)
SELECT * FROM (
  SELECT sid, coalesce(product, '[' || module || ']') AS what, count(*) AS n,
         count(*) FILTER (WHERE attribution_tier IN ('A1', 'A2')) AS owned
  FROM signal_hits GROUP BY 1, 2)
QUALIFY row_number() OVER (PARTITION BY sid ORDER BY n DESC) <= 8 ORDER BY sid, n DESC;

SELECT * FROM (
  SELECT sid, left(http_title, 60) AS title, count(*) AS n
  FROM signal_hits WHERE http_title IS NOT NULL GROUP BY 1, 2)
QUALIFY row_number() OVER (PARTITION BY sid ORDER BY n DESC) <= 10 ORDER BY sid, n DESC;

-- Q6.3  S06 TLS sub-flags
SELECT count(*) AS s06_services,
       count_if(cert_expired) AS expired,
       count_if(NOT cert_expired AND cert_expires < ts + INTERVAL 30 DAY) AS expiring_within_30d,
       count_if(list_has_any(ssl_versions, ['TLSv1', 'TLSv1.1'])) AS legacy_tls,
       count_if(list_has_any(ssl_versions, ['SSLv3', 'SSLv2'])) AS ssl_v2_v3,
       count_if(cert_key_type = 'rsa' AND cert_key_bits < 2048) AS weak_rsa,
       count_if(regexp_matches(lower(coalesce(cert_sig_alg, '')), 'sha1|md5')) AS weak_sig
FROM signal_hits WHERE sid = 'S06';

-- Q6.4  examples per signal from attributed tiers (IP masked to /24)
SELECT * EXCLUDE (h) FROM (
  SELECT sid, hash(ip) AS h, attribution_tier AS tier, org, cc, regexp_replace(ip, '\.\d+$', '.x') AS ip24,
         port, product, version, left(http_title, 40) AS title, customer_domains[1:2] AS domains,
         domain_sources, ntlm_dns_domain, cert_expired, tags, any_kev, ts
  FROM signal_hits WHERE attribution_tier IN ('A1', 'A2', 'B') AND hash(ip || sid) % 97 = 1)
QUALIFY row_number() OVER (PARTITION BY sid ORDER BY h) <= 3 ORDER BY sid;

-- Q6.5  counterexamples: raw rule matches that the noise filters removed
SELECT 'S11 OT module answered by CDN/web server' AS case, org, port, module, product, left(banner_head, 60) AS banner
FROM obs WHERE module IN ('dicom', 'melsec-q-tcp', 'omron-tcp') AND (is_cdn OR banner_head LIKE 'HTTP/%') LIMIT 5;
SELECT 'KEV on fingerprint soup' AS case, org, port, len(cpe23) AS n_cpe, len(vuln_ids) AS n_cves, http_title
FROM obs WHERE is_fp_soup AND any_kev LIMIT 5;
SELECT 'Port open, empty banner, enterprise BYOIP on Google' AS case, org, isp, port, module, banner_len
FROM obs WHERE org = 'Wal-Mart Stores, Inc.' AND isp = 'Google LLC' LIMIT 5;
SELECT 'Vendor default cert CN as customer domain' AS case, org, product, cert_subject_cn
FROM obs WHERE cert_subject_cn IN ('draytek.com', 'unifi.local') LIMIT 5;


-- =============================================================================
-- §7  ACCOUNT ROLL-UP, COMPOUND SIGNALS, CHANGE DETECTION
-- =============================================================================

CREATE OR REPLACE TABLE account_signals AS
SELECT CASE WHEN attribution_tier IN ('A1', 'A2') THEN 'org:' || org_key
            WHEN attribution_tier = 'B' THEN 'dom:' || customer_domains[1] END AS account,
       attribution_tier, sid, ip, port, transport, ts
FROM signal_hits WHERE attribution_tier IN ('A1', 'A2', 'B');

CREATE OR REPLACE TABLE account_summary AS
SELECT account, any_value(attribution_tier) AS tier, list_sort(list_distinct(list(sid))) AS sids,
       count(DISTINCT ip) AS ips, count(DISTINCT (ip, port, transport)) AS services, max(ts) AS last_seen
FROM account_signals GROUP BY account;

-- Q7.1  compound signals (account level)
SELECT tier IN ('A1', 'A2') AS owned_space, count(*) AS accounts_with_any_signal,
  count_if(list_contains(sids, 'S01') AND list_has_any(sids, ['S07', 'S08']))               AS c1_aging_remote_access_edge,
  count_if(list_contains(sids, 'S03') AND list_contains(sids, 'S10'))                       AS c2_remote_admin_with_identity_leak,
  count_if(list_has_any(sids, ['S04', 'S05']) AND list_contains(sids, 'S06'))               AS c3_mgmt_plane_with_tls_debt,
  count_if(len(list_filter(sids, lambda s: s IN ('S01','S03','S04','S05','S10','S11','S13','S14','S15'))) >= 3) AS c4_exposure_sprawl,
  count_if(list_contains(sids, 'S14') AND list_has_any(sids, ['S07', 'S08']))               AS c5_aging_onprem_mail,
  count_if(list_contains(sids, 'S11') AND list_has_any(sids, ['S01', 'S03']))               AS c6_ot_with_remote_access
FROM account_summary GROUP BY 1;

-- Q7.2  same-service compounds (stronger than same-account co-occurrence)
SELECT 'S01 edge + S07/S08 on same ip:port' AS compound, count(DISTINCT a.ip) AS ips
FROM account_signals a JOIN account_signals b USING (ip, port, transport)
WHERE a.sid = 'S01' AND b.sid IN ('S07', 'S08')
UNION ALL
SELECT 'S03 remote admin + S10 NTLM leak on same ip:port', count(DISTINCT a.ip)
FROM account_signals a JOIN account_signals b USING (ip, port, transport)
WHERE a.sid = 'S03' AND b.sid = 'S10';

-- Q7.3  change detection template. This file is ONE ~5 h snapshot, so it can
--       only be exercised across repeated probes minutes apart. With two
--       snapshot Parquets (prev, curr) the same query yields new/removed
--       exposures and version/cert changes per account.
--       SET VARIABLE prev = '.../snapshot_A.parquet'; SET VARIABLE curr = '.../snapshot_B.parquet';
-- WITH p AS (SELECT ip, port, transport, coalesce(scan_hostname,'') sni, arg_max(product, ts) product, arg_max(version, ts) version,
--                   arg_max(cert_sha256, ts) cert, arg_max(http_title, ts) title, max(ts) ts
--            FROM read_parquet(getvariable('prev')) WHERE coalesce(banner_len,0) > 0 GROUP BY ALL),
--      c AS (... same over getvariable('curr') ...)
-- SELECT coalesce(c.ip, p.ip) ip, coalesce(c.port, p.port) port,
--        CASE WHEN p.ip IS NULL THEN 'new_exposure' WHEN c.ip IS NULL THEN 'closed'
--             WHEN c.version IS DISTINCT FROM p.version THEN 'version_change'
--             WHEN c.cert IS DISTINCT FROM p.cert THEN 'cert_rotated'
--             WHEN c.product IS DISTINCT FROM p.product THEN 'product_change' END AS change
-- FROM p FULL OUTER JOIN c USING (ip, port, transport, sni) WHERE change IS NOT NULL;
