"""Attribution org classification (v1-v5): norm_org, accent folding, curated classify_org, data-driven backstops."""

from __future__ import annotations

import re

import pytest

from firmable.attribution.providers import (
    classify_org,
    is_access_network_name,
    org_backstop,
    org_backstop_class,
    norm_org,
    org_names_match,
)


@pytest.mark.parametrize(
    "org, expected",
    [
        ("Incapsula Inc", "incapsula"),
        ("Incapsula Inc.", "incapsula"),
        ("Aliyun Computing Co., LTD", "aliyun computing"),
        ("Aliyun Computing Co.LTD", "aliyun computing"),
        ("UnitedHealth Group Incorporated", "unitedhealth group"),
        ("Wal-Mart Stores, Inc.", "wal-mart stores"),
        ("  Example   Corp ", "example"),
        (None, ""),
    ],
)
def test_norm_org(org, expected):
    assert norm_org(org) == expected


@pytest.mark.parametrize(
    "org, isp, expected",
    [
        # businesses (A1/A2 candidates)
        ("UnitedHealth Group Incorporated", "Unitedhealthcare", "business"),
        ("Wal-Mart Stores, Inc.", "Google LLC", "business"),
        ("Apple Inc.", "Apple Inc.", "business"),
        ("Example Corp", "Example ISP", "business"),
        # cloud / hosting
        ("Google LLC", "Google LLC", "cloud_hosting"),
        ("Amazon Technologies Inc.", "Amazon.com, Inc.", "cloud_hosting"),
        ("Hetzner Online GmbH", "Hetzner Online GmbH", "cloud_hosting"),
        ("DigitalOcean, LLC", "DigitalOcean, LLC", "cloud_hosting"),
        ("Unified Layer", "Oracle Corporation", "cloud_hosting"),
        ("Strato GmbH", "Strato GmbH", "cloud_hosting"),
        # CDN / WAF edges
        ("Incapsula Inc", "Incapsula Inc", "cdn"),
        ("Cloudflare, Inc.", "Cloudflare, Inc.", "cdn"),
        ("Akamai Technologies, Inc.", "Akamai Technologies, Inc.", "cdn"),
        ("Fastly, Inc.", "Fastly, Inc.", "cdn"),
        # SaaS / site platforms (serve customer brands)
        ("Salesforce, Inc.", "Amazon.com, Inc.", "saas_platform"),
        ("Shopify, Inc.", "Cloudflare, Inc.", "saas_platform"),
        ("WPEngine, Inc.", "Cloudflare London, LLC", "saas_platform"),
        ("HubSpot, Inc.", "Amazon.com, Inc.", "saas_platform"),
        ("Automattic, Inc", "Automattic, Inc", "saas_platform"),
        # ISPs / telcos, including the misses listed in company-attribution.md §4
        ("Comcast Cable Communications, LLC", "Comcast Cable Communications, LLC", "isp_telco"),
        ("BIGLOBE Inc.", "BIGLOBE Inc.", "isp_telco"),
        ("Asahi Net", "Asahi Net", "isp_telco"),
        ("Yettel Hungary Zrt.", "Yettel Hungary Zrt.", "isp_telco"),
        ("XFone 018 Ltd", "XFone 018 Ltd", "isp_telco"),
        ("SingNet Pte Ltd", "SingNet Pte Ltd", "isp_telco"),
        ("BSNL", "BSNL", "isp_telco"),
        ("OPTAGE Inc.", "OPTAGE Inc.", "isp_telco"),
        ("INTERNEXA S.A. E.S.P", "INTERNEXA S.A. E.S.P", "isp_telco"),
        ("MTN Nigeria", "MTN Nigeria", "isp_telco"),
        ("Puerto Rico Telephone Company", "Puerto Rico Telephone Company", "isp_telco"),
        ("Fatbeam, LLC", "Fatbeam, LLC", "isp_telco"),
        ("EDPNET", "EDPNET", "isp_telco"),
        ("Bell Canada", "Bell Canada", "isp_telco"),
        # found in the top A1 orgs of the first full run (2026-11-09)
        ("Free Pro SAS", "Free Pro SAS", "isp_telco"),
        ("CANTV Servicios, Venezuela", "CANTV Servicios, Venezuela", "isp_telco"),
        ("FreeBit Co., Ltd.", "FreeBit Co.,Ltd.", "isp_telco"),
        ("Optimum", "Optimum", "isp_telco"),
        ("JCOM Co., Ltd.", "JCOM Co., Ltd.", "isp_telco"),
        ("IP range for xDSL, IPTV, Fixed Phone service at HCMC", "VNPT Corp", "isp_telco"),
        ("This space is statically assigned.", "Example Telecom", "isp_telco"),
        ("GMO-Z com NetDesign Holdings Co., Ltd.", "GMO-Z com NetDesign Holdings Co., Ltd.", "cloud_hosting"),
        ("AdminVPS OOO", "AdminVPS OOO", "cloud_hosting"),
        ("iboss,inc", "iboss,inc", "saas_platform"),
        # real organisations that must stay accounts
        ("West Virginia University", "West Virginia University", "business"),
        ("The Bank of New York Mellon Corporation", "The Bank of New York Mellon Corporation", "business"),
        ("Medidata Solutions, Inc", "Medidata Solutions, Inc", "business"),
        ("Department of Customer Service", "Department of Customer Service", "business"),
        ("Bredband2 Customer", "Bredband2 AB", "isp_telco"),
        # pool labels take the network operator's class
        ("IP pools", "Example Telecom", "isp_telco"),
        ("Dynamic pools", "Example Telecom", "isp_telco"),
        ("Static IP Services", "Example Telecom", "isp_telco"),
        ("Customers", "KPN B.V.", "isp_telco"),
        ("Private Customer", "Amazon.com, Inc.", "cloud_hosting"),
        # no usable org
        ("Company 64d3451abc9f", "Example Telecom", "unknown"),
        ("Company 67a08938l6y7Sxyw", "Cloudflare, Inc.", "unknown"),
        (None, "Example Telecom", "unknown"),
        ("", None, "unknown"),
        ("Inc.", None, "unknown"),
        # postal addresses used as registrant names (e.g. a cloud provider's regional office)
        ("21/F, Ciputra World 1 (DBS Tower), JalanProf. DR. Satrio Kav 3-5, Jakarta 12940, Indonesia",
         "Alibaba (US) Technology Co., Ltd.", "unknown"),
        ("1 Raffles Place,", "Alibaba (US) Technology Co., Ltd.", "unknown"),
        ("1359 S DREXEL WAY", "Nebula Global LLC", "unknown"),
        ("314 krishna netaji subhash place pitampura", "314 krishna netaji subhash place pitampura", "unknown"),
        # company names that merely start with digits stay businesses
        ("84 Grams AB", "84 Grams AB", "business"),
        ("365 Group LLC", "365 Group LLC", "business"),
        ("3 Customer dynamic address pool", "Hi3G Access AB", "isp_telco"),
        ("YouStable", "YouStable", "cloud_hosting"),
        # fix round 2026-11-10: curated ISPs / hosters confirmed in the 2026-11-07 data
        ("Eircom Limited", "Eircom Limited", "isp_telco"),
        ('PrJSC "VF Ukraine"', 'PrJSC "VF Ukraine"', "isp_telco"),
        ("Hutchison Drei Austria GmbH", "Hutchison Drei Austria GmbH", "isp_telco"),
        ("HERABIT S.p.A.", "HERABIT S.p.A.", "isp_telco"),
        ("BRASIL TECPAR | AMIGO | AVATO", "BRASIL TECPAR | AMIGO | AVATO", "isp_telco"),
        ("LEW TelNet GmbH", "LEW TelNet GmbH", "isp_telco"),
        ("PUNTONET S.A.", "PUNTONET S.A.", "isp_telco"),
        ("Núcleo S.A.", "Núcleo S.A.", "isp_telco"),
        ("Saba Abr Mizban LLC", "Saba Abr Mizban LLC", "isp_telco"),
        ("Globalways GmbH", "Globalways GmbH", "isp_telco"),
        ("TELY Ltda.", "TELY Ltda.", "isp_telco"),
        ("Wana Corporate - Wana Corporate", "Wana Corporate - Wana Corporate", "isp_telco"),
        ("New Century InfoComm Tech. Co., Ltd.", "New Century InfoComm Tech. Co., Ltd.", "isp_telco"),
        ("Logix", "Logix", "isp_telco"),
        ("Conterra", "Conterra", "isp_telco"),
        ("C.C.S. (Leeds) Ltd", "C.C.S. (Leeds) Ltd", "isp_telco"),
        ("Pioneer Elabs Ltd.", "Pioneer Elabs Ltd.", "isp_telco"),
        ("Operbes, S.A. de C.V.", "Operbes, S.A. de C.V.", "isp_telco"),
        ("Bharat Sanchar Nigam Ltd", "Bharat Sanchar Nigam Ltd", "isp_telco"),
        ("Magticom Ltd.", "Magticom Ltd.", "isp_telco"),
        ("HAIonNet", "HAIonNet", "isp_telco"),
        ("Iran Information Technology Company PJSC", "Iran Information Technology Company PJSC", "isp_telco"),
        ("Register.com, Inc", "Register.com, Inc", "cloud_hosting"),
        ("xTom GmbH", "xTom GmbH", "cloud_hosting"),
        ("Voxility LLP", "Voxility LLP", "cloud_hosting"),
        ("Beijing CNISP Technology Co., Ltd.", "Beijing CNISP Technology Co., Ltd.", "cloud_hosting"),
        ("UberGlobal UBRCBRCCA", "UberGlobal UBRCBRCCA", "cloud_hosting"),
        ("Nucleo Brasil Servidores Ltda", "Nucleo Brasil Servidores Ltda", "cloud_hosting"),
        # iteration on the top owned orgs by exposure-signal services (2026-11-10)
        ("Binary Racks Limited", "Binary Racks Limited", "cloud_hosting"),
        ("Nexeon Technologies, Inc.", "DataWagon LLC", "cloud_hosting"),
        ("Dynu Systems Incorporated", "Dynu Systems Incorporated", "cloud_hosting"),
        ("PacketStream Korea", "PacketStream Korea", "cloud_hosting"),
        ("Rapid Infocare Pvt Ltd", "URLSTART", "cloud_hosting"),
        ("Tecpoint Global Solution limited", "Tecpoint Global Solution limited", "cloud_hosting"),
        ("SAS KALANDA", "KALANDA SAS KALANDA", "cloud_hosting"),
        ("PT. INDUSTRI KREATIF DIGITAL", "PT Industri Kreatif Digital", "cloud_hosting"),
        ("Part Payam Paya LLC", "Part Payam Paya LLC", "cloud_hosting"),
        ("Optimus Technologies", "Optimus Technologies", "cloud_hosting"),
        ("PetroSky", "PETROSKY CLOUD LLC", "cloud_hosting"),
        ("Grupo Interdominios S.A", "cloudbuilders Cloud Builders SA", "cloud_hosting"),
        ("Liasail Global Hongkong Limited", "Liasail Global Hongkong Limited", "cloud_hosting"),
        ("InterLIR LLC", "TWO-E-Telekom", "cloud_hosting"),
        ("ScaleMatrix", "ScaleMatrix", "cloud_hosting"),
        ("Enreach Netherlands B.V.", "Enreach Netherlands B.V.", "isp_telco"),
        ("INTEGRATEL PERÚ S.A.A.", "INTEGRATEL PERU S.A.A.", "isp_telco"),
        ("GLOBAL CONNECTIVITY SOLUTIONS LLP", "GLOBAL CONNECTIVITY SOLUTIONS LLP", "isp_telco"),
        ("Office of Info.Tech. Admin. for Educational Development", "UNINET-TH", "isp_telco"),
        ("+27 (82) 7774140", "JACQCO MANAGEMENT CC", "unknown"),      # phone number as registrant
        ("Washington State Board for Community & Technical Colleges", "Washington State K-20", "business"),
        ("State Street Bank and Trust Company", "State Street Bank and Trust Company", "business"),
        # static pools take the operator's class
        ("ADSL-TT net_Static Pool", "Turk Telekom", "isp_telco"),
        ("Business Static Pool", "Example Telecom", "isp_telco"),
        ("Corporate Static Pool Assignment", "Example Telecom", "isp_telco"),
        ("Fontel Static Pool Business", "Fontel S.A.", "isp_telco"),
        # must stay businesses
        ("Núcleo de Inf. e Coord. do Ponto BR - NIC.BR", "Núcleo de Inf. e Coord. do Ponto BR - NIC.BR", "business"),
        ("Columbia University", "Columbia University", "business"),
        ("GreyLogix GmbH", "GreyLogix GmbH", "business"),
    ],
)
def test_classify_org(org, isp, expected):
    assert classify_org(org, isp) == expected


def test_org_names_match_uses_first_significant_token():
    assert org_names_match("UnitedHealth Group Incorporated", "UnitedHealth Group Inc.")
    assert org_names_match("Wal-Mart Stores, Inc.", "Walmart Inc.")
    assert org_names_match("Apple Inc.", "Apple Inc.")
    assert not org_names_match("Unified Layer", "Plesk")
    assert not org_names_match("China Telecom", "China Unicom")   # generic first token ignored
    assert not org_names_match("Example Corp", None)
    assert not org_names_match(None, "Example Corp")


@pytest.mark.parametrize(
    "n_domains, n_services, own_certs, o_certs, cdn_cloud_share, cdn_share, expected",
    [
        (343, 5608, 2608, 2680, 0.0, 0.0, None),          # UnitedHealth-like: own OV certs on 46% of services
        (180, 299, 61, 61, 0.0, 0.0, None),               # CIGNA-like: 20% own, but every O-bearing cert is its own
        (1545, 3977, 0, 9, 0.0, 0.0, "saas_platform"),     # WPEngine-like: tenant domains, no own certs
        (351, 464, 40, 43, 0.0, 0.0, "saas_platform"),     # registrar-like: own cert on < 50 services
        (101, 1000, 240, 600, 0.0, 0.0, "saas_platform"),  # 24% own and only 40% of O-bearing certs
        (100, 1000, 0, 0, 0.0, 0.0, None),                 # threshold is strictly > 100 domains
        (5, 10, 0, 0, 0.9, 0.9, "cdn"),                    # CDN-tagged majority
        (5, 10, 0, 0, 0.6, 0.1, "cloud_hosting"),          # cloud-tagged majority
        (5, 10, 0, 0, 0.5, 0.3, None),                     # share 0.5 is not > 0.5
        (5, 10, 0, 0, 0.0, 0.0, None),
    ],
)
def test_org_backstop_class(n_domains, n_services, own_certs, o_certs, cdn_cloud_share, cdn_share, expected):
    assert org_backstop_class(n_domains, n_services, own_certs, o_certs, cdn_cloud_share, cdn_share) == expected


@pytest.mark.parametrize(
    "name, expected",
    [
        ("adsl-12-34.example-isp.net", True),
        ("dsl5.example-isp.de", True),
        ("dynamic-77.example-isp.com", True),
        ("cpe-1.example-isp.com", True),
        ("ftth2.example.net.br", True),
        ("res-9.example-cable.com", True),
        ("lte4.mobile-op.example", True),
        ("subscriber-001.example.net", True),
        ("host-198-51-100-7.example-isp.net", False),      # plain IP-embedded PTR is not an access label
        ("ec2-198-51-100-7.compute-1.amazonaws.com", False),
        ("server-198-51-100-7.cloud.example.com", False),
        ("www.example.com", False),
        ("mail.residence-hotel.com", False),
    ],
)
def test_is_access_network_name(name, expected):
    assert is_access_network_name(name) is expected


@pytest.mark.parametrize(
    "n_services, access_services, expected",
    [
        (20, 6, ("isp_telco", "org_access_network_ptr")),   # 0.30 >= 0.30
        (100, 86, ("isp_telco", "org_access_network_ptr")), # conterra-like 0.86
        (100, 27, None),                                    # Columbia-like 0.27 stays business
        (19, 19, None),                                     # fewer than 20 services: no decision
        (100, 0, None),                                     # MIT / Apple / UnitedHealth-like
    ],
)
def test_org_backstop_access_network(n_services, access_services, expected):
    assert org_backstop(0, n_services, 0, 0, 0.0, 0.0, access_services) == expected


def test_org_backstop_access_network_wins_over_other_backstops():
    assert org_backstop(500, 100, 0, 0, 0.9, 0.9, 40) == ("isp_telco", "org_access_network_ptr")
    assert org_backstop(500, 100, 0, 0, 0.0, 0.0, 0) == ("saas_platform", "org_multi_tenant")
    assert org_backstop(5, 100, 0, 0, 0.9, 0.9, 0) == ("cdn", "org_cdn_cloud_tagged")


# Ownership corroboration (accounts layer): stricter than the reviewer aid `plausibly_names_org`.
import pytest as _pytest  # noqa: E402

from firmable.attribution.providers import ownership_names_org  # noqa: E402


@_pytest.mark.parametrize("domain, org, ok", [
    ("ucdavis.edu", "University of California, Davis", True),     # short prefix + distinctive word
    ("berkeley.edu", "University of California at Berkeley", True),
    ("mit.edu", "Massachusetts Institute of Technology", True),     # initials
    ("sap.com", "SAP SE", True),
    ("mcgill.ca", "McGill University", True),
    ("telecomitalia.it", "LUXURY GOODS ITALIA SPA", False),         # word buried in another name
    ("missouricareereducation.org", "University of Central Missouri", False),
    ("thorsystems.net", "Hopkinsville Electric System", False),
    ("preventivehealth.net.au", "eHealth NSW", False),
])
def test_ownership_names_org_rejects_buried_substrings(domain, org, ok):
    assert ownership_names_org(domain, org) is ok


# ----------------------------------------------------------------------------- attribution v5: accent folding
# Registrant names arrive with and without diacritics ("Telefónica" / "Telefonica" / "Telefônica"). Every org
# and ISP name is folded (NFKD, combining diacritics stripped, casefolded, plus letters that do not decompose)
# before it is normalised or matched, so the curated ASCII tables read all spellings alike.
from firmable.attribution.providers import (  # noqa: E402
    domain_matches_org,
    first_significant_token,
    plausibly_names_org,
)
from firmable.attribution.text import fold_name  # noqa: E402


@_pytest.mark.parametrize("raw, folded", [
    ("Telefónica", "telefonica"),
    ("Telefônica", "telefonica"),
    ("TELEFÓNICA CHILE S.A.", "telefonica chile s.a."),
    ("Société Générale", "societe generale"),
    ("Universität Zürich", "universitat zurich"),
    ("Linköpings universitet", "linkopings universitet"),
    ("Türk Telekomünikasyon A.Ş.", "turk telekomunikasyon a.s."),
    ("TÜRK TELEKOMÜNİKASYON ANONİM ŞİRKETİ", "turk telekomunikasyon anonim sirketi"),
    ("Superonline İletişim Hizmetleri", "superonline iletisim hizmetleri"),
    ("ılıca", "ilica"),                                   # Turkish dotless i
    ("Øresund Æblegård", "oresund aeblegard"),            # letters NFKD does not decompose
    ("Œuvre Straße", "oeuvre strasse"),
    ("Łódź Đakovo Þórshöfn Garðabær", "lodz dakovo thorshofn gardabaer"),
    ("ＦＵＬＬＷＩＤＴＨ Ｃｏ", "fullwidth co"),             # compatibility forms
    ("Plain ASCII Inc.", "plain ascii inc."),
    ("Москва-Телеком", "москва-телеком"),                 # other scripts are only case-folded
    ("Дом.ru Й", "дом.ru и"),                             # ... and lose Cyrillic diacritics (й -> и)
    ("ประเทศไทย", "ประเทศไทย"),                           # Thai vowel marks are kept (not diacritics)
    ("กิ่ง", "กิ่ง"),                                       # Thai tone mark + vowel sign (combining marks)
    ("हिन्दी", "हिन्दी"),                                    # Devanagari virama and vowel signs
    ("مُحَمَّد", "مُحَمَّد"),                                    # Arabic harakat
    ("삼성전자", "삼성전자"),                                # Hangul syllables stay precomposed
    ("株式会社ガス", "株式会社ガス"),                          # kana with dakuten stays precomposed
    ("ǿ", "o"),                                           # needs more than two passes to reach a fixed point
    (None, ""),
    ("", ""),
])
def test_fold_name(raw, folded):
    assert fold_name(raw) == folded


@_pytest.mark.parametrize("raw", [
    "Telefónica", "TÜRK TELEKOMÜNİKASYON ANONİM ŞİRKETİ", "Øresund", "Straße", "ＦＵＬＬ", "ǅemal", "ﬁnance ℌ",
    "Москва", "ประเทศไทย", "東京大学", "İ", "ı", "", "á̂",
])
def test_fold_name_is_idempotent(raw):
    once = fold_name(raw)
    assert fold_name(once) == once


def _bmp_letters():
    import unicodedata
    return [chr(cp) for cp in range(0x20, 0x10000)
            if unicodedata.category(chr(cp))[0] in "LM" and not 0xD800 <= cp <= 0xDFFF]


def test_fold_name_is_idempotent_on_every_bmp_letter_and_mark():
    bad = [c for c in _bmp_letters() if fold_name(fold_name(c)) != fold_name(c)]
    assert bad == []


def test_fold_name_is_idempotent_on_deterministic_mixed_strings():
    import random
    import unicodedata
    letters = _bmp_letters()
    blocks = [range(0x41, 0x7B), range(0xC0, 0x250), range(0x370, 0x400), range(0x400, 0x530),
              range(0x1E00, 0x1F00), range(0x3040, 0x3100), range(0xAC00, 0xAC80), range(0x0E00, 0x0E60),
              range(0x0900, 0x0980), range(0x0600, 0x0700), range(0x0300, 0x0370)]
    pool = [chr(c) for b in blocks for c in b if unicodedata.category(chr(c))[0] in "LMN"] + [" ", "-", "."]
    rng = random.Random(20261111)
    for _ in range(20000):
        x = "".join(rng.choice(pool if rng.random() < 0.8 else letters) for _ in range(rng.randint(1, 12)))
        once = fold_name(x)
        assert fold_name(once) == once, x


@_pytest.mark.parametrize("org", [
    "Telefónica", "Telefonica", "Telefônica", "TELEFÓNICA CHILE S.A.", "Telefónica del Perú S.A.A.",
    "Türk Telekomünikasyon A.Ş.", "TÜRK TELEKOMÜNİKASYON ANONİM ŞİRKETİ", "Turk Telekom",
    "Superonline İletişim Hizmetleri A.Ş.", "Turkcell İletişim Hizmetleri A.Ş.",
    "Teléfonos de México", "Telefonos de Mexico", "Núcleo S.A.", "Nucleo S.A.",
    "Brasil Telecomunicações Ltda", "Algar Comunicações", "Netcom İletişim",
])
def test_accented_isp_names_are_isps(org):
    assert classify_org(org, None) == "isp_telco"


@_pytest.mark.parametrize("org", [
    "Société Générale", "Universität Zürich", "Linköpings universitet", "Universidade de São Paulo",
    "Østfold fylkeskommune", "Technische Universität München", "Zürcher Kantonalbank",
    "Boğaziçi Üniversitesi", "İstanbul Teknik Üniversitesi",
])
def test_accented_business_names_stay_business(org):
    assert classify_org(org, None) == "business"


def test_norm_org_folds_accents_so_spellings_share_a_key():
    assert norm_org("Telefónica Chile S.A.") == norm_org("TELEFONICA CHILE SA") == "telefonica chile"
    assert norm_org("Universität Zürich") == "universitat zurich"
    assert norm_org("Türk Telekomünikasyon A.Ş.") == norm_org("TÜRK TELEKOMÜNİKASYON A.Ş.")


def test_first_significant_token_keeps_accented_letters():
    # before folding the accented letter was dropped ("telefnica", "socit")
    assert first_significant_token("Telefónica Chile S.A.") == "telefonica"
    assert first_significant_token("Société Générale") == "societe"
    assert first_significant_token("École Polytechnique Fédérale de Lausanne") == "ecole"


def test_org_names_match_across_accent_spellings():
    assert org_names_match("Telefónica Chile S.A.", "Telefonica Chile SA")
    assert org_names_match("TÜRK TELEKOMÜNİKASYON A.Ş.", "Turk Telekomunikasyon AS")
    assert not org_names_match("Société Générale", "Generali")


@_pytest.mark.parametrize("domain, org, ok", [
    ("telefonica.cl", "Telefónica Chile S.A.", True),          # first significant token prefix
    ("societegenerale.com", "Société Générale", True),         # tokens concatenated
    ("turktelekom.com.tr", "Türk Telekomünikasyon A.Ş.", True),
])
def test_domain_matches_accented_org(domain, org, ok):
    assert domain_matches_org(domain, org) is ok


@_pytest.mark.parametrize("domain, org, ok", [
    ("epfl.ch", "École Polytechnique Fédérale de Lausanne", True),   # initials need the folded É
    ("tum.de", "Technische Universität München", True),               # initials
    ("societegenerale.fr", "Société Générale", True),
    ("uzh.ch", "Universität Zürich", False),       # not initials of the name: unsupported, stays unmatched
    ("liu.se", "Linköpings universitet", False),   # syllable abbreviation: unsupported, stays unmatched
])
def test_ownership_matching_of_accented_orgs(domain, org, ok):
    assert plausibly_names_org(domain, org) is ok
    assert ownership_names_org(domain, org) is ok


def test_accented_pool_label_takes_operator_class():
    # pool / address / phone checks run on the folded name
    assert classify_org("STATİC IP SERVİCES", "Telefônica Brasil S.A.") == "isp_telco"
    assert classify_org("STATİC IP SERVİCES", "Hetzner Online GmbH") == "cloud_hosting"   # operator's class
    assert classify_org("Customers", "Telefónica de España") == "isp_telco"
    assert classify_org("+56 (2) 2691 0000", None) == "unknown"


def test_is_access_network_name_lower_cases_but_does_not_fold_dns_names():
    # hostnames are DNS names: the SQL mirrors use lower(), so Python must not fold them either
    assert is_access_network_name("ADSL-12.EXAMPLE-ISP.NET")
    assert not is_access_network_name("dšl-12.example-isp.net")
    assert not is_access_network_name(None)


def test_curated_name_patterns_are_ascii_so_folded_names_can_match():
    import firmable.accounts.eligibility as elig
    import firmable.attribution.providers as prov

    patterns = {k: v for m in (prov, elig) for k, v in vars(m).items() if isinstance(v, re.Pattern)}
    assert patterns
    assert {k for k, p in patterns.items() if not p.pattern.isascii()} == set()
    assert all(w.isascii() for w in prov._STOPWORDS | prov._COMMON_WORDS | prov._GENERIC_TOKENS)


# ----------------------------------------------------------------------------- attribution v5: named additions
# Each org string was seen in the 2026-11-07 data and each entry is corroborated by OpenASN or the snapshot's
# own `isp` field (citations in docs/attribution-implementation.md §7.2). Tigo Energy (a solar company) is not
# an operator.
@_pytest.mark.parametrize("org, isp, expected", [
    ("Bite Lietuva", 'UAB "Bite Lietuva"', "isp_telco"),            # AS13194 OpenASN "Bitė Lietuva" hosting
    ('UAB "Bite Lietuva"', 'UAB "Bite Lietuva"', "isp_telco"),
    ("Axtel, S.A.B. de C.V.", "Alestra, S. de R.L. de C.V.", "isp_telco"),   # OpenASN AS6503 "Axtel" isp
    ("BIT BV", "NL-BIT BIT BV", "isp_telco"),                      # AS12859 OpenASN "BIT internetprovider" isp
    ("BIT B.V.", "NL-BIT BIT BV", "isp_telco"),
    ("Tigo Guatemala Corp", "COMCEL GUATEMALA S.A.", "isp_telco"),  # OpenASN: six Tigo ASNs filed isp
    ("TIGO-CORPORATIVO", "Navega.com S.A.", "isp_telco"),
    ("Corporativos TIGO GT", "METRORED S.A. DE C.V.", "isp_telco"),
    ("For TIGO B2B clients", "SAGA AFRICA HOLDINGS LIMITED", "isp_telco"),
    ("TIGO PUBLIC IP", "SAGA AFRICA HOLDINGS LIMITED", "isp_telco"),
    ("Tigo", "Telecel S.A.", "isp_telco"),
    ("Batelco Jordan", "Al Bahrainia al Urdunia Liltaknia Wa Alitisalat Plc. Co", "isp_telco"),  # AS9038 Umniah isp
    ("Batelco MPLS service", "BEYON B.S.C.", "isp_telco"),          # AS5416 OpenASN "Beyon (Batelco)" isp
    ("VODIEN AUSTRALIA PTY LTD", "Dreamscape Networks Limited", "cloud_hosting"),  # web host on Dreamscape AS38719
    ("Vodien Internet Solutions Pte Ltd", "Vodien Internet Solutions Pte Ltd", "cloud_hosting"),
    ("Azion Technologies Ltda.", "Azion Technologies Ltda.", "cdn"),          # AS52580 OpenASN flag cdn
    ("Clientes NETLIFE Quito - gepon", "Telconet S.A", "isp_telco"),          # Telconet AS27947 OpenASN isp
    ("Clientes NETLIFE Guayaquil - gepon - zona 6", "Telconet S.A", "isp_telco"),
    ("shanghai branch, china netcom", "China Unicom Shanghai network", "isp_telco"),   # AS17621 OpenASN isp
    ("Jazztel triple play services", "Orange Espagne SA", "isp_telco"),   # AS12479 OpenASN "Orange España" isp
    ("Jazztel Triple Play Services", "Orange Espagne SA", "isp_telco"),
    ("Fujian quanzhou branch of China Netcom", "CHINA169-Backbone - CHINA UNICOM China169 Backbone", "isp_telco"),
    ("EG VERI MERKEZI TEKNOLOJI LTD. STI.", "EG Veri Merkezi Teknoloji Ltd. Sti.", "cloud_hosting"),  # AS212249 hosting
    ("CHEOPS TECHNOLOGY FRANCE S.A.", "CHEOPS TECHNOLOGY FRANCE S.A.", "cloud_hosting"),  # AS58011 OpenASN hosting
    # not operators
    ("GPM informatique Transverse", "CHEOPS TECHNOLOGY FRANCE S.A.", "business"),   # a customer on Cheops' network
    ("TEKNET VERI MERKEZI HIZMETLERI A.S.", "Example ISP", "business"),   # no generic "veri merkezi" keyword
    ("Tigo Energy, Inc.", "Comcast Cable Communications, LLC", "business"),
    ("TIGO-ENERGY", "Example ISP", "business"),
    ("Tigo Solar", "Example ISP", "business"),
    ("Tigo Security", "Example ISP", "business"),
    ("Maxtel Systems", "Example ISP", "business"),          # \baxtel\b needs a word boundary
    ("Axtell Engineering", "Example ISP", "business"),
    ("Batelcom Holdings", "Example ISP", "business"),       # \bbatelco\b needs a word boundary
    ("Abatelco Imports", "Example ISP", "business"),
    ("Bitwise Industries BV", "Example ISP", "business"),
    ("Orbit B.V.", "Example ISP", "business"),
    ("Netlife Robotics", "Example ISP", "business"),
])
def test_v5_named_provider_additions(org, isp, expected):
    assert classify_org(org, isp) == expected
