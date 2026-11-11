"""Attribution v1, org layer: normalize registrant org names and classify them.

`classify_org` is a curated name classifier (keyword + named-provider tables), a port of
`is_provider_org` (sql/exploration.sql §4) split into classes and extended with the ISPs the
research found misread as companies (company-attribution.md §4). It is reference data about
networks, not prospect data.

`org_backstop_class` is the data-driven backstop computed per org over the snapshot in
`build.py`. Its thresholds are hypotheses chosen from the 2026-11-07 profile, not measured
against labels (see docs/attribution-implementation.md).
"""

from __future__ import annotations

import re

from .text import fold_name

ORG_CLASSES = ("business", "cloud_hosting", "cdn", "isp_telco", "saas_platform", "unknown")
PROVIDER_CLASSES = frozenset({"cloud_hosting", "cdn", "isp_telco", "saas_platform"})

# Backstop thresholds (hypotheses, see module docstring).
MULTI_TENANT_MIN_DOMAINS = 100      # strictly more distinct accepted customer domains than this ...
OWN_CERT_EXEMPT_SHARE = 0.25        # ... unless at least this share of the org's services present an
                                    # OV/EV certificate whose subject O names the org itself, or
OWN_CERT_EXEMPT_MIN = 50            # at least this many services do and they are
OWN_CERT_EXEMPT_PURITY = 0.8        # at least this share of the org's certificates that carry an O
CDN_CLOUD_TAG_SHARE = 0.5           # strictly more than this share of services tagged cdn/cloud
ACCESS_MIN_SERVICES = 20            # access-network backstop: orgs with at least this many services ...
ACCESS_SHARE = 0.30                 # ... where at least this share carry an access-network PTR label

# Subscriber / access-network reverse-DNS labels (an access token followed by digits). Plain
# IP-embedded PTRs are deliberately NOT used: enterprise and SaaS ranges have them too
# (measured 2026-11-10: Adobe 0.75, ServiceNow 0.99, ICE 0.87), while these labels give ISPs
# 0.4-1.0 and enterprises/universities ~0 (Columbia 0.27).
ACCESS_PTR_PATTERN = (
    r"(^|[.-])(a?dsl|xdsl|dhcp|dyn|dynamic|pool|cust|customer|client|ppp|pppoe|cpe|bb|broadband|ftth|fttx"
    r"|fttb|fiber|fibra|cable|res|resid|residential|mobile|static|subscriber|sub|wireless|wimax|lte|4g|5g"
    r"|gpon|cgnat|nat|user|home|dial|dialup)[-.]?\d"
)
_ACCESS_PTR = re.compile(ACCESS_PTR_PATTERN)

_LEGAL = re.compile(
    r"\b(inc|incorporated|llc|l l c|ltd|limited|corp|corporation|co|company|gmbh|ag|sa|sas|s a|bv|b v"
    r"|plc|pte|pty|llp|lp|kk|srl|spa|ab|oy|as|nv)\b"
)


def norm_org(org: str | None) -> str:
    """Port of the SQL `norm_org`: fold accents and case (`fold_name`, attribution v5), strip punctuation
    and legal suffixes, squeeze spaces. It is also the org account key (`org:<norm_org>`)."""
    s = re.sub(r"[.,\"'()]", " ", fold_name(org))
    s = _LEGAL.sub(" ", s)
    return re.sub(r"\s+", " ", s).strip()


def _rx(words: list[str]) -> re.Pattern[str]:
    return re.compile("(" + "|".join(words) + ")")


# ----------------------------------------------------------------------------- curated tables
# Named providers first (most specific), then generic keywords. Patterns run on the folded raw org
# (`fold_name`: accents removed, case-folded), so every literal below must be plain ASCII.
_SYNTHETIC = re.compile(r"^company [0-9a-z]{8,}$")           # e.g. "Company 64d3451..." registrant names
_PHONE = re.compile(r"^\+?[\d\s().-]{7,}$")                 # phone numbers used as registrant names
# Postal addresses used as registrant names ("21/F, Ciputra World 1 ...", "1 Raffles Place,"): a number
# followed by a street/building word. Company names that merely start with digits ("84 Grams AB") pass.
_ADDRESS = re.compile(
    r"^\d+[a-z]?(/f)?[, ]+.*\b(road|rd|street|st|place|way|avenue|ave|nagar|floor|tower|jalan\w*|lane"
    r"|blvd|boulevard|drive|dr|plaza|building|bldg)\b"
)
_POOL_LABEL = re.compile(
    r"static pools?|"
    r"^(customers?|infrastructure|subscribers?|residential|end user organi[sz]ation|private customers?"
    r"|ip pools?|dynamic pools?|static ip services?|dynamic ip|static ip|nat pool|cgnat)\b"
    r"|^customer-|customer pool|customers pool|broadband customers|dsl customers|ip pools|dynamic pools|static ip services"
)
# Enterprises caught by the deliberately broad keywords below.
_BUSINESS_OVERRIDE = _rx([r"juniper networks", r"arista networks", r"extreme networks"])

_NAMED_CDN = _rx([
    r"akamai", r"incapsula", r"imperva", r"cloudflare", r"fastly", r"edgecast", r"edgio", r"stackpath",
    r"limelight", r"cachefly", r"cdnetworks", r"chinacache", r"wangsu", r"chinanetcenter", r"bunny",
    r"cdn77", r"sucuri", r"radware", r"vercara", r"ddos-guard", r"ddos guard", r"stormwall", r"qrator",
    r"edgenext", r"quantil", r"g-core", r"gcore", r"medianova", r"belugacdn", r"keycdn",
    r"arvan", r"netskrt",
    # attribution v5 (2026-11-11), evidence in docs/attribution-implementation.md §7.2
    r"\bazion\b",           # own AS52580 (isp = Azion Technologies Ltda.), OpenASN flag `cdn`
])
_NAMED_SAAS = _rx([
    r"salesforce", r"servicenow", r"egnyte", r"bitly", r"squarespace", r"\bwix", r"shopify", r"hubspot",
    r"automattic", r"wordpress", r"wpengine", r"wp engine", r"pantheon", r"vercel", r"netlify",
    r"github", r"zendesk", r"^zoho", r"webflow", r"weebly", r"bigcommerce", r"sedo gmbh", r"parklogic",
    r"bodis", r"trellian", r"corporation service company", r"markmonitor", r"nameshield", r"key-systems",
    r"tucows", r"united-domains", r"gandi", r"porkbun", r"domain names registrar", r"metaregistrar",
    r"team\.blue", r"team blue", r"newfold", r"endurance international", r"palo alto networks",
    r"netskope", r"cato networks", r"zscaler", r"atlassian", r"heroku", r"fly\.io", r"pressable",
    r"kinsta", r"cloudways", r"flywheel", r"carsforsale", r"dealer\.com", r"wix_com", r"iboss",
    r"perimeter 81", r"zenfolio", r"cpanel", r"byteplus",
])
_NAMED_CLOUD = _rx([
    r"amazon", r"\baws\b", r"google", r"microsoft", r"azure", r"alibaba", r"aliyun", r"tencent",
    r"huawei", r"\bovh", r"hetzner", r"digitalocean", r"linode", r"vultr", r"scaleway", r"contabo",
    r"oracle", r"leaseweb", r"ionos", r"1&1 internet", r"\bstrato\b", r"godaddy", r"rackspace", r"equinix",
    r"choopa", r"constant company", r"\bm247", r"psychz", r"quadranet", r"unified layer", r"bluehost",
    r"hostgator", r"namecheap", r"netcup", r"liquid web", r"hivelocity", r"sharktech", r"timeweb",
    r"reg\.ru", r"beget", r"selectel", r"kamatera", r"upcloud", r"hostinger", r"hostpapa", r"inmotion",
    r"dreamhost", r"siteground", r"one\.com", r"loopia", r"combell", r"mittwald", r"dogado", r"webgo",
    r"iomart", r"aptum", r"tierpoint", r"expedient", r"internap", r"datacamp", r"volcano engine",
    r"bytedance", r"kingsoft", r"ucloud", r"qiniu", r"peg tech", r"raksmart", r"worldstream",
    r"reliablesite", r"nforce", r"serverius", r"\bi3d", r"fdcservers", r"datapacket", r"colocrossing",
    r"frantech", r"racknerd", r"dedipath", r"zenlayer", r"cloud innovation", r"aeza", r"stark industries",
    r"hostkey", r"aruba s\.p\.a", r"register s\.p\.a", r"netsons", r"glesys", r"oderland", r"wedos",
    r"websupport", r"masterdc", r"axarnet", r"arsys", r"dattatec", r"dinahosting", r"ibm cloud",
    r"softlayer", r"sakura internet", r"gmo internet", r"gmo pepabo", r"idc frontier", r"signet b\.v",
    r"transip", r"neue medien muennich", r"artfiles", r"23m gmbh", r"meerfarbig", r"webhuset",
    r"synergy wholesale", r"vimexx", r"stichting digi", r"oso grande", r"hdc/hw enterprise",
    r"a100 row", r"owgels", r"luogelang", r"play2go", r"posix systems", r"zone media", r"cluster logic",
    r"3nt solutions", r"b2 net solutions", r"web\.com group", r"monstercommerce", r"suresupport",
    r"openwave messaging", r"wiit ag", r"rackforest", r"tiggee", r"vnet a\.s", r"eonix",
    r"ntirety", r"dxtl", r"gnet inc", r"powerline", r"power line datacenter", r"cs loxinfo",
    r"csloxinfo-idc", r"p\.d\.r solutions", r"^pdr$", r"public-domain-registry", r"eukhost",
    r"robert meyer trading", r"michael sebastian schinzel", r"lennart seitz", r"romarg", r"ispgateway",
    r"\bidc\b", r"gmo-z", r"e-large", r"iqweb", r"dadeh gostar", r"3xk tech", r"green floid", r"whdot",
    r"binbox", r"edis gmbh", r"latitude\.sh", r"quickpacket", r"vi na data", r"packethub", r"light ?node",
    r"clouvider", r"novoserve", r"redluff", r"beyond\.pl", r"icuk", r"vh global", r"slashn",
    r"netcrafters", r"melbikomas", r"gthost", r"logicweb", r"netactuate", r"deluxhost", r"bangmod",
    r"readyidc", r"baxet", r"vapeline", r"servinga", r"rcs technologies", r"west dimension", r"gocodeit",
    r"ptisp", r"webhoster", r"upress", r"da international group", r"metrabyte", r"iens technology",
    r"ip matrix", r"strong technology", r"centersquare", r"leased ipv4", r"tier\.net", r"ramnode",
    r"nocix", r"greengeeks", r"xneelo", r"rumahweb", r"cyber_folks", r"firstcolo", r"ghostnet",
    r"alexhost", r"flexential", r"youstable", r"register\.com",
    r"\bxtom\b", r"voxility", r"\bcnisp\b", r"uberglobal", r"nucleo brasil servidores",
    r"binary racks", r"nexeon technologies", r"dynu systems", r"packetstream", r"rapid infocare",
    r"tecpoint global", r"kalanda", r"industri kreatif digital", r"part payam paya", r"^optimus technologies",
    r"petrosky", r"interdominios", r"liasail", r"interlir", r"scalematrix", r"quality technology services", r"dimension data", r"us signal", r"centrilogic", r"ecritel", r"velia\.net",
    # attribution v5 (2026-11-11): OpenASN files the ASN as `hosting`, with a role (access_provider /
    # content_network) that ADR 0008 does not treat as a provider on its own
    r"^eg veri merkezi\b",   # own AS212249 (isp = EG Veri Merkezi Teknoloji), OpenASN hosting / access_provider
    r"^cheops technology\b", # own AS58011 (isp = CHEOPS TECHNOLOGY FRANCE S.A.), OpenASN hosting / content_network
    r"\bvodien\b",          # web host: VODIEN AUSTRALIA on Dreamscape AS38719 (OpenASN hosting); Vodien's own
                             # AS58621 is filed `isp`, the brand sells hosting and domains
])
_NAMED_ISP = _rx([
    r"verizon", r"at&t", r"comcast", r"charter communications", r"spectrum (business|networks|enterprise)", r"cogent", r"level 3", r"lumen",
    r"centurylink", r"\bntt\b", r"\bkddi", r"softbank", r"china (mobile|unicom|telecom)", r"chinanet",
    r"reliance jio", r"bharti", r"airtel", r"vodafone", r"\borange\b(?! county)", r"telefonica",
    r"telstra", r"optus", r"\bvnpt", r"viettel", r"so-net", r"sony network", r"korea telecom",
    r"chunghwa", r"hinet", r"data communication business group", r"biglobe", r"asahi net", r"\bocn\b",
    r"\bnuro\b", r"yettel", r"xfone", r"singnet", r"singtel", r"starhub", r"\bbsnl\b", r"\bmtnl\b",
    r"optage", r"internexa", r"\bmtn\b", r"puerto rico telephone", r"fatbeam", r"edpnet", r"telenor",
    r"telia", r"tele2", r"\bkpn\b", r"swisscom", r"sunrise (gmbh|communications|upc|ag)", r"bell canada", r"rogers (communications|cable)",
    r"telus", r"shaw (communications|cable)", r"videotron", r"cogeco", r"virgin media", r"british telecom", r"\bbt\b", r"talktalk",
    r"fastweb", r"telecom italia", r"wind tre", r"iliad", r"free sas", r"\bsfr\b", r"bouygues",
    r"versatel", r"ewe tel", r"netcologne", r"\ba1 ", r"proximus", r"telenet", r"\btdc\b", 
    r"altice", r"\bclaro", r"\bvivo\b", r"telmex", r"telcel", r"movistar", r"\bentel\b",
    r"liberty (global|latin|cablevision|puerto rico|networks)", r"digicel", r"turk telekom", r"turkcell", r"superonline", r"rostelecom", r"mts pjsc", r"mobile telesystems",
    r"vimpelcom", r"beeline", r"megafon", r"er-telecom", r"ukrtelecom", r"kyivstar", r"^p4 ",
    r"\bnetia\b", r"\bupc\b", r"vectra s\.?a", r"rcs & rds", r"digi (romania|communications|tavkozlesi|spain|portugal)", r"telekom", r"cosmote", r"hellenic telecom",
    r"\bcyta\b", r"bezeq", r"partner communications", r"cellcom", r"etisalat", r"\bstc\b", r"\bzain\b",
    r"ooredoo", r"mobily", r"\bptcl\b", r"grameenphone", r"banglalink", r"\bpldt\b", r"globe telecom",
    r"converge ict", r"indosat", r"\btelkom", r"biznet", r"\bmaxis\b", r"\bcelcom\b", r"true internet",
    r"advanced info service", r"\b3bb\b", r"triple t", r"cat telecom", r"vocus", r"tpg (telecom|internet)", r"iinet", r"aussie broadband",
    r"superloop", r"spark new zealand", r"chorus limited", r"2degrees", r"safaricom", r"vodacom", r"cell c",
    r"liquid telecom", r"maroc telecom", r"te data", r"wateen", r"\bufone\b", r"\bsify\b",
    r"tata communications", r"tata teleservices", r"hathway", r"excitel", r"frontier communications",
    r"windstream", r"mediacom", r"optimum (online|lightpath)", r"suddenlink", r"\brcn\b", r"cable one",
    r"sparklight", r"brightspeed", r"ziply", r"starlink", r"spacex", r"viasat",
    r"crown castle", r"zayo", r"hurricane electric", r"\bgtt\b", r"colt technology", r"jpnic",
    r"japan network information center", r"unitymedia", r"t-mobile", r"telecel", r"\bjio\b",
    r"tim (celular|s\.?p\.?a|brasil)", r"\btelco\b", r"nos comunica", r"ziggo", r"sky (uk|broadband|italia|deutschland)", r"plusnet", r"\bee\b limited",
    r"free pro", r"cantv", r"asiatech", r"rsaweb", r"\baapt\b", r"freebit", r"sewan", r"tot public",
    r"uninet", r"\beolo\b", r"^optimum$", r"fidium", r"scancom", r"\bjcom\b", r"pt comunicacoes",
    r"polkomtel", r"cyberzone", r"united information highway", r"qtnet", r"mundivox", r"wideopenwest",
    r"general communication", r"\bkbro\b", r"metronet", r"^v tal$", r"wavenet", r"\bucom\b", r"elisa oyj",
    r"silknet", r"sarenet", r"seacom", r"telefonos", r"bahnhof", r"^go p\.?l\.?c", r"familynet",
    r"shatel", r"breezeline", r"seednet", r"blueconnect", r"bredband", r"globalconnect", r"afrihost",
    r"bell mobility", r"virtual1", r"m1 net", r"intred", r"gamma dsl", r"routit", r"^t-2", r"america movil",
    r"vianova", r"first media", r"sonic\.net", r"lg powercomm", r"lg dacom", r"ewe-tel", r"kt hcn",
    r"one new zealand", r"amx argentina", r"odido", r"timenet", r"techtel", r"ultranet", r"ttnet",
    r"turknet", r"webpass", r"exatel", r"dna oyj", r"pishgaman", r"pasargad arian", r"toloe rayaneh",
    r"ishan netsol", r"cyberindo", r"comnets", r"mora telematika", r"hipernet", r"celeste sas", r"green\.ch",
    r"philcom", r"nls kazakhstan", r"^abts", r"ledl\.net", r"starnet", r"adista", r"mynet s\.r\.l",
    r"t\.k bytech", r"orbital net", r"creative communication", r"atria convergence", r"antel",
    r"o2 czech", r"alestra", r"hkbn", r"vivacom", r"tt dotcom", r"init7", r"beanfield", r"syzefxis",
    r"swan, a\.s", r"tm technology services", r"retelit",
    # fix round 2026-11-10 (org strings confirmed in the 2026-11-07 data)
    r"eircom", r"vf ukraine", r"hutchison drei", r"herabit", r"brasil tecpar", r"lew telnet", r"puntonet",
    r"^nucleo s\.?a\.?$", r"saba abr mizban", r"globalways", r"^tely ltda", r"wana corporate",
    r"new century infocomm", r"^logix( communications)?\b", r"^conterra", r"c\.c\.s\. \(leeds\)",
    r"pioneer elabs", r"operbes", r"bharat sanchar", r"magticom", r"haionnet",
    r"iran information technology",
    r"enreach netherlands", r"integratel", r"global connectivity solutions",
    r"office of info\.tech\. admin\. for educational development",
    # national research and education networks: their customers are member institutions
    r"sunet", r"surf b\.v", r"renater", r"cedia", r"\bmcnc\b", r"\bgarr\b", r"\bjisc\b", r"aarnet",
    r"canarie", r"internet2", r"red de servicios ip", r"\brnp\b", r"national infrastructures for research",
    # attribution v5 (2026-11-11): operators found in the actionable enterprise list of scoring v3; each is
    # corroborated by OpenASN or the snapshot's isp field (docs/attribution-implementation.md §7.2)
    r"bite lietuva",        # isp 'UAB "Bite Lietuva"'; AS13194 OpenASN "Bitė Lietuva" hosting / midsize_transit
    r"\baxtel\b",           # OpenASN AS6503 "Axtel" isp; also on AS11172 (isp "Alestra", curated above)
    r"^bit b\.?v\.?$",       # isp "NL-BIT BIT BV"; AS12859 OpenASN "BIT internetprovider" isp
    # Tigo (Millicom): the exact org strings observed in 2026-11-07, on AS23243 / AS23383 / AS26617 / AS37649 /
    # AS23201; OpenASN files six Tigo ASNs as isp. Anchored: Tigo Energy / Tigo Solar are not operators.
    r"^tigo guatemala\b", r"^tigo-corporativo$", r"^corporativos tigo gt$", r"^for tigo b2b clients$",
    r"^tigo public ip$", r"^tigo$",
    r"\bbatelco\b",         # AS9038 OpenASN "Umniah" isp; AS5416 OpenASN "Beyon (Batelco)" isp
    r"^clientes netlife\b",  # "NETLIFE customers"; isp "Telconet S.A", AS27947 OpenASN "Telconet (Ecuador)" isp
    r"china netcom",        # isp "China Unicom ... network"; AS17621 OpenASN "China Unicom (Shanghai)" isp
    r"\bjazztel\b",         # isp "Orange Espagne SA"; AS12479 OpenASN "Orange España" isp / access_provider
])
# Generic keywords (port of is_provider_org), by class.
_KW_CDN = _rx([r"\bcdn\b", r"\bcdn", r"ddos", r"anti-ddos"])
_KW_HOSTING = _rx([
    r"cloud", r"hosting", r"\bhost", r"data ?cent", r"datacenter", r"server", r"vps", r"dedicated",
    r"\bcolo", r"webhotel", r"webhosting",
])
_KW_ISP = _rx([
    r"telecom", r"telekom", r"telecomunica", r"telecommunica", r"communications", r"network",
    r"internet", r"broadband", r"cable", r"mobile", r"wireless", r"\bisp\b", r"online", r"fiber",
    r"fibre", r"telephone", r"telefon", r"\bmeteverse", r"aceville", r"^ace$", r"internet rimon",
    r"end user organization", r"ip pools", r"dynamic pools", r"static ip", r"customer-", r"private customer",
    # access-network labels used as registrant names
    r"\bdsl\b", r"adsl", r"xdsl", r"ftth", r"\biptv\b", r"ip range", r"ip pool", r"statically assigned",
    r"home clients", r"\bdai ip\b", r"\bcustomers?$", r"customer (pool|ips?|block|assignment)", r"address pool", r"for spam/abuse", r"\b21cn\b", r"telematika",
    r"unicom", r"comunicacoes", r"comunicaciones", r"iletisim", r"^provider$",
])


def _name_class(o: str) -> str:
    if _BUSINESS_OVERRIDE.search(o):
        return "business"
    if _NAMED_CDN.search(o):
        return "cdn"
    if _NAMED_SAAS.search(o):
        return "saas_platform"
    if _NAMED_CLOUD.search(o):
        return "cloud_hosting"
    if _NAMED_ISP.search(o):
        return "isp_telco"
    if _KW_CDN.search(o):
        return "cdn"
    if _KW_HOSTING.search(o):
        return "cloud_hosting"
    if _KW_ISP.search(o):
        return "isp_telco"
    return "business"


def classify_org(org: str | None, isp: str | None = None) -> str:
    """Class of the IP registrant `org`, one of ORG_CLASSES.

    `isp` is used only for pool labels ("IP pools", "Customers", "Private Customer"): those name a
    block of the network operator's customers, so they take the operator's class (isp_telco when
    the operator itself reads as a business).
    """
    o = fold_name(org).strip()
    if not norm_org(o):
        return "unknown"
    if _SYNTHETIC.match(o) and re.search(r"\d", o):
        return "unknown"
    if _ADDRESS.search(o) and not _KW_ISP.search(o):
        return "unknown"
    if _PHONE.match(o):
        return "unknown"
    if _POOL_LABEL.search(o):
        operator = _name_class(fold_name(isp).strip()) if norm_org(isp) else "unknown"
        return operator if operator in PROVIDER_CLASSES else "isp_telco"
    return _name_class(o)


def is_provider_class(org_class: str) -> bool:
    return org_class in PROVIDER_CLASSES


# ----------------------------------------------------------------------------- org identity match
_GENERIC_TOKENS = frozenset({
    "the", "china", "national", "state", "first", "united", "general", "global", "international",
    "american", "new", "city", "university", "group", "holding", "holdings", "company", "de", "del",
    "la", "le", "of", "and", "pt", "jsc", "ooo", "llc", "ltd", "inc",
})


def first_significant_token(s: str | None) -> str | None:
    for tok in norm_org(s).split(" "):
        t = re.sub(r"[^0-9a-z]", "", tok)
        if len(t) >= 3 and t not in _GENERIC_TOKENS:
            return t
    return None


def org_names_match(org: str | None, cert_subject_o: str | None) -> bool:
    """True when a certificate subject O plausibly names the IP registrant org (first significant token)."""
    a, b = first_significant_token(org), first_significant_token(cert_subject_o)
    return a is not None and a == b


# First tokens too generic to anchor a prefix match between a domain and a provider name
# ("Cloud Telecom" must not claim cloudflare.com).
_DOMAIN_GENERIC_TOKENS = frozenset({
    "cloud", "data", "host", "hosting", "telecom", "tele", "net", "network", "networks", "internet",
    "online", "digital", "web", "server", "servers", "tech", "info", "mobile", "fiber", "fibre", "link",
    "connect", "cyber", "smart", "broadband", "wireless", "comm", "communications", "systems",
    "services", "solutions", "media", "star", "speed", "fast",
})
# A left-most label with a long digit run or a hex blob names one machine (vps-5f3a2b1c, ns3012345).
_PER_HOST_LABEL = re.compile(r"\d{3,}|[0-9a-f]{8,}")


def is_per_host_name(name: str | None) -> bool:
    """True when a hostname's first label looks machine-specific (a customer VPS or a numbered host)."""
    return bool(name) and bool(_PER_HOST_LABEL.search(name.split(".", 1)[0].lower()))


def domain_matches_org(reg_domain: str | None, org: str | None) -> bool:
    """True when a registrable domain's label plausibly names the org (a provider's own domain).

    The label (hyphens dropped) must equal the org's significant tokens concatenated
    (`skywaywest.net` / "Skyway West") or start with its first significant token of at least
    four characters that is not a generic word (`railtelindia.com` / "RailTel Corporation of India").
    """
    if not reg_domain or not org:
        return False
    label = reg_domain.split(".", 1)[0].replace("-", "")
    tokens = [t for t in (re.sub(r"[^0-9a-z]", "", tok) for tok in norm_org(org).split(" ")) if t]
    first = first_significant_token(org)
    if tokens and label == "".join(tokens):
        return True
    return (first is not None and len(first) >= 4 and first not in _DOMAIN_GENERIC_TOKENS
            and label.startswith(first))


# Ownership corroboration (looser than attribution's own match): moved from evaluation/inspect.py.
_STOPWORDS = frozenset({"of", "de", "da", "do", "das", "dos", "del", "la", "le", "les", "at", "the", "and",
                        "for", "des", "du", "und", "fur", "y", "e", "et"})
# Words too common in organisation names to identify one when found inside a domain label.
_COMMON_WORDS = frozenset({
    "university", "universidade", "universidad", "universitaet", "universitat", "universite", "college",
    "institute", "instituto", "technology", "national", "international", "corporation", "company",
    "limited", "group", "holdings", "services", "systems", "solutions", "network", "networks",
    "communications", "telecom", "government", "state", "county", "city", "medical", "health",
    "center", "centre", "science", "sciences", "research", "academic", "technologies",
    "system", "service", "solution", "technologie", "communication", "electric", "central", "general",
})

def plausibly_names_org(reg_domain: str | None, org: str | None) -> bool:
    """Looser than attribution's `domain_matches_org`; used for review and for ownership
    corroboration (accounts/eligibility), never to attribute a service. Also accepts the org's
    initials (`mit.edu`, `ucsb.edu`), a label equal to its first significant token (`sap.com`), or
    a distinctive word of five or more letters inside the label (`ucdavis.edu`, `berkeley.edu`)."""
    if not reg_domain or not org:
        return False
    if domain_matches_org(reg_domain, org):
        return True
    label = reg_domain.split(".", 1)[0].replace("-", "")
    tokens = [t for t in (re.sub(r"[^0-9a-z]", "", tok) for tok in norm_org(org).split(" ")) if t]
    words = [t for t in tokens if t not in _STOPWORDS]
    initials = "".join(t[0] for t in words)
    if len(initials) >= 2 and label == initials:
        return True
    first = first_significant_token(org)
    if first and label == first:
        return True
    return any(len(t) >= 5 and t not in _COMMON_WORDS and t in label for t in words)


MAX_AFFIX = 3  # letters a distinctive word may share its label with in `ownership_names_org`


def ownership_names_org(reg_domain: str | None, org: str | None) -> bool:
    """Stricter than `plausibly_names_org`, because it decides ownership confidence: a distinctive word
    (>= 5 letters, not a common organisation word) must be the whole label, or a prefix or suffix with
    at most 3 other letters (`berkeley.edu`, `ucdavis.edu`). A word buried in a longer name
    (`telecomitalia.it` for "... Italia SpA") does not count. Token-equality, initials and the
    first-token rules of `plausibly_names_org` are kept."""
    if not reg_domain or not org:
        return False
    if domain_matches_org(reg_domain, org):
        return True
    label = reg_domain.split(".", 1)[0].replace("-", "")
    tokens = [t for t in (re.sub(r"[^0-9a-z]", "", tok) for tok in norm_org(org).split(" ")) if t]
    words = [t for t in tokens if t not in _STOPWORDS]
    initials = "".join(t[0] for t in words)
    if len(initials) >= 2 and label == initials:
        return True
    first = first_significant_token(org)
    if first and label == first:
        return True
    return any(len(t) >= 5 and t not in _COMMON_WORDS
               and (label == t or (label.startswith(t) and len(label) - len(t) <= MAX_AFFIX)
                    or (label.endswith(t) and len(label) - len(t) <= MAX_AFFIX))
               for t in words)


def is_access_network_name(name: str | None) -> bool:
    """True when a hostname carries a subscriber / access-network label (`adsl-12`, `cpe-1`, `ftth2`)."""
    # a DNS name, not an org name: lower-cased only, like the SQL mirrors (`lower(h)`); never folded
    return bool(name) and bool(_ACCESS_PTR.search(name.lower()))


def org_backstop(n_customer_domains: int, n_services: int, own_cert_services: int, cert_o_services: int,
                 cdn_cloud_share: float, cdn_share: float, access_services: int = 0) -> tuple[str, str] | None:
    """Data-driven (provider class, reason) for an org the name table reads as a business, else None.

    Checked in order:
    1. Access network (`org_access_network_ptr`): >= 20 services and >= 0.30 of them have a hostname
       with a subscriber/access label (`is_access_network_name`) -> isp_telco.
    2. CDN/cloud-tag majority (`org_cdn_cloud_tagged`, ported rule (c)): > 0.5 of the services carry
       `cdn` or `cloud` -> `cdn` when cdn rows are at least as many as cloud-only rows, else
       `cloud_hosting`.
    3. Multi-tenant (`org_multi_tenant`, rule (b) reworked): > 100 distinct accepted customer domains,
       unless the org presents certificates in its own name: own-name subject O on >= 0.25 of its
       services, or on >= 50 services that are >= 0.8 of its O-bearing certificates. Enterprises with
       many brand domains (UnitedHealth, CIGNA) use OV certificates in their own name; shared-hosting
       tenants bring their own (mostly DV, O-less) certificates.
    """
    n_services = n_services or 0
    if n_services >= ACCESS_MIN_SERVICES and (access_services or 0) / n_services >= ACCESS_SHARE:
        return "isp_telco", "org_access_network_ptr"
    cdn_cloud_share = cdn_cloud_share or 0.0
    cdn_share = cdn_share or 0.0
    if cdn_cloud_share > CDN_CLOUD_TAG_SHARE:
        cls = "cdn" if cdn_share >= cdn_cloud_share - cdn_share else "cloud_hosting"
        return cls, "org_cdn_cloud_tagged"
    if (n_customer_domains or 0) <= MULTI_TENANT_MIN_DOMAINS:
        return None
    own, with_o = own_cert_services or 0, cert_o_services or 0
    if n_services and own / n_services >= OWN_CERT_EXEMPT_SHARE:
        return None
    if own >= OWN_CERT_EXEMPT_MIN and with_o and own / with_o >= OWN_CERT_EXEMPT_PURITY:
        return None
    return "saas_platform", "org_multi_tenant"


def org_backstop_class(n_customer_domains: int, n_services: int, own_cert_services: int,
                       cert_o_services: int, cdn_cloud_share: float, cdn_share: float,
                       access_services: int = 0) -> str | None:
    """Class part of `org_backstop`."""
    r = org_backstop(n_customer_domains, n_services, own_cert_services, cert_o_services,
                     cdn_cloud_share, cdn_share, access_services)
    return r[0] if r else None
