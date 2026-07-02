#!/usr/bin/env python3
"""App: orchestrator and CLI."""

import os, logging
from typing import Optional
import core
from core import (
    Config, HttpClient, domain_folder, save_text, save_json,
    Crawler, CrawlResult, parse_qs, urlparse, info, warn, debug, SCRIPT_DIR,
    parse_techniques
)
from scanner import Scanner

class App:
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self.client = HttpClient(self.config.timeout, self.config.delay,
                                 self.config.use_cookies, self.config.retries)
        self.scanner = Scanner(self.client, self.config)

    def _setup_logging(self, verbose: bool) -> None:
        level = logging.DEBUG if verbose else logging.INFO
        logging.basicConfig(level=level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[logging.FileHandler(os.path.join(SCRIPT_DIR,"sqli_scanner.log")),
                      logging.StreamHandler()])

    def run(self, args_list=None) -> None:
        import argparse
        parser = argparse.ArgumentParser(
            description=(
                "Evil SQLi — SQL Injection Scanner\n"
                "──────────────────────────────────────────────────\n"
                "Techniques:  E=Error-Based  B=Boolean-Blind\n"
                "             T=Time-Blind   U=Union-Based\n"
                "──────────────────────────────────────────────────"
            ),
            formatter_class=argparse.RawTextHelpFormatter,
            epilog=(
                "Examples:\n"
                "  python main.py -u 'http://target.com/page.php?id=1'\n"
                "  python main.py -u '...' --techniques EU\n"
                "  python main.py -u '...' --techniques error,union\n"
                "  python main.py -u '...' --dbms MySQL --time-delay 3\n"
                "  python main.py -u 'http://localhost/dvwa/...?id=1' --dvwa-login\n"
                "  python main.py -u '...' --techniques B --retries 8 --timeout 30\n"
            )
        )
        parser.add_argument('-u','--url', required=True, help='Target URL')
        parser.add_argument('--mode', choices=['crawl','scan'], default='scan',
                            help='crawl = discover only | scan = discover + test (default: scan)')
        parser.add_argument('--depth', type=int, default=2, help='Crawl depth (default: 2)')
        parser.add_argument('--delay', type=float, default=0.5, help='Delay between requests (default: 0.5)')
        parser.add_argument('--timeout', type=int, default=20, help='Request timeout (default: 20)')
        parser.add_argument('--retries', type=int, default=5, help='Retry count (default: 5)')
        parser.add_argument('--no-cookies', action='store_true', help='Disable session cookies')
        parser.add_argument('--verbose', action='store_true', help='Verbose logging')
        parser.add_argument('--debug', action='store_true', help='Extra debug output')
        parser.add_argument('--dvwa-login', action='store_true', help='Auto-login to DVWA')
        parser.add_argument('-c','--column', type=int, metavar='N',
                            help='Manually specify column count')
        parser.add_argument('--techniques', type=str, default=None, metavar='TECH',
                            help=("Techniques: short (BEUT) or long (error,boolean,union,time)"))
        parser.add_argument('--dbms', type=str, default=None,
                            choices=['MySQL','PostgreSQL','MSSQL','Oracle','SQLite'],
                            help='Force DBMS')
        parser.add_argument('--time-delay', type=int, default=5, help='Sleep delay for time-based tests (default: 5)')
        parser.add_argument('--true-keyword', type=str, action='append', default=[],
                            help='Keyword indicating TRUE condition (can specify multiple)')
        parser.add_argument('--false-keyword', type=str, action='append', default=[],
                            help='Keyword indicating FALSE condition (can specify multiple)')

        args = parser.parse_args(args_list)

        core.DEBUG = bool(args.debug)

        techniques = parse_techniques(args.techniques) if args.techniques else ["error","boolean","time","union"]
        self.config = Config(
            timeout=args.timeout, delay=args.delay,
            use_cookies=not args.no_cookies, retries=args.retries,
            time_delay=args.time_delay, techniques=techniques,
            forced_dbms=args.dbms, manual_column_count=args.column,
        )
        self._setup_logging(args.verbose)
        self.client = HttpClient(args.timeout, args.delay, not args.no_cookies, args.retries)
        self.scanner = Scanner(self.client, self.config)

        debug(f"Techniques: {techniques}")
        debug(f"Timeout: {args.timeout}s  Delay: {args.delay}s  Retries: {args.retries}")
        debug(f"Forced DBMS: {args.dbms}  Time-delay: {args.time_delay}s")

        if args.dvwa_login or "dvwa" in args.url.lower():
            pr = urlparse(args.url)
            base = f"{pr.scheme}://{pr.netloc}/dvwa"
            if self.client.login_dvwa(base, "admin", "password", "low"):
                info("DVWA authentication successful")
            else:
                warn("DVWA authentication failed, continuing unauthenticated")

        folder = domain_folder(args.url)

        if args.mode == 'crawl':
            info(f"Starting crawl on {args.url} with depth {args.depth}")
            self.do_crawl(args.url, args.depth, folder)
        else:
            info(f"Starting scan on {args.url} with depth {args.depth}")
            self.do_scan(args.url, args.depth, folder)

    def do_crawl(self, target: str, depth: int, folder: str) -> None:
        results = Crawler(target, depth=depth, client=self.client).run()
        save_text(folder, "crawl_result.txt", [f"{r.url} -> {r.params}" for r in results])

    def do_scan(self, target: str, depth: int, folder: str) -> None:
        parsed = urlparse(target)
        if parsed.query and parse_qs(parsed.query):
            params = list(parse_qs(parsed.query).keys())
            endpoints = [CrawlResult(target, params)]
            info(f"Scanning provided URL directly with parameters: {params}")
        else:
            crawler = Crawler(target, depth=depth, client=self.client)
            endpoints = crawler.run()
            if not endpoints:
                warn("No endpoints with query parameters discovered during crawl.")

        info("Using built-in payloads and error patterns")
        for ep in endpoints:
            if not ep.params: continue
            info(f"Testing URL: {ep.url}")
            for p in ep.params:
                findings = self.scanner.scan_param(ep.url, p)
                self.scanner.findings.extend(findings)

        if self.scanner.findings:
            lines = [f.summary() for f in self.scanner.findings]
            save_text(folder, "scan_result.txt", lines)
            save_json(folder, "scan_result.json",
                      {"target": target, "findings": [f.to_dict() for f in self.scanner.findings]})
        else:
            warn("No confirmed SQLi findings. Nothing to save.")