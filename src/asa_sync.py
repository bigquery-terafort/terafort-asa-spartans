#!/usr/bin/env python3
"""
================================================================================
 APPLE SEARCH ADS (Apple Ads) → BIGQUERY  — multi-org, PRODUCTION
================================================================================
 Pulls campaign-level DAILY reporting (spend, impressions, taps, installs,
 new downloads, redownloads, CPA, CPT, by country) for BOTH orgs and lands it
 in one table keyed by (date, org_id, campaign_id, country). The campaign's
 adam_id == App Store app id == apple_id → the join key into app_master_v2 /
 unified_daily_performance (iOS UA-spend source, same role as Facebook/GAds).

 AUTH (Apple's private-key JWT flow — unique vs AdMob):
   1. Build a client-secret JWT (ES256, signed by your private key)
        header  {alg:ES256, kid:keyId}
        payload {sub:clientId, iss:teamId, aud:appleid, iat, exp}
   2. POST to appleid.apple.com/auth/oauth2/token (grant_type=client_credentials,
      scope=searchadsorg) → short-lived access token (~1h)
   3. Per org: POST /api/v5/reports/campaigns with header X-AP-Context: orgId=<id>

 MULTI-ORG: one set of credentials reaches every org the API user can access.
 The script loops ASA_ORG_IDS and tags each row with org_id + org_name.

 IDEMPOTENT: per (org, month) it DELETEs that org's rows in the window then
 reloads — re-runnable, restatement-safe, never duplicates, never touches the
 other org's rows.

 Bleed-proof: explicit-fail on bad auth / non-USD-without-handling is flagged
 (spend_native + currency always kept); transient 5xx retried; 4xx never; the
 token is refreshed per run so it can't expire mid-flight.

 Required env:
   ASA_CLIENT_ID, ASA_TEAM_ID, ASA_KEY_ID
   ASA_PRIVATE_KEY            (the EC private-key PEM, full text)
   ASA_ORG_IDS               ("8762670,2340270")
   GCP_PROJECT_ID, GCP_CREDENTIALS_JSON
 Optional env:
   BQ_DATASET_ID (default apple_ads)   BQ_TABLE (default asa_campaign_daily)
   BQ_LOCATION (default US)
   BACKFILL_START (default 2026-01-01)
   LOOKBACK_DAYS (default 30)          FULL_BACKFILL ("1")
   ASA_TIMEZONE (default UTC)          DRY_RUN ("1")
================================================================================
"""
import datetime as dt
import json
import os
import sys
import time
import calendar

import jwt  # PyJWT (with cryptography for ES256)
import requests

TOKEN_URL  = "https://appleid.apple.com/auth/oauth2/token"
API_BASE   = "https://api.searchads.apple.com/api/v5"
HTTP_TIMEOUT = 90


def fail(msg):
    print(f"\n🚨 ASA PIPELINE FAILED: {msg}", file=sys.stderr)
    sys.exit(1)


def env(name, default=None, required=False):
    v = os.environ.get(name, default)
    if required and not v:
        fail(f"missing required env var: {name}")
    return v.strip() if isinstance(v, str) else v


# ------------------------------------------------------------------ config
CLIENT_ID   = env("ASA_CLIENT_ID", required=True)
TEAM_ID     = env("ASA_TEAM_ID", required=True)
KEY_ID      = env("ASA_KEY_ID", required=True)
PRIVATE_KEY = env("ASA_PRIVATE_KEY", required=True)
ORG_IDS     = [o.strip() for o in env("ASA_ORG_IDS", required=True).split(",") if o.strip()]
DRY_RUN     = env("DRY_RUN", "0") == "1"
BQ_PROJECT  = env("GCP_PROJECT_ID", required=not DRY_RUN)
BQ_CREDS    = env("GCP_CREDENTIALS_JSON", "")
BQ_DATASET  = env("BQ_DATASET_ID", "apple_ads")
BQ_TABLE    = env("BQ_TABLE", "asa_campaign_daily")
BQ_LOCATION = env("BQ_LOCATION", "US")
BACKFILL_START = env("BACKFILL_START", "2026-01-01")
LOOKBACK_DAYS  = int(env("LOOKBACK_DAYS", "30"))
FULL_BACKFILL  = env("FULL_BACKFILL", "0") == "1"
ASA_TIMEZONE   = env("ASA_TIMEZONE", "UTC")


# normalize the private key: GitHub secrets sometimes collapse newlines
def _normalize_pem(pem: str) -> str:
    pem = pem.strip()
    if "\\n" in pem and "\n" not in pem:
        pem = pem.replace("\\n", "\n")
    return pem


# --------------------------------------------------------------- auth
def make_client_secret() -> str:
    """ES256 JWT signed by the private key — Apple's 'client secret'."""
    now = int(time.time())
    headers = {"alg": "ES256", "kid": KEY_ID}
    payload = {
        "sub": CLIENT_ID,
        "iss": TEAM_ID,
        "aud": "https://appleid.apple.com",
        "iat": now,
        "exp": now + 3600,  # 1h — minted fresh every run; stays far from Apple's 180d cap
    }
    try:
        return jwt.encode(payload, _normalize_pem(PRIVATE_KEY),
                          algorithm="ES256", headers=headers)
    except Exception as exc:
        fail(f"failed to sign client-secret JWT (check ASA_PRIVATE_KEY / keyId): {exc}")


def get_access_token(session) -> str:
    secret = make_client_secret()
    data = {
        "client_id": CLIENT_ID,
        "client_secret": secret,
        "grant_type": "client_credentials",
        "scope": "searchadsorg",
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded",
               "Host": "appleid.apple.com"}
    delay = 5
    for i in range(1, 5):
        try:
            r = session.post(TOKEN_URL, data=data, headers=headers, timeout=HTTP_TIMEOUT)
        except requests.RequestException as exc:
            if i == 4:
                fail(f"token endpoint network error: {exc}")
            time.sleep(delay); delay *= 2; continue
        if r.status_code >= 500:
            if i == 4:
                fail(f"token endpoint HTTP {r.status_code}: {r.text[:200]}")
            time.sleep(delay); delay *= 2; continue
        if r.status_code >= 400:
            fail(f"token request rejected HTTP {r.status_code}: {r.text[:300]} "
                 f"-> check clientId/teamId/keyId + that the public key is uploaded.")
        tok = r.json().get("access_token")
        if not tok:
            fail(f"token response had no access_token: {r.text[:200]}")
        print("✅ access token acquired")
        return tok
    fail("token: exhausted retries")


# --------------------------------------------------------------- org access
def list_accessible_orgs(session, token) -> dict:
    """GET /acls → {orgId: orgName} the API user can reach. Used to validate
    the requested orgs and to fetch human-readable names."""
    r = _api(session, token, None, "GET", "/acls", None, step="acls")
    items = r if isinstance(r, list) else (r.get("data") or [])
    out = {}
    for item in items:
        oid = str(item.get("orgId") or item.get("orgID") or "")
        if oid:
            out[oid] = item.get("orgName") or item.get("parentOrgName") or oid
    return out


# --------------------------------------------------------------- api helper
def _api(session, token, org_id, method, path, body, step, retries=4):
    headers = {"Authorization": f"Bearer {token}",
               "Content-Type": "application/json",
               "Accept": "application/json"}
    if org_id is not None:
        headers["X-AP-Context"] = f"orgId={org_id}"
    url = API_BASE + path
    delay = 5
    for i in range(1, retries + 1):
        try:
            r = session.request(method, url, headers=headers,
                                json=body, timeout=HTTP_TIMEOUT)
        except requests.RequestException as exc:
            if i == retries:
                fail(f"[{step}] network error after {retries}: {exc}")
            print(f"⚠️  [{step}] attempt {i} network error; retry {delay}s")
            time.sleep(delay); delay *= 2; continue
        if r.status_code >= 500:
            if i == retries:
                fail(f"[{step}] HTTP {r.status_code} after {retries}: {r.text[:200]}")
            print(f"⚠️  [{step}] attempt {i} HTTP {r.status_code}; retry {delay}s")
            time.sleep(delay); delay *= 2; continue
        if r.status_code == 429:
            if i == retries:
                fail(f"[{step}] rate-limited (429) after {retries}")
            print(f"⚠️  [{step}] 429 rate limit; backing off {delay}s")
            time.sleep(delay); delay *= 2; continue
        if r.status_code >= 400:
            fail(f"[{step}] HTTP {r.status_code}: {r.text[:400]}")
        try:
            j = r.json()
        except ValueError:
            fail(f"[{step}] non-JSON response: {r.text[:200]}")
        err = j.get("error")
        if err and err.get("errors"):
            fail(f"[{step}] API error: {json.dumps(err)[:300]}")
        return j.get("data", j)
    fail(f"[{step}] exhausted retries")


# --------------------------------------------------------------- reporting
def _num(v):
    if v is None or v == "":
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def fetch_campaign_report(session, token, org_id, start, end):
    """Campaign-level DAILY report grouped by country for [start, end].
    Returns the list of report rows (each has metadata + per-day granularity)."""
    rows, offset, limit = [], 0, 1000
    while True:
        body = {
            "startTime": start,
            "endTime": end,
            "granularity": "DAILY",
            "selector": {
                "orderBy": [{"field": "countryOrRegion", "sortOrder": "ASCENDING"}],
                "pagination": {"offset": offset, "limit": limit},
            },
            "groupBy": ["countryOrRegion"],
            "timeZone": ASA_TIMEZONE,
            "returnRecordsWithNoMetrics": False,
            "returnRowTotals": False,
            "returnGrandTotals": False,
        }
        data = _api(session, token, org_id, "POST",
                    "/reports/campaigns", body, step=f"report[{org_id}]")
        rdr = (data or {}).get("reportingDataResponse", {})
        page = rdr.get("row", []) or []
        rows.extend(page)
        if len(page) < limit:
            break
        offset += limit
        if offset > 200000:
            break
    return rows


def normalize(report_rows, org_id, org_name, pulled_at):
    out = []
    for row in report_rows:
        meta = row.get("metadata", {}) or {}
        app  = meta.get("app", {}) or {}
        adam_id = app.get("adamId") or meta.get("adamId")
        campaign_id = meta.get("campaignId")
        country = meta.get("countryOrRegion") or meta.get("countryCode")
        for g in (row.get("granularity") or []):
            d = g.get("date")
            if not d:
                continue
            spend = g.get("localSpend", {}) or {}
            out.append({
                "date": str(d)[:10],
                "org_id": str(org_id),
                "org_name": org_name,
                "campaign_id": str(campaign_id) if campaign_id is not None else None,
                "campaign_name": meta.get("campaignName"),
                "adam_id": str(adam_id) if adam_id is not None else None,
                "app_name": app.get("appName") or meta.get("appName"),
                "country_or_region": country,
                "campaign_status": meta.get("campaignStatus") or meta.get("status"),
                "storefront": meta.get("countryOrRegion"),
                "impressions": int(_num(g.get("impressions")) or 0),
                "taps": int(_num(g.get("taps")) or 0),
                "installs": int(_num(g.get("installs")
                                     or g.get("totalInstalls")
                                     or g.get("tapInstalls")) or 0),
                "new_downloads": int(_num(g.get("newDownloads")
                                          or g.get("totalNewDownloads")) or 0),
                "redownloads": int(_num(g.get("redownloads")
                                        or g.get("totalRedownloads")) or 0),
                "ttr": _num(g.get("ttr")),
                "conversion_rate": _num(g.get("conversionRate")
                                        or g.get("tapInstallRate")),
                "avg_cpa_native": _num(((g.get("avgCPA") or g.get("totalAvgCPA")
                                         or g.get("tapInstallCPI") or {}) ).get("amount")),
                "avg_cpt_native": _num((g.get("avgCPT") or {}).get("amount")),
                "avg_cpm_native": _num((g.get("avgCPM") or {}).get("amount")),
                "spend_native": _num(spend.get("amount")),
                "spend_currency": spend.get("currency"),
                "spend_usd": (_num(spend.get("amount"))
                              if (spend.get("currency") == "USD") else None),
                "pulled_at_utc": pulled_at,
            })
    return out


# --------------------------------------------------------------- bigquery
SCHEMA_DDL = """
  date DATE NOT NULL, org_id STRING NOT NULL, org_name STRING,
  campaign_id STRING, campaign_name STRING,
  adam_id STRING, app_name STRING, country_or_region STRING,
  campaign_status STRING, storefront STRING,
  impressions INT64, taps INT64, installs INT64,
  new_downloads INT64, redownloads INT64,
  ttr FLOAT64, conversion_rate FLOAT64,
  avg_cpa_native FLOAT64, avg_cpt_native FLOAT64, avg_cpm_native FLOAT64,
  spend_native FLOAT64, spend_currency STRING, spend_usd FLOAT64,
  pulled_at_utc TIMESTAMP
"""


def load_bq(rows, org_id, win_start, win_end):
    local = f"/tmp/asa_{org_id}_{win_start}.ndjson"
    with open(local, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    print(f"   💾 {len(rows)} rows -> {local}")
    if DRY_RUN:
        print("   🟡 DRY_RUN=1 -> skip BigQuery")
        return

    from google.cloud import bigquery
    from google.oauth2 import service_account
    creds = service_account.Credentials.from_service_account_info(json.loads(BQ_CREDS))
    bq = bigquery.Client(project=BQ_PROJECT, credentials=creds, location=BQ_LOCATION)

    ds = bigquery.Dataset(f"{BQ_PROJECT}.{BQ_DATASET}")
    ds.location = BQ_LOCATION
    bq.create_dataset(ds, exists_ok=True)

    tgt = f"{BQ_PROJECT}.{BQ_DATASET}.{BQ_TABLE}"
    bq.query(f"""CREATE TABLE IF NOT EXISTS `{tgt}` ({SCHEMA_DDL})
                 PARTITION BY date CLUSTER BY org_id, adam_id, campaign_id""").result()

    # idempotent: clear this org's window, then append
    bq.query(f"""DELETE FROM `{tgt}`
                 WHERE org_id=@o AND date BETWEEN @s AND @e""",
             job_config=bigquery.QueryJobConfig(query_parameters=[
                 bigquery.ScalarQueryParameter("o", "STRING", str(org_id)),
                 bigquery.ScalarQueryParameter("s", "DATE", win_start),
                 bigquery.ScalarQueryParameter("e", "DATE", win_end),
             ])).result()

    if rows:
        job_cfg = bigquery.LoadJobConfig(
            source_format=bigquery.SourceFormat.NEWLINE_DELIMITED_JSON,
            schema=bq.get_table(tgt).schema,
            write_disposition=bigquery.WriteDisposition.WRITE_APPEND)
        with open(local, "rb") as f:
            bq.load_table_from_file(f, tgt, job_config=job_cfg).result()
    print(f"   ✅ loaded org {org_id} {win_start}..{win_end} ({len(rows)} rows)")


# --------------------------------------------------------------- windows
def month_windows(start_d, end_d):
    """Yield (win_start, win_end) month chunks — keeps each report request small
    and within Apple's daily-granularity range limits."""
    cur = start_d
    while cur <= end_d:
        last = dt.date(cur.year, cur.month,
                       calendar.monthrange(cur.year, cur.month)[1])
        yield cur, min(last, end_d)
        cur = last + dt.timedelta(days=1)


# --------------------------------------------------------------- main
def main():
    pulled_at = dt.datetime.now(dt.timezone.utc).isoformat()
    today = dt.datetime.now(dt.timezone.utc).date()
    if FULL_BACKFILL:
        start_d = dt.date.fromisoformat(BACKFILL_START or "2026-01-01")
    else:
        start_d = today - dt.timedelta(days=LOOKBACK_DAYS - 1)
    end_d = today

    print(f"🎯 ASA → BigQuery | orgs={ORG_IDS} | {start_d} → {end_d} "
          f"| {'FULL BACKFILL' if FULL_BACKFILL else 'rolling'} | tz={ASA_TIMEZONE}")

    session = requests.Session()
    token = get_access_token(session)

    accessible = list_accessible_orgs(session, token)
    if accessible:
        print(f"✅ API user can access orgs: "
              f"{', '.join(f'{k}({v})' for k,v in accessible.items())}")
    for oid in ORG_IDS:
        if accessible and oid not in accessible:
            fail(f"org {oid} not accessible by this API user. "
                 f"Grant API access for that account, or fix ASA_ORG_IDS.")

    grand_total = 0
    for oid in ORG_IDS:
        oname = accessible.get(oid, oid)
        print(f"\n=== ORG {oid} ({oname}) ===")
        for w_start, w_end in month_windows(start_d, end_d):
            # fresh token if a long backfill outruns the 1h token lifetime
            token = get_access_token(session)
            report = fetch_campaign_report(session, token, oid,
                                           w_start.isoformat(), w_end.isoformat())
            norm = normalize(report, oid, oname, pulled_at)
            print(f"   [{w_start}..{w_end}] {len(report)} report rows -> {len(norm)} daily rows")
            load_bq(norm, oid, w_start, w_end)
            grand_total += len(norm)
            time.sleep(1)

    print(f"\n🎯 DONE. {grand_total} daily rows across {len(ORG_IDS)} org(s).")


if __name__ == "__main__":
    main()
