# snoopy.py — BloodHound CE Attack Path Narrator

A Python tool that queries BloodHound Community Edition's Neo4j database directly and outputs human-readable, severity-tagged Active Directory attack paths. Built for pentesters who want actionable findings fast without clicking through the BloodHound UI.

---

## Why

BloodHound CE stores all AD data in Neo4j and its attack path analysis is just Cypher queries under the hood. This tool bypasses the UI entirely, runs a curated set of queries against Neo4j over Bolt, and narrates each path in plain English with a severity label — ready to drop into a report.

---

## Requirements

- BloodHound CE running with Neo4j exposed on `localhost:7687`
- Python 3.8+
- SharpHound or AzureHound data already ingested into BloodHound CE

---

## Installation

```bash
python3 -m venv ~/bh-tool
source ~/bh-tool/bin/activate
pip install neo4j rich
```

---

## Usage

```bash
python3 snoopy.py
```

Edit the config at the top of the script before running:

```python
NEO4J_URI      = "bolt://localhost:7687"
NEO4J_USER     = "neo4j"
NEO4J_PASSWORD = "bloodhoundcommunityedition"
MAX_PATHS      = 500   # increase for large domains, decrease for faster runs
```

---

## Output

Each finding is printed as a compact attack chain with a severity tag:

```
DA Paths — Privilege Abuse Only
  [CRITICAL]  User(CTRL_USER2) →[Owns]→ Group(DOMAIN ADMINS)  (1 hop)
  [CRITICAL]  User(CTRL_USER1) →[WriteDACL]→ User(DA_JSMITH) →[MemberOf]→ Group(DOMAIN ADMINS)  (2 hops)

DCSync Rights — Users and Groups
  [CRITICAL]  User(DOMAINUSER) →[DCSync]→ Domain(CORP.LOCAL)  (1 hop)
  [CRITICAL]  Group(DCSYNCERS) →[GetChangesAll]→ Domain(CORP.LOCAL)  (1 hop)

AdminTo — DC Access (Non-DA Users Only)
  [CRITICAL]  User(UNCON_USER1) →[AdminTo]→ Computer(DC01.CORP.LOCAL)  (1 hop)
```

A summary table at the end sorts all findings by severity:

```
─── FINDINGS SUMMARY ───
 Severity   Category                               Source               Hops
 CRITICAL   DA Paths — Privilege Abuse Only        User(CTRL_USER2)      1
 CRITICAL   DCSync Rights — Users and Groups       User(DOMAINUSER)      1
 HIGH       AdminTo — Non-DA Users on Non-DCs      User(LOCALADMIN)      1

  3 CRITICAL  1 HIGH  0 MEDIUM  findings identified.
```

---

## Severity Logic

| Severity | Meaning |
|---|---|
| **CRITICAL** | Guaranteed, exploitable right now — pure AD misconfiguration, no timing dependency |
| **HIGH** | Real finding but opportunistic (requires active session) or indirect chain |
| **MEDIUM** | Valid path but involves chained assumptions or expected configurations |

### Key rules
- Any path containing `HasSession` is capped at **HIGH** — session-based paths depend on a privileged user being logged in at the time of exploitation
- `DCSync` / `GetChangesAll` on non-default users or groups → **CRITICAL**
- Direct ACL abuse edges (`WriteDACL`, `Owns`, `GenericAll`, etc.) reaching Domain Admins → **CRITICAL**
- Non-DA user with local admin on a DC → **CRITICAL**
- `AddAllowedToAct` (RBCD abuse) → **CRITICAL**

---

## Query Categories

| Query | What It Finds |
|---|---|
| DA Paths — Privilege Abuse Only | Non-DA users who can reach Domain Admins via ACL abuse, delegation, or session chains. Excludes direct DA members. |
| Kerberoastable to DA | Users with SPNs set who have a path to Domain Admins — Kerberoast the account, crack the hash, follow the path. |
| DCSync Rights — Users and Groups | Non-default users and groups with DCSync or GetChangesAll rights — can dump all domain password hashes. |
| LAPS Readers | Users who can read LAPS (local admin) passwords from computer objects. |
| Unconstrained Delegation Computers (Non-DC) | Non-DC computers with unconstrained delegation — coerce DC authentication to capture TGTs. |
| AdminTo — Non-DA Users on Non-DCs | Regular users with local admin on workstations and servers. |
| AdminTo — DC Access (Non-DA Users Only) | Non-DA users with local admin on Domain Controllers — critical misconfiguration. |

---

## Design Decisions

**Query Neo4j directly over Bolt** rather than the BloodHound CE API — faster, no auth token management, and bypasses UI-layer timeouts that affect large datasets.

**`MAX_PATHS` parameter** — all queries use a single configurable limit passed as a Cypher parameter. Default is 500. On very large multi-domain environments this may produce significant output — reduce to 50-100 for a quick triage run.

**DC detection uses `c.isdc` property** rather than name matching — correctly identifies Domain Controllers regardless of naming conventions (e.g. EXTDC01, DC-PROD-01, etc.).

**DA filter is domain-agnostic** — uses `=~ '(?i)domain admins@.*'` regex rather than a hardcoded domain name so the tool works on any engagement without modification.

**Built-in groups excluded from DCSync results** — `ADMINISTRATORS`, `DOMAIN CONTROLLERS`, and `ENTERPRISE ADMINS` have replication rights by design in AD. Showing them as findings is noise. Only non-default groups and users with DCSync rights are reported.

---

## Known Limitations

- Large multi-domain datasets (3+ domains with cross-forest trusts) can produce significant output, particularly in DA Paths. The same root cause vulnerability may appear many times across different source users.
- `HasSession` paths reflect sessions at the time SharpHound ran — they may not exist when you attempt exploitation.
- ADCS escalation paths (ESC3, ESC10b, etc.) are detected when present in the graph but severity scoring for ADCS-specific chains is not yet fully tuned.

---

## Roadmap

- [ ] Markdown / text report export (`--output report.md`)
- [ ] Controlled single-domain test dataset for accuracy validation
- [ ] Hop depth filter option (`--max-hops 6`)
- [ ] Deduplication of paths sharing the same root cause
- [ ] ADCS-specific severity tuning

---

## Tested Against

- BloodHound CE v5.x
- Neo4j 4.4.x (Community Edition)
- SpecterOps official AD sample data (3-domain, cross-forest trust environment)
- Kali Linux 2026.x

---

## Disclaimer

This tool is intended for authorized penetration testing and security assessments only. Only use against systems you own or have explicit written permission to test.
