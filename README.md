# Snoopy — BloodHound CE Attack Path Narrator

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
MAX_HOPS       = 6     # maximum path depth for shortestPath queries
```

---

## Output

Each finding is printed as a compact attack chain with a severity tag:

```
DA Paths — Privilege Abuse Only
  [CRITICAL]  User(CTRL_USER2) →[Owns]→ Group(DOMAIN ADMINS)  (1 hop)
  [CRITICAL]  User(CTRL_USER1) →[WriteDACL]→ User(DA_JSMITH) →[MemberOf]→ Group(DOMAIN ADMINS)  (2 hops)
  [HIGH]  User(JSMITH) →[AdminTo]→ Computer(SERVER01) →[HasSession]→ User(DA_USER) →[MemberOf]→ Group(DOMAIN ADMINS)  (3 hops)

DCSync Rights — Users and Groups
  [CRITICAL]  User(DOMAINUSER) →[DCSync]→ Domain(CORP.LOCAL)  (1 hop)
  [CRITICAL]  Group(DCSYNCERS) →[GetChangesAll]→ Domain(CORP.LOCAL)  (1 hop)

ADCS — ESC Findings
  [CRITICAL]  Group(DOMAIN USERS) →[ESC1 — Enrollable template with SAN specification]→ Domain(CORP.LOCAL)  (1 hop)
  [CRITICAL]  Group(AUTHENTICATED USERS) →[ESC3 — Enrollment agent abuse]→ Domain(CORP.LOCAL)  (1 hop)
  [HIGH]  User(JSMITH) →[ESC10 — Weak certificate mapping (domain auth)]→ Domain(CORP.LOCAL)  (1 hop)

AdminTo — DC Access (Non-DA Users Only)
  [CRITICAL]  User(SVCACCOUNT) →[AdminTo]→ Computer(DC01.CORP.LOCAL)  (1 hop)
```

A deduplicated summary table at the end sorts all findings by severity:

```
─── FINDINGS SUMMARY ───
 Severity   Category                               Source                Hops
 CRITICAL   DA Paths — Privilege Abuse Only        User(CTRL_USER2)       1
 CRITICAL   DCSync Rights — Users and Groups       User(DOMAINUSER)       1
 CRITICAL   ADCS — ESC Findings                    Group(DOMAIN USERS)    1
 HIGH       AdminTo — Non-DA Users on Non-DCs      User(LOCALADMIN)       1

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
- Any path containing `HasSession` is capped at **HIGH** — session-based paths depend on a privileged user being logged in at the time of exploitation and are not guaranteed
- `DCSync` / `GetChangesAll` on non-default users or groups → **CRITICAL**
- Direct ACL abuse edges (`WriteDACL`, `Owns`, `GenericAll`, etc.) reaching Domain Admins → **CRITICAL**
- Non-DA user with local admin on a DC → **CRITICAL**
- `AddAllowedToAct` (RBCD abuse) → **CRITICAL**
- ADCS ESC1, ESC3, ESC4, ESC6 → **CRITICAL** (direct domain compromise)
- ADCS ESC9, ESC10 → **HIGH** (require additional conditions)

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
| ADCS — ESC Findings | Users and groups with ADCS escalation paths (ESC1, ESC3, ESC4, ESC6, ESC9, ESC10). Excludes Tier Zero sources. |

---

## Design Decisions

**Query Neo4j directly over Bolt** rather than the BloodHound CE API — faster, no auth token management, and bypasses UI-layer timeouts that affect large datasets.

**`MAX_PATHS` and `MAX_HOPS`** — two configurable limits at the top of the script. `MAX_PATHS` controls how many results each query returns (default 500). `MAX_HOPS` controls the maximum path depth for shortestPath queries (default 6). On large multi-domain environments, reducing `MAX_HOPS` to 4 significantly cuts noise from long chains that usually share the same root cause.

**DC detection uses `c.isdc` property with name-based fallback** — correctly identifies Domain Controllers regardless of naming conventions (e.g. EXTDC01, DC-PROD-01). Multiple detection layers prevent false positives in Unconstrained Delegation results.

**DA filter is domain-agnostic** — uses `=~ '(?i)domain admins@.*'` regex with recursive `MemberOf` traversal rather than a hardcoded domain name. Works correctly across multi-domain environments and catches nested group membership.

**Built-in groups excluded from DCSync results** — `ADMINISTRATORS`, `DOMAIN CONTROLLERS`, and `ENTERPRISE ADMINS` have replication rights by design in AD. Showing them as findings is noise. Only non-default groups and users with DCSync rights are reported.

**Summary table is deduplicated** — the same source appearing multiple times across different domains or hop counts is collapsed to a single row showing the shortest path. Full path detail is preserved in the output above the table.

**ADCS Tier Zero exclusion** — ADCS findings from already-privileged sources are excluded since they represent expected behavior rather than misconfigurations worth reporting.

---

## Known Limitations

- Large multi-domain datasets (3+ domains with cross-forest trusts) can produce significant output, particularly in DA Paths. Reduce `MAX_HOPS` to 4 to cut noise.
- `HasSession` paths reflect sessions at the time SharpHound ran — they may not exist when you attempt exploitation.
- DA accounts with excess ACL rights appear in DA Paths — these are valid privilege tier misconfigurations but are distinct from non-DA to DA attack paths. Context is needed when reporting.
- Unresolved SID objects (Base-only nodes) may appear in ADCS output if SharpHound did not fully resolve all principals.

---

## Roadmap

- [ ] Markdown / text report export (`--output report.md`)
- [ ] Controlled single-domain test dataset for accuracy validation
- [ ] ADCS ESC4, ESC7, ESC8 dedicated queries
- [ ] GPO abuse path detection
- [ ] Output filtering by domain (`--domain CORP.LOCAL`)

---

## Tested Against

- BloodHound CE v5.x
- Neo4j 4.4.x (Community Edition)
- SpecterOps official AD sample data (3-domain, cross-forest trust environment)
- Kali Linux 2026.x

---

## Disclaimer

This tool is intended for authorized penetration testing and security assessments only. Only use against systems you own or have explicit written permission to test.
