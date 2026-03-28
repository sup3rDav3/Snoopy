#!/usr/bin/env python3
"""
snoopy.py - BloodHound CE Attack Path Narrator
Queries Neo4j directly and outputs human-readable attack paths.
"""

from neo4j import GraphDatabase
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
import sys

# ── Config ────────────────────────────────────────────────────────────────────
NEO4J_URI      = "bolt://localhost:7687"
NEO4J_USER     = "neo4j"
NEO4J_PASSWORD = "bloodhoundcommunityedition"  # change if you set a custom password

# ── Limits ────────────────────────────────────────────────────────────────────
# Increase for large domains to avoid missing findings.
# Decrease for faster runs on small datasets.
MAX_PATHS = 500

# Maximum hops for shortestPath queries.
# Paths longer than this are usually the same root cause repeated
# across many users. Increase if you suspect findings are being missed.
MAX_HOPS = 6

# ── Edge Narratives ───────────────────────────────────────────────────────────
EDGE_NARRATIVES = {
    "GenericAll":            "has full control over",
    "GenericWrite":          "can write attributes on",
    "WriteDACL":             "can modify the ACL of",
    "WriteDacl":             "can modify the ACL of",
    "WriteOwner":            "can take ownership of",
    "Owns":                  "owns",
    "AddMember":             "can add members to",
    "AddSelf":               "can add themselves to",
    "ForceChangePassword":   "can reset the password of",
    "AllExtendedRights":     "has extended rights on",
    "AdminTo":               "has local admin on",
    "CanRDP":                "can RDP into",
    "CanPSRemote":           "can PSRemote into",
    "ExecuteDCOM":           "can execute DCOM on",
    "HasSession":            "has an active session on",
    "AllowedToDelegate":     "can delegate credentials to",
    "AllowedToAct":          "can act on behalf of users on",
    "AddAllowedToAct":       "can configure delegation on",
    "ReadLAPSPassword":      "can read the LAPS password of",
    "ReadGMSAPassword":      "can read the GMSA password of",
    "MemberOf":              "is a member of",
    "MemberOfLocalGroup":    "is a member of local group",
    "Contains":              "contains",
    "DCSync":                "can DCSync against",
    "GetChanges":            "can get changes on",
    "GetChangesAll":         "can get all changes on (DCSync)",
    "SQLAdmin":              "is a SQL admin on",
    "HasSIDHistory":         "has SID history linking to",
    "TrustedBy":             "is trusted by",
    "CrossForestTrust":      "has a cross-forest trust to",
    "ADCSESC1":              "ESC1 — Enrollable template with SAN specification",
    "ADCSESC3":              "ESC3 — Enrollment agent abuse",
    "ADCSESC4":              "ESC4 — Vulnerable certificate template ACL",
    "ADCSESC6a":             "ESC6 — CA flag EDITF_ATTRIBUTESUBJECTALTNAME2 (domain auth)",
    "ADCSESC6b":             "ESC6 — CA flag EDITF_ATTRIBUTESUBJECTALTNAME2 (any auth)",
    "ADCSESC9a":             "ESC9 — Certificate mapping abuse (domain auth)",
    "ADCSESC9b":             "ESC9 — Certificate mapping abuse (any auth)",
    "ADCSESC10a":            "ESC10 — Weak certificate mapping (domain auth)",
    "ADCSESC10b":            "ESC10 — Weak certificate mapping (any auth)",
}

# ── Severity Rules ────────────────────────────────────────────────────────────
#
# RULE ORDER MATTERS — first match wins.
#
# CRITICAL — guaranteed, no timing dependency, pure AD misconfiguration
# HIGH     — real finding but opportunistic (HasSession) or indirect
# MEDIUM   — valid but requires chained assumptions

DIRECT_ABUSE_EDGES = {
    "GenericAll", "GenericWrite", "WriteDACL", "WriteDacl",
    "WriteOwner", "Owns", "AddMember", "AddSelf",
    "AllExtendedRights", "ForceChangePassword",
}

DCSYNC_EDGES = {"DCSync", "GetChangesAll"}

SEVERITY_RULES = [
    # ── Opportunistic cap — MUST be first ────────────────────────────────────
    # HasSession paths are time-dependent — cap at HIGH regardless of other edges
    (lambda rels, dst, src: "HasSession" in rels, "HIGH"),

    # ── CRITICAL: guaranteed domain compromise ────────────────────────────────

    # DCSync rights on a user or group (not a DC computer — that's expected)
    (lambda rels, dst, src: (
        any(r in DCSYNC_EDGES for r in rels) and
        not src.lower().startswith("computer(dc")
    ), "CRITICAL"),

    # Direct ACL abuse path reaching Domain Admins
    (lambda rels, dst, src: (
        "domain admins" in dst.lower() and
        any(r in DIRECT_ABUSE_EDGES for r in rels)
    ), "CRITICAL"),

    # Local admin on a DC
    (lambda rels, dst, src: (
        "AdminTo" in rels and "dc" in dst.lower()
    ), "CRITICAL"),

    # RBCD / AddAllowedToAct — guaranteed delegation abuse
    (lambda rels, dst, src: (
        "AddAllowedToAct" in rels
    ), "CRITICAL"),

    # ── HIGH: real findings, less direct ─────────────────────────────────────

    # AdminTo on any machine
    (lambda rels, dst, src: "AdminTo" in rels, "HIGH"),

    # LAPS/GMSA password read
    (lambda rels, dst, src: (
        any(r in ["ReadLAPSPassword", "ReadGMSAPassword"] for r in rels)
    ), "HIGH"),

    # ACL abuse not directly reaching DA
    (lambda rels, dst, src: (
        any(r in DIRECT_ABUSE_EDGES for r in rels)
    ), "HIGH"),

    # ── CRITICAL: ADCS direct domain compromise ──────────────────────────────
    (lambda rels, dst, src: (
        any(r in ["ADCSESC1", "ADCSESC3", "ADCSESC4", "ADCSESC6a", "ADCSESC6b"]
            for r in rels)
    ), "CRITICAL"),

    # ── HIGH: ADCS certificate mapping abuse ─────────────────────────────────
    (lambda rels, dst, src: (
        any(r in ["ADCSESC9a", "ADCSESC9b", "ADCSESC10a", "ADCSESC10b"]
            for r in rels)
    ), "HIGH"),

    # ── MEDIUM: everything else ───────────────────────────────────────────────
    (lambda rels, dst, src: True, "MEDIUM"),
]

SEVERITY_COLOR = {
    "CRITICAL": "bold red",
    "HIGH":     "bold yellow",
    "MEDIUM":   "bold blue",
}

# ── Queries ───────────────────────────────────────────────────────────────────
QUERIES = [
    (
        "DA Paths — Privilege Abuse Only",
        """
        MATCH p=shortestPath(
            (u:User {enabled:true})-[*1..$max_hops]->(g:Group)
        )
        WHERE g.name =~ '(?i)domain admins@.*'
          AND NOT (u)-[:MemberOf*1..]->(g)
        RETURN p
        LIMIT $max_paths
        """,
    ),
    (
        "Kerberoastable to DA",
        """
        MATCH p=shortestPath(
            (u:User {hasspn:true, enabled:true})-[*1..$max_hops]->(g:Group)
        )
        WHERE g.name =~ '(?i)domain admins@.*'
          AND NOT (u)-[:MemberOf*1..]->(g)
        RETURN p
        LIMIT $max_paths
        """,
    ),
    (
        "DCSync Rights — Users and Groups",
        """
        MATCH p=(n)-[:DCSync|GetChangesAll]->(d:Domain)
        WHERE NOT 'Computer' IN labels(n)
          AND NOT (n.name =~ '(?i)administrators@.*'
               OR n.name =~ '(?i)domain controllers@.*'
               OR n.name =~ '(?i)enterprise admins@.*')
        RETURN p
        LIMIT $max_paths
        """,
    ),
    (
        "LAPS Readers",
        """
        MATCH p=(u:User {enabled:true})-[:ReadLAPSPassword]->(c:Computer)
        RETURN p
        LIMIT $max_paths
        """,
    ),
    (
        "Unconstrained Delegation Computers (Non-DC)",
        """
        MATCH (c:Computer {unconstraineddelegation:true})
        WHERE c.isdc <> true
          AND NOT c.name =~ '(?i)^dc[0-9-].*'
          AND NOT c.name =~ '(?i).*-dc[0-9].*'
          AND NOT c.name =~ '(?i).*dc[0-9]+\\..*'
          AND NOT EXISTS {
            MATCH (c)-[:DCFor]->(:Domain)
          }
        RETURN c.name AS name
        LIMIT $max_paths
        """,
    ),
    (
        "AdminTo — Non-DA Users on Non-DCs",
        """
        MATCH p=(u:User {enabled:true})-[:AdminTo]->(c:Computer)
        WHERE (c.isdc = false OR c.isdc IS NULL)
          AND NOT EXISTS {
            MATCH (u)-[:MemberOf*1..]->(dg:Group)
            WHERE dg.name =~ '(?i)domain admins@.*'
          }
        RETURN p
        LIMIT $max_paths
        """,
    ),
    (
        "ADCS — ESC Findings",
        """
        MATCH (n)-[r]->(d:Domain)
        WHERE type(r) STARTS WITH 'ADCS'
          AND NOT 'Tag_Tier_Zero' IN labels(n)
          AND NOT (n.name =~ '(?i)administrators@.*'
               OR n.name =~ '(?i)domain controllers@.*'
               OR n.name =~ '(?i)enterprise admins@.*'
               OR n.name =~ '(?i)domain admins@.*')
        RETURN
          labels(n) AS src_labels,
          n.name    AS src_name,
          type(r)   AS rel_type,
          d.name    AS domain
        ORDER BY type(r), n.name
        LIMIT $max_paths
        """,
    ),
    (
        "AdminTo — DC Access (Non-DA Users Only)",
        """
        MATCH p=(u:User {enabled:true})-[:AdminTo]->(c:Computer)
        WHERE c.isdc = true
          AND NOT EXISTS {
            MATCH (u)-[:MemberOf*1..]->(dg:Group)
            WHERE dg.name =~ '(?i)domain admins@.*'
          }
          AND NOT u.name =~ '(?i)administrator@.*'
        RETURN p
        LIMIT $max_paths
        """,
    ),
]

# ── Helpers ───────────────────────────────────────────────────────────────────
def get_display_name(node):
    labels = list(node.labels)
    name   = node.get("name") or node.get("objectid") or "Unknown"
    short  = name.split("@")[0] if "@" in name else name
    if "User"     in labels: return f"User({short})"
    if "Computer" in labels: return f"Computer({short})"
    if "Group"    in labels: return f"Group({short})"
    if "GPO"      in labels: return f"GPO({short})"
    if "Domain"   in labels: return f"Domain({name})"
    if "OU"       in labels: return f"OU({short})"
    return short


def get_severity(rel_types, dst_name, src_name):
    for rule, severity in SEVERITY_RULES:
        try:
            if rule(rel_types, dst_name, src_name):
                return severity
        except Exception:
            continue
    return "MEDIUM"


def inline_path(path):
    """Returns a compact single-line path summary."""
    nodes     = list(path.nodes)
    rels      = list(path.relationships)
    if not rels:
        return None, None, None, None

    rel_types = [rel.type for rel in rels]
    src_name  = get_display_name(nodes[0])
    dst_name  = get_display_name(nodes[-1])
    severity  = get_severity(rel_types, dst_name, src_name)

    parts = []
    for i, rel in enumerate(rels):
        parts.append(get_display_name(nodes[i]))
        parts.append(f"→[{rel.type}]→")
    parts.append(dst_name)

    hops    = len(rels)
    summary = " ".join(parts) + f"  ({hops} hop{'s' if hops > 1 else ''})"
    return summary, severity, src_name, hops


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    console = Console()
    console.print(Panel.fit(
        "[bold red]Snoopy — BloodHound CE Attack Path Narrator[/bold red]\n"
        "[dim]Querying Neo4j at localhost:7687[/dim]"
    ))

    try:
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        driver.verify_connectivity()
        console.print("[green]✓ Connected to Neo4j[/green]\n")
    except Exception as e:
        console.print(f"[red]✗ Failed to connect to Neo4j: {e}[/red]")
        sys.exit(1)

    summary = []

    with driver.session() as session:
        for query_name, cypher in QUERIES:
            try:
                cypher_final = cypher.replace("$max_hops", str(MAX_HOPS))
                results = session.run(cypher_final, max_paths=MAX_PATHS)
                records = list(results)

                if not records:
                    continue

                first_keys = list(records[0].keys())

                # ADCS queries return flat rows, not paths — check BEFORE non-path handler
                if "rel_type" in first_keys and "src_labels" in first_keys:
                    findings = []
                    for record in records:
                        src_labels  = list(record["src_labels"])
                        src_name    = record["src_name"] or "Unknown"
                        rel_type    = record["rel_type"]
                        domain      = record["domain"] or "Unknown"

                        # Build display name from labels and name
                        short = src_name.split("@")[0] if "@" in src_name else src_name
                        if "User" in src_labels:
                            src_display = f"User({short})"
                        elif "Group" in src_labels:
                            src_display = f"Group({short})"
                        elif "Computer" in src_labels:
                            src_display = f"Computer({short})"
                        else:
                            #src_display = f"Object({short})"
                            continue

                        # Get description from EDGE_NARRATIVES
                        esc_num = rel_type.replace("ADCSESC", "ESC")
                        description = EDGE_NARRATIVES.get(rel_type, f"{esc_num} — ADCS escalation path")
                        line = f"{src_display} →[{description}]→ Domain({domain})  (1 hop)"

                        # Severity based on ESC type
                        severity = get_severity([rel_type], f"domain({domain})", src_display)
                        findings.append((line, severity, src_display, 1))

                    if not findings:
                        continue

                    console.print(f"[bold yellow]{query_name}[/bold yellow]")
                    for line, severity, src_display, hops in findings:
                        color = SEVERITY_COLOR.get(severity, "white")
                        console.print(f"  [{color}][{severity}][/{color}]  {line}")
                        summary.append((severity, query_name, src_display, hops))
                    console.print()
                    continue

                # Non-path queries (e.g. unconstrained delegation)
                if "p" not in first_keys:
                    console.print(f"[bold yellow]{query_name}[/bold yellow]")
                    for record in records:
                        name = record.get("name", "Unknown")
                        console.print(f"  [bold red][CRITICAL][/bold red] {name}")
                        summary.append(("CRITICAL", query_name, name, "-"))
                    console.print()
                    continue

                # Path queries
                findings = []
                for record in records:
                    path = record["p"]
                    line, severity, src_name, hops = inline_path(path)
                    if line:
                        findings.append((line, severity, src_name, hops))

                if not findings:
                    continue

                console.print(f"[bold yellow]{query_name}[/bold yellow]")
                for line, severity, src_name, hops in findings:
                    color = SEVERITY_COLOR.get(severity, "white")
                    console.print(f"  [{color}][{severity}][/{color}]  {line}")
                    summary.append((severity, query_name, src_name, hops))
                console.print()

            except Exception as e:
                console.print(f"[red]  Query error in '{query_name}': {e}[/red]\n")

    driver.close()

    # ── Summary Table ─────────────────────────────────────────────────────────
    # Deduplicate by (severity, category, source) — keep shortest hop count.
    # Full path detail is preserved in the output above.
    seen = {}
    for severity, category, src, hops in summary:
        key = (severity, category, src)
        if key not in seen:
            seen[key] = hops
        else:
            # Keep shortest hop count — "-" for non-path entries
            if hops != "-" and seen[key] != "-":
                seen[key] = min(seen[key], hops)

    deduped = [(sev, cat, src, hops) for (sev, cat, src), hops in seen.items()]

    console.print("[bold white]─── FINDINGS SUMMARY ───[/bold white]")
    table = Table(show_header=True, header_style="bold white", border_style="dim")
    table.add_column("Severity", width=10)
    table.add_column("Category", width=45)
    table.add_column("Source",   width=35)
    table.add_column("Hops",     width=6, justify="center")

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    deduped.sort(key=lambda x: (order.get(x[0], 99), x[1], x[2]))

    for severity, category, src, hops in deduped:
        color = SEVERITY_COLOR.get(severity, "white")
        table.add_row(
            f"[{color}]{severity}[/{color}]",
            category,
            src,
            str(hops),
        )

    console.print(table)
    console.print()

    crits = sum(1 for s in deduped if s[0] == "CRITICAL")
    highs = sum(1 for s in deduped if s[0] == "HIGH")
    meds  = sum(1 for s in deduped if s[0] == "MEDIUM")
    console.print(
        f"  [bold red]{crits} CRITICAL[/bold red]  "
        f"[bold yellow]{highs} HIGH[/bold yellow]  "
        f"[bold blue]{meds} MEDIUM[/bold blue]  "
        f"findings identified.\n"
    )


if __name__ == "__main__":
    main()
