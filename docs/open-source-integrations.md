# Open-source integration decisions

Checked against upstream project documentation on 17 July 2026. Licences must
be re-checked before every distributed release; this document is technical
screening, not legal advice.

## Adopted in the first operational slice

| Capability | Upstream | Integration decision |
|---|---|---|
| System of record | [PostgreSQL](https://www.postgresql.org/about/licence/) | Core database. SQLAlchemy keeps local SQLite tests portable; production settings reject SQLite. |
| Schema migrations | [Alembic](https://alembic.sqlalchemy.org/) | Versioned migrations; production refuses automatic schema creation. |
| Architecture editor | [React Flow](https://reactflow.dev/) | MIT-licensed node editor with visible attribution, zoom, pan, selection, minimap and custom Traceless nodes. |
| Discovery/service fingerprinting | [Nmap](https://nmap.org/) | External, operator-installed CLI adapter with fixed profiles and bounded XML parsing. The binary is not bundled. NPSL/OEM terms require explicit legal/product review. |
| Permissive discovery fallback | [Naabu](https://github.com/projectdiscovery/naabu) | MIT-licensed JSONL import adapter. It discovers ports but is not treated as a version or vulnerability authority. |
| Vulnerability report normalization | Native bounded adapter contract + [defusedxml](https://github.com/tiran/defusedxml) | Tenable `.nessus` XML is parsed directly without external entities. Other scanner products map through the documented normalized JSON boundary instead of coupling their proprietary schemas to the core. |
| KEV | [CISA KEV](https://github.com/cisagov/kev-data) | Batch catalogue adapter with provenance. KEV is membership, never a score; its due date is a US federal deadline, not the customer's SLA. |
| Exploit probability | [FIRST EPSS](https://www.first.org/epss/data_stats) | Dated probability/percentile adapter. Kept separate from CVSS, KEV and risk. |
| Vulnerability enrichment | [NVD 2.0](https://nvd.nist.gov/developers/vulnerabilities) | Provider adapter for CPE applicability, CVSS and references. Exact applicability remains a separate explainable matching decision. |
| Internal CTI | STIX 2.1-like bounded feed contract, compatible with [OASIS STIX](https://github.com/oasis-open/cti-python-stix2) concepts | Configured HTTPS endpoint, strict schema, markings/references/provenance and CVE/ATT&CK correlation. |
| PDF reports | [ReportLab](https://docs.reportlab.com/developerfaqs/) | BSD-licensed server-side PDF renderer; JSON and CSV are generated without another engine. |

## Optional connectors, not core dependencies

| Upstream | Intended use | Why it stays separate |
|---|---|---|
| [NetBox](https://github.com/netbox-community/netbox) | Implemented optional read-only network source-of-truth connector for devices, VMs, interfaces, IPAM, VLANs and prefixes. Bounded syncs are persisted with a manifest hash as unreviewed source snapshots. | Imported objects are observations/proposals, never automatically approved architecture; review and promotion are still pending. |
| [Nautobot](https://github.com/nautobot/nautobot) | Alternative source connector for organizations already using Nautobot Jobs/SSoT. | Installing both NetBox and Nautobot inside Traceless adds no core value. |
| [Cartography](https://github.com/cartography-cncf/cartography) | Later cloud/identity enrichment worker for AWS, Azure, GCP, Kubernetes and Entra relationships. | It writes Neo4j and is not a CMDB/API service; Traceless imports bounded snapshots and never grants core-database access. |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | Later, targeted verification against already discovered and authorized services. | It is not asset inventory. Only signed/pinned safe templates may run; code, headless, fuzz, DoS, credential and OAST/cloud features remain disabled by default. |
| [Greenbone Community Edition](https://greenbone.github.io/docs/latest/architecture.html) | Later deep and credentialed vulnerability scanning through GMP. | Heavy multi-service stack with GPL/AGPL/feed conditions; deploy and operate it independently. |
| [MISP](https://github.com/MISP/MISP) | The canonical global-intelligence API now accepts MISP-derived events, reports and indicators. A native polling connector remains optional. | Map through REST/PyMISP and preserve UUIDs, distribution/TLP/sharing metadata; do not embed or fork MISP core. |
| [OpenCTI](https://github.com/OpenCTI-Platform/opencti) | CTI connector when a customer already runs OpenCTI. | Prefer TAXII/live stream and pin GraphQL compatibility; run as a separate TIP. |
| [Dependency-Track](https://github.com/DependencyTrack/dependency-track) | SBOM/SCA module through CycloneDX and REST. | It complements network evidence and is not Traceless' risk or asset system of record. |
| [OSV](https://google.github.io/osv.dev/api/) | Package/SBOM vulnerabilities by PURL/ecosystem/version. | Source-specific data licences and attribution travel with each record. |
| [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon) | UX/rule inspiration and possible versioned import/export. | Its diagram format does not replace the Traceless domain model. |

## Explicitly deferred

- Neo4j is not a core database. PostgreSQL recursive queries are sufficient until
  measured attack-path workloads prove otherwise.
- Masscan and internet-wide scanners are excluded from the initial safe contract.
- In-process Python/JavaScript plugins are excluded. Extensions use versioned,
  permissioned out-of-process HTTP or queue contracts.
- External source data never silently overwrites analyst decisions, published
  architecture or another provider's metric.
