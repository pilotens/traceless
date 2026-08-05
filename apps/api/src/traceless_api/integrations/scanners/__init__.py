"""Safe scanner adapter primitives.

The package parses scanner output and builds reviewed argv vectors. It deliberately
does not execute binaries, resolve hostnames, or accept arbitrary scanner flags.
"""

from traceless_api.integrations.scanners.naabu import (
    NaabuJsonlParser,
    NaabuOutputError,
    parse_naabu_jsonl,
)
from traceless_api.integrations.scanners.nmap import (
    NmapCommandBuilder,
    NmapOutputError,
    NmapXmlParser,
    build_nmap_command,
    parse_nmap_xml,
)
from traceless_api.integrations.scanners.scope import (
    DEFAULT_MAX_TARGET_HOSTS,
    ScannerScope,
    ScopeValidationError,
    ValidatedTargets,
    normalize_scope,
    validate_observations,
    validate_targets,
)
from traceless_api.integrations.scanners.types import (
    AddressObservation,
    HardwareAddressObservation,
    HostObservation,
    HostState,
    OperatingSystemObservation,
    ScanCompleteness,
    ScannerCommand,
    ScannerCommandBuilder,
    ScannerOutputParser,
    ScannerResult,
    ScanProfile,
    ServiceObservation,
)

__all__ = [
    "DEFAULT_MAX_TARGET_HOSTS",
    "AddressObservation",
    "HardwareAddressObservation",
    "HostObservation",
    "HostState",
    "NaabuJsonlParser",
    "NaabuOutputError",
    "NmapCommandBuilder",
    "NmapOutputError",
    "NmapXmlParser",
    "OperatingSystemObservation",
    "ScanCompleteness",
    "ScanProfile",
    "ScannerCommand",
    "ScannerCommandBuilder",
    "ScannerOutputParser",
    "ScannerResult",
    "ScannerScope",
    "ScopeValidationError",
    "ServiceObservation",
    "ValidatedTargets",
    "build_nmap_command",
    "normalize_scope",
    "parse_naabu_jsonl",
    "parse_nmap_xml",
    "validate_observations",
    "validate_targets",
]
