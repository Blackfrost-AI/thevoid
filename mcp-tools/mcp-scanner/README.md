# MCP Scanner

Bundled MCP scanning integration for THE VOID.

This package supplies the <code>Scanner</code> interface used by Frosty's
<code>mcp_scan</code> phase. It is included in the client repository and does
not require a second clone or download.

> **Current status: integration scaffold.** The package proves loading,
> orchestration, result flow, and report plumbing. It is not yet a production
> vulnerability authority, and its findings must not be presented as verified
> vulnerabilities.

## At a glance

| Detail | Value |
|---|---|
| Package version | 1.0.0 |
| Runtime | Local Python |
| THE VOID integration | <code>agent/shadow_agent.py</code> |
| Registered phase | <code>mcp_scan</code> |
| Network service | None in the supported client path |
| License | Root THE VOID proprietary license |

## Included modules

| Module | Intended responsibility |
|---|---|
| <code>scanner.py</code> | Coordinate analysis and return <code>ScanResult</code> |
| <code>analyzer.py</code> | Pattern-oriented configuration and code analysis |
| <code>config_parser.py</code> | Configuration discovery and baseline drift |
| <code>dependency_inspector.py</code> | Dependency inventory |
| <code>cve_matcher.py</code> | Local finding-to-advisory correlation |
| <code>report_generator.py</code> | HTML, JSON, and PDF report plumbing |

## Current limitations

The present source contains deterministic placeholder behavior in important
paths:

- Configuration and code analysis do not yet parse and evaluate the target
  files comprehensively.
- Configuration discovery currently produces a baseline fixture rather than a
  verified inventory of the target tree.
- Dependency inspection currently returns fixture dependencies rather than
  parsing lock files and manifests.
- Advisory matching uses a bundled sample data set and permissive correlation
  logic; matches are not validated findings.
- HTML output contains only a summary, JSON serialization is not complete for
  every nested result type, and PDF output is a placeholder.
- There is no supported standalone CLI or HTTP service.
- The bundled Dockerfile is a development artifact and references assets that
  are not part of this client package; it is not in the accepted build path.

These limitations are deliberately documented so a successful
<code>mcp_scan</code> phase cannot be mistaken for production-grade assurance.

## Supported use in this release

Use the package only for:

- Verifying that Frosty can load the scanner integration.
- Exercising phase orchestration and evidence flow in an authorized lab.
- Developing and testing real detector implementations behind the stable
  <code>Scanner</code> and <code>ScanResult</code> interfaces.

Do not use scaffold output as the sole basis for a client severity,
remediation, compliance, or exposure statement.

## Local smoke test

From the THE VOID repository root:

~~~bash
PYTHONPATH=mcp-tools/mcp-scanner python3 - <<'PY'
from pathlib import Path

from src import Scanner

result = Scanner().scan(Path("."))
print(
    {
        "target": result.target_path,
        "findings": len(result.vulnerabilities),
        "dependencies": len(result.dependencies),
        "drift": len(result.configuration_drift),
    }
)
PY
~~~

This confirms that the package imports and the orchestration surface runs. It
does not validate the accuracy of the returned findings.

To inspect how the phase would be planned without running tools:

~~~bash
thevoid engage <approved-target> --scenario mcp-critical \
  --profile client --authz /secure/path/engagement-scope.json --dry-run
~~~

The <code>mcp-critical</code> scenario also includes other active MCP phases.
Do not remove <code>--dry-run</code> unless every resolved phase is explicitly
authorized.

## Development verification

~~~bash
python3 -m compileall -q mcp-tools/mcp-scanner/src
python3 -m pytest tests -q
~~~

The root test suite covers THE VOID's broader phase and safety contracts.
Dedicated scanner fixtures and detector-level accuracy tests remain an
acceptance requirement.

## Production acceptance requirements

Before scanner findings are client-reportable:

1. Discover and parse supported configuration, source, manifest, and lock-file
   formats from the actual target path.
2. Replace fixture dependencies and drift records with evidence derived from
   inspected files.
3. Use a maintained, attributable advisory source with deterministic version
   matching and no unconditional correlations.
4. Normalize every result to serializable primitives and validate all advertised
   report formats.
5. Add positive, negative, malformed-input, path-boundary, and regression
   fixtures with documented expected results.
6. Define false-positive handling, severity rules, data provenance, and update
   policy.
7. Either complete and test the container assets or remove the unsupported
   Docker path.
8. Pass the root unit, secret, dependency, and lint gates on the intended Kali
   machine and in CI.

## Data handling

The scanner accepts a local path. Keep real client projects outside this
repository, constrain the path to approved material, and review any derived
evidence before export. Do not commit scanned source, target configuration,
credentials, generated reports, or customer identifiers.

## License

This bundled package is governed by the proprietary
[root license](../../LICENSE). No separate open-source license is granted by
this directory.
