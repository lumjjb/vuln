# Experimental: VEX

## What is VEX

[As defined by the NTIA](https://www.ntia.gov/files/ntia/publications/vex_one-page_summary.pdf), 
VEX stands for "Vulnerability Exploitability eXchange".

The primary use cases for VEX are to provide users (e.g., operators, developers, and services
providers) additional information on whether a product is impacted by a specific vulnerability in an
included component and, if affected, whether there are actions recommended to remediate. In
many cases , a vulnerability in an upstream component will not be “exploitable” in the final
product for various reasons (e.g., the affected code is not loaded by the compiler, or some inline
protections exist elsewhere in the software).

A VEX is an assertion about the status of a vulnerability in specific products. The status can be:
- Not affected – No remediation is required regarding this vulnerability.
- Affected – Actions are recommended to remediate or address this vulnerability.
- Fixed – Represents that these product versions contain a fix for the vulnerability.
- Under Investigation – It is not yet known whether these product versions are affected by
the vulnerability. An update will be provided in a later release.

## govulncheck VEX

`govulncheck` implements the ability to output a VEX document with the `-vex` flag. It creates
VEX statements using the following information:

- If `govulncheck` determines that a vulnerable function is not called, it will mark the vulnerability as "not affected"
- For other known vulnerabilities, a status of "under investigation" is set

??? Future work: If a `.vex`/`go.vex` file is present, users can annotate which vulnerabilities they are not affected by with justification
and `govulncheck -vex` will set the status of them to "not affected" with the optional justification and comments.

## VEX caveats

The VEX data model and specification is stil not finalized and subject to change.
