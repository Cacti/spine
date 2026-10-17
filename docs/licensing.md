# Source licensing and attribution

Maintained C sources, private headers and helper scripts carry SPDX license
identifiers. Existing file-specific GNU GPL or LGPL version and later-version
permissions are preserved. Previously unmarked maintained files identify the
repository's LGPL 2.1 license as `LGPL-2.1-only`; this does not infer a later-version
permission absent from an existing notice. The root `LICENSE` remains unchanged.

Copyright holders and dates from existing notices are preserved. Original
poller credits remain in the corresponding source headers. Fork-maintenance
credit identifies Thomas Vincent without assigning other authors' copyrights.
[CONTRIBUTORS.md](../CONTRIBUTORS.md) records additional major contributors from
Git history; it does not claim that each contributor authored every file.

The process implementation and extracted descriptor helpers retain the original
Xenadyne and Berkeley permission, advertising and disclaimer notices verbatim.
Their identifiers express the existing combined obligations, including the
nonstandard permission text in `LICENSES/LicenseRef-Xenadyne.txt`. This cleanup
does not relicense those contributions or resolve historical license-compatibility
questions.

Vendored sources, historical SQL/behavior fixtures and fuzz corpora retain their
original bytes. Generated Autotools files retain their generator's notices.
These scoped annotations are not a claim of whole-repository REUSE certification.
