"""
nessus_organiser.analysis.tls

Apply TLS-specific analysis and contextualisation to
consultant-facing findings.
"""

from nessus_organiser.models.finding import Finding


def analyse_tls_finding(
    finding: Finding,
    scope: str,
    content: dict,
) -> Finding:
    """
    Apply TLS-specific analysis and contextualisation to
    a generated finding.

    This function performs scope-aware adjustments and
    evidence-aware refinements to produce consultant-facing
    report content.

    Args:
        finding:
            Finding to analyse.

        scope:
            Assessment environment. Expected values are
            'internal' or 'external'.

        content:
            Loaded TLS content definitions used to resolve
            dynamic commentary, remediation guidance, and
            evidence-specific reporting adjustments.

    Returns:
        Analysed finding.
    """

    finding = _apply_scope(finding=finding, scope=scope)
    finding = _apply_evidence(finding=finding, content=content)

    return finding


def _apply_scope(
    finding: Finding,
    scope: str,
) -> Finding:
    """
    Apply scope-specific reporting adjustments.

    This currently resolves scope-dependent severity
    ratings defined within content definitions.
    """

    if isinstance(finding.severity, dict):
        finding.severity = finding.severity[scope]

    return finding


def _append_content(
    finding: Finding,
    definition: dict,
) -> None:
    """
    Append supplementary reporting content to a finding.

    Used when related observations require additional
    commentary, remediation guidance, or references to
    be included alongside the primary finding content.
    """

    if definition.get("commentary"):

        finding.commentary = (
            (finding.commentary or "")
            + "\n\n"
            + definition["commentary"]
        )

    if definition.get("solution"):

        finding.solution = (
            (finding.solution or "")
            + "\n\n"
            + definition["solution"]
        )

    for reference in definition.get("references", []):
        if reference not in finding.references:
            finding.references.append(reference)


def _apply_evidence(
    finding: Finding,
    content: dict,
) -> Finding:
    """
    Apply evidence-driven refinements to a finding.

    This includes dynamic title generation, evidence
    summarisation, and the inclusion of additional
    report content based on observed scanner evidence.
    """

    certificate_issues = content.get("certificate_issues", {})

    #---------------------------------------------------------------------------
    # SSL versions
    #---------------------------------------------------------------------------
    if finding.category == "deprecated_ssl_support":

        ssl2 = ("SSL 2.0 support" in finding.evidence)
        ssl3 = ("SSL 3.0 support" in finding.evidence)
        
        if ssl2 and ssl3:
            finding.title = (
                "Deprecated SSL Version 2 and SSL Version 3 Support"
            )
            finding.commentary_evidence = (
                "Testing identified support for SSL 2.0 and SSL 3.0."
            )

        elif ssl2 and not ssl3:
            finding.title = ("Deprecated SSL Version 2 Support")
            finding.commentary_evidence = (
                "Testing identified support for SSL 2.0."
            )

        elif ssl3 and not ssl2:
            finding.title = ("Deprecated SSL Version 3 Support")
            finding.commentary_evidence = (
                "Testing identified support for SSL 3.0."
            )

    #---------------------------------------------------------------------------
    # TLS versions
    #---------------------------------------------------------------------------
    if finding.category == "deprecated_tls_support":

        tls10 = ("TLS 1.0 support" in finding.evidence)
        tls11 = ("TLS 1.1 support" in finding.evidence)
        renegotiation = (
            "TLS 1.0 insecure renegotiation support" in finding.evidence
        )

        if tls10 and tls11:
            finding.title = ("Deprecated TLS 1.0 and TLS 1.1 Protocol Support")
            finding.commentary_evidence = (
                "Testing identified support for TLS 1.0 and TLS 1.1."
            )

        elif tls10 and not tls11:
            finding.title = ("Deprecated TLS 1.0 Protocol Support")
            finding.commentary_evidence = (
                "Testing identified support for TLS 1.0."
            )

        elif tls11 and not tls10:
            finding.title = ("Deprecated TLS 1.1 Protocol Support")
            finding.commentary_evidence = (
                            "Testing identified support for TLS 1.1."
                        )

        if renegotiation:

            if finding.commentary_evidence:
                finding.commentary_evidence += (
                    "\n\nTesting also identified support for insecure TLS "
                    "renegotiation."
                )
            else:
                finding.commentary_evidence = (
                    "Testing identified support for insecure TLS "
                    "renegotiation."
                )

            _append_content(
                finding=finding,
                definition=content["tls_insecure_renegotiation"],
            )

    #---------------------------------------------------------------------------
    # Weak cipher suites
    #---------------------------------------------------------------------------
    if finding.category == "weak_cipher_suites":

        des = ("3DES-based cipher suites" in finding.evidence)
        rc4 = ("RC4-based cipher suites" in finding.evidence)
        # TODO: Double-check these!
        cbc = ("CBC-mode cipher suites" in finding.evidence)
        export_grade = ("Export-grade RSA cipher suites" in finding.evidence)

        detected = []

        if rc4:
            detected.append("RC4-based")

        if des:
            detected.append("3DES-based")

        if cbc:
            detected.append("CBC-mode")

        if export_grade:
            detected.append("export-grade RSA")

        if len(detected) == 1:

            finding.commentary_evidence = (
                f"Testing identified support for {detected[0]} cipher suites."
            )

        elif len(detected) == 2:

            finding.commentary_evidence = (
                f"Testing identified support for {detected[0]} and "
                f"{detected[1]} cipher suites."
            )

        elif len(detected) > 2:

            finding.commentary_evidence = (
                "Testing identified support for "
                + ", ".join(detected[:-1])
                + f", and {detected[-1]} cipher suites."
            )


    # --------------------------------------------------------------------------
    # Certificate Configuration Issues
    # --------------------------------------------------------------------------
    if finding.category == "invalid_certificate_configuration":

        issue_titles = []
        issue_commentary = []

        seen_titles = set()

        for plugin in finding.affected_plugins:

            plugin_id = str(plugin.plugin_id)
            issue = certificate_issues.get(plugin_id)

            if not issue:
                continue

            title = issue["title"]

            if title in seen_titles:
                continue

            seen_titles.add(title)

            issue_titles.append(title)

            issue_commentary.append(
                f"#### {title}\n\n"
                f"{issue['commentary']}"
            )

        if issue_titles:

            finding.commentary_evidence = (
                "Testing identified the following TLS certificate "
                "configuration issues:\n\n"
                + "\n".join(
                    f"- {title}"
                    for title in sorted(set(issue_titles))
                )
            )

            finding.commentary = "\n\n".join(
                issue_commentary
            )

    #---------------------------------------------------------------------------
    # Weak Certificate Cryptography
    #---------------------------------------------------------------------------
    if finding.category == "weak_certificate_cryptography":

        weak_hash = (
            "Certificate chain signed using a weak hashing algorithm"
            in finding.evidence
        )

        sha1 = (
            "Certificate chain signed using SHA-1"
            in finding.evidence
        )

        rsa2048 = (
            "Certificate chain contains RSA keys smaller than 2048 bits"
            in finding.evidence
        )

        rsa1024 = (
            "Certificate chain contains RSA keys smaller than 1024 bits"
            in finding.evidence
        )
    
        detected = []

        if sha1:
            detected.append("SHA-1 certificate signatures")

        elif weak_hash:
            detected.append("weak certificate signature algorithms")

        if rsa1024:
            detected.append("RSA keys smaller than 1024 bits")

        elif rsa2048:
            detected.append("RSA keys smaller than 2048 bits")

        if len(detected) == 1:

            finding.commentary_evidence = (f"Testing identified {detected[0]}.")

        elif len(detected) == 2:

            finding.commentary_evidence = (
                f"Testing identified {detected[0]} and {detected[1]}."
            )

    return finding