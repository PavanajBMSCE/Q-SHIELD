
import ast
import io
import re
import tokenize


SUPPORTED_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java",
    ".c", ".cpp", ".h", ".hpp", ".cs", ".go",
    ".php", ".rb", ".json", ".yaml", ".yml",
    ".toml", ".ini", ".cfg", ".conf", ".env",
    ".properties", ".xml"
}

ALGORITHM_PATTERNS = {
    "RSA": re.compile(
        r"\bRSA\b|rsa\.generate_private_key|"
        r"rsa\.RSAPrivateKey|rsa\.RSAPublicKey",
        re.IGNORECASE
    ),
    "ECC": re.compile(
        r"\bECDSA\b|\bECDH\b|\bECC\b|"
        r"ec\.generate_private_key|ec\.SECP\d+[RK]?\d*|"
        r"\bX25519\b|\bX448\b|\bEd25519\b|\bEd448\b|"
        r"EllipticCurve",
        re.IGNORECASE
    ),
    "AES": re.compile(r"\bAES(?:-\d+)?(?:-GCM)?\b|\bAESGCM\b", re.IGNORECASE),
    "SHA-256": re.compile(r"\bSHA[-_]?256\b|sha256", re.IGNORECASE),
    "SHA-384": re.compile(r"\bSHA[-_]?384\b|sha384", re.IGNORECASE),
    "SHA-512": re.compile(r"\bSHA[-_]?512\b|sha512", re.IGNORECASE),
    "SHA-1": re.compile(r"\bSHA[-_]?1\b|sha1", re.IGNORECASE),
    "MD5": re.compile(r"\bMD5\b|md5", re.IGNORECASE),
    "DES": re.compile(r"\bDES\b|TripleDES|3DES", re.IGNORECASE),
}

WEAK_PATTERNS = [
    (
        re.compile(r"\bDES\b|TripleDES|\b3DES\b", re.IGNORECASE),
        "DES/3DES is deprecated or legacy cryptography",
        "HIGH"
    ),
    (
        re.compile(r"\bMD5\b|md5", re.IGNORECASE),
        "MD5 is unsuitable for security-sensitive hashing",
        "HIGH"
    ),
    (
        re.compile(r"\bSHA[-_]?1\b|sha1", re.IGNORECASE),
        "SHA-1 is deprecated for collision-resistant applications",
        "HIGH"
    ),
    (
        re.compile(r"AES[-_ ]?\d*[-_ ]?ECB|AES\.MODE_ECB", re.IGNORECASE),
        "AES ECB mode does not provide semantic security",
        "HIGH"
    ),
    (
        re.compile(r"AES[-_ ]?\d*[-_ ]?CBC|AES\.MODE_CBC", re.IGNORECASE),
        "AES CBC mode requires correct IV handling and separate authentication",
        "MEDIUM"
    ),
    (
        re.compile(r"TLSv?1\.0|TLSv?1\.1", re.IGNORECASE),
        "Legacy TLS protocol detected",
        "HIGH"
    ),
    (
        re.compile(r"verify\s*=\s*False", re.IGNORECASE),
        "TLS certificate verification appears disabled",
        "HIGH"
    ),
]

SECRET_PATTERNS = [
    re.compile(
        r"""(?:api[_-]?key|secret[_-]?key|access[_-]?token|password)
        \s*[:=]\s*["'][^"']{8,}["']""",
        re.IGNORECASE | re.VERBOSE
    ),
    re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        re.IGNORECASE
    ),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b")
]

AST_CRYPTO_APIS = {
    "generate_private_key",
    "generate_key",
    "AESGCM",
    "PBKDF2HMAC",
    "scrypt",
    "Scrypt",
    "Argon2id",
    "bcrypt",
    "sha256",
    "sha384",
    "sha512",
    "sha1",
    "md5",
    "encrypt",
    "decrypt",
}


def _remove_python_comments(source):
    try:
        tokens = tokenize.generate_tokens(io.StringIO(source).readline)
        result = []

        for token in tokens:
            if token.type == tokenize.COMMENT:
                token = tokenize.TokenInfo(
                    token.type, "", token.start, token.end, token.line
                )
            result.append(token)

        return tokenize.untokenize(result)
    except (tokenize.TokenError, IndentationError):
        return source


def _remove_other_comments(source):
    result = []

    for line in source.splitlines():
        output = []
        quote = None
        escaped = False
        i = 0

        while i < len(line):
            char = line[i]

            if escaped:
                output.append(char)
                escaped = False
                i += 1
                continue

            if quote:
                output.append(char)
                if char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
                i += 1
                continue

            if char in ("'", '"', "`"):
                quote = char
                output.append(char)
                i += 1
                continue

            if char == "#" or line[i:i + 2] == "//":
                break

            output.append(char)
            i += 1

        result.append("".join(output))

    return "\n".join(result)


def _mask_strings(source, is_python):
    """Mask strings for code detection, preserving line positions."""
    if is_python:
        try:
            lines = source.splitlines(keepends=True)
            tokens = tokenize.generate_tokens(io.StringIO(source).readline)

            string_token_types = {tokenize.STRING}
            for token_name in ("FSTRING_START", "FSTRING_MIDDLE", "FSTRING_END"):
                token_type = getattr(tokenize, token_name, None)
                if token_type is not None:
                    string_token_types.add(token_type)

            for token in tokens:
                if token.type not in string_token_types:
                    continue

                start_line, start_col = token.start
                end_line, end_col = token.end
                # Mask single-line and multi-line strings/docstrings while
                # preserving every newline and therefore source line numbers.
                for line_index in range(start_line - 1, end_line):
                    if line_index < 0 or line_index >= len(lines):
                        continue
                    line = lines[line_index]
                    segment_start = start_col if line_index == start_line - 1 else 0
                    segment_end = end_col if line_index == end_line - 1 else len(line.rstrip("\r\n"))
                    segment = line[segment_start:segment_end]
                    masked = "".join("\n" if char == "\n" else "\r" if char == "\r" else " " for char in segment)
                    lines[line_index] = line[:segment_start] + masked + line[segment_end:]

            return "".join(lines)
        except (tokenize.TokenError, IndentationError):
            return source

    return re.sub(
        r"""(['"`])(?:\\.|(?!\1).)*?\1""",
        lambda match: "".join(
            "\n" if char == "\n" else " "
            for char in match.group(0)
        ),
        source
    )


def _add_finding(findings, seen, file_name, line_number,
                 algorithm, algorithm_type, detected_usage,
                 finding, severity, recommendation):
    key = (file_name, line_number, algorithm)

    if key in seen:
        return

    seen.add(key)

    findings.append({
        "file_name": file_name,
        "line_number": line_number,
        "algorithm": algorithm,
        "algorithm_type": algorithm_type,
        "detected_usage": detected_usage[:200],
        "finding": finding,
        "severity": severity,
        "recommendation": recommendation
    })


def get_algorithm_type(algorithm):
    if algorithm in ("RSA", "ECC"):
        return "Asymmetric"
    if algorithm in ("AES", "DES"):
        return "Symmetric"
    if algorithm.startswith("SHA") or algorithm == "MD5":
        return "Hashing"
    return "Unknown"


def get_algorithm_assessment(algorithm):
    if algorithm in ("RSA", "ECC"):
        return (
            "Migration planning",
            "HIGH",
            "Review and plan post-quantum migration"
        )

    if algorithm in ("MD5", "SHA-1", "DES"):
        return (
            "Deprecated / weak",
            "HIGH",
            "Replace or redesign this cryptographic usage"
        )

    if algorithm == "AES":
        return (
            "Retain, review mode",
            "LOW",
            "Verify that an authenticated encryption mode is being used"
        )

    if algorithm in ("SHA-256", "SHA-384", "SHA-512"):
        return (
            "Modern digest adoption",
            "INFO",
            "Modern digest detected; confirm intended use and protocol compatibility."
        )

    return (
        "Review",
        "MEDIUM",
        "Review the cryptographic implementation"
    )


def _detect_ast_apis(source, file_name, findings, seen):
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        function_name = ""

        if isinstance(node.func, ast.Name):
            function_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            function_name = node.func.attr

        if function_name in AST_CRYPTO_APIS:
            _add_finding(
                findings, seen, file_name,
                getattr(node, "lineno", 1),
                "Cryptographic API", "Implementation",
                function_name,
                "Cryptographic API usage detected through Python AST",
                "INFO",
                "Review the cryptographic API implementation"
            )


def scan_file(filename, content):
    findings = []
    seen = set()

    extension = (
        "." + filename.rsplit(".", 1)[-1].lower()
        if "." in filename else ""
    )
    is_python = extension == ".py"

    if isinstance(content, bytes):
        source = content.decode("utf-8", errors="replace")
    else:
        source = str(content)

    comment_free = (
        _remove_python_comments(source)
        if is_python
        else _remove_other_comments(source)
    )

    original_lines = comment_free.splitlines()
    code_only = _mask_strings(comment_free, is_python)
    code_lines = code_only.splitlines()

    # Determine whether RSA is actually referenced in code.
    rsa_in_code = any(
        ALGORITHM_PATTERNS["RSA"].search(line)
        for line in code_lines
    )

    for index, original_line in enumerate(original_lines):
        line_number = index + 1
        code_line = code_lines[index] if index < len(code_lines) else ""
        code_match = code_line.strip()
        original = original_line.strip()

        if not original:
            continue

        is_import = code_match.startswith(("import ", "from "))

        # 1. Detect algorithms in executable code.
        for algorithm, pattern in ALGORITHM_PATTERNS.items():
            if is_import and algorithm in ("RSA", "ECC", "AES", "DES"):
                continue

            if pattern.search(code_line):
                finding, severity, recommendation = get_algorithm_assessment(
                    algorithm
                )

                if algorithm == "AES":
                    if re.search(r"GCM|AESGCM", original, re.IGNORECASE):
                        finding = "Authenticated encryption adoption"
                        severity = "INFO"
                        recommendation = (
                            "AES-GCM provides authenticated encryption; verify nonce uniqueness, "
                            "authentication-tag handling and associated-data consistency."
                        )
                    elif re.search(r"CBC|MODE_CBC", original, re.IGNORECASE):
                        finding = "Review encryption mode"
                        severity = "MEDIUM"
                        recommendation = (
                            "CBC does not provide authentication. "
                            "Consider authenticated encryption such as AES-GCM"
                        )
                    elif re.search(r"ECB|MODE_ECB", original, re.IGNORECASE):
                        finding = "Weak encryption mode"
                        severity = "HIGH"
                        recommendation = (
                            "Replace ECB with an authenticated mode such as AES-GCM"
                        )

                _add_finding(
                    findings, seen, filename, line_number,
                    algorithm, get_algorithm_type(algorithm),
                    original, finding, severity, recommendation
                )

        # 2. Inspect relevant configuration assignments containing strings.
        config_assignment = re.search(
            r"\b(algorithm|cipher|encryption|hash|tls_version|"
            r"tlsversion|protocol|legacy_cipher)\b\s*[:=]",
            original,
            re.IGNORECASE
        )

        if config_assignment:
            for algorithm, pattern in ALGORITHM_PATTERNS.items():
                if pattern.search(original):
                    finding, severity, recommendation = get_algorithm_assessment(
                        algorithm
                    )

                    if algorithm == "AES":
                        if re.search(r"GCM|AESGCM", original, re.IGNORECASE):
                            finding = "Authenticated encryption adoption"
                            severity = "INFO"
                            recommendation = (
                                "AES-GCM provides authenticated encryption; verify nonce uniqueness, "
                                "authentication-tag handling and associated-data consistency."
                            )
                        elif re.search(r"CBC", original, re.IGNORECASE):
                            finding = "Review encryption mode"
                            severity = "MEDIUM"
                            recommendation = (
                                "CBC does not provide authentication. "
                                "Consider authenticated encryption such as AES-GCM"
                            )
                        elif re.search(r"ECB", original, re.IGNORECASE):
                            finding = "Weak encryption mode"
                            severity = "HIGH"
                            recommendation = (
                                "Replace ECB with an authenticated mode such as AES-GCM"
                            )

                    _add_finding(
                        findings, seen, filename, line_number,
                        algorithm, get_algorithm_type(algorithm),
                        original, finding, severity, recommendation
                    )

        # 3. Weak configurations: inspect code and relevant config values.
        for pattern, description, severity in WEAK_PATTERNS:
            if pattern.search(code_line) or (
                config_assignment and pattern.search(original)
            ):
                # RSA key size is only meaningful when RSA is referenced.
                if "key size" in description.lower() and not rsa_in_code:
                    continue

                _add_finding(
                    findings, seen, filename, line_number,
                    "Weak Configuration", "Configuration",
                    original, description, severity,
                    "Review and replace the weak configuration"
                )

        # 4. Detect hardcoded secrets.
        for pattern in SECRET_PATTERNS:
            if pattern.search(original):
                _add_finding(
                    findings, seen, filename, line_number,
                    "Hardcoded Secret", "Secret",
                    "[REDACTED]",
                    "Potential hardcoded credential or secret",
                    "CRITICAL",
                    "Remove the secret from source code, store it securely and rotate it"
                )
                break

    # 5. Python AST API detection.
    if is_python:
        _detect_ast_apis(comment_free, filename, findings, seen)

    findings.sort(
        key=lambda item: (item["line_number"], item["algorithm"])
    )

    return findings
