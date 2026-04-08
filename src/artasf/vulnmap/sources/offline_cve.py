"""
Offline vulnerability catalog.

A curated list of vulnerabilities relevant to lab environments running
DVWA, Apache, PHP, MySQL, OpenSSH, vsftpd, and Samba.  This avoids
a network dependency on NVD/Shodan at scan time.

Each entry is a KnownVuln.  The mapper iterates over CATALOG and checks
each target port against every entry.
"""

from __future__ import annotations

from artasf.vulnmap.vuln_types import KnownVuln

CATALOG: list[KnownVuln] = [

    # -----------------------------------------------------------------------
    # DVWA application-level (detected via HTTP title / banner)
    # -----------------------------------------------------------------------
    KnownVuln(
        id="DVWA-SQLI",
        title="DVWA SQL Injection (GET/POST)",
        description=(
            "DVWA exposes a deliberate SQL injection endpoint at /vulnerabilities/sqli/. "
            "User-supplied input is passed directly into a MySQL query without sanitisation."
        ),
        cvss_score=9.8,
        port_numbers=[80, 8080, 443, 8443],
        service_patterns=["http", "https"],
        tags=["web", "sqli", "dvwa"],
        msf_modules=[],
        edb_ids=[],
    ),
    KnownVuln(
        id="DVWA-CMD-INJECT",
        title="DVWA OS Command Injection",
        description=(
            "DVWA /vulnerabilities/exec/ passes user input to shell_exec() without "
            "sanitisation, allowing arbitrary OS command execution as the web server user."
        ),
        cvss_score=9.8,
        port_numbers=[80, 8080, 443, 8443],
        service_patterns=["http", "https"],
        tags=["web", "rce", "command-injection", "dvwa"],
        msf_modules=[],
        edb_ids=[],
    ),
    KnownVuln(
        id="DVWA-FILE-UPLOAD",
        title="DVWA Unrestricted File Upload → RCE",
        description=(
            "DVWA /vulnerabilities/upload/ accepts arbitrary file uploads with no "
            "content-type or extension validation, allowing upload of PHP webshells."
        ),
        cvss_score=9.0,
        port_numbers=[80, 8080, 443, 8443],
        service_patterns=["http", "https"],
        tags=["web", "rce", "file-upload", "dvwa"],
        msf_modules=[],
        edb_ids=[],
    ),
    KnownVuln(
        id="DVWA-XSS-STORED",
        title="DVWA Stored XSS",
        description=(
            "DVWA /vulnerabilities/xss_s/ stores user-supplied script content in "
            "the database and reflects it to all visitors without encoding."
        ),
        cvss_score=6.1,
        port_numbers=[80, 8080],
        service_patterns=["http"],
        tags=["web", "xss", "dvwa"],
        msf_modules=[],
        edb_ids=[],
    ),
    KnownVuln(
        id="DVWA-CSRF",
        title="DVWA Cross-Site Request Forgery",
        description=(
            "DVWA /vulnerabilities/csrf/ changes the admin password without a "
            "CSRF token, allowing an attacker-controlled page to trigger it."
        ),
        cvss_score=6.5,
        port_numbers=[80, 8080],
        service_patterns=["http"],
        tags=["web", "csrf", "dvwa"],
        msf_modules=[],
        edb_ids=[],
    ),
    KnownVuln(
        id="DVWA-LFI",
        title="DVWA Local File Inclusion",
        description=(
            "DVWA /vulnerabilities/fi/ includes files via a user-controlled "
            "?page= parameter without path traversal restrictions at low security."
        ),
        cvss_score=7.5,
        port_numbers=[80, 8080],
        service_patterns=["http"],
        tags=["web", "lfi", "dvwa"],
        msf_modules=[],
        edb_ids=[],
    ),

    # -----------------------------------------------------------------------
    # Apache HTTP Server
    # -----------------------------------------------------------------------
    KnownVuln(
        id="CVE-2021-41773",
        title="Apache 2.4.49 Path Traversal / RCE",
        description=(
            "A flaw in path normalisation in Apache 2.4.49 allows an unauthenticated "
            "attacker to map URLs to files outside the expected document root.  If "
            "mod_cgi is enabled, this leads to remote code execution."
        ),
        cve="CVE-2021-41773",
        cvss_score=9.8,
        service_patterns=["http"],
        version_patterns=["2\\.4\\.49"],
        cpe_patterns=["apache:http_server:2\\.4\\.49"],
        msf_modules=["exploit/multi/http/apache_normalize_path_rce"],
        edb_ids=["50383"],
        tags=["apache", "rce", "path-traversal"],
    ),
    KnownVuln(
        id="CVE-2021-42013",
        title="Apache 2.4.49-2.4.50 Path Traversal / RCE (bypass)",
        description=(
            "Double URL-encoding bypass of the CVE-2021-41773 fix in Apache 2.4.50 "
            "restores the path traversal / RCE vector."
        ),
        cve="CVE-2021-42013",
        cvss_score=9.8,
        service_patterns=["http"],
        version_patterns=["2\\.4\\.50"],
        cpe_patterns=["apache:http_server:2\\.4\\.50"],
        msf_modules=["exploit/multi/http/apache_normalize_path_rce"],
        edb_ids=["50406"],
        tags=["apache", "rce", "path-traversal"],
    ),
    KnownVuln(
        id="CVE-2017-7679",
        title="Apache mod_mime Buffer Overread",
        description=(
            "mod_mime in Apache 2.x before 2.2.34 and 2.4.x before 2.4.27 allows "
            "a buffer overread if the server is configured with MultiViews."
        ),
        cve="CVE-2017-7679",
        cvss_score=9.8,
        service_patterns=["http"],
        version_patterns=["2\\.2\\.(?:[0-2][0-9]|3[0-3])", "2\\.4\\.(?:[0-1][0-9]|2[0-6])"],
        cpe_patterns=["apache:http_server:2\\.2\\.", "apache:http_server:2\\.4\\."],
        msf_modules=[],
        edb_ids=[],
        tags=["apache", "buffer-overread"],
    ),

    # -----------------------------------------------------------------------
    # PHP
    # -----------------------------------------------------------------------
    KnownVuln(
        id="CVE-2012-1823",
        title="PHP CGI Argument Injection RCE",
        description=(
            "PHP before 5.3.12 and 5.4.x before 5.4.2 when configured as a CGI "
            "script does not properly handle query strings, allowing remote code "
            "execution via the -d flag injection."
        ),
        cve="CVE-2012-1823",
        cvss_score=9.8,
        service_patterns=["http"],
        version_patterns=["PHP/5\\.3\\.[0-9]\\b", "PHP/5\\.4\\.[01]\\b"],
        cpe_patterns=["php:php:5\\.3\\.", "php:php:5\\.4\\."],
        msf_modules=["exploit/multi/http/php_cgi_arg_injection"],
        edb_ids=["18836"],
        tags=["php", "rce", "cgi"],
    ),
    KnownVuln(
        id="GENERIC-PHP-INFO",
        title="PHP info() Disclosure",
        description=(
            "A publicly accessible phpinfo() page reveals PHP version, server "
            "configuration, loaded modules, and environment variables that aid "
            "further exploitation."
        ),
        cvss_score=5.3,
        port_numbers=[80, 8080, 443],
        service_patterns=["http"],
        tags=["php", "information-disclosure"],
        msf_modules=["auxiliary/scanner/http/phpinfo"],
        edb_ids=[],
    ),

    # -----------------------------------------------------------------------
    # MySQL
    # -----------------------------------------------------------------------
    KnownVuln(
        id="MYSQL-NO-AUTH",
        title="MySQL Accessible Without Password (Anonymous / Blank Root)",
        description=(
            "MySQL root account has an empty password or anonymous access is enabled, "
            "allowing full database read/write and potential UDF-based privilege escalation."
        ),
        cvss_score=9.8,
        port_numbers=[3306],
        service_patterns=["mysql"],
        msf_modules=[
            "auxiliary/scanner/mysql/mysql_login",
            "exploit/multi/mysql/mysql_udf_payload",
        ],
        edb_ids=[],
        tags=["mysql", "authentication-bypass", "privesc"],
    ),
    KnownVuln(
        id="CVE-2012-2122",
        title="MySQL Authentication Bypass via Timing Attack",
        description=(
            "MariaDB/MySQL before 5.1.61, 5.2.11, 5.3.5, 5.5.22 allows remote "
            "attackers to bypass authentication with any password in about 1 in "
            "256 attempts due to a memcmp() timing issue."
        ),
        cve="CVE-2012-2122",
        cvss_score=9.8,
        port_numbers=[3306],
        service_patterns=["mysql"],
        version_patterns=["5\\.1\\.(?:[0-5][0-9]|60)\\b", "5\\.5\\.(?:[0-1][0-9]|2[01])\\b"],
        msf_modules=["auxiliary/scanner/mysql/mysql_authbypass_hashdump"],
        edb_ids=["19092"],
        tags=["mysql", "authentication-bypass"],
    ),

    # -----------------------------------------------------------------------
    # OpenSSH
    # -----------------------------------------------------------------------
    KnownVuln(
        id="CVE-2018-15473",
        title="OpenSSH User Enumeration",
        description=(
            "OpenSSH through 7.7 is prone to a user enumeration vulnerability due "
            "to not delaying bailout for an invalid authenticating user until after "
            "the packet containing the request is fully parsed."
        ),
        cve="CVE-2018-15473",
        cvss_score=5.3,
        port_numbers=[22],
        service_patterns=["ssh"],
        version_patterns=["OpenSSH_[0-6]\\.", "OpenSSH_7\\.[0-7]"],
        cpe_patterns=["openssh:openssh:[0-7]\\."],
        msf_modules=["auxiliary/scanner/ssh/ssh_enumusers"],
        edb_ids=["45233"],
        tags=["ssh", "user-enumeration"],
    ),
    KnownVuln(
        id="SSH-WEAK-CREDS",
        title="SSH Weak / Default Credentials",
        description=(
            "SSH service may accept default or easily-guessable credentials "
            "(e.g. root:toor, admin:admin, ubuntu:ubuntu)."
        ),
        cvss_score=9.8,
        port_numbers=[22],
        service_patterns=["ssh"],
        msf_modules=["auxiliary/scanner/ssh/ssh_login"],
        edb_ids=[],
        tags=["ssh", "brute-force", "default-credentials"],
    ),

    # -----------------------------------------------------------------------
    # FTP — vsftpd backdoor (classic Metasploitable)
    # -----------------------------------------------------------------------
    KnownVuln(
        id="CVE-2011-2523",
        title="vsftpd 2.3.4 Backdoor Command Execution",
        description=(
            "vsftpd 2.3.4 was distributed with a malicious backdoor.  A smiley face "
            ":) in the username triggers a root shell on TCP port 6200."
        ),
        cve="CVE-2011-2523",
        cvss_score=10.0,
        port_numbers=[21],
        service_patterns=["ftp"],
        version_patterns=["vsftpd 2\\.3\\.4", "2\\.3\\.4"],
        msf_modules=["exploit/unix/ftp/vsftpd_234_backdoor"],
        edb_ids=["17491"],
        tags=["ftp", "backdoor", "rce"],
    ),
    KnownVuln(
        id="FTP-ANON",
        title="FTP Anonymous Login Enabled",
        description=(
            "The FTP server accepts anonymous logins, potentially exposing "
            "sensitive files or writable directories."
        ),
        cvss_score=7.5,
        port_numbers=[21],
        service_patterns=["ftp"],
        msf_modules=["auxiliary/scanner/ftp/anonymous"],
        edb_ids=[],
        tags=["ftp", "anonymous", "information-disclosure"],
    ),

    # -----------------------------------------------------------------------
    # Samba / SMB
    # -----------------------------------------------------------------------
    KnownVuln(
        id="CVE-2017-0144",
        title="MS17-010 EternalBlue SMB Remote Code Execution",
        description=(
            "A critical vulnerability in the SMBv1 server in Microsoft Windows "
            "allows remote code execution via a specially crafted packet."
        ),
        cve="CVE-2017-0144",
        cvss_score=9.8,
        port_numbers=[445, 139],
        service_patterns=["microsoft-ds", "netbios-ssn", "smb"],
        msf_modules=["exploit/windows/smb/ms17_010_eternalblue"],
        edb_ids=["42315"],
        tags=["smb", "rce", "windows"],
    ),
    KnownVuln(
        id="CVE-2007-2447",
        title="Samba 3.x MS-RPC Remote Code Execution (username map script)",
        description=(
            "The MS-RPC functionality in smbd in Samba 3.0.0 through 3.0.25rc3 "
            "allows remote attackers to execute arbitrary commands via shell "
            "metacharacters in the username field during MSRPC authentication."
        ),
        cve="CVE-2007-2447",
        cvss_score=10.0,
        port_numbers=[139, 445],
        service_patterns=["netbios-ssn", "microsoft-ds", "smb"],
        version_patterns=["Samba 3\\.0\\.[0-9]\\b", "Samba 3\\.0\\.1[0-9]\\b",
                          "Samba 3\\.0\\.2[0-5]"],
        msf_modules=["exploit/multi/samba/usermap_script"],
        edb_ids=["16320"],
        tags=["samba", "rce"],
    ),

    # -----------------------------------------------------------------------
    # Generic / catch-all
    # -----------------------------------------------------------------------
    KnownVuln(
        id="GENERIC-HTTP-METHODS",
        title="Dangerous HTTP Methods Enabled (PUT/DELETE/TRACE)",
        description=(
            "The web server allows HTTP methods that can be abused: PUT to upload "
            "files, DELETE to remove them, or TRACE for cross-site tracing attacks."
        ),
        cvss_score=5.0,
        port_numbers=[80, 8080, 443, 8443],
        service_patterns=["http"],
        msf_modules=["auxiliary/scanner/http/options"],
        edb_ids=[],
        tags=["web", "misconfiguration"],
    ),
    KnownVuln(
        id="GENERIC-HTTP-DIR-LIST",
        title="HTTP Directory Listing Enabled",
        description=(
            "The web server has directory listing enabled, exposing the file "
            "structure and potentially sensitive files."
        ),
        cvss_score=5.3,
        port_numbers=[80, 8080],
        service_patterns=["http"],
        msf_modules=["auxiliary/scanner/http/dir_listing"],
        edb_ids=[],
        tags=["web", "information-disclosure"],
    ),
]
