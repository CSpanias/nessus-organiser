"""
nessus_organiser.rules.tls

Defines TLS-related plugin groupings and evidence mappings used to organise 
Nessus findings into consultant-friendly root cause categories.
"""

TLS_CATEGORIES = {

    "deprecated_ssl_support": {
        "plugin_ids": {
            "20007",
            "78447",
            "78479",
            "89058",
        }
    },

    "deprecated_tls_support": {
        "plugin_ids": {
            "104743",
            "157288",
            "42880",
        }
    },

    "weak_cipher_suites": {
        "plugin_ids": {
            "26928",
            "65821",
            "42873",
            "81606",
        }
    },

    "invalid_certificate_configuration": {
        "plugin_ids": {
            "51192",
            "57582",
            "45410",
            "45411",
            "15901",
            "56284",
        }
    },

    "weak_certificate_cryptography": {
        "plugin_ids": {
            "35291",
            "69551",
            "60108",
            "86067",
        }
    },

    "weak_dh_parameters": {
        "plugin_ids": {
            "83875",
            "53360",
        }
    },

    "anonymous_cipher_suites": {
        "plugin_ids": {
            "31705",
        }
    },
}

TLS_EVIDENCE = {
    # SSL
    "78447": "SSL 3.0 support",
    "78479": "SSL 3.0 support",
    "89058": "SSL 2.0 support",

    # TLS
    "104743": "TLS 1.0 support",
    "157288": "TLS 1.1 support",
    "42880": "TLS 1.0 insecure renegotiation support",

    # Weak Cipher Suites
    "65821": "RC4-based cipher suites",
    "42873": "3DES-based cipher suites",
    "81606": "Export-grade RSA cipher suites",
    "31705": "Anonymous cipher suites",

    # DH
    "83875": "Weak Diffie-Hellman parameters (≤1024-bit)",
    "53360": "Weak Diffie-Hellman key exchange implementation",

    # Certificate with weak hashing algorithm
    "35291": "Certificate chain signed using a weak hashing algorithm",
    "86067": "Certificate chain signed using SHA-1",

    # Certificate with small RSA keys
    "69551": "Certificate chain contains RSA keys smaller than 2048 bits",
    "60108": "Certificate chain contains RSA keys smaller than 1024 bits",
}