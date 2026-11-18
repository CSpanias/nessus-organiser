"""
nessus_organiser.rules.ssh

Defines SSH-related plugin groupings and evidence mappings used to organise
Nessus findings into consultant-friendly root cause categories.
"""

SSH_CATEGORIES = {

    "terrapin_prefix_truncation": {
        "plugin_ids": {
            "187315",
        },
    },

    "weak_mac_algorithms": {
        "plugin_ids": {
            "71049",
        },
    },

    "weak_key_exchange_algorithms": {
        "plugin_ids": {
            "153953",
        },
    },

    "cbc_mode_ciphers": {
        "plugin_ids": {
            "70658",
        },
    },

    "weak_algorithms_supported": {
        "plugin_ids": {
            "90317",
        },
    },

    "ssh_protocol_v1": {
        "plugin_ids": {
            "10882",
        },
    },
}

SSH_EVIDENCE = {
    "187315": "Terrapin prefix truncation weakness (CVE-2023-48795)",
    "71049": "Weak Message Authentication Code (MAC) algorithms enabled",
    "153953": "Weak SSH key exchange algorithms enabled",
    "70658": "SSH CBC mode ciphers enabled",
    "90317": "Weak SSH cipher algorithms supported (Arcfour/RC4)",
    "10882": "SSH protocol version 1 supported",
}