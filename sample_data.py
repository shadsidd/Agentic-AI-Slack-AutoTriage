"""
This file contains sample data for the Slack alert triage system.
It includes:
1. Sample Slack messages in the format received from Slack
2. Sample alerts in the format stored in the vector database
"""

# Sample Slack messages received from Slack
# Format: List of dictionaries with 'text' and 'timestamp' keys
slack_messages = [
    {
        "text": """JR-Praetorian APP 7:33 PM
Account: js_tilemedia(200304247802), Region: ap-south-1
Instance: tm-08b748f2-2732-415a-9100d-25e3b5bc5512-live-cpu-0, (i-05e1678d505ebcb58), (13.235.57.48)
SG: sg-0be620a6ee6f78157, [udp:2376,tcp:2112,udp:22,tcp:22,tcp:2376,udp:9100,udp:2112,tcp:9100]
Owner:""",
        "timestamp": "2025-04-11T19:33:00Z"
    },
    {
        "text": """AWS-Moody APP 10:34 PM
A command was executed inside a pod in the kube-system namespace on EKS Cluster hs-eks-video-prod-api-aps1. If this behavior is not expected, it may indicate that your credentials are compromised.
Severity: 5 MFA-USED: None
Account Name: js_tilemedia(200304247802); Region: ap-south-1""",
        "timestamp": "2025-04-14T22:34:00Z"
    },
    {
        "text": """AWS-Moody APP 5:49 PM
An unprotected port on EC2 instance i-0d379a348bfef22d75 is being probed.
Severity: 2
Account Name: js_tilemedia(200304247802); Region: ap-south-1""",
        "timestamp": "2025-04-14T17:49:00Z"
    },
    {
        "text": """AWS-Moody APP 6:32 PM
Credentials for the EC2 instance role dp-dbr-ap-south-1-data-access were used from a remote AWS account 414351767826.
Severity: 8 MFA-USED: None
Account Name: js_tilemedia(200304247802); Region: ap-south-1""",
        "timestamp": "2025-04-14T18:32:00Z"
    },
    {
        "text": """AWS-Moody APP 9:49 PM
36.161.39.192.22 is performing SSH brute force attacks against i-0379a348bfef22d75.
Severity: 2
Account Name: js_tilemedia(200304247802); Region: ap-south-1""",
        "timestamp": "2025-04-14T21:49:00Z"
    }
]

# Sample alerts stored in the vector database
# Format: List of dictionaries with structured alert information
sample_alerts = [
    {
        "alert_type": "AWS-Moody",
        "title": "Unprotected Port Probed",
        "description": "An unprotected port on EC2 instance i-0d379a348bfef22d75 is being probed.",
        "account": "js_tilemedia(200304247802)",
        "region": "ap-south-1",
        "instance": "i-0d379a348bfef22d75",
        "source_ip": None,
        "severity": "2",
        "mfa_used": "None",
        "timestamp": "2025-04-10T12:00:00Z",
        "threat_details": "Known malicious host"
    },
    {
        "alert_type": "AWS-Moody",
        "title": "SSH Brute Force Attack",
        "description": "45.32.11.78 is performing SSH brute force attacks against i-0d427a6a3bd437862.",
        "account": "js_tilemedia(200304247802)",
        "region": "ap-south-1",
        "instance": "i-0d427a6a3bd437862",
        "source_ip": "45.32.11.78",
        "severity": "2",
        "mfa_used": "None",
        "timestamp": "2025-04-11T14:00:00Z",
        "threat_details": "Brute force attack"
    },
    {
        "alert_type": "JR-Praetorian",
        "title": "Port Scanning Detected",
        "description": "Instance exposed to potential port scanning.",
        "account": "js_tilemedia(200304247802)",
        "region": "ap-south-1",
        "instance": "tm-08b748f2-2732-415a-9100d-25e3b5bc5512-live-cpu-0",
        "source_ip": None,
        "severity": "3",
        "mfa_used": "None",
        "timestamp": "2025-04-12T16:00:00Z",
        "threat_details": "Port scanning"
    },
    {
        "alert_type": "AWS-Moody",
        "title": "Credential Misuse",
        "description": "Credentials for the EC2 instance role dp-dbr-ap-south-1-data-access were used from a remote AWS account 987654321.",
        "account": "js_tilemedia(200304247802)",
        "region": "ap-south-1",
        "instance": None,
        "source_ip": None,
        "severity": "8",
        "mfa_used": "None",
        "timestamp": "2025-04-13T18:00:00Z",
        "threat_details": "Unauthorized access"
    },
    {
        "alert_type": "AWS-Moody",
        "title": "Command Execution in Pod",
        "description": "A command was executed inside a pod in the kube-system namespace on EKS Cluster hs-eks-video-prod-api-aps1.",
        "account": "js_tilemedia(200304247802)",
        "region": "ap-south-1",
        "instance": None,
        "source_ip": None,
        "severity": "5",
        "mfa_used": "None",
        "timestamp": "2025-04-14T20:00:00Z",
        "threat_details": "Potential credential compromise"
    },
    {
        "alert_type": "AWS-Moody",
        "title": "Unprotected Port Probed",
        "description": "An unprotected port on EC2 instance i-0d427a6a3bd437862 is being probed.",
        "account": "js_tilemedia(200304247802)",
        "region": "ap-south-1",
        "instance": "i-0d427a6a3bd437862",
        "source_ip": None,
        "severity": "2",
        "mfa_used": "None",
        "timestamp": "2025-04-15T10:00:00Z",
        "threat_details": "Known malicious host"
    },
    {
        "alert_type": "AWS-Moody",
        "title": "SSH Brute Force Attack",
        "description": "78.45.23.12 is performing SSH brute force attacks against i-0d379a348bfef22d75.",
        "account": "js_tilemedia(200304247802)",
        "region": "ap-south-1",
        "instance": "i-0d379a348bfef22d75",
        "source_ip": "78.45.23.12",
        "severity": "2",
        "mfa_used": "None",
        "timestamp": "2025-04-16T12:00:00Z",
        "threat_details": "Brute force attack"
    },
    {
        "alert_type": "JR-Praetorian",
        "title": "Port Scanning Detected",
        "description": "Instance exposed to potential port scanning.",
        "account": "js_tilemedia(200304247802)",
        "region": "ap-south-1",
        "instance": "tm-08b748f2-2732-415a-9100d-25e3b5bc5512-live-cpu-1",
        "source_ip": None,
        "severity": "3",
        "mfa_used": "None",
        "timestamp": "2025-04-17T14:00:00Z",
        "threat_details": "Port scanning"
    },
    {
        "alert_type": "AWS-Moody",
        "title": "Credential Misuse",
        "description": "Credentials for the EC2 instance role dp-dbr-ap-south-1-data-access were used from a remote AWS account 123456789.",
        "account": "js_tilemedia(200304247802)",
        "region": "ap-south-1",
        "instance": None,
        "source_ip": None,
        "severity": "8",
        "mfa_used": "None",
        "timestamp": "2025-04-18T16:00:00Z",
        "threat_details": "Unauthorized access"
    },
    {
        "alert_type": "AWS-Moody",
        "title": "Command Execution in Pod",
        "description": "A command was executed inside a pod in the kube-system namespace on EKS Cluster hs-eks-video-prod-api-aps2.",
        "account": "js_tilemedia(200304247802)",
        "region": "ap-south-1",
        "instance": None,
        "source_ip": None,
        "severity": "5",
        "mfa_used": "None",
        "timestamp": "2025-04-19T18:00:00Z",
        "threat_details": "Potential credential compromise"
    }
] 