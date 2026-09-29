import random
import time
from datetime import datetime, timezone
from typing import List, Dict, Any

class SyntheticLogGenerator:
    """
    Produces reproducible, multi-vendor enterprise perimeter logs
    spanning diverse actions: ALLOW, DENY, DROP, SCAN, MALWARE, LOGIN, DNS, VPN.
    """
    
    PUBLIC_IPS = [
        "203.0.113.5", "203.0.113.10", "203.0.113.50", "8.8.8.8", "8.8.4.4",
        "1.1.1.1", "198.51.100.22", "198.51.100.99", "185.220.101.5", "45.33.32.156"
    ]
    INTERNAL_IPS = [
        "10.0.0.10", "10.0.0.50", "10.0.0.100", "192.168.1.15", "192.168.1.20",
        "192.168.1.50", "172.16.0.5", "172.16.0.25", "10.10.1.5", "10.10.1.20"
    ]
    PORTS = [22, 53, 80, 443, 3389, 8080, 8443, 445, 12345, 54321]
    PROTOCOLS = ["tcp", "udp", "icmp"]
    ACTIONS = ["allow", "deny", "drop", "built", "teardown"]

    @classmethod
    def generate_cisco_asa(cls) -> str:
        action = random.choice(["Built", "Deny", "Teardown"])
        proto = random.choice(["TCP", "UDP"])
        src_ip = random.choice(cls.PUBLIC_IPS)
        dst_ip = random.choice(cls.INTERNAL_IPS)
        spt = random.choice(cls.PORTS)
        dpt = random.choice(cls.PORTS)
        conn_id = random.randint(10000, 99999)
        sev = random.choice([4, 6])
        code = random.choice(["302013", "106023", "302015"])

        if action == "Deny":
            return f"%ASA-4-106023: Deny {proto.lower()} src outside:{src_ip}/{spt} dst inside:{dst_ip}/{dpt} by access-group \"OUTSIDE_IN\" [0x0, 0x0]"
        else:
            return f"%ASA-6-{code}: {action} outbound {proto} connection {conn_id} for outside:{src_ip}/{spt} ({src_ip}/{spt}) to inside:{dst_ip}/{dpt} ({dst_ip}/{dpt})"

    @classmethod
    def generate_fortinet(cls) -> str:
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        time_str = datetime.now(timezone.utc).strftime("%H:%M:%S")
        action = random.choice(["accept", "deny", "drop"])
        proto_num = 6 if random.choice([True, False]) else 17
        src = random.choice(cls.INTERNAL_IPS)
        dst = random.choice(cls.PUBLIC_IPS)
        spt = random.choice(cls.PORTS)
        dpt = random.choice(cls.PORTS)
        logid = f"{random.randint(10, 99):010d}"
        sent = random.randint(100, 5000)
        rcvd = random.randint(100, 10000)
        return (f"date={date_str} time={time_str} devname=FGT-EDGE devid=FGT60E1234567890 logid={logid} "
                f"type=traffic subtype=forward level=notice vd=root srcip={src} srcport={spt} srcintf=port1 "
                f"dstip={dst} dstport={dpt} dstintf=wan1 proto={proto_num} action={action} policyid=1 "
                f"service=NET sentbyte={sent} rcvdbyte={rcvd}")

    @classmethod
    def generate_palo_alto(cls) -> str:
        ts = int(time.time())
        action = random.choice(["allow", "deny", "drop"])
        src = random.choice(cls.INTERNAL_IPS)
        dst = random.choice(cls.PUBLIC_IPS)
        spt = random.choice(cls.PORTS)
        dpt = random.choice(cls.PORTS)
        proto = "tcp"
        user = random.choice(["jdoe", "alice", "bob", "operator", "admin"])
        sess = random.randint(1000, 9999)
        bytes_sent = random.randint(500, 20000)
        bytes_rcvd = random.randint(500, 50000)
        return (f"{ts},002201234567,TRAFFIC,end,2049,2026/09/29 10:00:00,{src},{dst},0.0.0.0,0.0.0.0,"
                f"DefaultRule,{user},,,ssl,vsys1,trust,untrust,ae1.100,ae2,Panorama-log,2026/09/29 10:00:01,"
                f"{sess},1,{spt},{dpt},0,0,0x400000,{proto},{action},{bytes_sent+bytes_rcvd},{bytes_sent},"
                f"{bytes_rcvd},5,2026/09/29 10:00:00,60,any,0,1234567890,0x0,US,US,0,3,2,tcp-fin,CORP,{user},0,1,2,N/A,0,0,0,0,GlobalProtect")

    @classmethod
    def generate_cef(cls) -> str:
        src = random.choice(cls.PUBLIC_IPS)
        dst = random.choice(cls.INTERNAL_IPS)
        spt = random.choice(cls.PORTS)
        dpt = random.choice(cls.PORTS)
        action = random.choice(["Deny", "Permit", "Block"])
        sev = random.choice([2, 5, 8])
        name = random.choice(["Port Scan Detected", "Firewall Filter Drop", "Malicious Inbound Connection"])
        return f"CEF:0|PaloAlto|Firewall|10.1|SCAN-01|{name}|{sev}|src={src} spt={spt} dst={dst} dpt={dpt} proto=TCP act={action} msg=Perimeter Policy Violation"

    @classmethod
    def generate_json(cls) -> str:
        src = random.choice(cls.PUBLIC_IPS)
        dst = random.choice(cls.INTERNAL_IPS)
        spt = random.choice(cls.PORTS)
        dpt = random.choice(cls.PORTS)
        action = random.choice(["allow", "deny", "block", "alert"])
        user = random.choice(["unknown", "attacker", "employee", "service_account"])
        now_iso = datetime.now(timezone.utc).isoformat()
        import json
        return json.dumps({
            "timestamp": now_iso,
            "source_ip": src,
            "dest_ip": dst,
            "src_port": spt,
            "dst_port": dpt,
            "protocol": "tcp",
            "action": action,
            "user": user,
            "threat_category": "scanner" if action == "block" else "routine"
        })

    @classmethod
    def generate_batch(cls, count: int = 1000) -> List[Dict[str, str]]:
        generators = [
            (cls.generate_cisco_asa, "fw-perimeter-01"),
            (cls.generate_fortinet, "fgt-branch-01"),
            (cls.generate_palo_alto, "pa-dmz-01"),
            (cls.generate_cef, "siem-collector-01"),
            (cls.generate_json, "app-server-01")
        ]
        logs = []
        for _ in range(count):
            gen, source = random.choice(generators)
            logs.append({
                "raw_log": gen(),
                "source_id": source,
                "source_ip": "10.0.0.1"
            })
        return logs
