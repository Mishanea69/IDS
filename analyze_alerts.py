#!/usr/bin/env python3
"""
Alert Analysis Tool for Hybrid IDS
Provides comprehensive analysis of generated alerts from pcap files
"""

import os
import csv
import glob
from collections import defaultdict, Counter
from datetime import datetime

ALERT_DIR = "alerts"

# Rule severity classification
SEVERITY = {
    # Brute force & scanning
    range(9001, 9015): "HIGH",
    # Malware & C&C
    range(4001, 4009): "CRITICAL",
    # Backdoors & RCE
    range(3001, 3010): "CRITICAL",
    range(3100, 3103): "HIGH",
    range(3200, 3204): "HIGH",
    range(3300, 3302): "CRITICAL",
    range(3400, 3403): "HIGH",
    range(3500, 3501): "CRITICAL",
    # Exploit signatures
    range(2001, 2011): "HIGH",
    # Auth attacks
    range(5001, 5012): "MEDIUM",
    # Reconnaissance
    range(6001, 6006): "MEDIUM",
    # Data exfiltration
    range(7002, 7004): "HIGH",
}

def get_severity(sid):
    """Determine severity level for a rule SID"""
    for sid_range, level in SEVERITY.items():
        if sid in sid_range:
            return level
    return "LOW"

def categorize_pcap(filename):
    """Categorize pcap file as attack or normal"""
    normal_patterns = ["normal", "Normal"]
    for pattern in normal_patterns:
        if pattern in filename:
            return "NORMAL"
    return "ATTACK"

def analyze_alerts():
    """Main analysis function"""
    
    if not os.path.exists(ALERT_DIR):
        print(f"Error: {ALERT_DIR} directory not found!")
        return
    
    # Data structures
    pcap_stats = {}
    rule_counts = Counter()
    severity_counts = Counter()
    attack_summary = defaultdict(lambda: {"total": 0, "unique_rules": set()})
    
    # Process all alert CSVs
    csv_files = sorted(glob.glob(f"{ALERT_DIR}/*.csv"))
    
    if not csv_files:
        print(f"No CSV files found in {ALERT_DIR}/")
        return
    
    for csv_path in csv_files:
        filename = os.path.basename(csv_path)
        pcap_name = filename.replace(".csv", "")
        category = categorize_pcap(pcap_name)
        
        alerts = []
        try:
            with open(csv_path, 'r') as f:
                reader = csv.DictReader(f)
                alerts = list(reader)
        except Exception as e:
            print(f"Warning: Could not read {filename}: {e}")
            continue
        
        alert_count = len(alerts)
        pcap_stats[pcap_name] = {
            "count": alert_count,
            "category": category,
            "rules": Counter(),
            "severity": Counter()
        }
        
        # Analyze each alert
        for alert in alerts:
            try:
                sid = int(alert["rule_sid"])
                msg = alert["rule_msg"].strip('"')
                severity = get_severity(sid)
                
                pcap_stats[pcap_name]["rules"][f"{sid}: {msg}"] += 1
                pcap_stats[pcap_name]["severity"][severity] += 1
                
                rule_counts[f"{sid}: {msg}"] += 1
                severity_counts[severity] += 1
                
                attack_summary[category]["total"] += 1
                attack_summary[category]["unique_rules"].add(sid)
            except (KeyError, ValueError) as e:
                continue
    
    # ============= DISPLAY RESULTS =============
    
    print("=" * 80)
    print(" " * 25 + "IDS ALERT ANALYSIS REPORT")
    print("=" * 80)
    print()
    
    # Overall Summary
    total_alerts = sum(s["count"] for s in pcap_stats.values())
    total_pcaps = len(pcap_stats)
    attack_pcaps = sum(1 for s in pcap_stats.values() if s["category"] == "ATTACK")
    normal_pcaps = sum(1 for s in pcap_stats.values() if s["category"] == "NORMAL")
    
    print("📊 OVERALL SUMMARY")
    print("-" * 80)
    print(f"Total PCAPs analyzed:     {total_pcaps}")
    print(f"  - Attack captures:      {attack_pcaps}")
    print(f"  - Normal captures:      {normal_pcaps}")
    print(f"Total alerts generated:   {total_alerts}")
    print(f"Unique rules triggered:   {len(rule_counts)}")
    print()
    
    # Severity breakdown
    print("🚨 SEVERITY BREAKDOWN")
    print("-" * 80)
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = severity_counts.get(severity, 0)
        if count > 0:
            pct = (count / total_alerts * 100) if total_alerts > 0 else 0
            print(f"{severity:10s}: {count:6d} alerts ({pct:5.1f}%)")
    print()
    
    # Attack vs Normal
    print("⚔️  ATTACK vs NORMAL TRAFFIC")
    print("-" * 80)
    for category in ["ATTACK", "NORMAL"]:
        if category in attack_summary:
            count = attack_summary[category]["total"]
            unique = len(attack_summary[category]["unique_rules"])
            print(f"{category:8s}: {count:6d} alerts from {unique} unique rules")
    print()
    
    # Top alerting rules
    print("🔥 TOP 10 ALERTING RULES")
    print("-" * 80)
    for i, (rule, count) in enumerate(rule_counts.most_common(10), 1):
        print(f"{i:2d}. [{count:5d}x] {rule}")
    print()
    
    # Per-PCAP breakdown
    print("📁 PER-PCAP BREAKDOWN")
    print("-" * 80)
    
    # Sort by category then by alert count
    sorted_pcaps = sorted(
        pcap_stats.items(),
        key=lambda x: (x[1]["category"] == "NORMAL", -x[1]["count"])
    )
    
    for pcap_name, stats in sorted_pcaps:
        if stats["count"] == 0:
            status = "✅ CLEAN" if stats["category"] == "NORMAL" else "❌ MISSED"
        else:
            status = "⚠️  ALERTS" if stats["category"] == "NORMAL" else "🎯 DETECTED"
        
        print(f"\n{status} {pcap_name:25s} ({stats['count']:4d} alerts)")
        
        if stats["count"] > 0:
            # Show top 3 rules for this pcap
            top_rules = stats["rules"].most_common(3)
            for rule, count in top_rules:
                print(f"       └─ [{count:3d}x] {rule}")
    
    print()
    print("=" * 80)
    
    # Detection effectiveness
    attack_files = [p for p, s in pcap_stats.items() if s["category"] == "ATTACK"]
    detected_attacks = [p for p in attack_files if pcap_stats[p]["count"] > 0]
    missed_attacks = [p for p in attack_files if pcap_stats[p]["count"] == 0]
    
    if attack_files:
        detection_rate = len(detected_attacks) / len(attack_files) * 100
        print(f"Detection Rate: {len(detected_attacks)}/{len(attack_files)} attacks detected ({detection_rate:.1f}%)")
    
    if missed_attacks:
        print(f"\n⚠️  Missed attacks: {', '.join(missed_attacks)}")
    
    normal_with_fps = [p for p, s in pcap_stats.items() 
                       if s["category"] == "NORMAL" and s["count"] > 0]
    if normal_with_fps:
        total_fps = sum(pcap_stats[p]["count"] for p in normal_with_fps)
        print(f"\n⚠️  False Positives: {total_fps} alerts on normal traffic")
        for pcap in normal_with_fps:
            print(f"     - {pcap}: {pcap_stats[pcap]['count']} alerts")
    else:
        print("\n✅ Zero false positives on normal traffic!")
    
    print("=" * 80)

if __name__ == "__main__":
    analyze_alerts()
