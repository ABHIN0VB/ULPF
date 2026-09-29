import os
import sys
import json
import hashlib
from typing import Dict, Any, List

# Ensure backend modules are on path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend')))

from parser_engine.plugin_registry import PluginRegistry
from normalization.normalizer import normalize

def run_evaluation() -> Dict[str, Any]:
    gt_file = os.path.join(os.path.dirname(__file__), 'ground_truth.json')
    with open(gt_file, 'r') as f:
        ground_truth: List[Dict] = json.load(f)

    registry = PluginRegistry()

    total_samples = len(ground_truth)
    parser_matches = 0
    total_fields = 0
    matched_fields = 0
    lossless_hashes_ok = 0
    results = []

    for item in ground_truth:
        raw = item["raw"]
        expected_parser = item["expected_parser"]
        expected = item["expected"]

        # Step 1: Detect and Parse
        parser, conf = registry.detect_parser(raw, {})
        detected_name = parser.__class__.__name__ if parser else "None"
        parser_match = (detected_name == expected_parser)
        if parser_match:
            parser_matches += 1

        parsed_fields = parser.parse(raw, {}) if parser else {}

        # Step 2: Normalize
        ues = normalize(
            parsed_fields=parsed_fields,
            source_id=item["source_id"],
            raw=raw,
            parser_plugin=detected_name,
            confidence=conf
        )

        # Step 3: Verify Lossless Hash
        computed_hash = hashlib.sha256(raw.encode('utf-8')).hexdigest()
        if ues['ulpf']['raw_hash'] == computed_hash and ues['ulpf']['raw'] == raw:
            lossless_hashes_ok += 1

        # Step 4: Compare extracted fields
        sample_field_errors = []
        for field, exp_val in expected.items():
            total_fields += 1
            act_val = None
            if field == "source_ip":
                act_val = ues.get("source", {}).get("ip")
            elif field == "source_port":
                act_val = ues.get("source", {}).get("port")
            elif field == "destination_ip":
                act_val = ues.get("destination", {}).get("ip")
            elif field == "destination_port":
                act_val = ues.get("destination", {}).get("port")
            elif field == "protocol":
                act_val = ues.get("network", {}).get("protocol")
            elif field == "outcome":
                act_val = ues.get("event", {}).get("outcome")

            if str(act_val).lower() == str(exp_val).lower():
                matched_fields += 1
            else:
                sample_field_errors.append(f"{field}: expected '{exp_val}', got '{act_val}'")

        results.append({
            "id": item["id"],
            "parser_detected": detected_name,
            "parser_expected": expected_parser,
            "parser_matched": parser_match,
            "errors": sample_field_errors
        })

    field_accuracy = round((matched_fields / max(total_fields, 1)) * 100.0, 2)
    parser_accuracy = round((parser_matches / max(total_samples, 1)) * 100.0, 2)
    lossless_accuracy = round((lossless_hashes_ok / max(total_samples, 1)) * 100.0, 2)

    summary = {
        "total_test_samples": total_samples,
        "parser_detection_accuracy": f"{parser_accuracy}%",
        "field_extraction_accuracy": f"{field_accuracy}%",
        "lossless_integrity_guarantee": f"{lossless_accuracy}%",
        "sample_results": results
    }

    print("\n==================================================")
    print("  ULPF PARSER ACCURACY & GROUND TRUTH EVALUATION")
    print("==================================================")
    print(f"  Total Test Samples          : {total_samples}")
    print(f"  Parser Identification Rate  : {parser_accuracy}%")
    print(f"  Field Extraction Accuracy   : {field_accuracy}%")
    print(f"  Lossless Hash Integrity     : {lossless_accuracy}%")
    print("==================================================\n")

    return summary

if __name__ == '__main__':
    run_evaluation()
