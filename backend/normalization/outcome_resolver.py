from typing import Dict, Any, Optional, Tuple, List

class OutcomeResolver:
    """
    Universal semantic outcome and action resolver for ULPF.
    Normalizes heterogeneous source status/result/action/disposition fields
    into the canonical UES outcomes ('success', 'failure', 'unknown')
    with clear precedence and lossless preservation of original source values.
    """

    # Semantic outcome dictionary
    SUCCESS_VALUES = {
        'success', 'successful', 'succeeded', 'pass', 'passed', 'ok', 'true',
        'valid', 'clean', 'authorized', 'granted', 'allow', 'allowed', 'accept',
        'accepted', 'permit', 'permitted', 'approve', 'approved', 'built',
        'connected', 'open', 'opened', 'enable', 'enabled', 'established'
    }

    FAILURE_VALUES = {
        'failure', 'failed', 'fail', 'unsuccessful', 'error', 'err', 'fatal',
        'exception', 'false', 'invalid', 'abort', 'aborted', 'deny', 'denied',
        'block', 'blocked', 'reject', 'rejected', 'drop', 'dropped', 'discard',
        'discarded', 'prevent', 'prevented', 'quarantine', 'quarantined',
        'isolate', 'isolated', 'threat', 'malicious', 'violation', 'unauthorized',
        'forbidden', 'teardown', 'reset', 'rst', 'close', 'closed', 'timeout',
        'timed out', 'timed_out', 'refuse', 'refused', 'unreachable', 'down'
    }

    UNKNOWN_VALUES = {
        'unknown', 'ambiguous', 'info', 'informational', 'notice', 'routine',
        'na', 'n/a', 'none', 'null', 'undefined', ''
    }

    # Candidate field keys in order of precedence
    OUTCOME_CANDIDATE_KEYS = [
        'event.outcome', 'outcome', 'event_outcome',
        'event.result', 'result', 'event_result',
        'event.status', 'status', 'event_status', 'response_status',
        'disposition', 'decision'
    ]

    ACTION_CANDIDATE_KEYS = [
        'event.action', 'action', 'event_action',
        'act', 'decision', 'disposition',
        'reason', 'event.reason', 'command', 'operation'
    ]

    @classmethod
    def resolve(
        cls,
        mapped: Dict[str, Any],
        parsed: Dict[str, Any]
    ) -> Tuple[str, str, Optional[str], Optional[str]]:
        """
        Resolves universal semantic outcome and action.
        Returns:
            (outcome: str, action: str, raw_outcome_val: Optional[str], raw_action_val: Optional[str])
        """
        # 1. Search for raw candidate outcome value
        raw_outcome_val = cls._find_field_value(mapped, cls.OUTCOME_CANDIDATE_KEYS)
        if raw_outcome_val is None:
            raw_outcome_val = cls._find_field_value(parsed, cls.OUTCOME_CANDIDATE_KEYS)

        # 2. Search for raw candidate action value
        raw_action_val = cls._find_field_value(mapped, cls.ACTION_CANDIDATE_KEYS)
        if raw_action_val is None:
            raw_action_val = cls._find_field_value(parsed, cls.ACTION_CANDIDATE_KEYS)

        outcome = "unknown"

        # Precedence Rule 1: Explicit canonical outcome already provided
        if raw_outcome_val is not None:
            clean_out = str(raw_outcome_val).strip().lower()
            if clean_out in ('success', 'failure', 'unknown'):
                outcome = clean_out
            elif clean_out in cls.SUCCESS_VALUES:
                outcome = "success"
            elif clean_out in cls.FAILURE_VALUES:
                outcome = "failure"
            elif clean_out in cls.UNKNOWN_VALUES:
                outcome = "unknown"

        # Precedence Rule 2: Derive from action/disposition/decision if outcome is still unknown or not explicitly provided
        if outcome == "unknown" and raw_action_val is not None:
            clean_act = str(raw_action_val).strip().lower()
            if clean_act in cls.SUCCESS_VALUES:
                outcome = "success"
            elif clean_act in cls.FAILURE_VALUES:
                outcome = "failure"
            elif clean_act in cls.UNKNOWN_VALUES:
                outcome = "unknown"

        # Clean up action string for presentation
        if raw_action_val is not None:
            action_str = str(raw_action_val).strip()
        elif raw_outcome_val is not None:
            action_str = str(raw_outcome_val).strip()
        else:
            action_str = "traffic"

        return outcome, action_str, str(raw_outcome_val) if raw_outcome_val is not None else None, str(raw_action_val) if raw_action_val is not None else None

    @classmethod
    def _find_field_value(cls, data: Dict[str, Any], candidate_keys: List[str]) -> Optional[Any]:
        """
        Searches data for candidate keys, supporting both exact flat keys,
        flattened dot-notation keys (e.g. 'event.outcome'), and nested dict traversal.
        """
        if not data or not isinstance(data, dict):
            return None

        for key in candidate_keys:
            # 1. Exact match on literal key (handles flattened dicts like {'event.outcome': 'failure'})
            if key in data and data[key] is not None and str(data[key]).strip() != "":
                return data[key]

            # 2. Dot-notation traversal for nested dicts (handles {'event': {'outcome': 'failure'}})
            if '.' in key:
                parts = key.split('.')
                curr = data
                found = True
                for p in parts:
                    if isinstance(curr, dict) and p in curr:
                        curr = curr[p]
                    else:
                        found = False
                        break
                if found and curr is not None and str(curr).strip() != "":
                    return curr

        # 3. Case-insensitive top-level scan
        data_lower = {str(k).lower(): v for k, v in data.items()}
        for key in candidate_keys:
            key_lower = key.lower()
            if key_lower in data_lower and data_lower[key_lower] is not None and str(data_lower[key_lower]).strip() != "":
                val = data_lower[key_lower]
                if not isinstance(val, dict):
                    return val

        # 4. Recursive nested search for leaf keys (up to 3 levels)
        for key in candidate_keys:
            leaf = key.split('.')[-1].lower()
            val = cls._search_nested(data, leaf, depth=0)
            if val is not None and not isinstance(val, dict) and str(val).strip() != "":
                return val

        return None

    @classmethod
    def _search_nested(cls, d: Dict[str, Any], target_key: str, depth: int = 0) -> Optional[Any]:
        if depth > 3 or not isinstance(d, dict):
            return None
        for k, v in d.items():
            if str(k).lower() == target_key and v is not None and not isinstance(v, dict):
                return v
            if isinstance(v, dict):
                res = cls._search_nested(v, target_key, depth + 1)
                if res is not None:
                    return res
        return None
