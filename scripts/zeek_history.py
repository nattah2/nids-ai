#!/usr/bin/env python3

def categorize_zeek_history(history):
    if not isinstance(history, str) or not history:
        return "unknown"

    # Is it a potential scan?
    if history == "S":
        return "syn_scan"
    if history in ["SF", "SR"]:
        return "fin_scan"

    # Check handshake completion
    has_syn_orig = "S" in history
    has_syn_resp = "s" in history or "h" in history
    has_data_orig = "D" in history
    has_data_resp = "d" in history
    has_reset = "R" in history or "r" in history
    has_fin = "F" in history or "f" in history

    # Connection categorization
    if has_syn_orig and not has_syn_resp:
        return "unanswered_syn"
    elif has_syn_orig and has_syn_resp and not (has_data_orig or has_data_resp):
        return "handshake_only"
    elif has_syn_orig and has_syn_resp and (has_data_orig or has_data_resp):
        if has_reset:
            return "data_with_reset"
        elif has_fin:
            return "normal_with_data"
        else:
            return "data_without_close"
    elif has_reset:
        return "reset_connection"
    elif "I" in history or "i" in history:
        return "protocol_violation"
    else:
        return "other"
