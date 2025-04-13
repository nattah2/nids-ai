#!/usr/bin/env python3

import pandas as pd
import argparse
import logging
import os
import sys
from feature_engineering import compute_requests_per_time, calculate_history_entropy

# Associated Headers
# ts,uid,id.orig_h,id.resp_h,proto,service,duration,orig_bytes,resp_bytes,conn_state,history,log_type,is_incomplete_conn,ts_dns,id.orig_h_dns,query,log_type_dns,ts_http,id.orig_h_http,id.resp_h_http,method,log_type_http,Malicious

# Argument parsing
parser = argparse.ArgumentParser(description="Extract data.")
parser.add_argument("--pcap", dest="pcap", action="store", default=None, help="optional pcap parameter")
parser.add_argument("--zeek_dir", dest="zeek_dir", default="./logs", action="store", help="Location of Zeek files to analyze")
parser.add_argument("--output", dest="output", action="store", default="output.csv", help="the CSV file to save traffic data")
args = parser.parse_args()

if not args.pcap and not args.zeek_dir:
    print("Error: At least one of --pcap or --zeek_dir must be provided.")
    parser.print_help()
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger(__name__)

def parse_zeek_log(file_path, separator='\t', chunksize=10000):
    """Parses a Zeek log file in chunks and returns a DataFrame."""
    try:
        with open(file_path, 'r') as file:
            for line in file:
                if line.startswith('#fields'):
                    fields = line.strip().split(separator)[1:]
                    break
            else:
                logger.error(f"No #fields header found in {file_path}")
                return None
    except Exception as e:
        logger.error(f"Failed to read {file_path}: {e}")
        return None

    try:
        chunks = pd.read_csv(
            file_path,
            sep=separator,
            comment='#',
            names=fields,
            chunksize=chunksize,
            low_memory=False
        )
        return chunks
    except Exception as e:
        logger.error(f"Failed to parse {file_path}: {e}")
        return None

def process_zeek_logs(log_directory, chunksize=10000):
    """Processes Zeek logs and merges them on 'uid'."""
    all_conn, all_dns, all_http = [], [], []
    logger.info(f"Processing logs in {log_directory}")

    for log_file in os.listdir(log_directory):
        file_path = os.path.join(log_directory, log_file)
        if not log_file.endswith('.log'):
            continue

        chunks = parse_zeek_log(file_path, chunksize=chunksize)
        if chunks is None:
            continue

        for chunk in chunks:
            if 'conn.log' in log_file:
                df_conn = extract_conn_features(chunk)
                if df_conn is not None:
                    all_conn.append(df_conn)
            elif 'dns.log' in log_file:
                df_dns = extract_dns_features(chunk)
                if df_dns is not None:
                    all_dns.append(df_dns)
            elif 'http.log' in log_file:
                df_http = extract_http_features(chunk)
                if df_http is not None:
                    all_http.append(df_http)

    # Concatenate and merge with duplicate checks
    df_combined = pd.concat(all_conn, ignore_index=True) if all_conn else pd.DataFrame()

    if all_dns:
        df_dns = pd.concat(all_dns, ignore_index=True)
        df_combined = df_combined.merge(
            df_dns,
            on='uid',
            how='left',
            suffixes=('', '_dns'),
            validate='one_to_one'  # Ensures no duplicate UIDs
        )

    if all_http:
        df_http = pd.concat(all_http, ignore_index=True)
        df_combined = df_combined.merge(
            df_http,
            on='uid',
            how='left',
            suffixes=('', '_http'),
            validate='one_to_one'
        )

    return df_combined

def make_zeek_log(pcap_path: str, zeek_dir: str = "./logs") -> None:
    """Generates Zeek logs from a PCAP file."""
    if not os.path.exists(pcap_path):
        logger.error(f"PCAP file not found: {pcap_path}")
        return

    is_attack = 'attack' in pcap_path.lower()
    traffic_type = 'Attack' if is_attack else 'Normal'
    pcap_name = os.path.splitext(os.path.basename(pcap_path))[0]
    output_dir = os.path.join(zeek_dir, traffic_type, pcap_name)

    if os.path.exists(output_dir):
        logger.info(f"Zeek logs already exist at {output_dir}")
        return

    os.makedirs(output_dir, exist_ok=True)
    zeek_cmd = f'zeek -r "{pcap_path}" Log::default_logdir="{output_dir}"'
    logger.info(f"Running: {zeek_cmd}")

    if os.system(zeek_cmd) != 0:
        logger.error("Zeek command failed!")
        return

    logger.info(f"Zeek logs created at {output_dir}")

def extract_conn_features(df):
    """Extracts connection features with validation."""
    required_cols = ['ts', 'uid', 'id.orig_h', 'id.resp_h', 'proto', 'service',
                    'duration', 'orig_bytes', 'resp_bytes', 'conn_state', 'history']
    missing_cols = [col for col in required_cols if col not in df.columns]
    if missing_cols:
        logger.warning(f"Missing columns in conn.log: {missing_cols}")
        return None

    df = df[required_cols].copy()
    for col in ['duration', 'orig_bytes', 'resp_bytes']:
        df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

    df['is_incomplete_conn'] = df['conn_state'].isna().astype(int)
    df['log_type'] = 'conn'
    return df

def extract_dns_features(df):
    """Extracts DNS features with basic query analysis."""
    required_cols = ['ts', 'uid', 'id.orig_h', 'query']
    missing_cols = [col for col in required_cols if col not in df.columns]
    if missing_cols:
        logger.warning(f"Missing columns in dns.log: {missing_cols}")
        return None

    df = df[required_cols].copy()
    df['query_length'] = df['query'].str.len()  # New derived feature
    df['log_type'] = 'dns'
    return df

def extract_http_features(df):
    """Extracts HTTP features with method checks."""
    required_cols = ['ts', 'uid', 'id.orig_h', 'id.resp_h', 'method']
    missing_cols = [col for col in required_cols if col not in df.columns]
    if missing_cols:
        logger.warning(f"Missing columns in http.log: {missing_cols}")
        return None

    df = df[required_cols].copy()
    df['is_http_post'] = (df['method'] == 'POST').astype(int)  # New derived feature
    df['log_type'] = 'http'
    return df

def extra_processing(df):
    """Applies final transformations with error handling."""
    if df.empty:
        return df

    # Timestamp handling (fallback to 0 if missing)
    ts_cols = ['ts', 'ts_conn', 'ts_http', 'ts_dns']
    ts_found = [col for col in ts_cols if col in df.columns]
    if ts_found:
        df['hour'] = pd.to_datetime(df[ts_found[0]], unit='s').dt.hour.fillna(0)
        df['day_of_week'] = pd.to_datetime(df[ts_found[0]], unit='s').dt.dayofweek.fillna(0)
    else:
        logger.warning("No timestamp column found; skipping time features.")
        df['hour'] = 0
        df['day_of_week'] = 0

    # One-hot encoding (skip if columns missing)
    for col in ['proto', 'service', 'conn_state']:
        if col in df.columns:
            df = pd.get_dummies(df, columns=[col], drop_first=True)
        else:
            logger.warning(f"Column {col} not found; skipping one-hot encoding.")

    # Feature engineering (defined in feature_engineering.py)
    df = compute_requests_per_time(df)
    df = calculate_history_entropy(df)
    return df

# Main execution
if args.pcap:
    make_zeek_log(args.pcap, args.zeek_dir)  # Don't pass pre-constructed path
    folder = 'Attack' if 'attack' in args.pcap.lower() else 'Normal'
    pcap_name = os.path.splitext(os.path.basename(args.pcap))[0]
    zeek_subdir = os.path.join(args.zeek_dir, folder, pcap_name)
    combined_features = process_zeek_logs(zeek_subdir)
else:
    combined_features = process_zeek_logs(args.zeek_dir)

print("WE SHOULD HAVE SOMETHING!")

combined_features = extra_processing(combined_features)

print("OUTPUTTING!")
output_dir = os.path.dirname(args.output)
if output_dir:
    os.makedirs(output_dir, exist_ok=True)

if not combined_features.empty:
    base_output = args.output
    name, ext = os.path.splitext(base_output)
    ext = ext or ".csv"
    output_path = base_output
    counter = 1

    # If file exists, keep incrementing until a new name is found
    while os.path.exists(output_path):
        output_path = f"{name}_{counter}{ext}"
        counter += 1

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    combined_features.to_csv(output_path, index=False)
    logger.info(f"Saved processed data to {output_path}")
else:
    logger.error("No data processed; output CSV is empty.")
