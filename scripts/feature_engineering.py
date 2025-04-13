#!/usr/bin/env python3
#
from collections import Counter
import numpy as np
import pandas as pd
import argparse
import logging
import os

def compute_requests_per_time(df, time_window=60):
    """
    Compute the number of requests per given time window (e.g., per 60 seconds).

    :param df: Pandas DataFrame with 'ts' (timestamp) and 'id.orig_h' (source IP).
    :param time_window: Time window in seconds (default is 60 seconds).
    :return: DataFrame with new 'requests_per_window' feature.
    """
    df = df.copy()

    # Handle missing timestamps/IPs (optional)
    # df = df.dropna(subset=['ts', 'id.orig_h'])

    # Convert timestamps to numeric and create time buckets
    df['time_bucket'] = (df['ts'].astype(float) // time_window) * time_window

    # Calculate requests per window using transform for efficiency
    df['requests_per_window'] = df.groupby(
        ['id.orig_h', 'time_bucket']
    )['id.orig_h'].transform('size')

    return df.drop(columns=['time_bucket'])

def calculate_history_entropy(df):
    """
    Calculates the Shannon entropy for the 'history' field in a DataFrame.
    Theoretically, this is good because something like a syn flood would have low entropy
    Adds a new column 'history_entropy' to store the results.
    """
    def entropy(history):
        if pd.isna(history) or len(history) == 0:
            return 0  # If history is missing or empty, return 0 entropy

        counts = Counter(history)  # Count occurrences of each character
        total = sum(counts.values())  # Total number of characters
        probs = np.array(list(counts.values())) / total  # Probabilities of each character

        return -np.sum(probs * np.log2(probs))  # Compute entropy

    df['history_entropy'] = df['history'].astype(str).map(entropy)
    return df  # Return the modified DataFrame
