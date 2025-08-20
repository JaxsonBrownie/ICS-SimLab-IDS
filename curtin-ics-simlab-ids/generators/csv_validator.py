#!/usr/bin/env python3

# FILE:     csv_validator.py
# PURPOSE:  A helper file that can validate CSV files.

import csv
import argparse

def check_csv_validity(file_path):
    with open(file_path, newline='', encoding='utf-8') as csvfile:
        reader = csv.reader(csvfile)
        expected_columns = None
        for i, row in enumerate(reader, start=1):
            if expected_columns is None:
                expected_columns = len(row)
            elif len(row) != expected_columns:
                print(f"Inconsistent row at line {i}: expected {expected_columns} columns, found {len(row)}")
                return False
        print(f"CSV is valid with {expected_columns} columns per row.")
        return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", required=True)

    args = parser.parse_args()
    csv_file = args.file
    check_csv_validity(csv_file)
