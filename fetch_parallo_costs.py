#!/usr/bin/env python3
"""
Unified script to fetch Azure cost data from Parallo Power BI.

This script:
1. Checks if we have a valid token
2. If not, authenticates and captures a new token
3. Fetches cost data and exports to CSV

For GitHub Actions:
- Set PARALLO_USERNAME and PARALLO_PASSWORD as secrets
- Run on a schedule (e.g., daily)
"""

import os
import sys
import json
import csv
import requests
import asyncio
from datetime import datetime
from pathlib import Path


# Configuration - load from environment or config file
def load_config():
    """Load configuration from config.json or environment variables."""
    config_file = Path(__file__).parent / "config.json"
    config = {}
    if config_file.exists():
        with open(config_file) as f:
            config = json.load(f)

    return {
        'powerbi_endpoint': os.environ.get('PARALLO_POWERBI_ENDPOINT', config.get('powerbi_endpoint', '')),
        'dataset_id': os.environ.get('PARALLO_DATASET_ID', config.get('dataset_id', '')),
        'report_id': os.environ.get('PARALLO_REPORT_ID', config.get('report_id', '')),
        'model_id': int(os.environ.get('PARALLO_MODEL_ID', config.get('model_id', 0))),
        'company_id': os.environ.get('PARALLO_COMPANY_ID', config.get('company_id', '')),
    }

_config = load_config()
POWERBI_ENDPOINT = _config['powerbi_endpoint']
DATASET_ID = _config['dataset_id']
REPORT_ID = _config['report_id']
MODEL_ID = _config['model_id']
COMPANY_ID = _config['company_id']

TOKEN_FILE = "captured_token.txt"
OUTPUT_FILE = "azure_costs.csv"


def check_token_valid(token):
    """Check if the token is still valid by making a simple query."""
    query = {
        "version": "1.0.0",
        "queries": [{
            "Query": {
                "Commands": [{
                    "SemanticQueryDataShapeCommand": {
                        "Query": {
                            "Version": 2,
                            "From": [{"Name": "r", "Entity": "ReportVersion", "Type": 0}],
                            "Select": [{
                                "Column": {"Expression": {"SourceRef": {"Source": "r"}}, "Property": "ReportVersion"},
                                "Name": "Version"
                            }]
                        },
                        "Binding": {
                            "Primary": {"Groupings": [{"Projections": [0]}]},
                            "DataReduction": {"DataVolume": 3, "Primary": {"Window": {"Count": 1}}},
                            "Version": 1
                        }
                    }
                }]
            },
            "QueryId": "test",
            "ApplicationContext": {"DatasetId": DATASET_ID, "Sources": [{"ReportId": REPORT_ID}]}
        }],
        "modelId": MODEL_ID
    }

    headers = {
        'Authorization': token,
        'Content-Type': 'application/json',
    }

    try:
        resp = requests.post(POWERBI_ENDPOINT, json=query, headers=headers, timeout=30)
        return resp.status_code == 200
    except Exception:
        return False


def build_cost_query():
    """Build the Power BI semantic query for detailed cost data."""
    return {
        "version": "1.0.0",
        "queries": [{
            "Query": {
                "Commands": [{
                    "SemanticQueryDataShapeCommand": {
                        "Query": {
                            "Version": 2,
                            "From": [
                                {"Name": "d", "Entity": "DimMeterCategories", "Type": 0},
                                {"Name": "d1", "Entity": "DimMeterSubcategories", "Type": 0},
                                {"Name": "d2", "Entity": "DimMeterNames", "Type": 0},
                                {"Name": "d3", "Entity": "DimCloudLogicalContainers", "Type": 0},
                                {"Name": "d4", "Entity": "DimCloudResources", "Type": 0},
                                {"Name": "f1", "Entity": "FactUsageDetails", "Type": 0}
                            ],
                            "Select": [
                                {"Column": {"Expression": {"SourceRef": {"Source": "d"}}, "Property": "Category"}, "Name": "DimMeterCategories.Category", "NativeReferenceName": "Category"},
                                {"Column": {"Expression": {"SourceRef": {"Source": "d1"}}, "Property": "Subcategory"}, "Name": "DimMeterSubcategories.Subcategory", "NativeReferenceName": "Subcategory"},
                                {"Column": {"Expression": {"SourceRef": {"Source": "d2"}}, "Property": "Meter Name"}, "Name": "DimMeterNames.Meter Name", "NativeReferenceName": "Meter Name"},
                                {"Column": {"Expression": {"SourceRef": {"Source": "d3"}}, "Property": "DisplayName"}, "Name": "DimCloudLogicalContainers.DisplayName", "NativeReferenceName": "Resource Group"},
                                {"Column": {"Expression": {"SourceRef": {"Source": "d4"}}, "Property": "Resource Name"}, "Name": "DimResources.Resource Name", "NativeReferenceName": "Resource Name"},
                                {"Aggregation": {"Expression": {"Column": {"Expression": {"SourceRef": {"Source": "f1"}}, "Property": "Quantity"}}, "Function": 0}, "Name": "Sum(FactUsageDetails.Quantity)", "NativeReferenceName": "Quantity"},
                                {"Aggregation": {"Expression": {"Column": {"Expression": {"SourceRef": {"Source": "f1"}}, "Property": "ChargedCost"}}, "Function": 0}, "Name": "Sum(FactUsageDetails.ChargedCost)", "NativeReferenceName": "Cost"}
                            ],
                            "OrderBy": [{
                                "Direction": 2,
                                "Expression": {
                                    "Aggregation": {
                                        "Expression": {"Column": {"Expression": {"SourceRef": {"Source": "f1"}}, "Property": "ChargedCost"}},
                                        "Function": 0
                                    }
                                }
                            }]
                        },
                        "Binding": {
                            "Primary": {"Groupings": [{"Projections": [0, 1, 2, 3, 4, 5, 6], "Subtotal": 1}]},
                            "DataReduction": {"DataVolume": 3, "Primary": {"Window": {"Count": 1000}}},
                            "Version": 1
                        },
                        "ExecutionMetricsKind": 1
                    }
                }]
            },
            "QueryId": "",
            "ApplicationContext": {"DatasetId": DATASET_ID, "Sources": [{"ReportId": REPORT_ID, "VisualId": "cost-query"}]}
        }],
        "cancelQueries": [],
        "modelId": MODEL_ID,
        "userPreferredLocale": "en-US",
        "allowLongRunningQueries": True
    }


def parse_powerbi_response(response_data):
    """Parse the Power BI DSR format into rows."""
    rows = []

    try:
        result = response_data['results'][0]['result']['data']
        dsr = result['dsr']

        for ds in dsr.get('DS', []):
            value_dicts = ds.get('ValueDicts', {})
            last_values = [None] * 7

            for ph in ds.get('PH', []):
                for key, data_rows in ph.items():
                    if key.startswith('DM1'):
                        for row in data_rows:
                            parsed_row = parse_row(row, value_dicts, last_values)
                            if parsed_row and parsed_row.get('Cost'):
                                rows.append(parsed_row)
                                last_values = [
                                    parsed_row.get('Category'),
                                    parsed_row.get('Subcategory'),
                                    parsed_row.get('Meter Name'),
                                    parsed_row.get('Resource Group'),
                                    parsed_row.get('Resource Name'),
                                    parsed_row.get('Quantity'),
                                    parsed_row.get('Cost'),
                                ]
    except Exception as e:
        print(f"Error parsing response: {e}")

    return rows


def parse_row(row, value_dicts, last_values):
    """Parse a single row from the DSR format."""
    c_values = row.get('C', [])
    repeat_mask = row.get('R', 0)

    if not c_values:
        return None

    def get_value(idx, dict_name):
        if idx is None:
            return None
        if isinstance(idx, str):
            try:
                return float(idx)
            except ValueError:
                return idx
        if isinstance(idx, (int, float)) and dict_name in value_dicts:
            idx = int(idx)
            if idx < len(value_dicts[dict_name]):
                return value_dicts[dict_name][idx]
        return idx

    try:
        result_values = []
        c_idx = 0

        for i in range(7):
            if repeat_mask & (1 << i):
                result_values.append(last_values[i] if last_values else None)
            else:
                if c_idx < len(c_values):
                    result_values.append(c_values[c_idx])
                    c_idx += 1
                else:
                    result_values.append(None)

        return {
            'Category': get_value(result_values[0], 'D0'),
            'Subcategory': get_value(result_values[1], 'D1'),
            'Meter Name': get_value(result_values[2], 'D2'),
            'Resource Group': get_value(result_values[3], 'D3'),
            'Resource Name': get_value(result_values[4], 'D4'),
            'Quantity': float(result_values[5]) if result_values[5] is not None else 0,
            'Cost': float(result_values[6]) if result_values[6] is not None else 0,
        }
    except (ValueError, TypeError, IndexError):
        return None


def fetch_costs(token):
    """Fetch cost data from Power BI."""
    headers = {
        'Authorization': token,
        'Content-Type': 'application/json',
        'ActivityId': f'fetch-costs-{datetime.now().strftime("%Y%m%d%H%M%S")}'
    }

    query = build_cost_query()
    response = requests.post(POWERBI_ENDPOINT, headers=headers, json=query, timeout=60)

    if response.status_code != 200:
        print(f"Error fetching costs: {response.status_code}")
        return None

    return response.json()


def save_to_csv(rows, filename):
    """Save cost data to CSV."""
    if not rows:
        print("No data to save")
        return

    fieldnames = ['Category', 'Subcategory', 'Meter Name', 'Resource Group', 'Resource Name', 'Quantity', 'Cost']

    with open(filename, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Saved {len(rows)} rows to {filename}")


async def refresh_token():
    """Refresh the token using Playwright automation."""
    try:
        from playwright.async_api import async_playwright
        from parallo_auth import ParalloAuth
    except ImportError as e:
        print(f"Missing dependencies for token refresh: {e}")
        return None

    username = os.environ.get('PARALLO_USERNAME')
    password = os.environ.get('PARALLO_PASSWORD')

    if not username or not password:
        print("Set PARALLO_USERNAME and PARALLO_PASSWORD to enable token refresh")
        return None

    # This is a placeholder for the full token refresh flow
    # The actual implementation would use Playwright to:
    # 1. Authenticate via parallo_auth.py
    # 2. Load the reports page
    # 3. Intercept the embed token
    # 4. Exchange for MWC token

    print("Token refresh not yet implemented for headless mode")
    print("Please run the authentication manually")
    return None


def main():
    print("=" * 60)
    print("Parallo Azure Cost Data Fetcher")
    print(f"Run time: {datetime.now().isoformat()}")
    print("=" * 60)
    print()

    # Check for existing token
    if Path(TOKEN_FILE).exists():
        with open(TOKEN_FILE) as f:
            token = f.read().strip()
        print(f"[1] Checking existing token...")
    else:
        print("[1] No token file found")
        token = None

    # Validate token
    if token and check_token_valid(token):
        print("    Token is valid!")
    else:
        print("    Token is invalid or expired")
        print()
        print("[2] Attempting to refresh token...")

        # Try to refresh
        token = asyncio.run(refresh_token())
        if not token:
            print("    Could not refresh token")
            print()
            print("To get a new token:")
            print("  1. Run: python parallo_auth.py")
            print("  2. Log in with your credentials")
            print("  3. Extract token from browser Network tab")
            print("  4. Save to captured_token.txt (including 'MWCToken ' prefix)")
            return 1

    # Fetch cost data
    print()
    print("[3] Fetching cost data from Power BI...")
    response = fetch_costs(token)

    if not response:
        print("    Failed to fetch data")
        return 1

    # Parse response
    print("[4] Parsing response...")
    rows = parse_powerbi_response(response)
    print(f"    Parsed {len(rows)} rows")

    if not rows:
        print("    No cost data found")
        return 1

    # Save to CSV
    print(f"[5] Saving to {OUTPUT_FILE}...")
    save_to_csv(rows, OUTPUT_FILE)

    # Print summary
    total_cost = sum(r.get('Cost', 0) for r in rows)
    print()
    print("=" * 60)
    print(f"Total Cost: ${total_cost:,.2f}")
    print()
    print("Top 10 by cost:")
    for i, row in enumerate(sorted(rows, key=lambda x: x.get('Cost', 0), reverse=True)[:10]):
        print(f"  {i+1}. {row['Resource Name']}: ${row['Cost']:.2f}")
    print("=" * 60)

    return 0


if __name__ == '__main__':
    sys.exit(main())
