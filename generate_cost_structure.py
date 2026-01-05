#!/usr/bin/env python3
"""
Generate cost directory structure with symlinks for easy navigation.

Fetches daily costs per resource and calculates rolling 30-day aggregates.

Structure:
  costs/
  ├── by-resource/
  │   └── {resource_name}/
  │       └── cost.json         # Rolling 30-day aggregate + daily breakdown
  ├── by-category/
  │   └── {category}/
  │       └── {resource_name} -> ../../by-resource/{resource_name}
  ├── by-resource-group/
  │   └── {resource_group}/
  │       └── {resource_name} -> ../../by-resource/{resource_name}
  └── summary.json              # Rolling 30-day totals
"""

import os
import sys
import json
import shutil
from datetime import datetime, timedelta
from pathlib import Path

# Add script directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))
from fetch_parallo_costs import (
    check_token_valid, POWERBI_ENDPOINT, TOKEN_FILE, DATASET_ID, REPORT_ID, MODEL_ID
)
import requests


COSTS_DIR = Path("costs")


def sanitize_name(name):
    """Sanitize resource name for filesystem."""
    if not name:
        return "_unknown_"
    # Replace problematic characters
    return name.replace("/", "_").replace("\\", "_").replace(":", "_").replace(" ", "_")


def fetch_daily_totals(token):
    """Fetch total daily costs (no grouping) to get accurate totals."""
    headers = {
        'Authorization': token,
        'Content-Type': 'application/json',
    }

    query = {
        "version": "1.0.0",
        "queries": [{
            "Query": {
                "Commands": [{
                    "SemanticQueryDataShapeCommand": {
                        "Query": {
                            "Version": 2,
                            "From": [
                                {"Name": "f1", "Entity": "FactUsageDetails", "Type": 0}
                            ],
                            "Select": [
                                {"Column": {"Expression": {"SourceRef": {"Source": "f1"}}, "Property": "Date"}, "Name": "Date"},
                                {"Aggregation": {"Expression": {"Column": {"Expression": {"SourceRef": {"Source": "f1"}}, "Property": "ChargedCost"}}, "Function": 0}, "Name": "Cost"}
                            ]
                        },
                        "Binding": {
                            "Primary": {"Groupings": [{"Projections": [0, 1]}]},
                            "DataReduction": {"DataVolume": 4, "Primary": {"Window": {"Count": 1000}}},
                            "Version": 1
                        }
                    }
                }]
            },
            "QueryId": "",
            "ApplicationContext": {"DatasetId": DATASET_ID, "Sources": [{"ReportId": REPORT_ID}]}
        }],
        "modelId": MODEL_ID
    }

    resp = requests.post(POWERBI_ENDPOINT, headers=headers, json=query, timeout=120)
    if resp.status_code != 200:
        return None
    return resp.json()


def parse_daily_totals(response_data):
    """Parse simple date/cost response into daily totals dict."""
    totals = {}
    try:
        result = response_data['results'][0]['result']['data']
        dsr = result['dsr']
        for ds in dsr.get('DS', []):
            for ph in ds.get('PH', []):
                for key, rows in ph.items():
                    if key.startswith('DM') and isinstance(rows, list):
                        for row in rows:
                            c = row.get('C', [])
                            if len(c) >= 2:
                                date_val = c[0]
                                cost = float(c[1]) if c[1] else 0
                                if isinstance(date_val, (int, float)):
                                    date_str = datetime.fromtimestamp(date_val/1000).strftime('%Y-%m-%d')
                                    totals[date_str] = cost
    except Exception as e:
        print(f"Error parsing totals: {e}")
    return totals


def fetch_daily_costs(token):
    """Fetch costs with date for daily breakdown per resource."""
    headers = {
        'Authorization': token,
        'Content-Type': 'application/json',
    }

    # Query with date from FactUsageDetails for daily costs per resource
    query = {
        "version": "1.0.0",
        "queries": [{
            "Query": {
                "Commands": [{
                    "SemanticQueryDataShapeCommand": {
                        "Query": {
                            "Version": 2,
                            "From": [
                                {"Name": "f1", "Entity": "FactUsageDetails", "Type": 0},
                                {"Name": "d", "Entity": "DimMeterCategories", "Type": 0},
                                {"Name": "d3", "Entity": "DimCloudLogicalContainers", "Type": 0},
                                {"Name": "d4", "Entity": "DimCloudResources", "Type": 0}
                            ],
                            "Select": [
                                {"Column": {"Expression": {"SourceRef": {"Source": "f1"}}, "Property": "Date"}, "Name": "Date"},
                                {"Column": {"Expression": {"SourceRef": {"Source": "d"}}, "Property": "Category"}, "Name": "Category"},
                                {"Column": {"Expression": {"SourceRef": {"Source": "d3"}}, "Property": "DisplayName"}, "Name": "ResourceGroup"},
                                {"Column": {"Expression": {"SourceRef": {"Source": "d4"}}, "Property": "Resource Name"}, "Name": "Resource"},
                                {"Aggregation": {"Expression": {"Column": {"Expression": {"SourceRef": {"Source": "f1"}}, "Property": "ChargedCost"}}, "Function": 0}, "Name": "Cost"}
                            ],
                            "OrderBy": [
                                {"Direction": 2, "Expression": {"Column": {"Expression": {"SourceRef": {"Source": "f1"}}, "Property": "Date"}}},
                                {"Direction": 2, "Expression": {"Aggregation": {"Expression": {"Column": {"Expression": {"SourceRef": {"Source": "f1"}}, "Property": "ChargedCost"}}, "Function": 0}}}
                            ]
                        },
                        "Binding": {
                            "Primary": {"Groupings": [{"Projections": [0, 1, 2, 3, 4], "Subtotal": 1}]},
                            "DataReduction": {"DataVolume": 4, "Primary": {"Window": {"Count": 30000}}},
                            "Version": 1
                        }
                    }
                }]
            },
            "QueryId": "",
            "ApplicationContext": {"DatasetId": DATASET_ID, "Sources": [{"ReportId": REPORT_ID}]}
        }],
        "modelId": MODEL_ID
    }

    resp = requests.post(POWERBI_ENDPOINT, headers=headers, json=query, timeout=120)
    if resp.status_code != 200:
        print(f"Error: {resp.status_code} - {resp.text[:500]}")
        return None
    return resp.json()


def parse_daily_response(response_data):
    """Parse the Power BI DSR format into rows with date info."""
    rows = []

    try:
        result = response_data['results'][0]['result']['data']
        dsr = result['dsr']

        for ds in dsr.get('DS', []):
            value_dicts = ds.get('ValueDicts', {})
            last_values = [None] * 5  # Date, Category, ResourceGroup, Resource, Cost

            for ph in ds.get('PH', []):
                for key, data_rows in ph.items():
                    if key.startswith('DM'):
                        for row in data_rows:
                            parsed_row = parse_daily_row(row, value_dicts, last_values)
                            if parsed_row and parsed_row.get('Cost'):
                                rows.append(parsed_row)
                                last_values = [
                                    parsed_row.get('Date'),
                                    parsed_row.get('Category'),
                                    parsed_row.get('Resource Group'),
                                    parsed_row.get('Resource Name'),
                                    parsed_row.get('Cost'),
                                ]
    except Exception as e:
        print(f"Error parsing response: {e}")
        import traceback
        traceback.print_exc()

    return rows


def parse_daily_row(row, value_dicts, last_values):
    """Parse a single row from the DSR format with date."""
    c_values = row.get('C', [])
    repeat_mask = row.get('R', 0)

    if not c_values and not repeat_mask:
        return None

    def get_value(idx, dict_name):
        if idx is None:
            return None
        if isinstance(idx, str):
            # Could be a date string or numeric string
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

        for i in range(5):  # Date, Category, ResourceGroup, Resource, Cost
            if repeat_mask & (1 << i):
                result_values.append(last_values[i] if last_values else None)
            else:
                if c_idx < len(c_values):
                    result_values.append(c_values[c_idx])
                    c_idx += 1
                else:
                    result_values.append(None)

        # Parse date - it comes as epoch milliseconds or date string
        date_val = result_values[0]
        if isinstance(date_val, (int, float)):
            # Epoch milliseconds
            date_str = datetime.fromtimestamp(date_val / 1000).strftime('%Y-%m-%d')
        elif isinstance(date_val, str):
            date_str = date_val
        else:
            date_str = None

        return {
            'Date': date_str,
            'Category': get_value(result_values[1], 'D0'),
            'Resource Group': get_value(result_values[2], 'D1'),
            'Resource Name': get_value(result_values[3], 'D2'),
            'Cost': float(result_values[4]) if result_values[4] is not None else 0,
        }
    except (ValueError, TypeError, IndexError) as e:
        return None


def generate_structure(rows, accurate_totals=None):
    """Generate the directory structure with daily costs and rolling 30-day aggregates."""
    today = datetime.now().strftime("%Y-%m-%d")

    # Clean and recreate structure
    if COSTS_DIR.exists():
        shutil.rmtree(COSTS_DIR)

    by_resource = COSTS_DIR / "by-resource"
    by_category = COSTS_DIR / "by-category"
    by_rg = COSTS_DIR / "by-resource-group"

    by_resource.mkdir(parents=True)
    by_category.mkdir(parents=True)
    by_rg.mkdir(parents=True)

    # Get all unique dates and determine date range
    all_dates = sorted(set(row.get('Date') for row in rows if row.get('Date')))
    if accurate_totals:
        all_dates = sorted(set(all_dates) | set(accurate_totals.keys()))
    if all_dates:
        data_start = all_dates[0]
        data_end = all_dates[-1]
    else:
        data_start = data_end = today

    # Calculate rolling 30-day cutoff from END of data, not today
    data_end_dt = datetime.strptime(data_end, "%Y-%m-%d")
    cutoff_date = (data_end_dt - timedelta(days=30)).strftime("%Y-%m-%d")

    # Aggregate costs by resource with daily breakdown
    resources = {}
    for row in rows:
        resource_name = row.get('Resource Name') or '_unknown_'
        safe_name = sanitize_name(resource_name)
        date = row.get('Date')
        cost = row.get('Cost', 0)

        if safe_name not in resources:
            resources[safe_name] = {
                'resource_name': resource_name,
                'resource_group': row.get('Resource Group'),
                'categories': set(),
                'daily_costs': {},  # date -> cost
                'total_cost': 0,
                'rolling_30d_cost': 0
            }

        # Add category
        if row.get('Category'):
            resources[safe_name]['categories'].add(row.get('Category'))

        # Add to daily costs
        if date:
            if date not in resources[safe_name]['daily_costs']:
                resources[safe_name]['daily_costs'][date] = 0
            resources[safe_name]['daily_costs'][date] += cost

        resources[safe_name]['total_cost'] += cost

        # Rolling 30-day: only count costs from last 30 days
        if date and date >= cutoff_date:
            resources[safe_name]['rolling_30d_cost'] += cost

    # Calculate unallocated costs (difference between accurate totals and detailed data)
    if accurate_totals:
        # Sum detailed costs per day
        detailed_by_day = {}
        for res_data in resources.values():
            for date, cost in res_data['daily_costs'].items():
                if date not in detailed_by_day:
                    detailed_by_day[date] = 0
                detailed_by_day[date] += cost

        # Calculate unallocated per day
        unallocated_daily = {}
        total_unallocated = 0
        rolling_unallocated = 0
        for date, accurate_cost in accurate_totals.items():
            detailed_cost = detailed_by_day.get(date, 0)
            diff = accurate_cost - detailed_cost
            if abs(diff) > 0.01:  # Only track if significant
                unallocated_daily[date] = round(diff, 2)
                total_unallocated += diff
                if date >= cutoff_date:
                    rolling_unallocated += diff

        # Add _unallocated_ as a resource if there are unallocated costs
        if unallocated_daily:
            resources['_unallocated_'] = {
                'resource_name': '_unallocated_',
                'resource_group': None,
                'categories': {'Unallocated'},
                'daily_costs': unallocated_daily,
                'total_cost': total_unallocated,
                'rolling_30d_cost': rolling_unallocated
            }

    # Create per-resource directories and JSON files
    categories_seen = set()
    rgs_seen = set()

    for safe_name, data in resources.items():
        # Create resource directory
        resource_dir = by_resource / safe_name
        resource_dir.mkdir(parents=True, exist_ok=True)

        # Sort daily costs by date (most recent first)
        daily_sorted = sorted(data['daily_costs'].items(), key=lambda x: x[0], reverse=True)

        # Write cost.json with daily breakdown
        cost_data = {
            'resource_name': data['resource_name'],
            'resource_group': data['resource_group'],
            'rolling_30d_cost': round(data['rolling_30d_cost'], 2),
            'total_cost': round(data['total_cost'], 2),
            'categories': sorted(data['categories']),
            'last_updated': today,
            'data_range': {'start': data_start, 'end': data_end},
            'daily_costs': {date: round(cost, 2) for date, cost in daily_sorted}
        }

        with open(resource_dir / "cost.json", 'w') as f:
            json.dump(cost_data, f, indent=2)

        # Create category symlinks
        for cat in data['categories']:
            safe_cat = sanitize_name(cat)
            if safe_cat:
                cat_dir = by_category / safe_cat
                cat_dir.mkdir(parents=True, exist_ok=True)
                link_path = cat_dir / safe_name
                if not link_path.exists():
                    target = Path("../../by-resource") / safe_name
                    link_path.symlink_to(target)
                categories_seen.add(cat)

        # Create resource group symlinks
        rg = sanitize_name(data['resource_group'])
        if rg:
            rg_dir = by_rg / rg
            rg_dir.mkdir(parents=True, exist_ok=True)
            link_path = rg_dir / safe_name
            if not link_path.exists():
                target = Path("../../by-resource") / safe_name
                link_path.symlink_to(target)
            rgs_seen.add(data['resource_group'])

    # Calculate rolling 30-day totals
    rolling_total = sum(r['rolling_30d_cost'] for r in resources.values())
    total_all_time = sum(r['total_cost'] for r in resources.values())

    # Top resources by rolling 30-day cost
    top_resources = sorted(resources.items(), key=lambda x: x[1]['rolling_30d_cost'], reverse=True)[:20]

    # Daily totals for the entire subscription
    daily_totals = {}
    for data in resources.values():
        for date, cost in data['daily_costs'].items():
            if date not in daily_totals:
                daily_totals[date] = 0
            daily_totals[date] += cost

    daily_totals_sorted = {k: round(v, 2) for k, v in sorted(daily_totals.items(), reverse=True)}

    # Aggregate by category (rolling 30-day)
    by_category_totals = {}
    for safe_name, data in resources.items():
        for cat in data['categories']:
            if cat not in by_category_totals:
                by_category_totals[cat] = 0
            # Approximate category share based on rolling cost
            by_category_totals[cat] += data['rolling_30d_cost'] / len(data['categories']) if data['categories'] else 0

    by_category_totals = {k: round(v, 2) for k, v in sorted(by_category_totals.items(), key=lambda x: x[1], reverse=True)}

    # Aggregate by resource group (rolling 30-day)
    by_rg_totals = {}
    for safe_name, data in resources.items():
        rg = data['resource_group'] or '_unknown_'
        if rg not in by_rg_totals:
            by_rg_totals[rg] = 0
        by_rg_totals[rg] += data['rolling_30d_cost']

    by_rg_totals = {k: round(v, 2) for k, v in sorted(by_rg_totals.items(), key=lambda x: x[1], reverse=True)}

    summary = {
        'date': today,
        'rolling_30d_cost': round(rolling_total, 2),
        'total_all_time_cost': round(total_all_time, 2),
        'data_range': {'start': data_start, 'end': data_end},
        'rolling_30d_cutoff': cutoff_date,
        'resource_count': len(resources),
        'category_count': len(categories_seen),
        'resource_group_count': len(rgs_seen),
        'top_20_resources': [
            {'name': name, 'rolling_30d_cost': round(data['rolling_30d_cost'], 2)}
            for name, data in top_resources
        ],
        'daily_totals': daily_totals_sorted,
        'by_category': by_category_totals,
        'by_resource_group': by_rg_totals
    }

    with open(COSTS_DIR / "summary.json", 'w') as f:
        json.dump(summary, f, indent=2)

    return summary


def main():
    print("=" * 60)
    print("Azure Cost Structure Generator")
    print("Daily costs + rolling 30-day aggregation")
    print("=" * 60)
    print()

    # Load token
    if not Path(TOKEN_FILE).exists():
        print(f"Error: {TOKEN_FILE} not found")
        return 1

    with open(TOKEN_FILE) as f:
        token = f.read().strip()

    if not check_token_valid(token):
        print("Token is invalid or expired")
        return 1

    print("[1] Fetching daily totals (accurate)...")
    totals_response = fetch_daily_totals(token)
    if not totals_response:
        print("Failed to fetch totals")
        return 1
    accurate_totals = parse_daily_totals(totals_response)
    print(f"    Got {len(accurate_totals)} days of totals")

    print("[2] Fetching daily cost data (detailed)...")
    response = fetch_daily_costs(token)
    if not response:
        print("Failed to fetch data")
        return 1

    print("[3] Parsing response...")
    rows = parse_daily_response(response)
    print(f"    Parsed {len(rows)} daily cost entries")

    if not rows:
        print("    No data parsed - check response format")
        return 1

    # Show date range
    dates = sorted(set(r.get('Date') for r in rows if r.get('Date')))
    if dates:
        print(f"    Date range: {dates[0]} to {dates[-1]} ({len(dates)} days)")

    print("[4] Generating directory structure...")
    summary = generate_structure(rows, accurate_totals)

    print()
    print("=" * 60)
    print(f"Generated structure in {COSTS_DIR}/")
    print(f"  Rolling 30-day cost: ${summary['rolling_30d_cost']:,.2f}")
    print(f"  Total all-time cost: ${summary['total_all_time_cost']:,.2f}")
    print(f"  Data range: {summary['data_range']['start']} to {summary['data_range']['end']}")
    print(f"  Resources: {summary['resource_count']}")
    print(f"  Categories: {summary['category_count']}")
    print(f"  Resource Groups: {summary['resource_group_count']}")
    print()
    print("Top 5 by rolling 30-day cost:")
    for r in summary['top_20_resources'][:5]:
        print(f"  {r['name']}: ${r['rolling_30d_cost']:,.2f}")
    print("=" * 60)

    return 0


if __name__ == '__main__':
    exit(main())
