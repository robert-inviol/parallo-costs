#!/usr/bin/env python3
"""
Generate monthly summary from Parallo daily cost data.

Maps Parallo categories to standard Azure invoice categories for consistency.
"""

import os
import sys
import json
from datetime import datetime
from pathlib import Path

# Map Parallo categories to Azure invoice categories
CATEGORY_MAP = {
    # Storage
    "Storage": "Storage",

    # Networking
    "Bandwidth": "Networking",
    "Azure Front Door Service": "Networking",
    "Virtual Network": "Networking",
    "Azure DNS": "Networking",

    # Databases
    "SQL Database": "Databases",

    # Compute
    "Azure App Service": "Compute",
    "Functions": "Compute",

    # Containers
    "Container Registry": "Containers",

    # Analytics / Management
    "Log Analytics": "Analytics",
    "Azure Monitor": "Analytics",
    "Azure Data Factory v2": "Analytics",

    # Security
    "Microsoft Defender for Cloud": "Security",
    "Key Vault": "Security",

    # Integration
    "Logic Apps": "Integration",
    "Event Grid": "Integration",
    "Service Bus": "Integration",

    # Developer Tools
    "Developer Tools": "Developer Tools",

    # Catch-all
    "Unallocated": "Other",
}


def load_daily_costs(costs_dir):
    """Load daily costs from resource JSON files."""
    daily_costs = {}  # date -> category -> cost

    by_resource = costs_dir / "by-resource"
    if not by_resource.exists():
        return daily_costs

    for resource_dir in by_resource.iterdir():
        if not resource_dir.is_dir():
            continue

        cost_file = resource_dir / "cost.json"
        if not cost_file.exists():
            continue

        with open(cost_file) as f:
            data = json.load(f)

        categories = data.get("categories", [])
        daily = data.get("daily_costs", {})

        for date, cost in daily.items():
            if date not in daily_costs:
                daily_costs[date] = {}

            for cat in categories:
                mapped_cat = CATEGORY_MAP.get(cat, "Other")
                if mapped_cat not in daily_costs[date]:
                    daily_costs[date][mapped_cat] = 0
                daily_costs[date][mapped_cat] += cost / len(categories)  # Split evenly if multiple categories

    return daily_costs


def aggregate_by_month(daily_costs):
    """Aggregate daily costs into monthly totals."""
    monthly = {}  # month -> category -> cost

    for date_str, categories in daily_costs.items():
        try:
            dt = datetime.strptime(date_str, "%Y-%m-%d")
            month_key = dt.strftime("%Y-%m")
        except ValueError:
            continue

        if month_key not in monthly:
            monthly[month_key] = {}

        for cat, cost in categories.items():
            if cat not in monthly[month_key]:
                monthly[month_key][cat] = 0
            monthly[month_key][cat] += cost

    return monthly


def generate_summary(month, categories, output_dir):
    """Generate a monthly summary JSON file."""
    total = sum(categories.values())

    summary = {
        "month": month,
        "source": "parallo",
        "currency": "NZD",
        "total_pretax": round(total, 2),
        "by_category": {k: round(v, 2) for k, v in sorted(
            categories.items(),
            key=lambda x: -x[1]
        )}
    }

    output_file = output_dir / f"{month}.json"
    with open(output_file, 'w') as f:
        json.dump(summary, f, indent=2)

    return summary


def update_index(output_dir):
    """Update the index.json with all available months."""
    months = []
    total = 0

    for f in sorted(output_dir.glob("*.json")):
        if f.name == "index.json":
            continue
        months.append(f.stem)
        with open(f) as fp:
            data = json.load(fp)
            total += data.get("total_pretax", 0)

    # Determine source cutoff
    parallo_months = []
    invoice_months = []
    for m in months:
        month_file = output_dir / f"{m}.json"
        with open(month_file) as f:
            data = json.load(f)
            if data.get("source") == "parallo":
                parallo_months.append(m)
            else:
                invoice_months.append(m)

    index = {
        "months": months,
        "total_all_time": round(total, 2),
        "source_cutoff": {
            "azure-invoice": max(invoice_months) if invoice_months else None,
            "parallo": min(parallo_months) if parallo_months else None
        }
    }

    with open(output_dir / "index.json", 'w') as f:
        json.dump(index, f, indent=2)


def main():
    # Determine paths
    script_dir = Path(__file__).parent
    # When run from azurkosts, costs/ is in the repo root
    costs_dir = Path("costs")
    output_dir = Path("summary/monthly")

    if not costs_dir.exists():
        print(f"Costs directory not found: {costs_dir}")
        return 1

    output_dir.mkdir(parents=True, exist_ok=True)

    # Load and aggregate costs
    print("Loading daily costs...")
    daily_costs = load_daily_costs(costs_dir)
    print(f"  Found {len(daily_costs)} days of data")

    print("Aggregating by month...")
    monthly = aggregate_by_month(daily_costs)

    # Generate summaries for each month
    for month in sorted(monthly.keys()):
        # Skip months that already have invoice data (up to 2025-10)
        existing = output_dir / f"{month}.json"
        if existing.exists():
            with open(existing) as f:
                data = json.load(f)
                source = data.get("source", "")
                if source != "parallo":
                    print(f"  {month}: Skipping (source: {source})")
                    continue

        summary = generate_summary(month, monthly[month], output_dir)
        print(f"  {month}: ${summary['total_pretax']:,.2f} NZD")

    # Update index
    update_index(output_dir)
    print("\nUpdated index.json")

    return 0


if __name__ == '__main__':
    sys.exit(main())
