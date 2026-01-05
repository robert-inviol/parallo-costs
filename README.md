# parallo-costs

Scripts for fetching Azure costs from the Parallo Power BI dashboard.

## Scripts

- **`refresh_token.py`** - Authenticates to Parallo via browser automation and captures the API token
- **`generate_cost_structure.py`** - Fetches cost data from Power BI API and generates structured JSON files
- **`parallo_auth.py`** - Authentication utilities for Parallo B2C login
- **`fetch_parallo_costs.py`** - Core API queries for fetching cost data

## Usage

These scripts are designed to be used as a submodule.

## Configuration

Create a `config.json` file (see `config.json.example`) or set environment variables:

### Power BI Configuration

- `PARALLO_POWERBI_ENDPOINT` - Power BI dedicated capacity query endpoint
- `PARALLO_DATASET_ID` - Power BI dataset ID
- `PARALLO_REPORT_ID` - Power BI report ID
- `PARALLO_MODEL_ID` - Power BI model ID
- `PARALLO_COMPANY_ID` - Parallo company ID

### Authentication

- `PARALLO_USERNAME` - Parallo service account email
- `PARALLO_PASSWORD` - Parallo account password
- `PARALLO_TOTP_SECRET` - TOTP secret for MFA
- `HEADLESS` - Set to 'true' for headless browser operation
