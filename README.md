# Azure Terminal Copilot with FedRAMP Compliance Checker

A Python-based tool that combines natural language Azure CLI capabilities with comprehensive FedRAMP compliance evaluation.

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Installation Steps](#installation-steps)
- [Troubleshooting](#troubleshooting)
- [FedRAMP Compliance Evaluation](#fedramp-compliance-evaluation)
  - [Interactive FedRAMP Questions](#interactive-fedramp-questions)
  - [Automated Compliance Checks](#automated-compliance-checks)
  - [Basic Usage](#basic-usage)
  - [Output Formats](#output-formats)
  - [Saving Results](#saving-results)
  - [Configuration Options](#configuration-options)
  - [Understanding the Results](#understanding-the-results)
- [Executive Summary Reports](#executive-summary-reports)
  - [Generating Executive Summaries](#generating-executive-summaries)
  - [LLM Integration](#llm-integration)
- [Attribution](#attribution)
- [License](#license)

## Overview

This tool offers three main features:

1. **Natural Language Azure CLI**: Ask questions in plain English and get Azure CLI commands executed
2. **FedRAMP Compliance Checker**: Evaluate your Azure environment against FedRAMP 20x Phase One Key Security Indicators
3. **Executive Summary Reports**: Generate leadership-friendly compliance posture summaries with insights and recommendations

## Prerequisites

- Python 3.11+ (as specified in pyproject.toml)
- [Azure CLI](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli) installed and authenticated
- [Ollama](https://ollama.com) with a model downloaded (for natural language processing)
- [uv](https://github.com/astral-sh/uv) for Python package management
- [Azure MCP server](https://github.com/Azure/azure-mcp) installed and running

## Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/azure-terminal-copilot.git
cd azure-terminal-copilot

# Set up Python environment
uv venv
uv pip install .

# Configure environment
cp .env-sample .env
# Edit .env with your Ollama and Azure MCP settings

# Launch interactive CLI
python main.py

# Run FedRAMP compliance check
python main.py --evaluate-fedramp --subscription <subscription-id>

# Generate executive summary report
python executive_summary.py --subscription <subscription-id>
```

## Installation Steps

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/azure-terminal-copilot.git
   cd azure-terminal-copilot
   ```

2. **Set up Python environment**
   ```bash
   uv venv
   uv pip install .
   ```

3. **Configure services**
   - Start Ollama and note its local address
   - Start Azure MCP server and note its local address
   - Copy `.env-sample` to `.env` and update with your configuration

4. **Configure environment variables**
   - Update the `.env` file with the values for your Ollama instance and Azure MCP server
   - Make sure your Azure CLI is logged in (run `az login` if needed)

5. **Run the application**
   ```bash
   python main.py
   ```

## Troubleshooting

- **Authentication**: Ensure Azure CLI is logged in with `az login`
- **Ollama**: Verify Ollama is running and the model is downloaded
- **MCP Server**: Check that Azure MCP server is running and accessible
- **Environment Variables**: Verify `.env` file contains correct URLs and API keys

## FedRAMP Compliance Evaluation

This tool provides comprehensive FedRAMP compliance checking capabilities for Azure environments through:

1. **Interactive Mode**: Ask natural language questions about FedRAMP requirements
2. **Evaluation Mode**: Run automated compliance checks against all KSI categories

### Interactive FedRAMP Questions

Get answers to specific FedRAMP compliance questions using natural language:

```bash
# Start the interactive CLI
python main.py
```

Example questions you can ask:
- "What resources meet FedRAMP KSI-CNA requirements for DoS protection?"
- "How do I check if my storage accounts comply with FedRAMP encryption requirements?"
- "List Azure resources required for FedRAMP MFA compliance"
- "Show me resources with diagnostic settings for FedRAMP monitoring"

### Automated Compliance Checks

The compliance checker evaluates your Azure subscription against the following FedRAMP 20x Key Security Indicators:

| Category | Description | Key Requirements |
|----------|-------------|------------------|
| **KSI-CNA** | Cloud Native Architecture | DoS protection, Network security, Containerization |
| **KSI-SC** | Service Configuration | Encryption, Key management, Secure protocols |
| **KSI-IAM** | Identity & Access Management | MFA, Strong passwords, Least-privilege access |
| **KSI-MLA** | Monitoring, Logging & Auditing | SIEM, Vulnerability scanning, Log review |
| **KSI-CM** | Change Management | Activity logs, Immutable deployments, Testing |
| **KSI-PI** | Policy & Inventory | Resource inventory, Security policies, Tagging |
| **KSI-3IR** | Third Party Information Resources | Supply chain risk, SBOM, Zero trust |
| **KSI-CE** | Cybersecurity Education | Security awareness, Role-specific training |
| **KSI-IR** | Incident Response | Backups, Disaster recovery, Incident reporting |

### Basic Usage

Run a complete compliance check with a single command:

```bash
python main.py --evaluate-fedramp --subscription <subscription-id>
```

Example:
```bash
python main.py --evaluate-fedramp --subscription 00000000-0000-0000-0000-000000000000
```

This connects to Azure and runs 50+ checks across all KSI categories, providing a detailed compliance report.

### Output Formats

Choose your preferred output format:

```bash
# Default table format (human-readable)
python main.py --evaluate-fedramp --subscription <id>

# JSON format (for programmatic use)
python main.py --evaluate-fedramp --subscription <id> --output-format json

# CSV format (for spreadsheet analysis)
python main.py --evaluate-fedramp --subscription <id> --output-format csv
```

### Saving Results

Save compliance results to a file for documentation or further analysis:

```bash
# Save JSON report
python main.py --evaluate-fedramp --subscription <id> --output-format json --output-file compliance-report.json

# Save CSV report
python main.py --evaluate-fedramp --subscription <id> --output-format csv --output-file compliance-report.csv
```

### Configuration Options

#### Focus on Specific Categories

Check only selected KSI categories:

```bash
python main.py --evaluate-fedramp --subscription <id> --categories "KSI-CNA,KSI-SC,KSI-IAM"
```

#### Optimize Performance

```bash
# Skip manual checks (faster execution)
python main.py --evaluate-fedramp --subscription <id> --skip-manual

# Run more checks in parallel
python main.py --evaluate-fedramp --subscription <id> --concurrent-checks 10

# View detailed progress
python main.py --evaluate-fedramp --subscription <id> --verbose
```

#### Advanced Example

Combine multiple options for a customized compliance check:

```bash
python main.py --evaluate-fedramp \
  --subscription <id> \
  --categories "KSI-CNA,KSI-SC" \
  --skip-manual \
  --output-format json \
  --output-file report.json \
  --concurrent-checks 8 \
  --verbose
```

### Understanding the Results

The compliance report includes detailed status for each check:

| Status | Meaning |
|--------|---------|
| **PASS** | Requirement successfully met |
| **FAIL** | Requirement not met - needs remediation |
| **MANUAL** | Requires human verification |
| **ERROR** | Check couldn't be performed |

A summary table shows compliance percentages by KSI category to help identify areas requiring attention.

For detailed remediation guidance, see the [Compliance Guide](./COMPLIANCE_GUIDE.md).

### Example Output

```
FedRAMP 20x KSI Compliance Results
┌─────────┬─────────────────────────────────┬──────────┬───────────────────────┐
│ KSI     │ Check                           │ Status   │ Details               │
├─────────┼─────────────────────────────────┼──────────┼───────────────────────┤
│ KSI-CNA │ DoS Protection Enabled          │ PASS     │ 1 DDoS protection pl… │
│ KSI-SC  │ Storage Accounts Encrypted      │ PASS     │ 3/3 storage accounts… │
│ KSI-IAM │ MFA Enforced                    │ FAIL     │ 0 MFA-enforcing poli… │
│ KSI-MLA │ SIEM Present                    │ PASS     │ 2 workspace(s) found  │
│ KSI-CM  │ Activity Logs Monitored         │ PASS     │ 150 activity log rec… │
└─────────┴─────────────────────────────────┴──────────┴───────────────────────┘

FedRAMP 20x KSI Compliance Summary
┌──────────────┬──────┬──────┬────────┬───────┬──────────────┐
│ KSI Category │ PASS │ FAIL │ MANUAL │ ERROR │ Compliance % │
├──────────────┼──────┼──────┼────────┼───────┼──────────────┤
│ KSI-CNA      │ 6    │ 1    │ 0      │ 0     │ 85.7%        │
│ KSI-SC       │ 4    │ 0    │ 1      │ 0     │ 100.0%       │
│ KSI-IAM      │ 1    │ 1    │ 2      │ 0     │ 50.0%        │
│ ...          │ ...  │ ...  │ ...    │ ...   │ ...          │
│ TOTAL        │ 28   │ 5    │ 12     │ 0     │ 84.8%        │
└──────────────┴──────┴──────┴────────┴───────┴──────────────┘
```

## Executive Summary Reports

The tool provides the ability to generate executive-level summaries of your FedRAMP compliance posture, perfect for leadership briefings and compliance reviews.

### Generating Executive Summaries

Generate a professional executive summary with key insights about your compliance posture:

```bash
python executive_summary.py --subscription <subscription-id>
```

This creates a comprehensive report that includes:

- Overall compliance status and score
- Environment context (subscription info, resource counts)
- Compliance breakdown by KSI category 
- Key strength areas where compliance is high
- Critical gap areas requiring attention
- Prioritized recommendations with business benefits

The summary is displayed in a visually appealing format and also saved as a JSON file for reference.

Example:

```
FEDRAMP COMPLIANCE EXECUTIVE SUMMARY
┌───────────────────────────────────────────────┐
│ Environment Information                        │
├───────────────────────────────────────────────┤
│ Subscription: Production Environment           │
│ ID: 00000000-0000-0000-0000-000000000000      │
│ Resources: 156                                 │
│ Assessment Date: 2025-04-30 15:30:42           │
└───────────────────────────────────────────────┘

┌───────────────────────────────────────────────┐
│ Compliance Posture                             │
├───────────────────────────────────────────────┤
│ Overall Status: MOSTLY COMPLIANT               │
│ Compliance Score: 84.8%                        │
│ Automated Checks: 28 passed, 5 failed          │
│ Manual Verification Required: 12 checks        │
└───────────────────────────────────────────────┘
```

### LLM Integration

You can enhance the executive summary with natural language insights by connecting it to an LLM:

#### Remote LLM API

Connect to a remote LLM API service:

```bash
python executive_summary.py --subscription <subscription-id> --llm-api-url <api-url> --llm-api-key <api-key>
```

#### Local Ollama Models

Use your existing local Ollama installation (the same one used for the CLI):

```bash
python executive_summary.py --subscription <subscription-id> --use-ollama --ollama-model llama2
```

The `--use-ollama` flag automatically uses the Ollama host from your `.env` file, or you can specify a different host:

```bash
python executive_summary.py --subscription <subscription-id> --use-ollama --ollama-model llama2 --ollama-host http://localhost:11434
```

This integration allows the tool to generate concise, executive-friendly narrative summaries that contextualize the compliance findings in business-relevant terms, either using cloud-based APIs or running entirely on your local machine.

## Attribution

This project is a fork of [azure-terminal-copilot](https://github.com/madebygps/azure-terminal-copilot) by [madebygps](https://github.com/madebygps), which provided the foundation for the natural language Azure CLI interface. 

Our fork adds comprehensive FedRAMP 20x Phase One Key Security Indicators (KSIs) compliance checking capabilities, including:
- Automated compliance evaluation against all KSI categories
- Interactive FedRAMP compliance questions
- Multiple output formats for compliance reports
- Detailed compliance documentation and remediation guides

## License

This project is licensed under the MIT License - see the LICENSE file for details.
