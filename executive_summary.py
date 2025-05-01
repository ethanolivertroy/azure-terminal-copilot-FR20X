import asyncio
import json
import argparse
import os
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
import httpx
from dotenv import load_dotenv

from fedramp_compliance import KSICompliancer
from main import MCPClient

class ExecutiveSummaryGenerator:
    """Generate executive summary report for FedRAMP compliance based on KSI evaluation."""
    
    def __init__(self, client, subscription, llm_api_url=None, llm_api_key=None, 
                 use_ollama=False, ollama_model=None, ollama_host=None):
        self.client = client
        self.subscription = subscription
        self.llm_api_url = llm_api_url
        self.llm_api_key = llm_api_key
        self.use_ollama = use_ollama
        self.ollama_model = ollama_model
        self.ollama_host = ollama_host
        self.console = Console()
        self.summary_data = {}
        
    async def generate_summary(self):
        """Generate an executive summary of FedRAMP compliance."""
        # Run compliance check and gather data
        await self._collect_compliance_data()
        
        # Get basic subscription information
        sub_info = await self._get_subscription_info()
        
        # Generate summary report sections
        overview = await self._generate_overview()
        strength_areas = await self._identify_strengths()
        gap_areas = await self._identify_gaps()
        recommendations = await self._generate_recommendations()
        
        # Display the executive summary
        self._display_summary(sub_info, overview, strength_areas, gap_areas, recommendations)
        
    async def _collect_compliance_data(self):
        """Run compliance check and collect data for analysis."""
        self.console.print(Panel("Running FedRAMP KSI compliance assessment...", title="Step 1: Data Collection"))
        
        # Initialize compliance checker with JSON output format
        evaluator = KSICompliancer(self.client, self.subscription, "json")
        
        # Run evaluation
        await evaluator.evaluate()
        
        # Store results and summary for analysis
        self.summary_data = {
            "results": evaluator.results,
            "summary": evaluator.summary,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
    
    async def _get_subscription_info(self):
        """Get basic information about the subscription."""
        self.console.print(Panel("Retrieving subscription information...", title="Step 2: Environment Context"))
        
        cmd = f"account show --subscription {self.subscription} -o json"
        resp = await self.client.run_cli_command(cmd)
        
        # Get resource count
        res_cmd = f"resource list --subscription {self.subscription} --query 'length(@)' -o json"
        res_count = await self.client.run_cli_command(res_cmd)
        
        # Get subscription policies
        policy_cmd = f"policy assignment list --subscription {self.subscription} --query 'length(@)' -o json"
        policy_count = await self.client.run_cli_command(policy_cmd)
        
        return {
            "subscription_name": resp.get("name", "Unknown"),
            "subscription_id": resp.get("id", "Unknown"),
            "tenant_id": resp.get("tenantId", "Unknown"),
            "resource_count": res_count if isinstance(res_count, int) else 0,
            "policy_count": policy_count if isinstance(policy_count, int) else 0
        }
    
    async def _generate_overview(self):
        """Generate overall compliance summary."""
        self.console.print(Panel("Analyzing compliance posture...", title="Step 3: Compliance Analysis"))
        
        # Calculate overall compliance percentage
        total_counts = self.summary_data["summary"].get("TOTAL", {})
        automated_total = total_counts.get("PASS", 0) + total_counts.get("FAIL", 0)
        overall_percentage = (total_counts.get("PASS", 0) / automated_total * 100) if automated_total > 0 else 0
        
        # Count checks by status
        total_checks = sum(total_counts.values()) - total_counts.get("total", 0)
        manual_checks = total_counts.get("MANUAL", 0)
        automated_checks = automated_total
        passed_checks = total_counts.get("PASS", 0)
        failed_checks = total_counts.get("FAIL", 0)
        
        # Determine compliance status
        if overall_percentage >= 90:
            compliance_status = "HIGHLY COMPLIANT"
        elif overall_percentage >= 70:
            compliance_status = "MOSTLY COMPLIANT"
        elif overall_percentage >= 50:
            compliance_status = "PARTIALLY COMPLIANT"
        else:
            compliance_status = "MINIMALLY COMPLIANT"
            
        return {
            "status": compliance_status,
            "overall_percentage": overall_percentage,
            "total_checks": total_checks,
            "manual_checks": manual_checks,
            "automated_checks": automated_checks,
            "passed_checks": passed_checks,
            "failed_checks": failed_checks
        }
    
    async def _identify_strengths(self):
        """Identify compliance strength areas."""
        strengths = []
        
        # Look for categories with high compliance
        for category, counts in self.summary_data["summary"].items():
            if category == "TOTAL":
                continue
                
            automated_checks = counts.get("PASS", 0) + counts.get("FAIL", 0)
            if automated_checks > 0:
                pass_percentage = (counts.get("PASS", 0) / automated_checks * 100)
                
                if pass_percentage >= 80:
                    strengths.append({
                        "category": category,
                        "percentage": pass_percentage,
                        "passed": counts.get("PASS", 0),
                        "total_automated": automated_checks
                    })
        
        # Sort by percentage descending
        strengths.sort(key=lambda x: x["percentage"], reverse=True)
        return strengths[:3]  # Return top 3 strengths
    
    async def _identify_gaps(self):
        """Identify compliance gap areas."""
        gaps = []
        
        # Look for categories with low compliance
        for category, counts in self.summary_data["summary"].items():
            if category == "TOTAL":
                continue
                
            automated_checks = counts.get("PASS", 0) + counts.get("FAIL", 0)
            if automated_checks > 0:
                pass_percentage = (counts.get("PASS", 0) / automated_checks * 100)
                
                if pass_percentage < 70:
                    gaps.append({
                        "category": category,
                        "percentage": pass_percentage,
                        "failed": counts.get("FAIL", 0),
                        "total_automated": automated_checks,
                        "examples": []
                    })
        
        # Find specific examples of failures for each gap area
        for gap in gaps:
            for check in self.summary_data["results"]:
                if check["KSI"] == gap["category"] and check["Status"] == "FAIL":
                    gap["examples"].append({
                        "check": check["Check"],
                        "details": check["Details"]
                    })
                    if len(gap["examples"]) >= 3:
                        break
        
        # Sort by percentage ascending
        gaps.sort(key=lambda x: x["percentage"])
        return gaps[:3]  # Return top 3 gaps
    
    async def _generate_recommendations(self):
        """Generate prioritized recommendations based on compliance gaps."""
        self.console.print(Panel("Generating actionable recommendations...", title="Step 4: Recommendation Analysis"))
        
        recommendations = []
        
        # Analyze each failed check and generate a recommendation
        for check in self.summary_data["results"]:
            if check["Status"] == "FAIL":
                ksi = check["KSI"]
                check_name = check["Check"]
                
                # Generate recommendation based on the KSI and check
                if "DoS Protection" in check_name:
                    recommendations.append({
                        "priority": "HIGH",
                        "ksi": ksi,
                        "recommendation": "Deploy Azure DDoS Protection Standard for critical virtual networks",
                        "benefit": "Protects against volumetric and protocol attacks that could cause service outages"
                    })
                elif "MFA" in check_name:
                    recommendations.append({
                        "priority": "HIGH",
                        "ksi": ksi,
                        "recommendation": "Configure Conditional Access policies to enforce MFA for all users",
                        "benefit": "Prevents credential compromise and unauthorized access to sensitive data"
                    })
                elif "Encryption" in check_name:
                    recommendations.append({
                        "priority": "HIGH",
                        "ksi": ksi,
                        "recommendation": "Enable encryption at rest for all storage accounts",
                        "benefit": "Protects data confidentiality and meets FedRAMP data protection requirements"
                    })
                elif "Security Center" in check_name or "auto-provisioning" in check_name.lower():
                    recommendations.append({
                        "priority": "MEDIUM",
                        "ksi": ksi,
                        "recommendation": "Enable Microsoft Defender for Cloud with auto-provisioning",
                        "benefit": "Provides continuous security assessment and advanced threat protection"
                    })
                elif "Firewall" in check_name:
                    recommendations.append({
                        "priority": "MEDIUM",
                        "ksi": ksi, 
                        "recommendation": "Deploy Azure Firewall to control outbound and inbound traffic",
                        "benefit": "Enforces network security policies and prevents unauthorized communication"
                    })
                elif "SIEM" in check_name or "Log Analytics" in check_name:
                    recommendations.append({
                        "priority": "MEDIUM",
                        "ksi": ksi,
                        "recommendation": "Implement Log Analytics workspace for centralized logging",
                        "benefit": "Enables security monitoring, audit logging, and incident response capabilities"
                    })
                elif "Diagnostic" in check_name:
                    recommendations.append({
                        "priority": "MEDIUM",
                        "ksi": ksi,
                        "recommendation": "Configure diagnostic settings to capture all audit logs",
                        "benefit": "Ensures comprehensive audit trail for security and compliance investigations"
                    })
                else:
                    recommendations.append({
                        "priority": "LOW",
                        "ksi": ksi,
                        "recommendation": f"Address the failed check: {check_name}",
                        "benefit": "Improves overall FedRAMP compliance posture"
                    })
        
        # Deduplicate recommendations
        unique_recommendations = []
        seen = set()
        for recommendation in recommendations:
            rec_key = f"{recommendation['ksi']}-{recommendation['recommendation']}"
            if rec_key not in seen:
                seen.add(rec_key)
                unique_recommendations.append(recommendation)
        
        # Sort by priority (HIGH, MEDIUM, LOW)
        priority_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        unique_recommendations.sort(key=lambda x: priority_order[x["priority"]])
        
        return unique_recommendations[:5]  # Return top 5 recommendations
    
    async def _generate_ai_summary(self, data):
        """Use LLM to generate a natural language summary of compliance status."""
        # Check if we should use Ollama or remote API
        if not (self.llm_api_url or self.use_ollama):
            return None
            
        try:
            prompt = f"""
            You are a FedRAMP compliance expert. Based on the following compliance data from an Azure environment, 
            write a concise executive summary (3-4 paragraphs) assessing the overall security posture:
            
            Subscription: {data['subscription']['subscription_name']}
            Overall Compliance: {data['overview']['overall_percentage']:.1f}% ({data['overview']['status']})
            Passed Checks: {data['overview']['passed_checks']} out of {data['overview']['automated_checks']} automated checks
            
            Top Strengths:
            {json.dumps(data['strengths'], indent=2)}
            
            Top Gaps:
            {json.dumps(data['gaps'], indent=2)}
            
            Top Recommendations:
            {json.dumps(data['recommendations'], indent=2)}
            
            The executive summary should:
            1. Assess overall FedRAMP readiness
            2. Highlight key strengths and gaps
            3. Provide high-level recommendations 
            4. Use professional, concise language suitable for executives
            
            DO NOT include any lengthy explanations, technical details, or mention that this was generated by AI.
            """
            
            if self.use_ollama:
                # Get Ollama configuration
                ollama_host = self.ollama_host
                ollama_model = self.ollama_model
                
                if not ollama_host:
                    # Use from environment if not specified
                    ollama_host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
                
                if not ollama_model:
                    # Use from environment if not specified
                    ollama_model = os.getenv("OLLAMA_MODEL", "llama2")
                
                self.console.print(f"[dim]Using Ollama model: {ollama_model} at {ollama_host}[/dim]")
                
                async with httpx.AsyncClient(timeout=60.0) as client:
                    response = await client.post(
                        f"{ollama_host}/api/chat",
                        json={
                            "model": ollama_model,
                            "messages": [
                                {"role": "system", "content": "You are a FedRAMP compliance expert helping create executive summaries."},
                                {"role": "user", "content": prompt}
                            ],
                            "stream": False,
                            "temperature": 0.7
                        }
                    )
                    
                    if response.status_code == 200:
                        result = response.json()
                        return result.get("message", {}).get("content", "")
            else:
                # Use remote LLM API
                headers = {}
                if self.llm_api_key:
                    headers["Authorization"] = f"Bearer {self.llm_api_key}"
                    
                async with httpx.AsyncClient(timeout=30.0) as client:
                    response = await client.post(
                        self.llm_api_url,
                        json={
                            "prompt": prompt,
                            "max_tokens": 500,
                            "temperature": 0.7
                        },
                        headers=headers
                    )
                    
                    if response.status_code == 200:
                        result = response.json()
                        return result.get("text", "")
                    
            return None
        except Exception as e:
            self.console.print(f"[red]Error generating AI summary: {str(e)}[/red]")
            return None
    
    def _display_summary(self, subscription, overview, strengths, gaps, recommendations):
        """Display the executive summary report."""
        # Create summary data for AI processing
        summary_data = {
            "subscription": subscription,
            "overview": overview,
            "strengths": strengths,
            "gaps": gaps,
            "recommendations": recommendations
        }
        
        # Clear console and start report
        self.console.clear()
        self.console.print()
        
        # Header
        title = Text("FEDRAMP COMPLIANCE EXECUTIVE SUMMARY", style="bold white on blue")
        self.console.print(Panel(title, expand=False))
        self.console.print()
        
        # Subscription info
        sub_panel = Panel(
            f"[bold]Subscription:[/bold] {subscription['subscription_name']}\n"
            f"[bold]ID:[/bold] {subscription['subscription_id']}\n"
            f"[bold]Resources:[/bold] {subscription['resource_count']}\n"
            f"[bold]Assessment Date:[/bold] {self.summary_data['timestamp']}",
            title="Environment Information"
        )
        self.console.print(sub_panel)
        self.console.print()
        
        # Compliance overview
        status_color = {
            "HIGHLY COMPLIANT": "green",
            "MOSTLY COMPLIANT": "green",
            "PARTIALLY COMPLIANT": "yellow",
            "MINIMALLY COMPLIANT": "red"
        }.get(overview["status"], "yellow")
        
        overview_panel = Panel(
            f"[bold]Overall Status:[/bold] [bold {status_color}]{overview['status']}[/bold {status_color}]\n"
            f"[bold]Compliance Score:[/bold] [bold {status_color}]{overview['overall_percentage']:.1f}%[/bold {status_color}]\n"
            f"[bold]Automated Checks:[/bold] {overview['passed_checks']} passed, {overview['failed_checks']} failed\n"
            f"[bold]Manual Verification Required:[/bold] {overview['manual_checks']} checks",
            title="Compliance Posture"
        )
        self.console.print(overview_panel)
        self.console.print()
        
        # Compliance by category
        cat_table = Table(title="Compliance by KSI Category")
        cat_table.add_column("KSI Category", style="cyan")
        cat_table.add_column("Compliance %", style="green")
        cat_table.add_column("Status", style="white")
        
        for category, counts in self.summary_data["summary"].items():
            if category == "TOTAL":
                continue
                
            automated_checks = counts.get("PASS", 0) + counts.get("FAIL", 0)
            if automated_checks > 0:
                pass_percentage = (counts.get("PASS", 0) / automated_checks * 100)
                
                status = ""
                if pass_percentage >= 90:
                    status = "[green]COMPLIANT[/green]"
                elif pass_percentage >= 70:
                    status = "[yellow]PARTIAL[/yellow]"
                else:
                    status = "[red]GAP[/red]"
                    
                cat_table.add_row(
                    category,
                    f"{pass_percentage:.1f}%",
                    status
                )
        
        self.console.print(cat_table)
        self.console.print()
        
        # Key strength areas
        strength_panel = Panel.fit(
            "\n".join([
                f"[green]✓[/green] [bold]{s['category']}[/bold] - {s['percentage']:.1f}% compliant "
                f"({s['passed']} of {s['total_automated']} checks passed)"
                for s in strengths
            ]) or "[yellow]No significant strength areas identified[/yellow]",
            title="Key Strength Areas"
        )
        self.console.print(strength_panel)
        self.console.print()
        
        # Gap areas
        gaps_panel = Panel.fit(
            "\n".join([
                f"[red]⚠[/red] [bold]{g['category']}[/bold] - {g['percentage']:.1f}% compliant "
                f"({g['failed']} of {g['total_automated']} checks failed)\n"
                f"   [dim]Example: {g['examples'][0]['check'] if g['examples'] else 'N/A'}[/dim]"
                for g in gaps
            ]) or "[green]No significant gap areas identified[/green]",
            title="Critical Gap Areas"
        )
        self.console.print(gaps_panel)
        self.console.print()
        
        # Top recommendations
        rec_table = Table(title="Priority Recommendations")
        rec_table.add_column("Priority", style="bold")
        rec_table.add_column("KSI", style="cyan")
        rec_table.add_column("Recommendation", style="white")
        rec_table.add_column("Benefit", style="dim")
        
        for rec in recommendations:
            priority_style = {
                "HIGH": "red",
                "MEDIUM": "yellow",
                "LOW": "green"
            }.get(rec["priority"], "white")
            
            rec_table.add_row(
                f"[{priority_style}]{rec['priority']}[/{priority_style}]",
                rec["ksi"],
                rec["recommendation"],
                rec["benefit"]
            )
            
        self.console.print(rec_table)
        self.console.print()
        
        # Footer
        footer = Panel(
            "[dim]This report provides an automated analysis of FedRAMP compliance posture based on "
            "Azure resource configurations. For a complete assessment, refer to the detailed compliance "
            "report and consult with security professionals.[/dim]",
            title="Disclaimer"
        )
        self.console.print(footer)
        self.console.print()
        
        # Save report to file
        report_file = f"fedramp_executive_summary_{self.subscription}_{datetime.now().strftime('%Y%m%d')}.json"
        with open(report_file, "w") as f:
            json.dump(summary_data, f, indent=2)
            
        self.console.print(f"[green]✓[/green] Report saved to {report_file}")
        

async def main():
    load_dotenv()
    
    parser = argparse.ArgumentParser(
        description="Generate FedRAMP compliance executive summary"
    )
    parser.add_argument(
        "--subscription", type=str, required=True,
        help="Azure subscription ID to evaluate for compliance"
    )
    # Remote LLM API options
    parser.add_argument(
        "--llm-api-url", type=str,
        help="API URL for LLM to generate natural language summary (optional)"
    )
    parser.add_argument(
        "--llm-api-key", type=str,
        help="API key for LLM service (optional)"
    )
    # Ollama options
    parser.add_argument(
        "--use-ollama", action="store_true",
        help="Use local Ollama for generating natural language summary"
    )
    parser.add_argument(
        "--ollama-model", type=str,
        help="Ollama model to use (defaults to OLLAMA_MODEL from .env or 'llama2')"
    )
    parser.add_argument(
        "--ollama-host", type=str,
        help="Ollama host URL (defaults to OLLAMA_HOST from .env or 'http://localhost:11434')"
    )
    
    args = parser.parse_args()
    
    # Initialize MCPClient
    client = MCPClient()
    
    try:
        # Connect to MCP server
        server_url = os.getenv("SERVER_URL")
        
        if not server_url:
            print("ERROR: SERVER_URL environment variable not set")
            return
            
        await client.connect_to_server(server_url)
        
        # Generate executive summary
        summarizer = ExecutiveSummaryGenerator(
            client=client, 
            subscription=args.subscription,
            llm_api_url=args.llm_api_url,
            llm_api_key=args.llm_api_key,
            use_ollama=args.use_ollama,
            ollama_model=args.ollama_model,
            ollama_host=args.ollama_host
        )
        await summarizer.generate_summary()
        
    finally:
        await client.cleanup()

if __name__ == "__main__":
    asyncio.run(main())