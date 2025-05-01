import asyncio
import json
import os
from typing import Any, Dict, List, Tuple, Optional
from rich.table import Table
from rich.console import Console
from datetime import datetime


class KSICompliancer:
    """
    Evaluate Azure environment for FedRAMP 20x Phase One Key Security Indicators (KSIs).
    """
    def __init__(self, client: Any, subscription: str, output_format: str = "table", config: Dict = None):
        self.client = client
        self.subscription = subscription
        self.output_format = output_format
        self.results: List[Dict[str, str]] = []
        self.summary: Dict[str, Dict[str, int]] = {}
        
        # Default configuration
        self.config = {
            "include_manual_checks": True,  # Include checks that require manual verification
            "include_categories": ["KSI-CNA", "KSI-SC", "KSI-IAM", "KSI-MLA", "KSI-CM", "KSI-PI", "KSI-3IR", "KSI-CE", "KSI-IR"],
            "max_concurrent_checks": 5,  # Maximum number of checks to run concurrently
            "timeout_seconds": 30,  # Timeout for individual checks
            "verbose": False  # Show detailed progress information
        }
        
        # Update with user-provided configuration
        if config:
            self.config.update(config)

    async def evaluate(self) -> None:
        """Run all KSI checks and display results."""
        self.results = []
        # Define checks: (KSI code, description, check coroutine)
        all_checks: List[Tuple[str, str, Any]] = [
            # KSI-CNA: Cloud Native Architecture
            ("KSI-CNA", "DoS Protection Enabled", self.check_ddos_protection),
            ("KSI-CNA", "Network Security Groups Defined", self.check_nsg_defined),
            ("KSI-CNA", "Azure Firewall(s) Configured", self.check_firewalls),
            ("KSI-CNA", "Container Registries Exist", self.check_acr_registry),
            ("KSI-CNA", "Virtual Networks Defined", self.check_vnets_defined),
            ("KSI-CNA", "Network Segmentation (Subnets)", self.check_network_segmentation),
            ("KSI-CNA", "Security Center Auto-Provisioning Enabled", self.check_security_auto_provisioning),
            ("KSI-CNA", "High Availability (Availability Sets/Zones)", self.check_ha_design),
            # KSI-SC: Service Configuration
            ("KSI-SC", "Storage Accounts Encrypted at Rest", self.check_storage_encryption),
            ("KSI-SC", "Storage Accounts HTTPS Only", self.check_storage_https_only),
            ("KSI-SC", "Central Configuration (Policy Assignments)", self.check_policy_assignments),
            ("KSI-SC", "Key Vaults Present (Key Management)", self.check_key_vaults),
            ("KSI-SC", "Key Rotation Enabled", self.check_key_rotation),
            ("KSI-SC", "Update Management (Patch Management)", self.check_update_management),
            ("KSI-SC", "Network Traffic Encryption", self.check_ssl_policies),
            # KSI-IAM: Identity and Access Management
            ("KSI-IAM", "Phishing-resistant MFA Enforced", self.check_mfa_policy),
            ("KSI-IAM", "Strong Password Enforcement", self.check_password_policy),
            ("KSI-IAM", "Secure API Authentication Methods", self.check_api_management),
            ("KSI-IAM", "Least-privileged RBAC Configuration", self.check_rbac_assignments),
            ("KSI-IAM", "PIM/JIT Access Controls", self.check_pim_enabled),
            # KSI-MLA: Monitoring, Logging, and Auditing
            ("KSI-MLA", "SIEM (Log Analytics Workspace) Present", self.check_log_analytics_workspace),
            ("KSI-MLA", "Security Pricing (Defender) Configured", self.check_security_pricing),
            ("KSI-MLA", "Diagnostic Settings Configured", self.check_diagnostic_settings),
            ("KSI-MLA", "Vulnerability Assessment Enabled", self.check_vulnerability_assessments),
            ("KSI-MLA", "Periodic Log Review (Alert Rules)", self.check_alert_rules),
            ("KSI-MLA", "IaC Scanning Configuration", self.check_security_devops),
            # KSI-CM: Change Management
            ("KSI-CM", "Activity Logs Monitored", self.check_activity_logs),
            ("KSI-CM", "Resource Locks Present", self.check_resource_locks),
            ("KSI-CM", "Immutable Deployments Practiced", self.check_container_instances),
            ("KSI-CM", "Blueprint/Templates Present", self.check_blueprint_definitions),
            ("KSI-CM", "Change Management Procedure Documented", self.check_manual),
            # KSI-PI: Policy and Inventory
            ("KSI-PI", "Resource Inventory (All Resources Listed)", self.check_resource_inventory),
            ("KSI-PI", "Policy Assignments Exist", self.check_policy_assignments),
            ("KSI-PI", "Tags Used for Resource Management", self.check_resource_tags),
            ("KSI-PI", "Vulnerability Disclosure Program", self.check_manual),
            ("KSI-PI", "SDLC Security Considerations", self.check_manual),
            # KSI-3IR: Third Party Information Resources
            ("KSI-3IR", "Third-Party FedRAMP Services Confirmed", self.check_marketplace_items),
            ("KSI-3IR", "Supply Chain Risk Identification", self.check_manual),
            ("KSI-3IR", "SBOM Obtained", self.check_manual),
            ("KSI-3IR", "CISA Attestations Confirmed", self.check_manual),
            ("KSI-3IR", "Zero Trust Design Implementation", self.check_zero_trust_config),
            # KSI-CE: Cybersecurity Education
            ("KSI-CE", "Security Awareness Training", self.check_manual),
            ("KSI-CE", "Role-specific Training", self.check_manual),
            # KSI-IR: Incident Response
            ("KSI-IR", "Backup Vaults Present", self.check_backup_vaults),
            ("KSI-IR", "Backup Policies Defined", self.check_backup_policies),
            ("KSI-IR", "Disaster Recovery Testing", self.check_site_recovery_configs),
            ("KSI-IR", "Incident Reporting Process Configured", self.check_action_groups),
            ("KSI-IR", "Incident Logs Maintained", self.check_security_incidents),
        ]
        
        # Filter checks based on config
        checks = []
        for ksi, desc, check in all_checks:
            # Filter by category
            if ksi not in self.config["include_categories"]:
                continue
                
            # Filter manual checks if configured
            if not self.config["include_manual_checks"] and check == self.check_manual:
                continue
                
            checks.append((ksi, desc, check))
        
        # Show progress info if verbose mode is enabled
        if self.config["verbose"]:
            self.client.console.print(f"Running {len(checks)} checks across {len(self.config['include_categories'])} KSI categories")
            
        # Set timeout for checks
        timeout = self.config["timeout_seconds"]
        
        # Run checks with concurrency limit
        semaphore = asyncio.Semaphore(self.config["max_concurrent_checks"])
        
        async def run_check(ksi, desc, check):
            async with semaphore:
                try:
                    if self.config["verbose"]:
                        self.client.console.print(f"Running check: {ksi} - {desc}")
                    
                    # Run check with timeout
                    status, detail = await asyncio.wait_for(check(), timeout)
                    
                    if self.config["verbose"]:
                        self.client.console.print(f"Completed: {ksi} - {desc} [{status}]")
                        
                except asyncio.TimeoutError:
                    status, detail = "ERROR", f"Check timed out after {timeout} seconds"
                except Exception as e:
                    status, detail = "ERROR", str(e)
                    
                self.results.append({"KSI": ksi, "Check": desc, "Status": status, "Details": detail})
                
        # Create tasks for all checks
        tasks = [run_check(ksi, desc, check) for ksi, desc, check in checks]
        
        # Run all checks concurrently with limits
        await asyncio.gather(*tasks)
        
        # Generate summary
        self.generate_summary()
        
        # Display results based on output format
        if self.output_format == "table":
            self.display_results_table()
        elif self.output_format == "json":
            self.export_results_json()
        elif self.output_format == "csv":
            self.export_results_csv()

    async def check_ddos_protection(self) -> Tuple[str, str]:
        """Check if any DDoS Protection plans are configured."""
        cmd = f"network ddos-protection list --subscription {self.subscription} -o json"
        resp = await self.client.run_cli_command(cmd)
        items = resp if isinstance(resp, list) else []
        status = "PASS" if items else "FAIL"
        detail = f"{len(items)} DDoS protection plan(s) found"
        return status, detail

    async def check_nsg_defined(self) -> Tuple[str, str]:
        """Check if any Network Security Groups are defined in the subscription."""
        cmd = f"network nsg list --subscription {self.subscription} -o json"
        resp = await self.client.run_cli_command(cmd)
        items = resp if isinstance(resp, list) else []
        status = "PASS" if items else "FAIL"
        detail = f"{len(items)} NSG resource(s) found"
        return status, detail

    async def check_storage_encryption(self) -> Tuple[str, str]:
        """Check if storage accounts have encryption enabled at rest."""
        # Query storage accounts and filter for encryption keySource
        cmd = (
            f"storage account list --subscription {self.subscription} -o json"
        )
        resp = await self.client.run_cli_command(cmd)
        count_total = 0
        count_encrypted = 0
        if isinstance(resp, list):
            for sa in resp:
                count_total += 1
                enc = sa.get("encryption", {})
                # Consider encrypted if keySource present
                if enc.get("keySource"):
                    count_encrypted += 1
        status = "PASS" if count_encrypted == count_total and count_total > 0 else "FAIL"
        detail = f"{count_encrypted}/{count_total} storage account(s) encrypted"
        return status, detail
    
    # KSI-CNA additional checks
    async def check_firewalls(self) -> Tuple[str, str]:
        """Check if any Azure Firewall instances are configured."""
        cmd = f"network firewall list --subscription {self.subscription} -o json"
        resp = await self.client.run_cli_command(cmd)
        items = resp if isinstance(resp, list) else []
        status = "PASS" if items else "FAIL"
        detail = f"{len(items)} firewall instance(s) found"
        return status, detail

    async def check_acr_registry(self) -> Tuple[str, str]:
        """Check if any Azure Container Registries are present."""
        cmd = f"acr list --subscription {self.subscription} -o json"
        resp = await self.client.run_cli_command(cmd)
        items = resp if isinstance(resp, list) else []
        status = "PASS" if items else "FAIL"
        detail = f"{len(items)} container registry(ies) found"
        return status, detail

    async def check_vnets_defined(self) -> Tuple[str, str]:
        """Check if any virtual networks are defined."""
        cmd = f"network vnet list --subscription {self.subscription} -o json"
        resp = await self.client.run_cli_command(cmd)
        items = resp if isinstance(resp, list) else []
        status = "PASS" if items else "FAIL"
        detail = f"{len(items)} virtual network(s) found"
        return status, detail

    async def check_network_segmentation(self) -> Tuple[str, str]:
        """Check if VNets have multiple subnets for network segmentation."""
        cmd = f"network vnet list --subscription {self.subscription} -o json"
        resp = await self.client.run_cli_command(cmd)
        vnets_with_multiple_subnets = 0
        total_vnets = 0
        
        if isinstance(resp, list):
            for vnet in resp:
                total_vnets += 1
                subnets = vnet.get("subnets", [])
                if len(subnets) > 1:
                    vnets_with_multiple_subnets += 1
        
        status = "PASS" if vnets_with_multiple_subnets > 0 else "FAIL"
        detail = f"{vnets_with_multiple_subnets}/{total_vnets} VNets with multiple subnets"
        return status, detail

    async def check_security_auto_provisioning(self) -> Tuple[str, str]:
        """Check if Security Center auto-provisioning is enabled."""
        cmd = f"security auto-provisioning-setting list --subscription {self.subscription} -o json"
        resp = await self.client.run_cli_command(cmd)
        enabled = 0
        total = 0
        if isinstance(resp, list):
            for item in resp:
                total += 1
                if item.get("autoProvision", "Off").lower() == "on":
                    enabled += 1
        status = "PASS" if enabled == total and total > 0 else "FAIL"
        detail = f"{enabled}/{total} auto-provisioning setting(s) enabled"
        return status, detail

    async def check_ha_design(self) -> Tuple[str, str]:
        """Check if any Availability Sets/Zones are configured for high availability."""
        # Check for Availability Sets
        cmd1 = f"vm availability-set list --subscription {self.subscription} -o json"
        resp1 = await self.client.run_cli_command(cmd1)
        avsets = resp1 if isinstance(resp1, list) else []
        
        # Check for VMs in Availability Zones
        cmd2 = f"vm list --subscription {self.subscription} -o json"
        resp2 = await self.client.run_cli_command(cmd2)
        vms_in_zones = 0
        if isinstance(resp2, list):
            for vm in resp2:
                if vm.get("zones"):
                    vms_in_zones += 1
        
        status = "PASS" if (avsets or vms_in_zones > 0) else "FAIL"
        detail = f"{len(avsets)} availability set(s), {vms_in_zones} VM(s) in zones"
        return status, detail
    
    # KSI-IAM automated checks
    async def check_mfa_policy(self) -> Tuple[str, str]:
        """Check if Conditional Access policies enforce MFA."""
        # Query CA policies via Microsoft Graph
        cmd = (
            "rest --method GET "
            "--uri https://graph.microsoft.com/beta/identity/conditionalAccess/policies "
            "--query \"value[?grantControls/any(c:c/controlType=='mfa')]\" -o json"
        )
        resp = await self.client.run_cli_command(cmd)
        items = resp if isinstance(resp, list) else []
        status = "PASS" if items else "FAIL"
        detail = f"{len(items)} MFA-enforcing policy(ies) found"
        return status, detail
    
    async def check_password_policy(self) -> Tuple[str, str]:
        """Check password policy strength in Azure AD."""
        try:
            cmd = (
                "rest --method GET "
                "--uri https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy"
                " -o json"
            )
            resp = await self.client.run_cli_command(cmd)
            
            if isinstance(resp, dict) and resp.get("passwordAuthenticationMethod"):
                policy = resp.get("passwordAuthenticationMethod", {})
                
                # Check for strong password requirements
                min_length = policy.get("passwordMinimumLength", 0)
                complexity = policy.get("passwordComplexity", False)
                
                if min_length >= 12 and complexity:
                    return "PASS", "Strong password policy configured (12+ chars with complexity)"
                elif min_length >= 8 and complexity:
                    return "PASS", "Moderate password policy configured (8+ chars with complexity)"
                else:
                    return "FAIL", f"Weak password policy (min length: {min_length}, complexity: {complexity})"
            
            return "MANUAL", "Unable to automatically check password policy"
        except Exception:
            return "MANUAL", "Password policy check requires manual verification"
    
    async def check_api_management(self) -> Tuple[str, str]:
        """Check for Azure API Management services with secure authentication."""
        cmd = f"apim list --subscription {self.subscription} -o json"
        resp = await self.client.run_cli_command(cmd)
        
        if not isinstance(resp, list) or not resp:
            return "MANUAL", "No API Management services found"
        
        # Count API Management services with OAuth or certificate auth
        secure_apis = 0
        for apim in resp:
            apim_name = apim.get("name", "")
            resource_group = apim.get("resourceGroup", "")
            
            if apim_name and resource_group:
                # Check API authentication settings
                auth_cmd = (
                    f"apim api list --service-name {apim_name} "
                    f"--resource-group {resource_group} "
                    f"--subscription {self.subscription} -o json"
                )
                apis_resp = await self.client.run_cli_command(auth_cmd)
                
                if isinstance(apis_resp, list):
                    for api in apis_resp:
                        auth_type = api.get("authenticationSettings", {}).get("oAuth2", {})
                        if auth_type:
                            secure_apis += 1
                            break
        
        if secure_apis > 0:
            return "PASS", f"{secure_apis}/{len(resp)} API Management service(s) with secure auth"
        else:
            return "MANUAL", "API authentication methods require manual verification"
    
    async def check_rbac_assignments(self) -> Tuple[str, str]:
        """Check for custom roles indicating least-privilege RBAC."""
        cmd = f"role definition list --subscription {self.subscription} --custom-role-only true -o json"
        resp = await self.client.run_cli_command(cmd)
        
        custom_roles = resp if isinstance(resp, list) else []
        
        if custom_roles:
            return "PASS", f"{len(custom_roles)} custom role(s) found for least-privilege access"
        else:
            # Check assignment counts to verify if built-in roles are used
            cmd2 = f"role assignment list --subscription {self.subscription} -o json"
            resp2 = await self.client.run_cli_command(cmd2)
            assignments = resp2 if isinstance(resp2, list) else []
            
            # Look for non-Owner/Contributor assignments indicating some least-privilege approach
            non_admin_roles = 0
            for assignment in assignments:
                role_def_id = assignment.get("roleDefinitionId", "")
                if "Owner" not in role_def_id and "Contributor" not in role_def_id:
                    non_admin_roles += 1
            
            if non_admin_roles > 0:
                return "PASS", f"{non_admin_roles} least-privilege role assignment(s) found"
            
            return "MANUAL", "No evidence of least-privilege RBAC implementation"
            
    async def check_pim_enabled(self) -> Tuple[str, str]:
        """Check if Privileged Identity Management is enabled."""
        try:
            # Check for PIM-eligible role assignments via Microsoft Graph
            cmd = (
                "rest --method GET "
                "--uri https://graph.microsoft.com/beta/privilegedAccess/azureResources/resources"
                " -o json"
            )
            resp = await self.client.run_cli_command(cmd)
            
            if isinstance(resp, dict) and resp.get("value"):
                return "PASS", f"{len(resp['value'])} resource(s) with PIM enabled"
            
            return "MANUAL", "PIM/JIT access controls require manual verification"
        except Exception:
            return "MANUAL", "PIM/JIT access check requires manual verification"

    # KSI-SC additional checks
    async def check_storage_https_only(self) -> Tuple[str, str]:
        """Check if storage accounts enforce HTTPS only."""
        cmd = f"storage account list --subscription {self.subscription} -o json"
        resp = await self.client.run_cli_command(cmd)
        total = 0
        enforced = 0
        if isinstance(resp, list):
            for sa in resp:
                total += 1
                if sa.get("enableHttpsTrafficOnly", False):
                    enforced += 1
        status = "PASS" if enforced == total and total > 0 else "FAIL"
        detail = f"{enforced}/{total} storage account(s) HTTPS-only"
        return status, detail

    async def check_policy_assignments(self) -> Tuple[str, str]:
        """Check if any Policy Assignments exist (central configuration)."""
        cmd = f"policy assignment list --subscription {self.subscription} -o json"
        resp = await self.client.run_cli_command(cmd)
        items = resp if isinstance(resp, list) else []
        status = "PASS" if items else "FAIL"
        detail = f"{len(items)} policy assignment(s) found"
        return status, detail

    async def check_key_vaults(self) -> Tuple[str, str]:
        """Check if any Key Vaults are present."""
        cmd = f"keyvault list --subscription {self.subscription} -o json"
        resp = await self.client.run_cli_command(cmd)
        items = resp if isinstance(resp, list) else []
        status = "PASS" if items else "FAIL"
        detail = f"{len(items)} key vault(s) found"
        return status, detail
    
    async def check_key_rotation(self) -> Tuple[str, str]:
        """Check if key rotation is enabled in Key Vaults."""
        # First get all key vaults
        cmd = f"keyvault list --subscription {self.subscription} -o json"
        resp = await self.client.run_cli_command(cmd)
        
        if not isinstance(resp, list) or not resp:
            return "MANUAL", "No Key Vaults found"
        
        # Check for rotation policy on keys
        rotation_enabled = 0
        for vault in resp:
            vault_name = vault.get("name")
            if vault_name:
                # Check keys in vault
                key_cmd = f"keyvault key list --vault-name {vault_name} -o json"
                keys_resp = await self.client.run_cli_command(key_cmd)
                
                if isinstance(keys_resp, list) and keys_resp:
                    for key in keys_resp:
                        key_name = key.get("name")
                        if key_name:
                            # Check rotation policy
                            policy_cmd = (
                                f"keyvault key rotation-policy show --vault-name {vault_name} "
                                f"--name {key_name} -o json"
                            )
                            try:
                                policy = await self.client.run_cli_command(policy_cmd)
                                if isinstance(policy, dict) and policy.get("lifetimeActions"):
                                    rotation_enabled += 1
                                    break  # Found at least one key with rotation in this vault
                            except Exception:
                                # Command may fail if rotation policy isn't supported
                                pass
        
        if rotation_enabled > 0:
            return "PASS", f"{rotation_enabled}/{len(resp)} Key Vault(s) with rotation enabled"
        else:
            return "MANUAL", "Key rotation requires manual verification"

    async def check_update_management(self) -> Tuple[str, str]:
        """Check if any Automation Accounts exist for Update Management."""
        cmd = f"automation account list --subscription {self.subscription} -o json"
        resp = await self.client.run_cli_command(cmd)
        items = resp if isinstance(resp, list) else []
        status = "PASS" if items else "FAIL"
        detail = f"{len(items)} automation account(s) found"
        return status, detail
    
    async def check_ssl_policies(self) -> Tuple[str, str]:
        """Check SSL/TLS policies on App Services and Application Gateways."""
        # Check App Service SSL settings
        cmd1 = f"webapp list --subscription {self.subscription} -o json"
        resp1 = await self.client.run_cli_command(cmd1)
        
        apps_enforcing_https = 0
        total_apps = 0
        
        if isinstance(resp1, list):
            for app in resp1:
                total_apps += 1
                config_cmd = (
                    f"webapp config show --name {app.get('name')} "
                    f"--resource-group {app.get('resourceGroup')} "
                    f"--subscription {self.subscription} -o json"
                )
                try:
                    config = await self.client.run_cli_command(config_cmd)
                    if isinstance(config, dict) and config.get("httpsOnly", False):
                        apps_enforcing_https += 1
                except Exception:
                    pass
        
        # Check Application Gateway SSL settings
        cmd2 = f"network application-gateway list --subscription {self.subscription} -o json"
        resp2 = await self.client.run_cli_command(cmd2)
        
        gateways_with_ssl = 0
        total_gateways = 0
        
        if isinstance(resp2, list):
            for gateway in resp2:
                total_gateways += 1
                ssl_settings = gateway.get("sslPolicy", {})
                # Check for minimum protocol version TLS 1.2
                if ssl_settings and ssl_settings.get("minProtocolVersion", "") in ["TLSv1_2", "TLSv1_3"]:
                    gateways_with_ssl += 1
        
        if (apps_enforcing_https > 0 or gateways_with_ssl > 0):
            status = "PASS"
        else:
            status = "MANUAL" if total_apps == 0 and total_gateways == 0 else "FAIL"
            
        detail = (
            f"{apps_enforcing_https}/{total_apps} Apps with HTTPS-only, "
            f"{gateways_with_ssl}/{total_gateways} Gateways with SSL/TLS 1.2+"
        )
        return status, detail

    # KSI-MLA enhanced checks
    async def check_log_analytics_workspace(self) -> Tuple[str, str]:
        """Check if any Log Analytics Workspaces exist (SIEM)."""
        cmd = f"monitor log-analytics workspace list --subscription {self.subscription} -o json"
        resp = await self.client.run_cli_command(cmd)
        items = resp if isinstance(resp, list) else []
        status = "PASS" if items else "FAIL"
        detail = f"{len(items)} workspace(s) found"
        return status, detail

    async def check_security_pricing(self) -> Tuple[str, str]:
        """Check if Security (Defender) pricing is configured beyond Free tier."""
        cmd = f"security pricing list --subscription {self.subscription} -o json"
        resp = await self.client.run_cli_command(cmd)
        non_free = 0
        total = 0
        if isinstance(resp, list):
            for item in resp:
                total += 1
                if item.get("tier", "Free").lower() != "free":
                    non_free += 1
        status = "PASS" if non_free == total and total > 0 else "FAIL"
        detail = f"{non_free}/{total} resource(s) on non-Free tier"
        return status, detail

    async def check_diagnostic_settings(self) -> Tuple[str, str]:
        """Check if any Diagnostic Settings are configured."""
        cmd = f"monitor diagnostic-settings list --subscription {self.subscription} -o json"
        resp = await self.client.run_cli_command(cmd)
        items = resp if isinstance(resp, list) else []
        status = "PASS" if items else "FAIL"
        detail = f"{len(items)} diagnostic setting(s) found"
        return status, detail
    
    async def check_vulnerability_assessments(self) -> Tuple[str, str]:
        """Check if Vulnerability Assessments are enabled in Defender for Cloud."""
        cmd = (
            f"security assessment list --subscription {self.subscription} "
            "--query \"[?displayName=='Vulnerability Assessments']\" -o json"
        )
        resp = await self.client.run_cli_command(cmd)
        items = resp if isinstance(resp, list) else []
        status = "PASS" if items else "FAIL"
        detail = f"{len(items)} vulnerability assessment record(s) found"
        return status, detail
    
    async def check_alert_rules(self) -> Tuple[str, str]:
        """Check if alert rules are configured for log monitoring."""
        cmd = f"monitor alert-rule list --subscription {self.subscription} -o json"
        resp = await self.client.run_cli_command(cmd)
        items = resp if isinstance(resp, list) else []
        
        if items:
            return "PASS", f"{len(items)} alert rule(s) configured"
        
        # Try scheduled query rules as an alternative
        cmd2 = f"monitor scheduled-query list --subscription {self.subscription} -o json"
        resp2 = await self.client.run_cli_command(cmd2)
        items2 = resp2 if isinstance(resp2, list) else []
        
        status = "PASS" if items2 else "FAIL"
        detail = f"{len(items2)} scheduled query alert(s) configured"
        return status, detail
    
    async def check_security_devops(self) -> Tuple[str, str]:
        """Check for Azure DevOps Security/IaC scanning."""
        cmd = f"security devops list --subscription {self.subscription} -o json"
        resp = await self.client.run_cli_command(cmd)
        
        if isinstance(resp, list) and resp:
            return "PASS", f"{len(resp)} DevOps security integration(s) configured"
        return "MANUAL", "IaC scanning requires manual verification"

    # KSI-CM enhanced checks
    async def check_activity_logs(self) -> Tuple[str, str]:
        """Check if Activity Logs are accessible (logging)."""
        cmd = f"monitor activity-log list --subscription {self.subscription} -o json"
        resp = await self.client.run_cli_command(cmd)
        items = resp if isinstance(resp, list) else []
        status = "PASS" if items else "FAIL"
        detail = f"{len(items)} activity log record(s) found"
        return status, detail
    
    async def check_resource_locks(self) -> Tuple[str, str]:
        """Check if any resource locks are in place to prevent changes."""
        cmd = f"lock list --subscription {self.subscription} -o json"
        resp = await self.client.run_cli_command(cmd)
        items = resp if isinstance(resp, list) else []
        status = "PASS" if items else "MANUAL"
        detail = f"{len(items)} resource lock(s) found"
        return status, detail
    
    async def check_container_instances(self) -> Tuple[str, str]:
        """Check for container instances as evidence of immutable deployments."""
        cmd = f"container group list --subscription {self.subscription} -o json"
        resp = await self.client.run_cli_command(cmd)
        
        if isinstance(resp, list) and resp:
            return "PASS", f"{len(resp)} container group(s) found (immutable)"
        
        # Also check for App Service deployment slots as evidence of immutable approach
        cmd2 = f"webapp deployment slot list --subscription {self.subscription} -o json"
        resp2 = await self.client.run_cli_command(cmd2)
        
        if isinstance(resp2, list) and resp2:
            return "PASS", f"{len(resp2)} deployment slot(s) found (immutable deploys)"
        
        return "MANUAL", "Immutable deployment practices require manual verification"
    
    async def check_blueprint_definitions(self) -> Tuple[str, str]:
        """Check for Blueprint definitions as evidence of automated deployments."""
        cmd = f"blueprint definition list --subscription {self.subscription} -o json"
        resp = await self.client.run_cli_command(cmd)
        
        if isinstance(resp, list) and resp:
            return "PASS", f"{len(resp)} blueprint definition(s) found"
        
        # Also check for ARM template deployments
        cmd2 = (
            f"deployment sub list --subscription {self.subscription} "
            "--query \"[?properties.provisioningState=='Succeeded']\" -o json"
        )
        resp2 = await self.client.run_cli_command(cmd2)
        
        if isinstance(resp2, list) and resp2:
            return "PASS", f"{len(resp2)} ARM template deployment(s) found"
        
        return "MANUAL", "Automated deployments require manual verification"

    # KSI-PI enhanced checks
    async def check_resource_inventory(self) -> Tuple[str, str]:
        """Check if Resources can be listed (inventory)."""
        cmd = f"resource list --subscription {self.subscription} -o json"
        resp = await self.client.run_cli_command(cmd)
        items = resp if isinstance(resp, list) else []
        status = "PASS" if items else "FAIL"
        detail = f"{len(items)} resource(s) found"
        return status, detail
    
    async def check_resource_tags(self) -> Tuple[str, str]:
        """Check if resources use tags for management."""
        cmd = f"resource list --subscription {self.subscription} -o json"
        resp = await self.client.run_cli_command(cmd)
        
        if not isinstance(resp, list) or not resp:
            return "FAIL", "No resources found"
        
        resources_with_tags = 0
        total_resources = len(resp)
        
        for resource in resp:
            if resource.get("tags") and len(resource.get("tags", {})) > 0:
                resources_with_tags += 1
        
        percentage = (resources_with_tags / total_resources) * 100 if total_resources > 0 else 0
        
        if percentage >= 50:
            status = "PASS"
        elif percentage > 0:
            status = "PASS"  # Still pass if some resources are tagged
        else:
            status = "FAIL"
            
        detail = f"{resources_with_tags}/{total_resources} resources tagged ({percentage:.1f}%)"
        return status, detail

    # KSI-3IR enhanced checks
    async def check_marketplace_items(self) -> Tuple[str, str]:
        """Check for marketplace items to verify third-party services."""
        cmd = f"vm image list --all --publisher microsoft-azure-marketplace -o json"
        resp = await self.client.run_cli_command(cmd)
        
        if isinstance(resp, list) and resp:
            return "MANUAL", f"{len(resp)} marketplace images found (manual verification required)"
        
        return "MANUAL", "Third-party FedRAMP services require manual verification"
    
    async def check_zero_trust_config(self) -> Tuple[str, str]:
        """Check for Zero Trust Network Architecture implementations."""
        # Check for Azure Firewall Policy with IDPS
        cmd1 = f"network firewall policy list --subscription {self.subscription} -o json"
        resp1 = await self.client.run_cli_command(cmd1)
        
        policies_with_idps = 0
        if isinstance(resp1, list):
            for policy in resp1:
                if policy.get("intrusionDetection", {}).get("mode", "").lower() in ["alert", "deny"]:
                    policies_with_idps += 1
        
        # Check for Azure AD Conditional Access policies
        cmd2 = (
            "rest --method GET "
            "--uri https://graph.microsoft.com/beta/identity/conditionalAccess/policies"
            " -o json"
        )
        resp2 = await self.client.run_cli_command(cmd2)
        ca_policies = 0
        if isinstance(resp2, dict) and resp2.get("value"):
            ca_policies = len(resp2.get("value", []))
        
        # Check for Private Link/Private Endpoint
        cmd3 = f"network private-endpoint list --subscription {self.subscription} -o json"
        resp3 = await self.client.run_cli_command(cmd3)
        private_endpoints = resp3 if isinstance(resp3, list) else []
        
        if policies_with_idps > 0 or ca_policies > 0 or private_endpoints:
            return "PASS", f"Zero Trust elements found: {policies_with_idps} IDPS, {ca_policies} CA policies, {len(private_endpoints)} private endpoints"
        
        return "MANUAL", "Zero Trust implementation requires manual verification"

    # KSI-IR enhanced checks
    async def check_backup_vaults(self) -> Tuple[str, str]:
        """Check if any Recovery Services Vaults exist for backups."""
        cmd = f"backup vault list --subscription {self.subscription} -o json"
        resp = await self.client.run_cli_command(cmd)
        items = resp if isinstance(resp, list) else []
        status = "PASS" if items else "FAIL"
        detail = f"{len(items)} recovery vault(s) found"
        return status, detail
    
    async def check_backup_policies(self) -> Tuple[str, str]:
        """Check if backup policies are defined with RTO/RPO."""
        cmd = f"backup vault list --subscription {self.subscription} -o json"
        resp = await self.client.run_cli_command(cmd)
        
        if not isinstance(resp, list) or not resp:
            return "FAIL", "No backup vaults found"
        
        vaults_with_policies = 0
        for vault in resp:
            vault_name = vault.get("name")
            resource_group = vault.get("resourceGroup")
            
            if vault_name and resource_group:
                policy_cmd = (
                    f"backup policy list --vault-name {vault_name} "
                    f"--resource-group {resource_group} "
                    f"--subscription {self.subscription} -o json"
                )
                policies = await self.client.run_cli_command(policy_cmd)
                
                if isinstance(policies, list) and policies:
                    vaults_with_policies += 1
        
        status = "PASS" if vaults_with_policies > 0 else "FAIL"
        detail = f"{vaults_with_policies}/{len(resp)} vault(s) with backup policies"
        return status, detail
    
    async def check_site_recovery_configs(self) -> Tuple[str, str]:
        """Check for Azure Site Recovery configurations."""
        cmd = f"site-recovery fabric list --subscription {self.subscription} -o json"
        resp = await self.client.run_cli_command(cmd)
        
        if isinstance(resp, list) and resp:
            return "PASS", f"{len(resp)} site recovery fabric(s) configured"
        
        return "MANUAL", "Disaster recovery testing requires manual verification"
    
    async def check_action_groups(self) -> Tuple[str, str]:
        """Check for Action Groups for incident reporting."""
        cmd = f"monitor action-group list --subscription {self.subscription} -o json"
        resp = await self.client.run_cli_command(cmd)
        
        items = resp if isinstance(resp, list) else []
        status = "PASS" if items else "MANUAL"
        detail = f"{len(items)} action group(s) for incident reporting"
        return status, detail
    
    async def check_security_incidents(self) -> Tuple[str, str]:
        """Check for security incidents logged."""
        cmd = f"security incident list --subscription {self.subscription} -o json"
        resp = await self.client.run_cli_command(cmd)
        
        items = resp if isinstance(resp, list) else []
        
        if items:
            return "PASS", f"{len(items)} security incident(s) logged and tracked"
        else:
            # No incidents could mean good security or no logging
            return "MANUAL", "Incident logging requires manual verification"

    # Stub for manual or non-automatable checks
    async def check_manual(self) -> Tuple[str, str]:
        """Placeholder for checks requiring manual review or not automatable."""
        return "MANUAL", "Manual review required."

    def generate_summary(self) -> None:
        """Generate a summary of the compliance check results."""
        self.summary = {}
        
        # Initialize KSI categories
        ksi_categories = [
            "KSI-CNA", "KSI-SC", "KSI-IAM", "KSI-MLA", 
            "KSI-CM", "KSI-PI", "KSI-3IR", "KSI-CE", "KSI-IR"
        ]
        
        for category in ksi_categories:
            self.summary[category] = {
                "PASS": 0,
                "FAIL": 0,
                "MANUAL": 0,
                "ERROR": 0,
                "total": 0
            }
        
        # Add totals category
        self.summary["TOTAL"] = {
            "PASS": 0,
            "FAIL": 0,
            "MANUAL": 0,
            "ERROR": 0,
            "total": 0
        }
        
        # Count results by category
        for result in self.results:
            ksi = result["KSI"]
            status = result["Status"]
            
            if ksi in self.summary:
                self.summary[ksi][status] += 1
                self.summary[ksi]["total"] += 1
                
                # Add to totals
                self.summary["TOTAL"][status] += 1
                self.summary["TOTAL"]["total"] += 1

    def display_results_table(self) -> None:
        """Display the compliance results in a table."""
        # Results table
        table = Table(title="FedRAMP 20x KSI Compliance Results")
        table.add_column("KSI", style="cyan", no_wrap=True)
        table.add_column("Check")
        table.add_column("Status", style="green")
        table.add_column("Details")
        for r in self.results:
            if r["Status"] == "PASS":
                style = "green"
            elif r["Status"] in ("ERROR", "MANUAL"):
                style = "yellow"
            else:
                style = "red"
            table.add_row(r["KSI"], r["Check"], f"[{style}]{r['Status']}[/{style}]", r["Details"])
        
        # Print results table
        self.client.console.print(table)
        
        # Summary table
        summary_table = Table(title="FedRAMP 20x KSI Compliance Summary")
        summary_table.add_column("KSI Category", style="cyan")
        summary_table.add_column("PASS", style="green")
        summary_table.add_column("FAIL", style="red")
        summary_table.add_column("MANUAL", style="yellow")
        summary_table.add_column("ERROR", style="yellow")
        summary_table.add_column("Compliance %", style="green")
        
        for category, counts in self.summary.items():
            if category != "TOTAL":
                # Calculate compliance percentage (excluding MANUAL and ERROR)
                automated_checks = counts["PASS"] + counts["FAIL"]
                pass_percent = (counts["PASS"] / automated_checks * 100) if automated_checks > 0 else 0
                
                summary_table.add_row(
                    category,
                    str(counts["PASS"]),
                    str(counts["FAIL"]),
                    str(counts["MANUAL"]),
                    str(counts["ERROR"]),
                    f"{pass_percent:.1f}%"
                )
        
        # Add total row
        total_counts = self.summary["TOTAL"]
        automated_total = total_counts["PASS"] + total_counts["FAIL"]
        total_pass_percent = (total_counts["PASS"] / automated_total * 100) if automated_total > 0 else 0
        
        summary_table.add_row(
            "TOTAL",
            str(total_counts["PASS"]),
            str(total_counts["FAIL"]),
            str(total_counts["MANUAL"]),
            str(total_counts["ERROR"]),
            f"{total_pass_percent:.1f}%",
            style="bold"
        )
        
        # Print summary table
        self.client.console.print("\n")
        self.client.console.print(summary_table)
        
        # Print timestamp and subscription info
        self.client.console.print(f"\n[dim]Report generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]")
        self.client.console.print(f"[dim]Subscription: {self.subscription}[/dim]")

    def export_results_json(self, output_file: Optional[str] = None) -> None:
        """Export compliance results to JSON format."""
        output = {
            "metadata": {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "subscription": self.subscription
            },
            "results": self.results,
            "summary": self.summary
        }
        
        json_output = json.dumps(output, indent=2)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(json_output)
            self.client.console.print(f"Results exported to {output_file}")
        else:
            self.client.console.print(json_output)

    def export_results_csv(self, output_file: Optional[str] = None) -> None:
        """Export compliance results to CSV format."""
        csv_rows = []
        
        # Header row
        csv_rows.append("KSI,Check,Status,Details")
        
        # Data rows
        for r in self.results:
            # Escape any commas in the details
            details = r["Details"].replace(",", ";")
            csv_rows.append(f"{r['KSI']},{r['Check']},{r['Status']},{details}")
        
        csv_output = "\n".join(csv_rows)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(csv_output)
            self.client.console.print(f"Results exported to {output_file}")
        else:
            self.client.console.print(csv_output)