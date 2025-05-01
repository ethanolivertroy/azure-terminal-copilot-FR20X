# FedRAMP Compliance Guide

This document provides guidance on interpreting and acting on the results of the FedRAMP 20x Phase One Key Security Indicators (KSIs) compliance evaluation.

## Understanding Compliance Results

The compliance checker produces results for each KSI check with the following statuses:

- **PASS**: The check was successful, indicating compliance with the requirement.
- **FAIL**: The check failed, indicating non-compliance with the requirement.
- **MANUAL**: The check requires manual review or verification, as it cannot be fully automated.
- **ERROR**: An error occurred while attempting the check.

A compliance summary is also provided, showing the percentage of automated checks that passed for each KSI category.

## Interpreting Results by KSI Category

### KSI-CNA: Cloud Native Architecture

This KSI evaluates whether your Azure environment uses cloud-native architecture and design principles to enforce confidentiality, integrity, and availability.

#### Key Checks:
- **DoS Protection**: Verify that Azure DDoS Protection is enabled.
- **Network Security Groups**: Confirm NSGs are defined to control inbound/outbound traffic.
- **Firewalls**: Ensure Azure Firewalls are deployed.
- **Network Segmentation**: Verify VNets are segmented with multiple subnets.
- **High Availability**: Check for availability sets/zones for resilience.

#### Remediation for Failed Checks:
- Enable Azure DDoS Protection: `az network ddos-protection create`
- Create NSGs: `az network nsg create`
- Deploy Azure Firewall: `az network firewall create`
- Segment VNets with subnets: `az network vnet subnet create`
- Use availability sets/zones: `az vm availability-set create`

### KSI-SC: Service Configuration

This KSI evaluates the use of approved cryptography, integrity verification, and restricted access to external services.

#### Key Checks:
- **Storage Encryption**: Verify Azure Storage accounts are encrypted at rest.
- **HTTPS-Only Storage**: Ensure HTTPS is enforced for storage accounts.
- **Key Vault Usage**: Check for Key Vault deployment for secret management.
- **Key Rotation**: Verify key rotation policies are in place.
- **Network Traffic Encryption**: Check SSL/TLS settings on web apps and gateways.

#### Remediation for Failed Checks:
- Enable storage encryption: `az storage account update --encryption-services blob`
- Enforce HTTPS-only: `az storage account update --https-only true`
- Create Key Vault: `az keyvault create`
- Configure key rotation: `az keyvault key rotation-policy update`
- Enable HTTPS on web apps: `az webapp update --https-only true`

### KSI-IAM: Identity and Access Management

This KSI evaluates secure user identity, access controls, and zero trust practices.

#### Key Checks:
- **MFA Enforcement**: Verify conditional access policies enforce MFA.
- **Password Policy**: Check for strong password requirements.
- **RBAC Implementation**: Verify least-privilege access control.
- **PIM/JIT Access**: Check for just-in-time privileged access.

#### Remediation for Failed Checks:
- Configure MFA: Use Azure AD Conditional Access policies
- Implement strong password policy: Update Azure AD password policies
- Configure RBAC: `az role assignment create` with appropriate scopes
- Enable PIM: Configure Azure AD Privileged Identity Management

### KSI-MLA: Monitoring, Logging, and Auditing

This KSI evaluates logging, monitoring, and auditing of important events and activities.

#### Key Checks:
- **Log Analytics Workspace**: Verify SIEM implementation.
- **Defender Configuration**: Check if Microsoft Defender is configured beyond Free tier.
- **Diagnostic Settings**: Verify resource diagnostic settings are configured.
- **Vulnerability Assessment**: Check if vulnerability scanning is enabled.
- **Alert Rules**: Verify monitoring alerts are configured.

#### Remediation for Failed Checks:
- Create Log Analytics workspace: `az monitor log-analytics workspace create`
- Enable Microsoft Defender: `az security pricing update --tier Standard`
- Configure diagnostics: `az monitor diagnostic-settings create`
- Enable vulnerability assessments: Enable in Microsoft Defender
- Create alert rules: `az monitor alert-rule create`

### KSI-CM: Change Management

This KSI evaluates procedures for managing system changes.

#### Key Checks:
- **Activity Logs**: Verify system modifications are logged.
- **Resource Locks**: Check for resource locks to prevent accidental changes.
- **Immutable Deployments**: Verify use of containers and immutable infrastructure.
- **Blueprint/Templates**: Check for IaC templates for deployment.

#### Remediation for Failed Checks:
- Enable activity log collection: `az monitor diagnostic-settings create`
- Create resource locks: `az lock create`
- Implement container deployments: Use ACI or AKS
- Use ARM templates: `az deployment group create`

### KSI-PI: Policy and Inventory

This KSI evaluates resource inventory and security policies.

#### Key Checks:
- **Resource Inventory**: Verify resources can be listed and tracked.
- **Policy Assignments**: Check for Azure Policy assignments.
- **Resource Tags**: Verify resource tagging for management.

#### Remediation for Failed Checks:
- Maintain resource inventory: Regularly review `az resource list`
- Assign policies: `az policy assignment create`
- Implement tagging: `az tag create`

### KSI-3IR: Third Party Information Resources

This KSI evaluates management of third-party services and supply chain risks.

#### Key Checks:
- **Marketplace Items**: Check for third-party services.
- **Zero Trust Configuration**: Verify zero trust principles implementation.

#### Remediation for Failed Checks:
- Validate third-party services: Verify FedRAMP authorization
- Implement zero trust: Deploy Private Link, Conditional Access, etc.

### KSI-CE: Cybersecurity Education

This KSI evaluates staff training on cybersecurity measures.

#### Key Checks:
This section primarily requires manual verification of training programs.

#### Remediation for Manual Checks:
- Implement security awareness training program
- Provide role-specific security training for administrators

### KSI-IR: Incident Response

This KSI evaluates incident response capabilities.

#### Key Checks:
- **Backup Vaults**: Verify recovery services vaults for backups.
- **Backup Policies**: Check backup policies with RTO/RPO.
- **Site Recovery**: Verify disaster recovery configuration.
- **Action Groups**: Check incident reporting configuration.

#### Remediation for Failed Checks:
- Create backup vaults: `az backup vault create`
- Configure backup policies: `az backup policy create`
- Setup site recovery: `az site-recovery fabric create`
- Configure action groups: `az monitor action-group create`

## Next Steps After Compliance Evaluation

1. **Address FAIL Results First**: Prioritize remediation of failed checks.
2. **Review MANUAL Checks**: Document evidence for checks that require manual verification.
3. **Regular Reassessment**: Run the compliance tool regularly to verify continued compliance.
4. **Document Deviations**: For any requirements that cannot be met, document reasons and mitigations.
5. **Continuous Improvement**: Implement automated deployment and policy-as-code to maintain compliance.

## FedRAMP Specific Recommendations

To better align with FedRAMP requirements:

1. **System Security Plan (SSP)**: Use the compliance results to inform your SSP documentation.
2. **Continuous Monitoring**: Implement the monitoring checks identified in KSI-MLA.
3. **Incident Response Plan**: Develop formal procedures aligned with KSI-IR checks.
4. **Supply Chain Risk Management**: Address third-party dependencies as per KSI-3IR.
5. **Automation**: When possible, automate compliance checking and remediation using Azure Policy and Azure Blueprints.

## Common Compliance Challenges and Solutions

| Challenge | Solution |
|-----------|----------|
| Multiple subscriptions to evaluate | Run the tool against each subscription and aggregate results |
| Manual checks too time-consuming | Focus on automating evidence collection for manual checks |
| Balancing security with usability | Use JIT/PIM to provide elevated access only when needed |
| Legacy systems | Consider refactoring or isolating non-compliant legacy systems |
| Cost concerns | Prioritize critical security controls, then phase in others |

## Additional Resources

- [FedRAMP Authorization Act](https://www.congress.gov/bill/117th-congress/house-bill/21/text)
- [NIST SP 800-53 Controls](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- [Azure Security Benchmarks](https://docs.microsoft.com/en-us/azure/security/benchmarks/introduction)
- [Cloud Security Alliance CAIQ](https://cloudsecurityalliance.org/research/artifacts/)