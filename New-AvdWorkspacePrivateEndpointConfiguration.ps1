<#
.SYNOPSIS
 Configures private endpoint connectivity for an Azure Virtual Desktop workspace.

.DESCRIPTION
 Creates or updates the workspace private endpoint, links it to private DNS, disables public network access, and validates connectivity.

.PARAMETER WorkspaceResourceGroupName
 Resource group that contains the Azure Virtual Desktop workspace.

.PARAMETER WorkspaceName
 Name of the Azure Virtual Desktop workspace.

.PARAMETER Location
 Azure region (U.S. only) where the resources reside. Defaults to westus2.

.PARAMETER VirtualNetworkResourceGroupName
 Resource group that contains the virtual network hosting the private endpoint subnet.

.PARAMETER VirtualNetworkName
 Name of the virtual network hosting the subnet for the private endpoint.

.PARAMETER SubnetName
 Name of the subnet where the private endpoint will be placed.

.PARAMETER PrivateDnsZoneResourceGroupName
 Resource group containing the Azure Private DNS zone for AVD.

.PARAMETER PrivateDnsZoneSubscriptionId
 Subscription ID that hosts the Azure Private DNS zone.

.PARAMETER DryRun
 When set to true, shows the planned operations without making changes.

.EXAMPLE
 .\New-AvdWorkspacePrivateEndpointConfiguration.ps1 -WorkspaceResourceGroupName rg-avd -WorkspaceName avd-ws -Location eastus -VirtualNetworkResourceGroupName rg-network -VirtualNetworkName avd-vnet -SubnetName avd-pe-subnet -PrivateDnsZoneResourceGroupName rg-dns -PrivateDnsZoneSubscriptionId 00000000-0000-0000-0000-000000000000

.NOTES
 Requires Azure PowerShell Az modules with permissions to manage virtual networks, private endpoints, private DNS, and Azure Virtual Desktop workspaces.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true, HelpMessage = 'Resource group name for the Azure Virtual Desktop workspace.')]
    [ValidateNotNullOrEmpty()][string]$WorkspaceResourceGroupName,

    [Parameter(Mandatory = $true, HelpMessage = 'Name of the Azure Virtual Desktop workspace.')]
    [ValidateNotNullOrEmpty()][string]$WorkspaceName,

    [Parameter(Mandatory = $true, HelpMessage = 'Azure region where the resources reside (U.S. regions only).')]
    [ValidateSet('westus', 'westus2', 'westcentralus', 'southcentralus', 'eastus', 'eastus2', 'centralus', 'northcentralus')][string]$Location = 'westus2',

    [Parameter(Mandatory = $true, HelpMessage = 'Resource group containing the virtual network for the private endpoint.')]
    [ValidateNotNullOrEmpty()][string]$VirtualNetworkResourceGroupName,

    [Parameter(Mandatory = $true, HelpMessage = 'Name of the virtual network that hosts the private endpoint subnet.')]
    [ValidateNotNullOrEmpty()][string]$VirtualNetworkName,

    [Parameter(Mandatory = $true, HelpMessage = 'Name of the subnet where the private endpoint will be created.')]
    [ValidateNotNullOrEmpty()][string]$SubnetName,

    [Parameter(Mandatory = $true, HelpMessage = 'Resource group containing the Azure Private DNS zone.')]
    [ValidateNotNullOrEmpty()][string]$PrivateDnsZoneResourceGroupName,

    [Parameter(Mandatory = $true, HelpMessage = 'Subscription ID containing the Azure Private DNS zone.')]
    [ValidateNotNullOrEmpty()][string]$PrivateDnsZoneSubscriptionId,

    [Parameter(HelpMessage = 'Set to $true to preview actions without applying changes.')]
    [bool]$DryRun = $false
)

# Derive the private endpoint name from the workspace name.
$PrivateEndpointName = "pe-$WorkspaceName"

# Hard-coded private DNS zone group name and DNS zone name used for the association.
$PrivateDnsZoneGroupName = 'default'
$PrivateDnsZoneName = 'privatelink.wvd.microsoft.com'

# Ensure required Az modules are loaded before execution.
$requiredModules = @(
    'Az.Accounts',
    'Az.Resources',
    'Az.Network',
    'Az.PrivateDns',
    'Az.DesktopVirtualization'
)

# Import required Az modules into the runspace if they are not already loaded.
foreach ($module in $requiredModules) {
    if (-not (Get-Module -Name $module)) {
        Write-Log -Message ("Importing module {0}" -f $module)
        try {
            Import-Module -Name $module -ErrorAction Stop
        }
        catch {
            throw "Required module '$module' could not be imported. Ensure the Az module is installed in the automation account."
        }
    }
}

# Constants for DNS wait behavior.
$dnsConfigTimeoutSeconds = 90
$dnsConfigPollSeconds = 5

function Write-Log {
    param(
        [ValidateSet('Info', 'Warning')]
        [string]$Level = 'Info',
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    switch ($Level) {
        'Info'    { Write-Verbose -Message ("[INFO] {0}" -f $Message) }
        'Warning' { Write-Warning -Message ("[WARN] {0}" -f $Message) }
    }
}

# Helper to produce consistent step/status output for workbook tables.
function Write-Step {
    param(
        [string]$Step,
        [string]$Status,
        [string]$Message
    )

    [PSCustomObject]@{
        Step    = $Step
        Status  = $Status
        Message = $Message
    }
}

# Retrieves the private endpoint and waits up to $dnsConfigTimeoutSeconds seconds for Azure to expose CustomDnsConfigs so records can be written reliably.
function Get-PrivateEndpointWithDnsConfig {
    param(
        [ValidateNotNullOrEmpty()][string]$ResourceGroupName,
        [ValidateNotNullOrEmpty()][string]$Name,
        [int]$TimeoutSeconds = $dnsConfigTimeoutSeconds
    )

    # Establish an absolute deadline for retrieving populated CustomDnsConfigs.
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        # Pull the latest private endpoint view, suppressing errors if it temporarily disappears.
        $privateEndpoint = Get-AzPrivateEndpoint -Name $Name -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
        if ($privateEndpoint -and $privateEndpoint.CustomDnsConfigs -and $privateEndpoint.CustomDnsConfigs.Count -gt 0) {
            # Exit once Azure supplies the DNS configuration payload we need.
            return $privateEndpoint
        }
        # Give Azure time to finish populating metadata before the next poll.
        Start-Sleep -Seconds $dnsConfigPollSeconds
    } while ((Get-Date) -lt $deadline)

    return $privateEndpoint
}

# Ensures the target subnet allows private endpoint attachments by disabling network policies when required.
function Set-PrivateEndpointSubnetPolicy {
    param(
        [Microsoft.Azure.Commands.Network.Models.PSVirtualNetwork]$VirtualNetwork,
        [string]$SubnetName,
        [string]$ResourceGroupName
    )

    # Attempt to pull the target subnet from the provided virtual network object.
    $subnet = $VirtualNetwork | Get-AzVirtualNetworkSubnetConfig -Name $SubnetName
    if (-not $subnet) {
        throw "Subnet '$SubnetName' not found in virtual network '$($VirtualNetwork.Name)'."
    }

    if ($subnet.PrivateEndpointNetworkPolicies -ne "Disabled") {
        # Flip the network policy so private endpoints can be attached to this subnet.
        $subnet.PrivateEndpointNetworkPolicies = "Disabled"
        # Persist the updated subnet configuration back to Azure.
        $VirtualNetwork | Set-AzVirtualNetwork | Out-Null
        $effectiveResourceGroup = if ($ResourceGroupName) { $ResourceGroupName } else { $VirtualNetwork.ResourceGroupName }
        if (-not $effectiveResourceGroup) {
            throw "Unable to resolve the virtual network resource group. Provide VirtualNetworkResourceGroupName."
        }
        # Refresh the virtual network to pick up the latest subnet state.
        $VirtualNetwork = Get-AzVirtualNetwork -Name $VirtualNetwork.Name -ResourceGroupName $effectiveResourceGroup
        # Pull the subnet again now that Azure has applied the change.
        $subnet = $VirtualNetwork | Get-AzVirtualNetworkSubnetConfig -Name $SubnetName
    }

    return $subnet
}

# Creates the workspace private endpoint only when one does not already exist.
function New-WorkspacePrivateEndpoint {
    param(
        [ValidateNotNullOrEmpty()][string]$ResourceGroupName,
        [ValidateNotNullOrEmpty()][string]$Name,
        [ValidateNotNullOrEmpty()][string]$Location,
        [Microsoft.Azure.Commands.Network.Models.PSSubnet]$Subnet,
        [ValidateNotNullOrEmpty()][string]$TargetResourceId,
        [string[]]$GroupIds = @('feed')
    )

    # Check for an existing private endpoint so the command remains idempotent.
    $existing = Get-AzPrivateEndpoint -Name $Name -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
    if ($existing) {
        return $existing
    }

    if (-not $GroupIds -or [string]::IsNullOrWhiteSpace($GroupIds[0])) {
        $GroupIds = @('feed')
    }

    # Build the connection payload that binds the endpoint to the workspace feed.
    $connectionParams = @{
        Name                 = "$Name-connection"
        PrivateLinkServiceId = $TargetResourceId
    }

    $connectionCommand = Get-Command -Name New-AzPrivateLinkServiceConnection -ErrorAction Stop
    if ($connectionCommand.Parameters.ContainsKey('GroupIds')) {
        $connectionParams['GroupIds'] = $GroupIds
    }
    elseif ($connectionCommand.Parameters.ContainsKey('GroupId')) {
        $connectionParams['GroupId'] = $GroupIds[0]
    }
    else {
        throw 'The current Az.Network module does not support specifying target subresources for private endpoints (GroupId/GroupIds).'
    }

    # Create the private link service connection that the endpoint needs.
    $connection = New-AzPrivateLinkServiceConnection @connectionParams
    if (-not $connection) {
        throw 'Failed to create private link service connection for the workspace.'
    }

    New-AzPrivateEndpoint -Name $Name -ResourceGroupName $ResourceGroupName -Location $Location -Subnet $Subnet -PrivateLinkServiceConnection $connection
}

# Retrieves or creates the private DNS zone.
function Get-PrivateDnsZoneResource {
    param(
        [string]$ResourceGroupName,
        [string]$ZoneName,
        [string]$SubscriptionId,
        [switch]$CreateIfMissing
    )

    $originalContext = Get-AzContext
    $contextChanged = $false
    if ($SubscriptionId -and $originalContext -and $originalContext.Subscription.Id -ne $SubscriptionId) {
        Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
        $contextChanged = $true
    }

    try {
        # Attempt to reuse the existing private DNS zone before creating one.
        $zone = Get-AzPrivateDnsZone -Name $ZoneName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
        if (-not $zone -and $CreateIfMissing.IsPresent) {
            $zone = New-AzPrivateDnsZone -Name $ZoneName -ResourceGroupName $ResourceGroupName
        }
        return $zone
    }
    finally {
        if ($contextChanged -and $originalContext) {
            Set-AzContext -SubscriptionId $originalContext.Subscription.Id | Out-Null
        }
    }
}

# Ensures the private endpoint is associated with the DNS zone group.
# Associates the private endpoint with the private DNS zone group if it is not already linked.
function Set-PrivateDnsZoneGroup {
    param(
        [Microsoft.Azure.Commands.Network.Models.PSPrivateEndpoint]$PrivateEndpoint,
        [Microsoft.Azure.Commands.PrivateDns.Models.PSPrivateDnsZone]$Zone,
        [string]$ZoneGroupName,
        [string]$PrivateEndpointResourceGroupName
    )

    # Without a hydrated private endpoint object we cannot project DNS records.
    if (-not $PrivateEndpoint) {
        throw 'A provisioning private endpoint instance is required to configure the DNS zone group.'
    }

    if (-not $Zone) {
        throw 'A private DNS zone is required to configure the DNS zone group.'
    }

    # Look for an existing zone group binding on the private endpoint.
    $zoneGroup = Get-AzPrivateDnsZoneGroup -ResourceGroupName $PrivateEndpointResourceGroupName -PrivateEndpointName $PrivateEndpoint.Name -Name $ZoneGroupName -ErrorAction SilentlyContinue
    if ($zoneGroup) {
        return $zoneGroup
    }

    $zoneId = if ($Zone.Id) {
        $Zone.Id
    } elseif ($Zone.ResourceId) {
        $Zone.ResourceId
    } else {
        throw 'The private DNS zone object does not contain an Id or ResourceId.'
    }

    # Prepare the zone configuration object required by the zone group command.
    $zoneConfig = New-AzPrivateDnsZoneConfig -Name "default" -PrivateDnsZoneId $zoneId
    New-AzPrivateDnsZoneGroup -ResourceGroupName $PrivateEndpointResourceGroupName -PrivateEndpointName $PrivateEndpoint.Name -Name $ZoneGroupName -PrivateDnsZoneConfig $zoneConfig
}

# Projects CustomDnsConfigs into A records in the private DNS zone.
function Update-PrivateDnsRecords {
    param(
        [Microsoft.Azure.Commands.Network.Models.PSPrivateEndpoint]$PrivateEndpoint,
        [Microsoft.Azure.Commands.PrivateDns.Models.PSPrivateDnsZone]$Zone
    )

    # Without a hydrated private endpoint object we cannot project DNS records.
    if (-not $PrivateEndpoint) {
        throw 'A private endpoint instance is required to synchronize DNS records.'
    }

    if (-not $Zone) {
        throw 'A private DNS zone instance is required to synchronize DNS records.'
    }

    if (-not $PrivateEndpoint.CustomDnsConfigs) {
        return
    }

    # Iterate through each DNS configuration returned on the private endpoint.
    foreach ($dnsConfig in $PrivateEndpoint.CustomDnsConfigs) {
        if (-not $dnsConfig.Fqdn) {
            continue
        }

        # Build the fully-qualified record set name from the endpoint FQDN.
        $recordSetName = $dnsConfig.Fqdn.TrimEnd('.')
        if (-not $recordSetName.EndsWith($Zone.Name, [System.StringComparison]::OrdinalIgnoreCase)) {
            continue
        }

        $relativeName = $recordSetName.Substring(0, $recordSetName.Length - $Zone.Name.Length).TrimEnd('.')
        if ([string]::IsNullOrWhiteSpace($relativeName)) {
            $relativeName = "@"
        }

        # Reuse an existing A record where possible to avoid duplicates.
        $existingRecordSet = Get-AzPrivateDnsRecordSet -ZoneName $Zone.Name -ResourceGroupName $Zone.ResourceGroupName -Name $relativeName -RecordType A -ErrorAction SilentlyContinue
        if ($existingRecordSet) {
            # Reset previously stored IPs so the record reflects current assignments.
            $existingRecordSet.Records.Clear()
            foreach ($ip in $dnsConfig.IPAddresses) {
                # Append each private endpoint IP address to the record set.
                $existingRecordSet | Add-AzPrivateDnsRecordConfig -Ipv4Address $ip | Out-Null
            }
            $existingRecordSet | Set-AzPrivateDnsRecordSet | Out-Null
        }
        else {
            $records = foreach ($ip in $dnsConfig.IPAddresses) {
                New-AzPrivateDnsRecordConfig -Ipv4Address $ip
            }
            # Create a brand new A record with all private endpoint IP addresses.
            New-AzPrivateDnsRecordSet -ZoneName $Zone.Name -ResourceGroupName $Zone.ResourceGroupName -Name $relativeName -RecordType A -Ttl 300 -PrivateDnsRecords $records | Out-Null
        }
    }
}

# Disables public access on the workspace, falling back to REST if the cmdlet lacks support.
function Disable-PublicNetworkAccess {
    param(
        [string]$WorkspaceResourceGroup,
        [string]$WorkspaceName
    )

    # Pull the current workspace state so we know whether updates are needed.
    $workspace = Get-AzWvdWorkspace -ResourceGroupName $WorkspaceResourceGroup -Name $WorkspaceName
    if (-not $workspace) {
        throw "Workspace '$WorkspaceName' not found in resource group '$WorkspaceResourceGroup'."
    }

    if ($workspace.PublicNetworkAccess -eq "Disabled") {
        return $workspace
    }

    try {
        # Prefer the native cmdlet when it supports toggling public network access.
        Update-AzWvdWorkspace -ResourceGroupName $WorkspaceResourceGroup -Name $WorkspaceName -PublicNetworkAccess Disabled | Out-Null
        return Get-AzWvdWorkspace -ResourceGroupName $WorkspaceResourceGroup -Name $WorkspaceName
    }
    catch {
        # Fall back to invoking the REST API when the Az module lacks the publicNetworkAccess parameter.
        $apiVersion = "2023-09-05-preview"
        $workspaceId = $workspace.Id.Trim()
        $body = @{ properties = @{ publicNetworkAccess = "Disabled" } } | ConvertTo-Json -Depth 5
        # Fall back to the REST API because some module versions lack the parameter.
        Invoke-AzRestMethod -Path "$workspaceId?api-version=$apiVersion" -Method PUT -Payload $body | Out-Null
        return Get-AzWvdWorkspace -ResourceGroupName $WorkspaceResourceGroup -Name $WorkspaceName
    }
}

# Honor PowerShell ShouldProcess to support -WhatIf and -Confirm.
if ($DryRun -eq $true) {
    Write-Log -Level Warning -Message 'DryRun specified (true). No changes will be made; displaying planned operations only.'
}

if (-not $PSCmdlet.ShouldProcess("Workspace '{0}'" -f $WorkspaceName, "Configure private endpoint connectivity")) {
    return
}

Write-Log -Message 'Authenticating to Azure using managed identity if available.'
$null = Connect-AzAccount -Identity -ErrorAction SilentlyContinue

$context = Get-AzContext
if (-not $context -or -not $context.Subscription) {
    throw "Unable to determine the current Azure subscription context. Ensure the automation account identity has access."
}

try {
    Get-AzResourceGroup -Name $WorkspaceResourceGroupName -ErrorAction Stop | Out-Null
}
catch {
    $subscriptions = Get-AzSubscription -ErrorAction Stop | Where-Object { $_.State -eq 'Enabled' }
    $context = $null
    foreach ($subscription in $subscriptions) {
        Set-AzContext -SubscriptionId $subscription.Id | Out-Null
        try {
            Get-AzResourceGroup -Name $WorkspaceResourceGroupName -ErrorAction Stop | Out-Null
            $context = Get-AzContext
            break
        }
        catch {
            $context = $null
        }
    }

    if (-not $context) {
        throw "Workspace resource group '$WorkspaceResourceGroupName' was not found in any accessible subscription."
    }
}

Set-AzContext -SubscriptionId $context.Subscription.Id | Out-Null
Write-Log -Message ("Using subscription {0} ({1})" -f $context.Subscription.Name, $context.Subscription.Id)

$workspaceResource = Get-AzResource -ResourceGroupName $WorkspaceResourceGroupName -ResourceType "Microsoft.DesktopVirtualization/workspaces" -Name $WorkspaceName -ErrorAction Stop
$workspaceCurrent = Get-AzWvdWorkspace -ResourceGroupName $WorkspaceResourceGroupName -Name $WorkspaceName -ErrorAction Stop

$virtualNetwork = Get-AzVirtualNetwork -Name $VirtualNetworkName -ResourceGroupName $VirtualNetworkResourceGroupName -ErrorAction Stop
$initialSubnet = $virtualNetwork | Get-AzVirtualNetworkSubnetConfig -Name $SubnetName
if (-not $initialSubnet) {
    throw "Subnet '$SubnetName' not found in virtual network '$VirtualNetworkName'."
}

$existingPrivateEndpoint = Get-AzPrivateEndpoint -Name $PrivateEndpointName -ResourceGroupName $WorkspaceResourceGroupName -ErrorAction SilentlyContinue
$existingDnsZone = Get-PrivateDnsZoneResource -ResourceGroupName $PrivateDnsZoneResourceGroupName -ZoneName $PrivateDnsZoneName -SubscriptionId $PrivateDnsZoneSubscriptionId
$existingZoneGroup = $null
if ($existingPrivateEndpoint) {
    $existingZoneGroup = Get-AzPrivateDnsZoneGroup -ResourceGroupName $WorkspaceResourceGroupName -PrivateEndpointName $PrivateEndpointName -Name $PrivateDnsZoneGroupName -ErrorAction SilentlyContinue
}

if ($DryRun -eq $true) {
    # Build a workbook-friendly preview when -DryRun is supplied.
    $plan = [System.Collections.Generic.List[object]]::new()

    $subnetPolicyStatus = if ($initialSubnet.PrivateEndpointNetworkPolicies -eq 'Disabled') { 'NoChange' } else { 'WillDisable' }
    $subnetPolicyMessage = if ($subnetPolicyStatus -eq 'NoChange') {
        "Subnet '$SubnetName' already allows private endpoints."
    } else {
        "Would disable private endpoint network policies on subnet '$SubnetName'."
    }
    $plan.Add((Write-Step -Step 'SubnetPolicy' -Status $subnetPolicyStatus -Message $subnetPolicyMessage))

    if ($existingPrivateEndpoint) {
        $plan.Add((Write-Step -Step 'PrivateEndpoint' -Status 'Existing' -Message "Would reuse private endpoint '$PrivateEndpointName'."))
    } else {
        $plan.Add((Write-Step -Step 'PrivateEndpoint' -Status 'Create' -Message "Would create private endpoint '$PrivateEndpointName' in resource group '$WorkspaceResourceGroupName'."))
    }

    if ($existingDnsZone) {
        $plan.Add((Write-Step -Step 'PrivateDnsZone' -Status 'Existing' -Message "Private DNS zone '$PrivateDnsZoneName' already present."))
    } else {
        $plan.Add((Write-Step -Step 'PrivateDnsZone' -Status 'Create' -Message "Would create private DNS zone '$PrivateDnsZoneName'."))
    }

    if ($existingZoneGroup) {
        $plan.Add((Write-Step -Step 'DnsZoneGroup' -Status 'Existing' -Message "Private endpoint already associated with DNS zone group '$PrivateDnsZoneGroupName'."))
    } else {
        $plan.Add((Write-Step -Step 'DnsZoneGroup' -Status 'Create' -Message "Would associate private endpoint with DNS zone group '$PrivateDnsZoneGroupName'."))
    }

    $plan.Add((Write-Step -Step 'DnsRecords' -Status 'ManualSync' -Message ("Script will poll up to {0} seconds for private endpoint DNS data before syncing records." -f $dnsConfigTimeoutSeconds)))

    $publicAccessStatus = if ($workspaceCurrent.PublicNetworkAccess -eq 'Disabled') { 'Disabled' } else { 'WillDisable' }
    $publicAccessMessage = if ($publicAccessStatus -eq 'Disabled') {
        'Workspace public network access already disabled.'
    } else {
        'Would disable workspace public network access.'
    }
    $plan.Add((Write-Step -Step 'PublicNetworkAccess' -Status $publicAccessStatus -Message $publicAccessMessage))

    $plan.Add((Write-Step -Step 'DryRun' -Status 'Complete' -Message 'Dry run completed. No changes were made.'))

    return $plan
}

# Apply subnet policy changes and provision the private endpoint as needed.
$targetSubnet = Set-PrivateEndpointSubnetPolicy -VirtualNetwork $virtualNetwork -SubnetName $SubnetName -ResourceGroupName $VirtualNetworkResourceGroupName

# Determine the correct private endpoint subresource (feed) for the workspace resource type.
$subresourceMap = @{
    'microsoft.desktopvirtualization/workspaces' = 'feed'
}
$workspaceResourceTypeKey = $workspaceResource.ResourceType.ToLowerInvariant()
$groupIds = @($subresourceMap[$workspaceResourceTypeKey])
if (-not $groupIds -or [string]::IsNullOrWhiteSpace($groupIds[0])) {
    $groupIds = @('feed')
}

if (-not $existingPrivateEndpoint) {
    $null = New-WorkspacePrivateEndpoint -ResourceGroupName $WorkspaceResourceGroupName -Name $PrivateEndpointName -Location $Location -Subnet $targetSubnet -TargetResourceId $workspaceResource.ResourceId -GroupIds $groupIds
}

$privateEndpoint = Get-AzPrivateEndpoint -Name $PrivateEndpointName -ResourceGroupName $WorkspaceResourceGroupName
$dnsZone = Get-PrivateDnsZoneResource -ResourceGroupName $PrivateDnsZoneResourceGroupName -ZoneName $PrivateDnsZoneName -SubscriptionId $PrivateDnsZoneSubscriptionId -CreateIfMissing
Set-PrivateDnsZoneGroup -PrivateEndpoint $privateEndpoint -Zone $dnsZone -ZoneGroupName $PrivateDnsZoneGroupName -PrivateEndpointResourceGroupName $WorkspaceResourceGroupName | Out-Null

# Wait for Azure to expose CustomDnsConfigs before writing DNS records.
$privateEndpoint = Get-PrivateEndpointWithDnsConfig -ResourceGroupName $WorkspaceResourceGroupName -Name $PrivateEndpointName -TimeoutSeconds $dnsConfigTimeoutSeconds
$dnsSyncStatus = 'Synced'
$dnsSyncMessage = 'Private endpoint DNS records updated.'
if (-not ($privateEndpoint -and $privateEndpoint.CustomDnsConfigs -and $privateEndpoint.CustomDnsConfigs.Count -gt 0)) {
    Write-Log -Level Warning -Message ("Private endpoint DNS configuration did not populate within {0} seconds. DNS records will not be synced automatically." -f $dnsConfigTimeoutSeconds)
    $dnsSyncStatus = 'Pending'
    $dnsSyncMessage = 'CustomDnsConfigs not available; no DNS records written.'
}
else {
    Update-PrivateDnsRecords -PrivateEndpoint $privateEndpoint -Zone $dnsZone
}

# Harden the workspace so it only responds through the private endpoint.
$workspace = Disable-PublicNetworkAccess -WorkspaceResourceGroup $WorkspaceResourceGroupName -WorkspaceName $WorkspaceName

$connectionState = $privateEndpoint.PrivateLinkServiceConnections | Select-Object -First 1
if (-not $connectionState) {
    $connectionState = [PSCustomObject]@{
        PrivateLinkServiceConnectionState = [PSCustomObject]@{
            Status      = "Unknown"
            Description = "No private link service connection returned."
        }
    }
}
$connectionStatus = if ($connectionState.PrivateLinkServiceConnectionState.Status) { $connectionState.PrivateLinkServiceConnectionState.Status } else { "Unknown" }
$connectionDescription = if ($connectionState.PrivateLinkServiceConnectionState.Description) { $connectionState.PrivateLinkServiceConnectionState.Description } else { "No private link service connection details returned." }
$validationSummary = [System.Collections.Generic.List[object]]::new()
$validationSummary.Add((Write-Step -Step "PrivateEndpoint" -Status $connectionStatus -Message $connectionDescription))
$validationSummary.Add((Write-Step -Step "DnsRecords" -Status $dnsSyncStatus -Message $dnsSyncMessage))

$publicAccessState = if ($workspace.PublicNetworkAccess) { $workspace.PublicNetworkAccess } else { "Unknown" }
$validationSummary.Add((Write-Step -Step "PublicNetworkAccess" -Status $publicAccessState -Message "Workspace public network access state."))

# Return results for workbook consumption.
return $validationSummary
