<#
.SYNOPSIS
    Endpoint agent for the Automated Insider Threat Digital Forensic
    Investigation Tool (Toronto Police Force USB / File Access monitoring).

.DESCRIPTION
    Runs on each monitored Windows workstation. Two responsibilities:

    1. USB ACTIVITY: Subscribes to Plug-and-Play device arrival/removal
       WMI events (Win32_USBHub) and forwards connect/disconnect events,
       including the device serial number, to the central station.

    2. FILE ACCESS ACTIVITY: Polls the Windows Security event log for
       object access events (Event ID 4663) on the folders you have
       tagged for monitoring. Those events only appear once a System
       Access Control List (SACL) is applied to the folder -- see
       Setup-Auditing below -- which is exactly the approach the project
       used to control ingestion volume instead of reading every file
       operation on the disk.

    Every event is POSTed as JSON to the Flask central station and, for
    file events, a SHA-256 hash of the file is attached so the server-side
    evidence ledger can prove the file's content at the time it was
    observed.

.NOTES
    Run as Administrator. Requires PowerShell 5.1+ (works with 7.x).
#>

param(
    [string]$ServerUrl = "http://localhost:5000",
    [string]$ApiKey    = "change-me-agent-key",
    [string[]]$WatchPaths = @("C:\CaseFiles", "C:\Evidence"),
    [int]$PollIntervalSeconds = 5
)

$ErrorActionPreference = "Stop"
$AgentId   = "agent-$($env:COMPUTERNAME)"
$Hostname  = $env:COMPUTERNAME
$Username  = $env:USERNAME
$Headers   = @{ "X-Agent-Key" = $ApiKey; "Content-Type" = "application/json" }

function Write-Log($msg) {
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $msg"
}

# -----------------------------------------------------------------------
# One-time setup: apply a SACL (audit rule) to each watched folder so the
# Security event log actually records access to it. Run once as admin,
# or call this script with -SetupOnly.
# -----------------------------------------------------------------------
function Setup-Auditing {
    param([string[]]$Paths)
    foreach ($p in $Paths) {
        if (-not (Test-Path $p)) {
            Write-Log "Skipping $p (does not exist on this host)"
            continue
        }
        try {
            $acl = Get-Acl -Path $p
            $rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
                "Everyone",
                [System.Security.AccessControl.FileSystemRights]::ReadData,
                "ContainerInherit,ObjectInherit",
                "None",
                [System.Security.AccessControl.AuditFlags]::Success
            )
            $acl.AddAuditRule($rule)
            Set-Acl -Path $p -AclObject $acl
            Write-Log "Auditing enabled on $p"
        } catch {
            Write-Log "Failed to set SACL on $p : $_"
        }
    }
    Write-Log "Reminder: object access auditing must also be enabled in Local Security Policy"
    Write-Log "  (Advanced Audit Policy Configuration > Object Access > Audit File System)."
}

# -----------------------------------------------------------------------
# Helper: POST an event to the central station
# -----------------------------------------------------------------------
function Send-Event {
    param([string]$Endpoint, [hashtable]$Body)
    $json = $Body | ConvertTo-Json -Depth 5
    try {
        Invoke-RestMethod -Uri "$ServerUrl$Endpoint" -Method Post -Headers $Headers -Body $json | Out-Null
    } catch {
        Write-Log "Failed to send event to $Endpoint : $_"
    }
}

# -----------------------------------------------------------------------
# USB monitoring via WMI device-change events
# -----------------------------------------------------------------------
function Start-UsbMonitor {
    Write-Log "Starting USB device monitor..."

    Register-WmiEvent -Query "SELECT * FROM Win32_DeviceChangeEvent WHERE EventType = 2" `
        -SourceIdentifier "USB_Connect" | Out-Null
    Register-WmiEvent -Query "SELECT * FROM Win32_DeviceChangeEvent WHERE EventType = 3" `
        -SourceIdentifier "USB_Disconnect" | Out-Null

    Write-Log "USB monitor active (device arrival/removal events registered)."
}

function Get-LatestUsbDeviceInfo {
    # Pull the most recently connected USB storage device's identifying info
    Get-WmiObject Win32_DiskDrive | Where-Object { $_.InterfaceType -eq "USB" } | ForEach-Object {
        $pnp = $_.PNPDeviceID
        [PSCustomObject]@{
            Serial      = ($pnp -split "\\")[-1]
            DeviceName  = $_.Caption
            VendorId    = $null
            ProductId   = $null
        }
    } | Select-Object -First 1
}

function Process-UsbEvents {
    $connect = Get-Event -SourceIdentifier "USB_Connect" -ErrorAction SilentlyContinue
    if ($connect) {
        $connect | ForEach-Object {
            $info = Get-LatestUsbDeviceInfo
            Send-Event -Endpoint "/api/agent/usb" -Body @{
                agent_id     = $AgentId
                hostname     = $Hostname
                username     = $Username
                action       = "connect"
                serial       = $info.Serial
                device_name  = $info.DeviceName
                vendor_id    = $info.VendorId
                product_id   = $info.ProductId
                event_time   = (Get-Date -Format "o")
            }
            Write-Log "USB connect reported: $($info.DeviceName) [$($info.Serial)]"
        }
        Remove-Event -SourceIdentifier "USB_Connect" -ErrorAction SilentlyContinue
    }

    $disconnect = Get-Event -SourceIdentifier "USB_Disconnect" -ErrorAction SilentlyContinue
    if ($disconnect) {
        $disconnect | ForEach-Object {
            Send-Event -Endpoint "/api/agent/usb" -Body @{
                agent_id     = $AgentId
                hostname     = $Hostname
                username     = $Username
                action       = "disconnect"
                serial       = "unknown"
                event_time   = (Get-Date -Format "o")
            }
            Write-Log "USB disconnect reported."
        }
        Remove-Event -SourceIdentifier "USB_Disconnect" -ErrorAction SilentlyContinue
    }
}

# -----------------------------------------------------------------------
# File access monitoring via Security log Event ID 4663 (object access)
# -----------------------------------------------------------------------
$Script:LastFileEventTime = (Get-Date)

function Process-FileEvents {
    $filter = @{
        LogName   = 'Security'
        Id        = 4663
        StartTime = $Script:LastFileEventTime
    }
    $events = Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue
    if (-not $events) { return }

    $Script:LastFileEventTime = Get-Date

    foreach ($evt in $events) {
        $xml = [xml]$evt.ToXml()
        $data = @{}
        foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }

        $path = $data['ObjectName']
        if (-not $path) { continue }
        if (-not ($WatchPaths | Where-Object { $path -like "$_*" })) { continue }

        $accessMask = $data['AccessMask']
        $action = switch -Wildcard ($accessMask) {
            "*1*" { "read" }
            "*2*" { "write" }
            default { "access" }
        }

        $fileHash = $null
        if (Test-Path $path -PathType Leaf) {
            try { $fileHash = (Get-FileHash -Path $path -Algorithm SHA256).Hash } catch {}
        }

        Send-Event -Endpoint "/api/agent/file" -Body @{
            agent_id         = $AgentId
            hostname         = $Hostname
            username         = $data['SubjectUserName']
            action           = $action
            path             = $path
            process          = $data['ProcessName']
            file_hash        = $fileHash
            event_time       = (Get-Date -Format "o")
            event_time_local = (Get-Date -Format "s")
        }
        Write-Log "File $action reported: $path"
    }
}

# -----------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------
if ($args -contains "-SetupOnly") {
    Setup-Auditing -Paths $WatchPaths
    return
}

Write-Log "Agent starting. Server: $ServerUrl  Watching: $($WatchPaths -join ', ')"
Setup-Auditing -Paths $WatchPaths
Start-UsbMonitor

while ($true) {
    Process-UsbEvents
    Process-FileEvents
    Start-Sleep -Seconds $PollIntervalSeconds
}
