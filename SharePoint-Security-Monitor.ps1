# SharePoint Security Monitor - Enhanced Edition with Performance Optimizations
# Protection against CVE-2023-29357, CVE-2023-33157 and bypass vulnerabilities
# PowerShell 5.1 Compatible - Version 3.9 - Performance Optimized with Auto Email
# Includes detection for known threat actors and advanced persistent threats
# Enhanced DLL detection with intelligent filtering and signature verification
# NEW: Incremental log reading with bookmarks and caching for improved performance
# AUTO EMAIL: Automatically sends email on alerts or warnings (use -NoAlertOnWarnings to disable)
# v3.8: Enhanced DLL management with auto-approval and detailed attack reporting
# v3.9: Advanced DLL validation with pattern analysis and security checks
#
# NOTE FOR SHAREPOINT 2019:
# - Security patches are included in Cumulative Updates (CU)
# - Minimum required build: 16.0.10398.20000 (December 2023 CU or higher)
# - To verify build: Get-SPFarm | Select BuildVersion
# - Download CU: https://docs.microsoft.com/en-us/officeupdates/sharepoint-updates
#
# USAGE EXAMPLES:
# .\SharePoint_Security_Monitoring.ps1                    # Standard scan (email on alerts/warnings)
# .\SharePoint_Security_Monitoring.ps1 -QuickScan        # Quick scan (last 12h)
# .\SharePoint_Security_Monitoring.ps1 -CreateBaseline   # Create DLL baseline
# .\SharePoint_Security_Monitoring.ps1 -CheckIntegrity   # Check SharePoint file integrity
# .\SharePoint_Security_Monitoring.ps1 -ForceAlert       # Force email alert
# .\SharePoint_Security_Monitoring.ps1 -AlwaysSendReport # Always send email report
# .\SharePoint_Security_Monitoring.ps1 -NoAlertOnWarnings # Only email on critical alerts
# .\SharePoint_Security_Monitoring.ps1 -DisableEventCache # Disable event caching
# .\SharePoint_Security_Monitoring.ps1 -MaxLogSizeMB 500 # Process larger log files
# .\SharePoint_Security_Monitoring.ps1 -ManageTasks -TaskAction Install  # Install scheduled tasks
# .\SharePoint_Security_Monitoring.ps1 -ResetBookmarks   # Reset log reading bookmarks
# .\SharePoint_Security_Monitoring.ps1 -FullHistoricalScan # Scan 30 days of logs
# .\SharePoint_Security_Monitoring.ps1 -AutoApproveDLLs  # Auto-approve legitimate DLLs
# .\SharePoint_Security_Monitoring.ps1 -ReviewPendingDLLs # Review and approve pending DLLs

param(
    [string]$AlertEmail = "soc@goline.ch",
    [string]$SMTPServer = "exchange.goline.ch",
    [string]$FromEmail = "sharepoint-security@goline.ch",
    [switch]$SendDailySummary = $false,
    [switch]$ForceAlert = $false,
    [switch]$AlwaysSendReport = $false,  # NEW: Always send email report
    [switch]$NoAlertOnWarnings = $false,  # NEW: Don't send email for warnings (only critical)
    [switch]$ManageTasks = $false,
    [ValidateSet("Install", "Remove", "Status", "Reinstall")]
    [string]$TaskAction = "Status",
    [switch]$QuickScan = $false,
    [switch]$VerboseDLL = $false,  # Parameter for detailed DLL reporting
    [switch]$CreateBaseline = $false,  # Create DLL baseline
    [switch]$CheckIntegrity = $false,   # Check SharePoint file integrity
    [ValidateRange(1, 365)]
    [int]$MaxDaysToScan = 2,           # NEW: Maximum days to scan (default 2)
    [switch]$FullHistoricalScan = $false,  # NEW: Full historical scan
    [switch]$ResetBookmarks = $false,  # NEW: Reset log reading bookmarks
    [switch]$ClearCache = $false,      # NEW: Clear processed events cache
    [ValidateRange(1, 10000)]
    [int]$MaxLogSizeMB = 250,          # NEW: Skip logs larger than X MB (default increased to 250MB)
    [switch]$DisableEventCache = $false,  # NEW: Disable event caching (by default events are cached)
    [switch]$AutoApproveDLLs = $false,    # NEW v3.8: Auto-approve legitimate DLLs
    [switch]$ReviewPendingDLLs = $false   # NEW v3.8: Review pending DLLs for approval
)

# Set default parameter values for timeouts
$PSDefaultParameterValues = @{
    'Send-MailMessage:SmtpServerPort' = 25
    'Invoke-WebRequest:TimeoutSec' = 30
}

# Script timezone information
$scriptTimeZone = [System.TimeZoneInfo]::Local
Write-Host "Script timezone: $($scriptTimeZone.DisplayName)" -ForegroundColor Cyan

# Function to manage scheduled tasks (defined early)
function Manage-ScheduledTasks {
    param(
        [string]$Action,
        [switch]$Silent = $false,
        [string]$ScriptPath
    )

    # If ScriptPath not provided, try to get it
    if (-not $ScriptPath) {
        $ScriptPath = $script:MyInvocation.MyCommand.Path
        if (-not $ScriptPath) {
            # Try alternative method
            $ScriptPath = "C:\GOLINE\SharePoint_Security_Monitoring.ps1"
            if (-not (Test-Path $ScriptPath)) {
                Write-Host "[X] Script not found at: $ScriptPath" -ForegroundColor Red
                return
            }
        }
    }

    $taskDefinitions = @(
        @{
            Name = "SharePoint Security Monitor - Hourly"
            Description = "Runs SharePoint security monitoring every hour to detect threats"
            Arguments = ""
            TriggerType = "Hourly"
        },
        @{
            Name = "SharePoint Security Monitor - Daily Report"
            Description = "Sends daily SharePoint security summary report at 8 AM"
            Arguments = "-SendDailySummary -AlwaysSendReport"
            TriggerType = "Daily"
        },
        @{
            Name = "SharePoint Security Monitor - Startup"
            Description = "Runs security check when system starts"
            Arguments = ""
            TriggerType = "Startup"
        }
    )

    switch ($Action) {
        "Check" {
            $existingTasks = @(Get-ScheduledTask -TaskName "SharePoint Security Monitor*" -ErrorAction SilentlyContinue)
            $expectedCount = $taskDefinitions.Count

            if ($existingTasks.Count -eq $expectedCount) {
                # All tasks exist, check if they're properly configured
                $allValid = $true
                foreach ($task in $existingTasks) {
                    if ($task.State -eq "Disabled" -or $task.Settings.Enabled -eq $false) {
                        $allValid = $false
                        break
                    }
                }
                return $allValid
            }
            return $false
        }

        "Status" {
            Write-Host "`nCurrent SharePoint Security Tasks:" -ForegroundColor Yellow
            $tasks = Get-ScheduledTask -TaskName "SharePoint Security Monitor*" -ErrorAction SilentlyContinue

            if ($tasks) {
                $tasks | ForEach-Object {
                    $info = Get-ScheduledTaskInfo -TaskName $_.TaskName -ErrorAction SilentlyContinue
                    [PSCustomObject]@{
                        TaskName = $_.TaskName
                        State = $_.State
                        LastRun = $info.LastRunTime
                        NextRun = $info.NextRunTime
                        LastResult = $info.LastTaskResult
                    }
                } | Format-Table -AutoSize
            } else {
                Write-Host "No SharePoint Security tasks found." -ForegroundColor Yellow
            }
        }

        "Install" {
            if (-not $Silent) {
                Write-Host "`nInstalling SharePoint Security tasks..." -ForegroundColor Yellow
            }

            $created = 0
            $updated = 0

            foreach ($taskDef in $taskDefinitions) {
                if (-not $Silent) {
                    Write-Host "`n  Task: $($taskDef.Name)" -ForegroundColor Cyan
                }

                # Check if exists
                $existingTask = Get-ScheduledTask -TaskName $taskDef.Name -ErrorAction SilentlyContinue
                if ($existingTask) {
                    if (-not $Silent) {
                        Write-Host "    [!] Task already exists" -ForegroundColor Yellow
                        Write-Host "    [-] Removing old version..." -ForegroundColor Yellow
                    }
                    Unregister-ScheduledTask -TaskName $taskDef.Name -Confirm:$false
                    $updated++
                } else {
                    $created++
                }

                # Use schtasks.exe for more reliable task creation
                try {
                    $taskName = $taskDef.Name
                    $arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$ScriptPath`" $($taskDef.Arguments)"

                    # Create the task using schtasks.exe
                    if ($taskName -like "*Hourly*") {
                        # Hourly task
                        $result = schtasks.exe /Create /TN "$taskName" `
                            /TR "powershell.exe $arguments" `
                            /SC HOURLY /MO 1 `
                            /RU SYSTEM /RL HIGHEST `
                            /F 2>&1
                    }
                    elseif ($taskName -like "*Daily*") {
                        # Daily task at 8 AM
                        $result = schtasks.exe /Create /TN "$taskName" `
                            /TR "powershell.exe $arguments" `
                            /SC DAILY /ST 08:00 `
                            /RU SYSTEM /RL HIGHEST `
                            /F 2>&1
                    }
                    elseif ($taskName -like "*Startup*") {
                        # Startup task
                        $result = schtasks.exe /Create /TN "$taskName" `
                            /TR "powershell.exe $arguments" `
                            /SC ONSTART `
                            /RU SYSTEM /RL HIGHEST `
                            /F 2>&1
                    }

                    if ($LASTEXITCODE -eq 0) {
                        if (-not $Silent) {
                            Write-Host "    [+] Task created successfully" -ForegroundColor Green
                        }
                    } else {
                        throw "schtasks.exe failed: $result"
                    }

                } catch {
                    if (-not $Silent) {
                        Write-Host "    [X] Failed to create task: $_" -ForegroundColor Red
                    }
                }
            }

            if (-not $Silent) {
                Write-Host "`n[Summary]" -ForegroundColor Cyan
                Write-Host "  Created: $created new tasks" -ForegroundColor Green
                Write-Host "  Updated: $updated existing tasks" -ForegroundColor Yellow
                Write-Host "`nTask installation complete!" -ForegroundColor Green
            }
        }
    }
}

# CHECK AND INSTALL TASKS AT STARTUP (ALWAYS, UNLESS MANAGING TASKS)
$currentScriptPath = $MyInvocation.MyCommand.Path

if (-not $ManageTasks -and -not $ReviewPendingDLLs) {
    Write-Host "Checking scheduled tasks..." -ForegroundColor Cyan
    $tasksValid = Manage-ScheduledTasks -Action "Check" -ScriptPath $currentScriptPath

    if (-not $tasksValid) {
        Write-Host "[!] Scheduled tasks are missing or misconfigured" -ForegroundColor Yellow
        Write-Host "[>] Installing/updating scheduled tasks..." -ForegroundColor Yellow
        Manage-ScheduledTasks -Action "Install" -Silent:$false -ScriptPath $currentScriptPath
        Write-Host ""
    } else {
        Write-Host "[OK] All scheduled tasks are properly configured" -ForegroundColor Green
    }
}

# Handle task management if requested
if ($ManageTasks) {
    Write-Host @"

=========================================================
   SharePoint Security Task Management
=========================================================
"@ -ForegroundColor Cyan

    Manage-ScheduledTasks -Action $TaskAction -ScriptPath $currentScriptPath

    if ($TaskAction -eq "Install") {
        $testNow = Read-Host "`nRun a security scan test now? [Y/N]"
        if ($testNow -eq 'Y') {
            Write-Host "`nRunning test..." -ForegroundColor Yellow
            Start-ScheduledTask -TaskName "SharePoint Security Monitor - Hourly"
            Start-Sleep -Seconds 3

            $info = Get-ScheduledTaskInfo -TaskName "SharePoint Security Monitor - Hourly"
            if ($info.LastTaskResult -eq 0) {
                Write-Host "Test successful!" -ForegroundColor Green
            } else {
                Write-Host "Test completed with code: $($info.LastTaskResult)" -ForegroundColor Yellow
            }
        }
    }

    # Exit after task management
    exit 0
}

$LogPath = "C:\GOLINE\SharePoint_Monitoring\Logs"
$ReportPath = "C:\GOLINE\SharePoint_Monitoring\Reports"
$BaselinePath = "C:\GOLINE\SharePoint_Monitoring\Baselines"
$BookmarkPath = "C:\GOLINE\SharePoint_Monitoring\Bookmarks"  # NEW
$CachePath = "C:\GOLINE\SharePoint_Monitoring\Cache"        # NEW
$LogFile = "$LogPath\SecurityMonitor_$(Get-Date -Format 'yyyyMMdd').log"
$BookmarkFile = "$BookmarkPath\LogReadingBookmarks.json"    # NEW
$CacheFile = "$CachePath\ProcessedEvents_$(Get-Date -Format 'yyyyMMdd').json"  # NEW
$PendingDLLFile = "$BaselinePath\PendingDLLApproval.json"  # NEW v3.8
$ApprovedDLLFile = "$BaselinePath\ApprovedDLLs.json"       # NEW v3.8

# Create directories if they don't exist
@($LogPath, $ReportPath, $BaselinePath, $BookmarkPath, $CachePath) | ForEach-Object {
    if (!(Test-Path $_)) {
        New-Item -ItemType Directory -Path $_ -Force | Out-Null
    }
}

# Log rotation for script logs
Get-ChildItem $LogPath -Filter "SecurityMonitor_*.log" |
    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } |
    Remove-Item -Force

# NEW v3.8: Handle DLL review mode
if ($ReviewPendingDLLs) {
    Write-Host @"

=========================================================
   DLL Review and Approval Mode
=========================================================
"@ -ForegroundColor Cyan

    if (Test-Path $PendingDLLFile) {
        $pendingDLLs = Get-Content $PendingDLLFile -Raw | ConvertFrom-Json

        if ($pendingDLLs.PendingDLLs.Count -eq 0) {
            Write-Host "No pending DLLs to review." -ForegroundColor Green
            exit 0
        }

        Write-Host "Found $($pendingDLLs.PendingDLLs.Count) pending DLLs for review:" -ForegroundColor Yellow

        # Load approved DLLs
        $approvedDLLs = @{ ApprovedDLLs = @() }
        if (Test-Path $ApprovedDLLFile) {
            $approvedDLLs = Get-Content $ApprovedDLLFile -Raw | ConvertFrom-Json
        }

        $approved = 0
        $rejected = 0

        foreach ($dll in $pendingDLLs.PendingDLLs) {
            Write-Host "`n----------------------------------------" -ForegroundColor Cyan
            Write-Host "DLL: $($dll.Name)" -ForegroundColor Yellow
            Write-Host "Path: $($dll.Path)" -ForegroundColor Gray
            Write-Host "Size: $('{0:N2}' -f ($dll.Size / 1KB)) KB" -ForegroundColor Gray
            Write-Host "Created: $($dll.Created)" -ForegroundColor Gray
            Write-Host "Modified: $($dll.Modified)" -ForegroundColor Gray
            Write-Host "Hash: $($dll.Hash.Substring(0,16))..." -ForegroundColor Gray

            if ($dll.SignatureStatus) {
                Write-Host "Signature: $($dll.SignatureStatus) $(if($dll.SignerCertificate) { "by $($dll.SignerCertificate)" })" -ForegroundColor $(if($dll.SignatureStatus -eq 'Valid') {'Green'} else {'Red'})
            }

            Write-Host "`nDetection reason: $($dll.Reason)" -ForegroundColor Yellow

            $response = Read-Host "`nApprove this DLL? [Y]es / [N]o / [S]kip / [Q]uit"

            switch ($response.ToUpper()) {
                'Y' {
                    # Add to approved list
                    $approvedDLLs.ApprovedDLLs += @{
                        Name = $dll.Name
                        Hash = $dll.Hash
                        Path = $dll.Path
                        ApprovedDate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                        ApprovedBy = $env:USERNAME
                        Reason = "Manual approval"
                    }
                    $approved++
                    Write-Host "DLL approved." -ForegroundColor Green
                }
                'N' {
                    $rejected++
                    Write-Host "DLL rejected - will continue to be flagged as suspicious." -ForegroundColor Red
                }
                'S' {
                    Write-Host "DLL skipped - will remain in pending list." -ForegroundColor Yellow
                }
                'Q' {
                    Write-Host "Quitting review process..." -ForegroundColor Yellow
                    break
                }
            }
        }

        # Save approved DLLs
        if ($approved -gt 0) {
            $approvedDLLs | ConvertTo-Json -Depth 3 | Out-File $ApprovedDLLFile -Force
            Write-Host "`nSaved $approved approved DLLs to whitelist." -ForegroundColor Green
        }

        # Remove processed DLLs from pending
        $remainingPending = $pendingDLLs.PendingDLLs | Where-Object {
            $hash = $_.Hash
            -not ($approvedDLLs.ApprovedDLLs | Where-Object { $_.Hash -eq $hash })
        }

        @{ PendingDLLs = $remainingPending } | ConvertTo-Json -Depth 3 | Out-File $PendingDLLFile -Force

        Write-Host "`nReview complete: Approved=$approved, Rejected=$rejected, Remaining=$($remainingPending.Count)" -ForegroundColor Cyan
    } else {
        Write-Host "No pending DLLs file found. Run a security scan first." -ForegroundColor Yellow
    }

    exit 0
}

# Handle reset bookmarks if requested
if ($ResetBookmarks) {
    Remove-Item $BookmarkFile -Force -ErrorAction SilentlyContinue
    Write-Host "[!] Bookmarks reset" -ForegroundColor Yellow
}

# Handle clear cache if requested
if ($ClearCache) {
    Remove-Item "$CachePath\*.json" -Force -ErrorAction SilentlyContinue
    Write-Host "[!] Cache cleared" -ForegroundColor Yellow
}

# Clean old cache files (keep only last 7 days)
Get-ChildItem $CachePath -Filter "ProcessedEvents_*.json" -ErrorAction SilentlyContinue |
    Where-Object { $_.CreationTime -lt (Get-Date).AddDays(-7) } |
    Remove-Item -Force

# Initialize results collection
$global:SecurityResults = @{
    StartTime = Get-Date
    EndTime = $null
    Alerts = @()
    Warnings = @()
    Info = @()
    Statistics = @{}
    ModifiedDLLDetails = @()  # NEW v3.9
    NewDLLDetails = @()       # NEW v3.9
}

# Initialize performance monitoring
$global:PerformanceTimers = @{}
$global:MainTimer = [System.Diagnostics.Stopwatch]::StartNew()

# Function to track performance
function Start-PerformanceTimer {
    param([string]$SectionName)
    $global:PerformanceTimers[$SectionName] = [System.Diagnostics.Stopwatch]::StartNew()
}

function Stop-PerformanceTimer {
    param([string]$SectionName)
    if ($global:PerformanceTimers.ContainsKey($SectionName)) {
        $global:PerformanceTimers[$SectionName].Stop()
        $elapsed = $global:PerformanceTimers[$SectionName].Elapsed.TotalSeconds
        Write-SecurityLog "  Section '$SectionName' completed in $([math]::Round($elapsed, 2)) seconds" "INFO"
    }
}

# Function to backup critical files
function Backup-CriticalFile {
    param([string]$FilePath)
    if (Test-Path $FilePath) {
        $backupPath = "$FilePath.backup_$(Get-Date -Format 'yyyyMMddHHmmss')"
        Copy-Item $FilePath $backupPath -Force
        # Keep only last 5 backups
        Get-ChildItem "$FilePath.backup_*" |
            Sort-Object CreationTime -Descending |
            Select-Object -Skip 5 |
            Remove-Item -Force
    }
}

# NEW: Bookmark management functions
function Get-LogBookmark {
    param([string]$LogFile)

    $bookmarks = @{}
    if (Test-Path $BookmarkFile) {
        try {
            $bookmarksJson = Get-Content $BookmarkFile -Raw | ConvertFrom-Json
            $bookmarksJson.PSObject.Properties | ForEach-Object { $bookmarks[$_.Name] = $_.Value }
        } catch {
            Write-SecurityLog "Could not read bookmarks file, starting fresh" "WARNING"
        }
    }

    if ($bookmarks.ContainsKey($LogFile)) {
        # Check if file was modified since bookmark
        $fileInfo = Get-Item $LogFile -ErrorAction SilentlyContinue
        if ($fileInfo) {
            $bookmarkTime = if ($bookmarks[$LogFile].LastReadTime) { [DateTime]::Parse($bookmarks[$LogFile].LastReadTime) } else { [DateTime]::MinValue }
            $bookmarkFileHash = $bookmarks[$LogFile].FileHash

            # Calculate current file hash for first 1KB to detect rotation
            $currentHash = ""
            try {
                $stream = [System.IO.FileStream]::new($LogFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                $bytes = New-Object byte[] ([Math]::Min(1024, $stream.Length))
                $stream.Read($bytes, 0, $bytes.Length) | Out-Null
                $stream.Close()
                $currentHash = [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes))
            } catch {}

            # If hash changed, file was rotated
            if ($bookmarkFileHash -and $currentHash -and $bookmarkFileHash -ne $currentHash) {
                Write-SecurityLog "  Log file rotated (hash mismatch), resetting bookmark" "INFO"
                return @{
                    LastPosition = 0
                    LastReadTime = [DateTime]::MinValue
                    FileSize = 0
                    FileHash = $currentHash
                }
            }
        }

        return @{
            LastPosition = $bookmarks[$LogFile].LastPosition
            LastReadTime = if ($bookmarks[$LogFile].LastReadTime) { [DateTime]::Parse($bookmarks[$LogFile].LastReadTime) } else { [DateTime]::MinValue }
            FileSize = $bookmarks[$LogFile].FileSize
            FileHash = $bookmarks[$LogFile].FileHash
        }
    }

    return @{
        LastPosition = 0
        LastReadTime = [DateTime]::MinValue
        FileSize = 0
        FileHash = ""
    }
}

function Set-LogBookmark {
    param(
        [string]$LogFile,
        [long]$Position,
        [DateTime]$LastReadTime,
        [long]$FileSize,
        [string]$FileHash
    )

    $bookmarks = @{}
    if (Test-Path $BookmarkFile) {
        try {
            $bookmarksJson = Get-Content $BookmarkFile -Raw | ConvertFrom-Json
            $bookmarksJson.PSObject.Properties | ForEach-Object { $bookmarks[$_.Name] = $_.Value }
        } catch {
            # If reading fails, start fresh
        }
    }

    $bookmarks[$LogFile] = @{
        LastPosition = $Position
        LastReadTime = $LastReadTime.ToString("yyyy-MM-dd HH:mm:ss")
        FileSize = $FileSize
        FileHash = $FileHash
    }

    Backup-CriticalFile -FilePath $BookmarkFile
    $bookmarks | ConvertTo-Json -Depth 3 | Out-File $BookmarkFile -Force
}

# NEW: Cache management functions
function Test-EventProcessed {
    param(
        [string]$EventHash,
        [string]$EventType
    )

    if ($DisableEventCache) {
        return $false
    }

    if (Test-Path $CacheFile) {
        try {
            $cache = Get-Content $CacheFile -Raw | ConvertFrom-Json
            return $cache.ProcessedEvents -contains "$EventType|$EventHash"
        } catch {
            return $false
        }
    }
    return $false
}

function Add-ProcessedEvent {
    param(
        [string]$EventHash,
        [string]$EventType
    )

    if ($DisableEventCache) {
        return
    }

    $cache = @{ ProcessedEvents = @() }
    if (Test-Path $CacheFile) {
        try {
            $cache = Get-Content $CacheFile -Raw | ConvertFrom-Json
        } catch {
            # If reading fails, start fresh
        }
    }

    # Ensure ProcessedEvents is an array
    if (-not $cache.ProcessedEvents) {
        $cache = @{ ProcessedEvents = @() }
    }

    # Add new event (limit cache size to prevent unbounded growth)
    $cache.ProcessedEvents += "$EventType|$EventHash"

    # Keep only last 10000 events
    if ($cache.ProcessedEvents.Count -gt 10000) {
        $cache.ProcessedEvents = $cache.ProcessedEvents[-10000..-1]
    }

    Backup-CriticalFile -FilePath $CacheFile
    $cache | ConvertTo-Json | Out-File $CacheFile -Force
}

# NEW: Function for incremental log reading with better error handling
function Read-LogIncremental {
    param(
        [string]$LogPath,
        [string[]]$Patterns,  # CHANGED: Now accepts array of patterns
        [hashtable]$Bookmark
    )

    $currentFile = Get-Item $LogPath -ErrorAction SilentlyContinue
    if (-not $currentFile) {
        Write-SecurityLog "  Log file not found: $LogPath" "WARNING"
        return @()
    }

    $results = @()

    # Check if file is too large
    if ($currentFile.Length -gt ($MaxLogSizeMB * 1MB)) {
        Write-SecurityLog "  Skipping large log file ($('{0:N2}' -f ($currentFile.Length / 1MB)) MB): $($currentFile.Name) - Use -MaxLogSizeMB parameter to increase limit" "WARNING"
        return $results
    }

    # Calculate file hash for rotation detection
    $currentFileHash = ""
    try {
        $hashStream = [System.IO.FileStream]::new($LogPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $bytes = New-Object byte[] ([Math]::Min(1024, $hashStream.Length))
        $hashStream.Read($bytes, 0, $bytes.Length) | Out-Null
        $hashStream.Close()
        $currentFileHash = [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes))
    } catch {}

    # If the file is smaller than bookmark or hash changed, it was rotated
    if ($currentFile.Length -lt $Bookmark.FileSize -or ($Bookmark.FileHash -and $currentFileHash -and $Bookmark.FileHash -ne $currentFileHash)) {
        Write-SecurityLog "  Log rotated, reading from start: $($currentFile.Name)" "INFO"
        $Bookmark.LastPosition = 0
        $Bookmark.FileHash = $currentFileHash
    }

    # Read only if there are new data
    if ($currentFile.Length -gt $Bookmark.LastPosition) {
        $stream = $null
        $reader = $null

        try {
            # Try to open with proper error handling
            try {
                $stream = [System.IO.FileStream]::new($LogPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
            } catch [System.IO.IOException] {
                if ($_.Exception.Message -match "being used by another process") {
                    Write-SecurityLog "  Log file locked by another process, skipping: $($currentFile.Name)" "WARNING"
                    return $results
                }
                throw
            }

            $reader = [System.IO.StreamReader]::new($stream)

            # Go to last read position
            if ($Bookmark.LastPosition -gt 0 -and $Bookmark.LastPosition -le $stream.Length) {
                $stream.Position = $Bookmark.LastPosition
            }

            $newDataSize = $currentFile.Length - $Bookmark.LastPosition
            Write-SecurityLog "    Reading $('{0:N2}' -f ($newDataSize / 1KB)) KB of new data" "INFO"

            $lineCount = 0
            $buffer = New-Object System.Text.StringBuilder

            # For very large files, use buffered reading
            if ($newDataSize -gt 100MB) {
                Write-SecurityLog "    Large file detected, using buffered reading" "INFO"
                $bufferSize = 65536 # 64KB buffer
                $charBuffer = New-Object char[] $bufferSize

                while (-not $reader.EndOfStream) {
                    $charsRead = $reader.Read($charBuffer, 0, $bufferSize)
                    if ($charsRead -gt 0) {
                        $buffer.Append($charBuffer, 0, $charsRead) | Out-Null

                        # Process complete lines in buffer
                        $bufferText = $buffer.ToString()
                        $lines = $bufferText -split "`n"

                        # Keep the last incomplete line in buffer
                        if ($lines.Count -gt 1) {
                            $buffer.Clear() | Out-Null
                            $buffer.Append($lines[-1]) | Out-Null

                            # Process complete lines
                            for ($i = 0; $i -lt $lines.Count - 1; $i++) {
                                $line = $lines[$i].TrimEnd("`r")
                                $lineCount++

                                # Check against all patterns
                                foreach ($pattern in $Patterns) {
                                    if ($line -match $pattern) {
                                        $results += @{
                                            Line = $line
                                            LineNumber = $lineCount
                                            Pattern = $pattern
                                            PatternName = $pattern
                                        }
                                    }
                                }

                                # Progress update every 10000 lines
                                if ($lineCount % 10000 -eq 0) {
                                    Write-Progress -Activity "Reading $($currentFile.Name)" -Status "$lineCount lines processed" -PercentComplete (($stream.Position / $currentFile.Length) * 100)
                                }
                            }
                        }
                    }
                }

                # Process any remaining text in buffer
                if ($buffer.Length -gt 0) {
                    $line = $buffer.ToString().TrimEnd("`r`n")
                    $lineCount++
                    foreach ($pattern in $Patterns) {
                        if ($line -match $pattern) {
                            $results += @{
                                Line = $line
                                LineNumber = $lineCount
                                Pattern = $pattern
                                PatternName = $pattern
                            }
                        }
                    }
                }
            } else {
                # Regular line-by-line reading for smaller files
                while (-not $reader.EndOfStream) {
                    $line = $reader.ReadLine()
                    $lineCount++

                    # Check against all patterns
                    foreach ($pattern in $Patterns) {
                        if ($line -match $pattern) {
                            $results += @{
                                Line = $line
                                LineNumber = $lineCount
                                Pattern = $pattern
                                PatternName = $pattern
                            }
                        }
                    }

                    # Progress update every 1000 lines
                    if ($lineCount % 1000 -eq 0) {
                        Write-Progress -Activity "Reading $($currentFile.Name)" -Status "$lineCount lines processed" -PercentComplete (($stream.Position / $currentFile.Length) * 100)
                    }
                }
            }

            Write-Progress -Activity "Reading $($currentFile.Name)" -Completed

            # Update bookmark
            $newPosition = $stream.Position

            Set-LogBookmark -LogFile $LogPath -Position $newPosition -LastReadTime (Get-Date) -FileSize $currentFile.Length -FileHash $currentFileHash

            Write-SecurityLog "    Found $($results.Count) total matches in $lineCount new lines" "INFO"
        } catch {
            Write-SecurityLog "    Error reading log: $_" "ERROR"
        } finally {
            if ($reader) { $reader.Close() }
            if ($stream) { $stream.Close() }
        }
    } else {
        Write-SecurityLog "    No new data since last scan" "INFO"
    }

    return $results
}

# NEW v3.9: Function to analyze DLL creation patterns
function Get-DLLCreationPattern {
    param([string]$Path)

    # Safety check
    if (-not $global:SecurityThresholds) {
        $global:SecurityThresholds = @{
            DLLCreationHourlyLimit = 500
            SharePointComponentLimit = 1000
            ReputationAutoApproveScore = 5
            SuspicionScoreThreshold = 85
        }
    }

    $patternFile = "$CachePath\DLLCreationPatterns.json"
    $patterns = @{}

    if (Test-Path $patternFile) {
        try {
            $patternsJson = Get-Content $patternFile -Raw | ConvertFrom-Json
            $patternsJson.PSObject.Properties | ForEach-Object {
                $patterns[$_.Name] = $_.Value
            }
        } catch {
            $patterns = @{}
        }
    }

    # Analyze pattern last 7 days
    $now = Get-Date
    $cutoffTime = $now.AddDays(-7)

    # Clean old data
    $keysToRemove = @()
    foreach ($key in $patterns.Keys) {
        if ($patterns[$key].LastSeen) {
            $lastSeen = [DateTime]::Parse($patterns[$key].LastSeen)
            if ($lastSeen -lt $cutoffTime) {
                $keysToRemove += $key
            }
        }
    }

    foreach ($key in $keysToRemove) {
        $patterns.Remove($key)
    }

    # Add/update current pattern
    $hourKey = $now.ToString("HH")
    $patternKey = "$Path|$hourKey"

    if ($patterns.ContainsKey($patternKey)) {
        $patterns[$patternKey].Count++
        $patterns[$patternKey].LastSeen = $now.ToString("yyyy-MM-dd HH:mm:ss")
    } else {
        $patterns[$patternKey] = @{
            Count = 1
            FirstSeen = $now.ToString("yyyy-MM-dd HH:mm:ss")
            LastSeen = $now.ToString("yyyy-MM-dd HH:mm:ss")
        }
    }

    # Save patterns
    $patterns | ConvertTo-Json -Depth 3 | Out-File $patternFile -Force

    # Check if pattern is anomalous
    $isAnomalous = $false
    $reason = ""

    # Check 1: Too many creations in same hour
    if ($patterns[$patternKey].Count -gt 50) {
        $isAnomalous = $true
        $reason = "Excessive DLL creation in same hour: $($patterns[$patternKey].Count)"
    }

    # Check 2: Night-time creations
    $hour = [int]$hourKey
    if ($hour -ge 2 -and $hour -le 5) {
        # Count night creations
        $nightCreations = 0
        foreach ($key in $patterns.Keys) {
            if ($key -match "\|0[2-5]$") {
                $nightCreations += $patterns[$key].Count
            }
        }

        if ($nightCreations -gt 10) {
            $isAnomalous = $true
            $reason = "Suspicious night-time DLL creation pattern"
        }
    }

    return @{
        IsAnomalous = $isAnomalous
        Reason = $reason
        CurrentHourCount = $patterns[$patternKey].Count
    }
}

# Initialize CVE indicators - Using real CVEs from 2023
$CVEIndicators = @{
    WebshellsFound = @()
    SuspiciousUploads = @()
    ExploitAttempts = @()
    AttackerIPs = @{}
    InternalSuspiciousActivity = @{}
    ToolPaneExploits = @()  # For CVE-2023-29357
    MachineKeyTheft = @()   # For machine key theft detection
    SignOutExploits = @()   # For SignOut.aspx monitoring
    RansomwareIndicators = @()  # For ransomware detection
    DLLPayloads = @()       # For DLL webshells
    CriticalPeriodActivity = @()  # For specific date range activity
    PostExploitationTools = @()  # For Mimikatz, Impacket, PsExec
    C2Communications = @()  # For C2 domain/IP communications
    ThreatActorActivity = @()  # For tracking threat actor patterns
    DefenderDisabled = @()  # NEW: For Defender disabling attempts
    GPOModifications = @()  # NEW: For GPO changes
    LSASSAccess = @()       # NEW: For LSASS memory access
    ReflectiveInjection = @() # NEW: For reflective DLL injection
    AllAttacks = @()        # NEW v3.8: Comprehensive attack tracking
}

# Comprehensive SharePoint Components List
$global:SharePointKnownComponents = @(
    "default", "home", "pages", "sitepages", "lists", "libraries",
    "allitems", "dispform", "editform", "newform", "upload", "download",
    "viewlsts", "mcontent", "userdisp", "listfeed", "viewpage",
    "settings", "admin", "farm", "application", "site", "web",
    "generalapplicationsettings", "farmcredentialmanagement",
    "deploysolution", "managefeatures", "backuprestore", "applications",
    "accessdenied", "error", "login", "signout", "logout", "authenticate",
    "unauthorized", "forbidden", "notfound", "servererror", "closeconnection",
    "incomingemail", "outgoingemail", "emailsettings", "workflow",
    "allposts", "posts", "categories", "archive", "newsfeed", "comments",
    "v4master", "oslo", "seattle", "errorv15", "applicationv15",
    "search", "results", "people", "searchresults"
)
# Known malicious IPs from recent threat intelligence
$KnownAttackerIPs = @(
    "107.191.58.76",      # Example threat actor IP
    "104.238.159.149",    # Example threat actor IP
    "96.9.125.147",       # Example threat actor IP
    "134.199.202.205",    # Example threat actor IP
    "188.130.206.168",    # Example threat actor IP
    "131.226.2.6",        # Example C2 server
    "65.38.121.198"       # Example C2 server
)

# Known C2 domains
$KnownC2Domains = @(
    "update.updatemicfosoft.com",
    "msupdate.updatemicfosoft.com",
    "c34718cbb4c6.ngrok-free.app"  # Example ngrok tunnel
)

# Known malicious file hashes (examples - replace with real threat intelligence)
$KnownMaliciousHashes = @{
    # Web shells
    "92bb4ddb98eeaf11fc15bb32e71d0a63256a0ed826a03ba293ce3a8bf057a514" = "spinstall0.aspx"
    "24480dbe306597da1ba393b6e30d542673066f98826cc07ac4b9033137f37dbf" = "Webshell variant A"
    "b5a78616f709859a0d9f830d28ff2f9dbbb2387df1753739407917e96dadf6b0" = "Webshell variant B"
    # IIS backdoors
    "4c1750a14915bf2c0b093c2cb59063912dfa039a2adfe6d26d6914804e2ae928" = "IIS_backdoor.dll"
    "83705c75731e1d590b08f9357bc3b0f04741e92a033618736387512b40dab060" = "IIS_backdoor.dll"
    # Tools
    "d6da885c90a5d1fb88d0a3f0b5d9817a82d5772d5510a0773c80ca581ce2486d" = "SharpTool.exe"
    "62881359e75c9e8899c4bc9f452ef9743e68ce467f8b3e4398bebacde9550dea" = "xd.exe - Fast reverse proxy"
}

# SharePoint legitimate files to exclude
$SharePointLegitimatePatterns = @(
    "\\16\\TEMPLATE\\LAYOUTS\\",
    "\\16\\ISAPI\\",
    "\\PWA\\",
    "\\SearchAdmin\\",
    "\\BDC\\",
    "workflow",
    "wsdl\.aspx$",
    "disco\.aspx$"
)

# ENHANCED: Legitimate DLL patterns and trusted vendors
$LegitimateSecurityVendors = @(
    "ESET",
    "Sophos",
    "Symantec",
    "McAfee",
    "TrendMicro",
    "Kaspersky",
    "BitDefender",
    "CrowdStrike",
    "SentinelOne",
    "Microsoft Defender",
    "Windows Defender"
)

# Legitimate ASP.NET temporary DLL patterns
$LegitimateASPNETPatterns = @(
    "^App_Web_.*\.dll$",
    "^App_GlobalResources.*\.dll$",
    "^App_Browsers.*\.dll$",
    "^App_global\.asax.*\.dll$"
)

# Legitimate Microsoft/System DLL patterns
$LegitimateSystemDLLs = @(
    "^api-ms-win-.*\.dll$",
    "^ucrtbase\.dll$",
    "^vcruntime.*\.dll$",
    "^msvcp.*\.dll$",
    "^concrt.*\.dll$",
    "^Microsoft\..*\.dll$",
    "^System\..*\.dll$"
)

# SharePoint legitimate DLL patterns
$SharePointLegitimeDLLs = @(
    "AddGallery\.Globalization\.resources\.dll$",
    "AddGallery\.OfficeOnlineProvider\.dll$",
    "Microsoft\.Online\.SharePoint.*\.dll$",
    "Microsoft\.SharePoint.*\.dll$",
    "Microsoft\.Office\..*\.dll$",
    ".*\.resources\.dll$"  # All resource DLLs
)


# WHITELIST: DLL legittime in _app_bin
$LegitimateAppBinDLLs = @(
    "Microsoft.FileServices.BETA.dll",
    "Microsoft.FileServices.ServerStub.Beta.dll",
    "Microsoft.FileServices.ServerStub.V1.dll",
    "Microsoft.FileServices.ServerStub.V2.dll",
    "Microsoft.FileServices.V1.dll",
    "Microsoft.FileServices.V2.dll",
    "Microsoft.Office.Discovery.Soap.dll",
    "Microsoft.Office.*",
    "Microsoft.SharePoint.*",
    "Microsoft.Online.*"
)
# Known legitimate software DLLs
$LegitimateToolDLLs = @{
    "7z.dll" = @{
        Vendors = @("Igor Pavlov", "7-Zip")
        MinSize = 50KB
        MaxSize = 2MB
    }
    "unrar.dll" = @{
        Vendors = @("Alexander Roshal", "win.rar GmbH")
        MinSize = 100KB
        MaxSize = 1MB
    }
}

# NEW v3.8: Load approved DLLs
$ApprovedDLLs = @{}
if (Test-Path $ApprovedDLLFile) {
    try {
        $approvedJson = Get-Content $ApprovedDLLFile -Raw | ConvertFrom-Json
        $approvedJson.ApprovedDLLs | ForEach-Object {
            $ApprovedDLLs[$_.Hash] = $_
        }
        Write-SecurityLog "Loaded $($ApprovedDLLs.Count) approved DLLs from whitelist" "INFO"
    } catch {
        Write-SecurityLog "Could not load approved DLLs file" "WARNING"
    }
}

# Function to check if DLL is suspicious - ENHANCED v3.9
function Test-SuspiciousDLL {
    param(
        [System.IO.FileInfo]$File,
        [string]$BasePath
    )

    # Calculate hash
    $hash = (Get-FileHash $File.FullName -Algorithm SHA256).Hash

    # Check creation patterns first
    $creationPattern = Get-DLLCreationPattern -Path $File.DirectoryName
    if ($creationPattern.IsAnomalous) {
        return @{
            IsSuspicious = $true
            Reason = "Anomalous creation pattern: $($creationPattern.Reason)"
            Severity = "High"
            Hash = $hash
        }
    }

    # NEW v3.8: Check if in approved list first
    if ($ApprovedDLLs.ContainsKey($hash)) {
        # NEW v3.9: Check if approval expired
        if ($ApprovedDLLs[$hash].ExpiresAfter) {
            $expirationDate = [DateTime]::Parse($ApprovedDLLs[$hash].ExpiresAfter)
            if ($expirationDate -lt (Get-Date)) {
                # Remove expired approval
                $ApprovedDLLs.Remove($hash)
                @{ ApprovedDLLs = $ApprovedDLLs.Values } | ConvertTo-Json -Depth 3 | Out-File $ApprovedDLLFile -Force
            } else {
                if ($VerboseDLL) {
                    Write-Host "  [Approved] $($File.Name) - Previously approved on $($ApprovedDLLs[$hash].ApprovedDate)" -ForegroundColor Green
                }
                return @{ IsSuspicious = $false; IsApproved = $true }
            }
        } else {
            if ($VerboseDLL) {
                Write-Host "  [Approved] $($File.Name) - Previously approved on $($ApprovedDLLs[$hash].ApprovedDate)" -ForegroundColor Green
            }
            return @{ IsSuspicious = $false; IsApproved = $true }
        }
    }

    # 1. Check against known malicious hashes
    if ($KnownMaliciousHashes.ContainsKey($hash)) {
        return @{
            IsSuspicious = $true
            Reason = "Known Malicious Hash"
            Details = $KnownMaliciousHashes[$hash]
            Severity = "Critical"
        }
    }

    # 2. NEW v3.9: Enhanced validation for ASP.NET temporary DLLs
    if ($File.DirectoryName -match "Temporary ASP\.NET Files") {

        # Verifica che sia una compilazione ASP.NET legittima
        $isLegitimateCompilation = $false
        $suspicionReasons = @()

        # Check 1: Nome file deve seguire pattern ASP.NET
        if ($File.Name -match "^App_Web_.*\.([a-z0-9]{8})\.([a-z0-9]{8})\.dll$") {

            # Check 2: Verifica la presenza di file correlati (ASP.NET crea sempre gruppi di file)
            $hashPart = if ($File.Name -match "\.([a-z0-9]{8})\.dll$") { $Matches[1] } else { $null }
            if ($hashPart) {
                $relatedFiles = Get-ChildItem -Path $File.DirectoryName -Filter "*.$hashPart.*" -ErrorAction SilentlyContinue

                if ($relatedFiles.Count -lt 2) {
                    $suspicionReasons += "Isolated DLL without ASP.NET compilation artifacts"
                } else {
                    # Check 3: Verifica presenza di file .compiled
                    $compiledFile = $relatedFiles | Where-Object { $_.Extension -eq ".compiled" }
                    if (-not $compiledFile) {
                        $suspicionReasons += "Missing .compiled marker file"
                    } else {
                        # Check 4: Analizza il contenuto del file .compiled
                        try {
                            [xml]$compiledXml = Get-Content $compiledFile.FullName
                            if ($compiledXml.preserve -and $compiledXml.preserve.assembly) {
                                # Verifica che il nome assembly corrisponda
                                if ($compiledXml.preserve.assembly -ne $File.BaseName) {
                                    $suspicionReasons += "Assembly name mismatch in .compiled file"
                                } else {
                                    $isLegitimateCompilation = $true
                                }
                            }
                        } catch {
                            $suspicionReasons += "Invalid or corrupted .compiled file"
                        }
                    }
                }
            }

            # Check 5: Verifica timing con IIS requests
            if ($isLegitimateCompilation) {
                # Controlla se ci sono state richieste web legittime negli ultimi 5 minuti
                $compilationTime = $File.CreationTime
                $timeLowerBound = $compilationTime.AddMinutes(-5)
                $timeUpperBound = $compilationTime.AddMinutes(1)

                # Cerca nei log IIS recenti
                $iisLogPath = "C:\inetpub\logs\LogFiles"
                $recentIISLogs = Get-ChildItem $iisLogPath -Recurse -Filter "*.log" -ErrorAction SilentlyContinue |
                    Where-Object { $_.LastWriteTime -ge $timeLowerBound } |
                    Select-Object -First 1

                if ($recentIISLogs) {
                    # Cerca richieste ASPX nel periodo di compilazione
                    $legitimateRequest = $false
                    try {
                        $logContent = Get-Content $recentIISLogs.FullName -Tail 1000 |
                            Where-Object { $_ -match "\.aspx|\.asmx|\.ashx" -and $_ -notmatch "404|403|500" }

                        if ($logContent) {
                            foreach ($line in $logContent) {
                                if ($line -match '(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})') {
                                    $logTime = [DateTime]::Parse("$($Matches[1]) $($Matches[2])")
                                    if ($logTime -ge $timeLowerBound -and $logTime -le $timeUpperBound) {
                                        $legitimateRequest = $true
                                        break
                                    }
                                }
                            }
                        }
                    } catch {
                        # Log reading failed, be conservative
                    }

                    if (-not $legitimateRequest) {
                        $suspicionReasons += "No corresponding web requests found near compilation time"
                        $isLegitimateCompilation = $false
                    }
                }
            }

            # Check 6: Verifica dimensione file (le DLL ASP.NET hanno range tipici)
            if ($File.Length -lt 4KB -or $File.Length -gt 500KB) {
                $suspicionReasons += "Unusual size for ASP.NET compiled DLL: $('{0:N2}' -f ($File.Length / 1KB)) KB"
                $isLegitimateCompilation = $false
            }

            # Check 7: Verifica PE headers e imports
            try {
                $bytes = [System.IO.File]::ReadAllBytes($File.FullName)
                if ($bytes.Length -gt 1024) {
                    # Cerca pattern sospetti nel binario
                    $binaryString = [System.Text.Encoding]::ASCII.GetString($bytes, 0, [Math]::Min($bytes.Length, 10000))

                    # Pattern malevoli comuni
                    $maliciousPatterns = @(
                        "mimikatz",
                        "sekurlsa",
                        "WScript.Shell",
                        "cmd.exe",
                        "powershell.exe",
                        "net user",
                        "reg add",
                        "schtasks",
                        "meterpreter",
                        "reverse_tcp",
                        "bind_tcp"
                    )

                    foreach ($pattern in $maliciousPatterns) {
                        if ($binaryString -match [regex]::Escape($pattern)) {
                            $suspicionReasons += "Suspicious string found: $pattern"
                            $isLegitimateCompilation = $false
                            break
                        }
                    }

                    # Verifica imports sospetti
                    if ($binaryString -match "VirtualAlloc|WriteProcessMemory|CreateRemoteThread|LoadLibrary") {
                        $suspicionReasons += "Suspicious API imports detected"
                        $isLegitimateCompilation = $false
                    }
                }
            } catch {
                # Binary analysis failed, be conservative
                $suspicionReasons += "Unable to analyze binary content"
            }

        } else {
            $suspicionReasons += "Does not match ASP.NET compilation pattern"
        }

        # Decision logic
        if ($isLegitimateCompilation -and $suspicionReasons.Count -eq 0) {
            # Solo se TUTTI i controlli passano
            if ($VerboseDLL) {
                Write-Host "  [Verified ASP.NET] $($File.Name) - All security checks passed" -ForegroundColor Green
            }

            # Add to temporary whitelist with short expiration
            if (-not $ApprovedDLLs.ContainsKey($hash)) {
                $ApprovedDLLs[$hash] = @{
                    Name = $File.Name
                    Hash = $hash
                    Path = $File.FullName
                    ApprovedDate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                    ApprovedBy = "Auto-approval (Verified ASP.NET)"
                    Reason = "Passed all ASP.NET compilation security checks"
                    ExpiresAfter = (Get-Date).AddHours(4).ToString("yyyy-MM-dd HH:mm:ss")  # Short expiration
                    SecurityChecks = @{
                        HasCompiledFile = $true
                        HasWebRequests = $true
                        NormalSize = $true
                        NoSuspiciousContent = $true
                    }
                }

                @{ ApprovedDLLs = $ApprovedDLLs.Values } | ConvertTo-Json -Depth 3 | Out-File $ApprovedDLLFile -Force
            }

            return @{ IsSuspicious = $false; IsApproved = $true }
        } else {
            # Suspicious - report it
            return @{
                IsSuspicious = $true
                Reason = "Failed ASP.NET validation: " + ($suspicionReasons -join "; ")
                Severity = if ($suspicionReasons.Count -gt 2) { "High" } else { "Medium" }
                Details = $suspicionReasons -join "; "
                Hash = $hash
            }
        }
    }

    # NUOVO: Auto-approvazione intelligente per DLL SharePoint compilate
    if ($File.Name -match "^App_Web_.*\.(aspx|ascx|master|asmx|ashx).*\.dll$") {
        # Lista estesa di pagine/componenti SharePoint legittimi
        $sharePointComponents = @(
            # Pagine di sistema
            "accessdenied", "error", "login", "signout", "logout", "authenticate",
            "unauthorized", "forbidden", "notfound", "servererror",

            # Pagine amministrative
            "settings", "admin", "farm", "application", "site", "web",
            "generalapplicationsettings", "farmcredentialmanagement",
            "deploysolution", "managefeatures", "backuprestore",

            # Pagine di contenuto
            "default", "home", "pages", "sitepages", "lists", "libraries",
            "allitems", "dispform", "editform", "newform", "upload",
            "download", "viewlsts", "mcontent", "userdisp", "listfeed",

            # Componenti funzionali
            "search", "results", "people", "groups", "users", "permissions",
            "workflow", "reports", "analytics", "usage", "audit",

            # Master pages e controlli
            "v4master", "oslo", "seattle", "errorv15", "applicationv15",
            "mysite", "onedrive", "personal",

            # API e servizi
            "client", "rest", "api", "service", "handler",
            "forms", "layouts", "controltemplates",

            # Componenti social
            "newsfeed", "comments", "allcomments", "social", "following",
            "microfeed", "tags", "ratings", "likes"
        )

        # Verifica se il nome contiene un componente SharePoint noto
        $isSharePointComponent = $false
        $componentFound = ""

        foreach ($component in $sharePointComponents) {
            if ($File.Name.ToLower() -match $component) {
                $isSharePointComponent = $true
                $componentFound = $component
                break
            }
        }

        if ($isSharePointComponent) {
            # Verifica aggiuntiva: la DLL deve avere il pattern di hash ASP.NET
            if ($File.Name -match "\.([a-f0-9]{8})\.([a-z0-9]{8})\.dll$") {

                if ($VerboseDLL) {
                    Write-Host "  [SharePoint ASP.NET] $($File.Name) - Auto-approved ($componentFound component)" -ForegroundColor Green
                }

                # Auto-approva se non già presente
                if (-not $ApprovedDLLs.ContainsKey($hash)) {
                    $ApprovedDLLs[$hash] = @{
                        Name = $File.Name
                        Hash = $hash
                        Path = $File.FullName
                        ApprovedDate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                        ApprovedBy = "Auto-approval (SharePoint ASP.NET)"
                        Reason = "Legitimate SharePoint component: $componentFound"
                    }

                    # Salva nel file delle approvazioni
                    @{ ApprovedDLLs = $ApprovedDLLs.Values } | ConvertTo-Json -Depth 3 | Out-File $ApprovedDLLFile -Force

                    Write-SecurityLog "  Auto-approved SharePoint DLL: $($File.Name) (component: $componentFound)" "INFO"
                }

                return @{ IsSuspicious = $false; IsApproved = $true }
            }
        }

        # Se non è un componente noto ma ha il pattern App_Web_, potrebbe essere sospetto
        # MA prima verifichiamo se è firmato da Microsoft
        try {
            $sig = Get-AuthenticodeSignature $File.FullName -ErrorAction Stop
            if ($sig.Status -eq "Valid" -and $sig.SignerCertificate.Subject -match "Microsoft") {
                # È firmato da Microsoft, quindi è legittimo
                if ($VerboseDLL) {
                    Write-Host "  [Microsoft Signed] $($File.Name) - Trusted ASP.NET component" -ForegroundColor Green
                }

                # Auto-approva
                if (-not $ApprovedDLLs.ContainsKey($hash)) {
                    $ApprovedDLLs[$hash] = @{
                        Name = $File.Name
                        Hash = $hash
                        Path = $File.FullName
                        ApprovedDate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                        ApprovedBy = "Auto-approval (Microsoft Signed)"
                        Reason = "Microsoft signed ASP.NET component"
                    }

                    @{ ApprovedDLLs = $ApprovedDLLs.Values } | ConvertTo-Json -Depth 3 | Out-File $ApprovedDLLFile -Force
                }

                return @{ IsSuspicious = $false; IsApproved = $true }
            }
        } catch {
            # Continua con altri controlli se la verifica firma fallisce
        }
    }

    # 3. Check if it's from a legitimate security vendor
    foreach ($vendor in $LegitimateSecurityVendors) {
        if ($File.DirectoryName -match $vendor -or $File.Name -match $vendor) {
            return @{ IsSuspicious = $false }
        }
    }

    # 4. Check if it's a legitimate system DLL
    foreach ($pattern in $LegitimateSystemDLLs) {
        if ($File.Name -match $pattern) {
            return @{ IsSuspicious = $false }
        }
    }

    # 5. Check if it's a legitimate SharePoint DLL
    foreach ($pattern in $SharePointLegitimeDLLs) {
        if ($File.Name -match $pattern) {
            return @{ IsSuspicious = $false }
        }
    }

    # 6. Check if it's in SharePoint version-specific folders
    if ($File.DirectoryName -match "\\16\.0\.\d+\.\d+\\" -or
        $File.DirectoryName -match "\\15\.0\.\d+\.\d+\\") {
        return @{ IsSuspicious = $false }
    }

    # 7. Check known legitimate tool DLLs with signature verification
    if ($LegitimateToolDLLs.ContainsKey($File.Name)) {
        $toolInfo = $LegitimateToolDLLs[$File.Name]

        # Check file size
        if ($File.Length -ge $toolInfo.MinSize -and $File.Length -le $toolInfo.MaxSize) {
            # Verify digital signature
            try {
                $sig = Get-AuthenticodeSignature $File.FullName -ErrorAction Stop
                if ($sig.Status -eq "Valid") {
                    foreach ($vendor in $toolInfo.Vendors) {
                        if ($sig.SignerCertificate.Subject -match [regex]::Escape($vendor)) {
                            if ($VerboseDLL) {
                                Write-Host "  [Verified] $($File.Name) - Signed by $vendor" -ForegroundColor Green
                            }
                            return @{ IsSuspicious = $false }
                        }
                    }
                }
            } catch {
                # If signature check fails, continue with other checks
            }
        }
    }

    # 8. Check for suspicious characteristics
    $suspicious = $false
    $reasons = @()
    $canAutoApprove = $true  # NEW v3.8

    # Check if DLL has unusual characteristics
    if ($File.Length -lt 1KB -or $File.Length -gt 50MB) {
        $suspicious = $true
        $reasons += "Unusual file size: $('{0:N2}' -f ($File.Length / 1KB)) KB"
        $canAutoApprove = $false
    }

    # Check if DLL is in temp but doesn't match expected patterns
    if ($File.DirectoryName -match "(Temp|TEMP|tmp|TMP|cache|Cache)" -and
        $File.CreationTime -gt (Get-Date).AddDays(-7)) {

        # Additional checks for temp DLLs
        $isTrulySystemTemp = $false

        # Check if it's in a Microsoft installation temp folder
        if ($File.DirectoryName -match "EsetRemoteAdminAgent" -or
            $File.DirectoryName -match "\\{[A-F0-9-]+}\\" -or
            $File.DirectoryName -match "\\InstallTemp\\" -or
            $File.DirectoryName -match "\\Updates\\") {
            $isTrulySystemTemp = $true
        }

        if (-not $isTrulySystemTemp) {
            # Check for suspicious naming patterns
            if ($File.Name -match "^[a-z0-9]{6,8}\.dll$" -or
                $File.Name -match "^tmp[0-9A-F]+\.dll$" -or
                $File.Name -match "^~.*\.dll$") {
                $suspicious = $true
                $reasons += "Suspicious filename pattern in temp location"
                $canAutoApprove = $false
            }

            # Skip "isolated DLL" check for known tools
            if (-not $LegitimateToolDLLs.ContainsKey($File.Name)) {
                # Check if it's a single DLL without accompanying files
                $siblingFiles = Get-ChildItem -Path $File.DirectoryName -Filter "*.dll" |
                    Where-Object { $_.Name -ne $File.Name }

                if ($siblingFiles.Count -eq 0) {
                    # Additional check: is there an associated EXE?
                    $exeName = $File.BaseName + ".exe"
                    $hasExe = Test-Path (Join-Path $File.DirectoryName $exeName)

                    if (-not $hasExe) {
                        $suspicious = $true
                        $reasons += "Isolated DLL in temp location"
                    }
                }
            }
        }
    }

    # Check if DLL is in web-accessible location
    if ($BasePath -match "(wwwroot|inetpub)" -and
        $File.DirectoryName -notmatch "(bin|App_Code|App_Data)") {

        # Check if it's not in a protected folder
        if ($File.DirectoryName -notmatch "\\(16|15|14)\\(TEMPLATE|ISAPI)\\") {
            $suspicious = $true
            $reasons += "DLL in web-accessible location"
            $canAutoApprove = $false
        }
    }

    # Check for double extensions or suspicious patterns
    if ($File.Name -match "\.(aspx|asp|ashx|asmx)\.dll$") {
        $suspicious = $true
        $reasons += "Double extension pattern"
        $canAutoApprove = $false
    }

    # NEW v3.8: Auto-approval logic
    if ($suspicious -and $AutoApproveDLLs -and $canAutoApprove) {
        # Additional verification for auto-approval
        $autoApprove = $false

        # Check if signed by trusted publisher
        try {
            $sig = Get-AuthenticodeSignature $File.FullName -ErrorAction Stop
            if ($sig.Status -eq "Valid") {
                # List of trusted publishers for auto-approval
                $trustedPublishers = @(
                    "Microsoft Corporation",
                    "Microsoft Windows",
                    "Adobe Systems",
                    "Intel Corporation",
                    "NVIDIA Corporation"
                )

                foreach ($publisher in $trustedPublishers) {
                    if ($sig.SignerCertificate.Subject -match [regex]::Escape($publisher)) {
                        $autoApprove = $true
                        Write-SecurityLog "  Auto-approving signed DLL: $($File.Name) (signed by $publisher)" "INFO"

                        # Add to approved list
                        $ApprovedDLLs[$hash] = @{
                            Name = $File.Name
                            Hash = $hash
                            Path = $File.FullName
                            ApprovedDate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                            ApprovedBy = "Auto-approval"
                            Reason = "Signed by $publisher"
                        }

                        # Save updated approved list
                        @{ ApprovedDLLs = $ApprovedDLLs.Values } | ConvertTo-Json -Depth 3 | Out-File $ApprovedDLLFile -Force

                        return @{ IsSuspicious = $false; IsApproved = $true }
                    }
                }
            }
        } catch {
            # Signature check failed, cannot auto-approve
        }
    }

    # Return result
    if ($suspicious) {
        return @{
            IsSuspicious = $true
            Reason = $reasons -join "; "
            Severity = "Medium"
            Hash = $hash
            CanAutoApprove = $canAutoApprove
        }
    }

    return @{ IsSuspicious = $false }
}

# Function to check if IP belongs to GOLINE
function Test-GOLINEIPAddress {
    param([string]$IPAddress)

    # Check IPv4 - GOLINE range: 185.54.80.0/22
    if ($IPAddress -match "^(\d+)\.(\d+)\.(\d+)\.(\d+)$") {
        $octets = $IPAddress -split '\.'
        $firstOctet = [int]$octets[0]
        $secondOctet = [int]$octets[1]
        $thirdOctet = [int]$octets[2]

        # 185.54.80.0/22 includes 185.54.80.0 - 185.54.83.255
        if ($firstOctet -eq 185 -and $secondOctet -eq 54 -and $thirdOctet -ge 80 -and $thirdOctet -le 83) {
            return $true
        }
    }

    # Check IPv6 - GOLINE range: 2A02:4460::/32
    if ($IPAddress -match "^2[aA]02:4460:") {
        return $true
    }

    return $false
}

# Function to check if IP is internal/private
function Test-InternalIPAddress {
    param([string]$IPAddress)

    # Check RFC1918 private IPv4 addresses
    if ($IPAddress -match "^10\." -or
        $IPAddress -match "^192\.168\." -or
        ($IPAddress -match "^172\.(\d+)\." -and [int]$Matches[1] -ge 16 -and [int]$Matches[1] -le 31) -or
        $IPAddress -match "^127\.") {
        return $true
    }

    # Check IPv6 private/link-local addresses
    if ($IPAddress -match "^[fF][eE]80:" -or    # Link-local
        $IPAddress -match "^[fF][cCdD]" -or      # Unique local
        $IPAddress -eq "::1") {                  # Loopback
        return $true
    }

    # Check if it's a GOLINE IP
    if (Test-GOLINEIPAddress $IPAddress) {
        return $true
    }

    return $false
}

# Logging function
function Write-SecurityLog {
    param([string]$Message, [string]$Level = "INFO", [object]$Data = $null)

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp [$Level] $Message" | Add-Content -Path $LogFile

    $color = switch ($Level) {
        "ALERT" { "Red" }
        "WARNING" { "Yellow" }
        "ERROR" { "Red" }
        "SUCCESS" { "Green" }
        default { "White" }
    }

    Write-Host $Message -ForegroundColor $color

    # Store in results
    $entry = @{
        Time = $timestamp
        Message = $Message
        Data = $Data
    }

    switch ($Level) {
        "ALERT" { $global:SecurityResults.Alerts += $entry }
        "WARNING" { $global:SecurityResults.Warnings += $entry }
        default { $global:SecurityResults.Info += $entry }
    }
}

Write-SecurityLog "=== SharePoint Security Monitoring Started (v3.9 - Advanced DLL Validation) ===" "INFO"
Write-SecurityLog "Enhanced with real-time threat detection and performance optimizations" "INFO"
Write-SecurityLog "Advanced threat detection for APT groups and post-exploitation tools" "INFO"
Write-SecurityLog "Performance optimizations: Incremental log reading, event caching, smart bookmarks" "INFO"
Write-SecurityLog "Auto email alerts: Enabled for warnings and critical alerts" "INFO"
Write-SecurityLog "DLL management: $(if ($AutoApproveDLLs) { 'Auto-approval enabled' } else { 'Manual approval mode' })" "INFO"
Write-SecurityLog "v3.9: Advanced DLL validation with pattern analysis and security checks" "INFO"
Write-SecurityLog "Timezone: $($scriptTimeZone.DisplayName)" "INFO"

# 0. CHECK SHAREPOINT VERSION FOR EOL
Write-SecurityLog "Checking SharePoint version..." "INFO"
try {
    Add-PSSnapin Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue
    $spFarm = Get-SPFarm -ErrorAction SilentlyContinue
    if ($spFarm) {
        $spVersion = $spFarm.BuildVersion
        Write-SecurityLog "SharePoint version: $($spVersion.ToString())" "INFO"

        # SharePoint 2013 is version 15, 2010 is 14, etc.
        if ($spVersion.Major -le 15) {
            Write-SecurityLog "CRITICAL: End-of-Life SharePoint version detected! Version $($spVersion.Major) should be disconnected from internet!" "ALERT"
            $global:SecurityResults.Statistics.IsEOL = $true
        } else {
            $global:SecurityResults.Statistics.IsEOL = $false
        }

        # Store version details for patch checking
        $global:SecurityResults.Statistics.SharePointVersion = $spVersion
        $global:SecurityResults.Statistics.SharePointMajor = $spVersion.Major

        # For SharePoint 2019, show how to check and update
        if ($spVersion.Major -eq 16 -and $spVersion.Build -ge 10000 -and $spVersion.Build -lt 10398) {
            Write-SecurityLog "" "INFO"
            Write-SecurityLog "TIP: To check available SharePoint 2019 updates:" "INFO"
            Write-SecurityLog "  1. Visit: https://docs.microsoft.com/en-us/officeupdates/sharepoint-2019-updates" "INFO"
            Write-SecurityLog "  2. Download the latest Cumulative Update (CU)" "INFO"
            Write-SecurityLog "  3. Install using: Start-Process 'sts2019-kb5xxxxxx-fullfile-x64-glb.exe'" "INFO"
            Write-SecurityLog "" "INFO"
        }
    }
} catch {
    Write-SecurityLog "Could not determine SharePoint version" "WARNING"
    $global:SecurityResults.Statistics.IsEOL = "Unknown"
}

# NEW: 0a. CHECK REQUIRED PATCHES
Write-SecurityLog "Checking for required security patches..." "INFO"

# Using real patch numbers for CVE-2023-29357 and CVE-2023-33157
$requiredPatches = @{
    "15" = @("KB5002358", "KB5002359")  # SharePoint 2013
    "16" = @{
        # Check build number to distinguish 2016 from 2019
        # SharePoint 2016: 16.0.4xxx.xxxx to 16.0.5xxx.xxxx
        # SharePoint 2019: 16.0.10xxx.xxxx and higher
        "2016" = @("KB5002358", "KB5002359")  # SharePoint 2016
        "2019" = @()  # SharePoint 2019 - empty for now, see below
    }
    "Subscription" = @("KB5002358")      # SharePoint Subscription Edition
}

# For SharePoint 2019, check minimum build instead of specific patches
# Build 16.0.10398.20000 or higher includes fixes for CVE-2023-29357/33157
$sharePoint2019MinimumBuild = [version]"16.0.10398.20000"

$installedPatches = @()
$missingPatches = @()

# Check installed updates
try {
    $installedUpdates = Get-HotFix | Select-Object -ExpandProperty HotFixID

    if ($global:SecurityResults.Statistics.SharePointMajor) {
        $versionKey = $global:SecurityResults.Statistics.SharePointMajor.ToString()

        # Check if it's subscription edition
        if ($global:SecurityResults.Statistics.SharePointVersion.Build -ge 16000) {
            $versionKey = "Subscription"
        }

        if ($versionKey -eq "16") {
            # Distinguish between SharePoint 2016 and 2019 based on build number
            if ($global:SecurityResults.Statistics.SharePointVersion.Build -ge 10000) {
                # SharePoint 2019 has build 16.0.10xxx and higher
                Write-SecurityLog "Detected SharePoint 2019 (Build: $($global:SecurityResults.Statistics.SharePointVersion.Build))" "INFO"

                # For SharePoint 2019, check build instead of KB patches
                $currentVersion = $global:SecurityResults.Statistics.SharePointVersion

                # Mapping of SharePoint 2019 builds to CUs
                $sp2019CUMapping = @{
                    "16.0.10337.12109" = "RTM (March 2019)"
                    "16.0.10340.12101" = "April 2019 CU"
                    "16.0.10346.20001" = "May 2019 CU"
                    "16.0.10351.20000" = "June 2019 CU"
                    "16.0.10354.20001" = "July 2019 CU"
                    "16.0.10357.20002" = "August 2019 CU"
                    "16.0.10361.12106" = "September 2019 CU"
                    "16.0.10364.20001" = "October 2019 CU"
                    "16.0.10367.12107" = "November 2019 CU"
                    "16.0.10370.20001" = "December 2019 CU"
                    "16.0.10372.20060" = "January 2020 CU"
                    "16.0.10375.20000" = "February 2020 CU"
                    "16.0.10398.20000" = "December 2023 CU (Security Update)"
                }

                # Find installed CU
                $installedCU = "Unknown"
                foreach ($build in $sp2019CUMapping.Keys | Sort-Object -Descending) {
                    if ($currentVersion -ge [version]$build) {
                        $installedCU = $sp2019CUMapping[$build]
                        break
                    }
                }

                Write-SecurityLog "SharePoint 2019 current CU: $installedCU" "INFO"

                if ($currentVersion -ge $sharePoint2019MinimumBuild) {
                    Write-SecurityLog "SharePoint 2019 build $currentVersion includes security fixes (minimum required: $sharePoint2019MinimumBuild)" "SUCCESS"
                    $installedPatches += "Build $currentVersion - $installedCU"
                } else {
                    Write-SecurityLog "CRITICAL: SharePoint 2019 build $currentVersion is vulnerable! Minimum required: $sharePoint2019MinimumBuild" "ALERT"
                    $missingPatches += "SharePoint 2019 December 2023 CU or later (current: $installedCU)"
                }
            } else {
                # SharePoint 2016 has build 16.0.4xxx to 16.0.5xxx
                $patchList = $requiredPatches["16"]["2016"]
                Write-SecurityLog "Detected SharePoint 2016 (Build: $($global:SecurityResults.Statistics.SharePointVersion.Build))" "INFO"

                foreach ($patch in $patchList) {
                    if ($installedUpdates -contains $patch) {
                        $installedPatches += $patch
                        Write-SecurityLog "Required patch $patch is installed" "SUCCESS"
                    } else {
                        $missingPatches += $patch
                        Write-SecurityLog "CRITICAL: Required patch $patch is MISSING!" "ALERT"
                    }
                }
            }
        } elseif ($requiredPatches.ContainsKey($versionKey)) {
            foreach ($patch in $requiredPatches[$versionKey]) {
                if ($installedUpdates -contains $patch) {
                    $installedPatches += $patch
                    Write-SecurityLog "Required patch $patch is installed" "SUCCESS"
                } else {
                    $missingPatches += $patch
                    Write-SecurityLog "CRITICAL: Required patch $patch is MISSING!" "ALERT"
                }
            }
        }
    }
} catch {
    Write-SecurityLog "Could not check installed patches" "WARNING"
}

$global:SecurityResults.Statistics.InstalledPatches = $installedPatches
$global:SecurityResults.Statistics.MissingPatches = $missingPatches

# 1. CHECK FOR SHAREPOINT RCE EXPLOITATION (CVE-2023-29357, CVE-2023-33157)
Write-SecurityLog "Checking for SharePoint RCE exploitation indicators..." "INFO"
Start-PerformanceTimer "SharePoint RCE Detection"

# Check IIS logs for ToolPane exploitation
$IISLogPath = "C:\inetpub\logs\LogFiles"
$ToolPanePattern = "POST.*/_layouts/15/ToolPane\.aspx\?DisplayMode=Edit"
$SignOutPattern = ".*/_layouts/SignOut\.aspx"

# Critical date range for enhanced scanning (using real dates)
$criticalDateStart = Get-Date "2023-09-01"
$criticalDateEnd = Get-Date "2023-09-30 23:59:59"

# Earlier exploitation attempts
$earlyExploitDateStart = Get-Date "2023-07-01"

# OPTIMIZED: Adjust days to scan based on parameters
$daysToScan = if ($FullHistoricalScan) {
    30  # Full historical scan
    Write-SecurityLog "  Full historical scan mode - scanning 30 days of logs" "INFO"
} elseif ($QuickScan) {
    0.5  # 12 hours for quick scan
    Write-SecurityLog "  Quick scan mode - scanning last 12 hours" "INFO"
} else {
    $MaxDaysToScan  # Use parameter value (default 2)
    Write-SecurityLog "  Standard scan mode - scanning last $MaxDaysToScan days" "INFO"
}

Write-SecurityLog "  Scanning IIS logs from last $daysToScan days..." "INFO"

$recentIISLogs = Get-ChildItem $IISLogPath -Recurse -Filter "*.log" -ErrorAction SilentlyContinue |
    Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-$daysToScan)} |
    Sort-Object LastWriteTime -Descending

Write-SecurityLog "  Found $($recentIISLogs.Count) log files to scan" "INFO"
$logCount = 0
$totalEventsProcessed = 0
$cachedEventsSkipped = 0

foreach ($log in $recentIISLogs) {
    $logCount++
    Write-Progress -Activity "Scanning IIS Logs" -Status "Processing $($log.Name)" -PercentComplete (($logCount / $recentIISLogs.Count) * 100)

    # Get bookmark for this log
    $bookmark = Get-LogBookmark -LogFile $log.FullName

    # Skip if file hasn't changed since last read
    if ($log.LastWriteTime -le $bookmark.LastReadTime -and $bookmark.FileSize -eq $log.Length) {
        Write-SecurityLog "  Skipping unchanged log: $($log.Name)" "INFO"
        continue
    }

    Write-SecurityLog "  Scanning: $($log.Name) ($('{0:N2}' -f ($log.Length / 1MB)) MB)" "INFO"

    # OPTIMIZED: Read log once for all patterns
    $allPatterns = @(
        $ToolPanePattern,
        $SignOutPattern,
        ".*\.devtunnels\.ms"
    )

    $allMatches = Read-LogIncremental -LogPath $log.FullName -Patterns $allPatterns -Bookmark $bookmark

    # Process matches by pattern type
    foreach ($match in $allMatches) {
        $line = $match.Line
        $totalEventsProcessed++

        # Create event hash to check if already processed
        $crypto = [System.Security.Cryptography.SHA256]::Create()
        $eventBytes = [System.Text.Encoding]::UTF8.GetBytes($line)
        $hashBytes = $crypto.ComputeHash($eventBytes)
        $eventHashString = [BitConverter]::ToString($hashBytes).Replace("-", "")
        $crypto.Dispose()

        # Determine event type based on pattern
        $eventType = if ($match.Pattern -match "ToolPane") { "ToolPane" }
                     elseif ($match.Pattern -match "SignOut") { "SignOut" }
                     elseif ($match.Pattern -match "devtunnels") { "DevTunnels" }
                     else { "Unknown" }

        # Check if already processed
        if (Test-EventProcessed -EventHash $eventHashString -EventType $eventType) {
            $cachedEventsSkipped++
            continue
        }

        # Process ToolPane matches
        if ($eventType -eq "ToolPane") {
            # Extract IP and time from IIS log
            if ($line -match '(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+([^\s]+).*\s+(\d{3})') {
                $timeValue = "$($Matches[1]) $($Matches[2])"
                $logDate = [DateTime]::Parse($timeValue)
                $clientIP = $Matches[9]
                $status = $Matches[11]
                $fullRequest = $line

                # Check if in critical date range
                $inCriticalPeriod = $logDate -ge $criticalDateStart -and $logDate -le $criticalDateEnd
                $inEarlyExploit = $logDate -ge $earlyExploitDateStart -and $logDate -lt $criticalDateStart

                if ($inCriticalPeriod) {
                    $CVEIndicators.CriticalPeriodActivity += @{
                        Type = "ToolPane"
                        Time = $timeValue
                        ClientIP = $clientIP
                        Status = $status
                    }
                }

                # Flag as critical if from known attacker IPs
                $isKnownAttacker = $clientIP -in $KnownAttackerIPs
                $isInternal = Test-InternalIPAddress $clientIP

                # Determine threat actor based on timing and IP
                $threatActor = "Unknown"
                if ($inEarlyExploit) {
                    $threatActor = "Early Exploitation Group"
                } elseif ($inCriticalPeriod -and $clientIP -in @("131.226.2.6", "65.38.121.198")) {
                    $threatActor = "Advanced Threat Actor"
                }

                # NEW v3.8: Track all attacks comprehensively
                $attackDetails = @{
                    Type = "CVE-2023-29357 (ToolPane RCE)"
                    Time = $timeValue
                    AttackerIP = $clientIP
                    TargetFile = "/_layouts/15/ToolPane.aspx"
                    Method = "POST"
                    Status = $status
                    ThreatActor = $threatActor
                    IsKnownAttacker = $isKnownAttacker
                    IsInternal = $isInternal
                    InCriticalPeriod = $inCriticalPeriod
                    LogFile = $log.Name
                    FullRequest = $fullRequest
                }

                $CVEIndicators.AllAttacks += $attackDetails

                # Categorize based on IP type
                if ($isInternal) {
                    # Suspicious internal activity
                    $CVEIndicators.InternalSuspiciousActivity[$clientIP] = @{
                        Time = $timeValue
                        ClientIP = $clientIP
                        Status = $status
                        Pattern = "ToolPane.aspx POST"
                        Request = $fullRequest
                        LogFile = $log.Name
                        InCriticalPeriod = $inCriticalPeriod
                        Count = if ($CVEIndicators.InternalSuspiciousActivity.ContainsKey($clientIP)) {
                            $CVEIndicators.InternalSuspiciousActivity[$clientIP].Count + 1
                        } else { 1 }
                    }

                    Write-SecurityLog "SUSPICIOUS: Internal IP accessing ToolPane.aspx: $clientIP" "WARNING"
                } else {
                    # External attack
                    $CVEIndicators.ToolPaneExploits += @{
                        Time = $timeValue
                        ClientIP = $clientIP
                        Status = $status
                        IsKnownAttacker = $isKnownAttacker
                        InCriticalPeriod = $inCriticalPeriod
                        InEarlyExploit = $inEarlyExploit
                        ThreatActor = $threatActor
                        LogFile = $log.Name
                    }

                    if ($isKnownAttacker) {
                        Write-SecurityLog "CRITICAL: Known attacker IP exploiting ToolPane.aspx: $clientIP ($threatActor)" "ALERT"

                        # Track threat actor activity
                        $CVEIndicators.ThreatActorActivity += @{
                            Actor = $threatActor
                            IP = $clientIP
                            Time = $timeValue
                            Activity = "ToolPane Exploitation"
                        }
                    } else {
                        Write-SecurityLog "ALERT: External IP exploiting ToolPane.aspx: $clientIP" "ALERT"
                    }
                }
            }
        }
        # Process SignOut matches
        elseif ($eventType -eq "SignOut") {
            if ($line -match '(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\S+)') {
                $timeValue = "$($Matches[1]) $($Matches[2])"
                $clientIP = $Matches[3]

                $CVEIndicators.SignOutExploits += @{
                    Time = $timeValue
                    ClientIP = $clientIP
                    LogFile = $log.Name
                }

                # NEW v3.8: Track attack
                $CVEIndicators.AllAttacks += @{
                    Type = "SignOut.aspx Access"
                    Time = $timeValue
                    AttackerIP = $clientIP
                    TargetFile = "/_layouts/SignOut.aspx"
                    Method = "GET/POST"
                    ThreatActor = "Unknown"
                    IsInternal = Test-InternalIPAddress $clientIP
                    LogFile = $log.Name
                }

                Write-SecurityLog "SUSPICIOUS: SignOut.aspx access detected - potential exploitation vector from $clientIP" "WARNING"
            }
        }
        # Process DevTunnels matches
        elseif ($eventType -eq "DevTunnels") {
            if ($line -match '(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2}).*\s+(\S+\.devtunnels\.ms)') {
                $timeValue = "$($Matches[1]) $($Matches[2])"
                $c2Domain = $Matches[3]

                $CVEIndicators.C2Communications += @{
                    Time = $timeValue
                    Domain = $c2Domain
                    Type = "DevTunnels"
                    LogFile = $log.Name
                }

                # NEW v3.8: Track C2 as attack
                $CVEIndicators.AllAttacks += @{
                    Type = "C2 Communication (DevTunnels)"
                    Time = $timeValue
                    AttackerIP = "Unknown"
                    TargetFile = $c2Domain
                    Method = "C2"
                    ThreatActor = "Unknown"
                    LogFile = $log.Name
                }

                Write-SecurityLog "ALERT: Potential C2 communication detected to $c2Domain" "ALERT"
            }
        }

        # Mark as processed
        Add-ProcessedEvent -EventHash $eventHashString -EventType $eventType
    }
}

Write-Progress -Activity "Scanning IIS Logs" -Completed
Write-SecurityLog "  Total events processed: $totalEventsProcessed" "INFO"
Write-SecurityLog "  Cached events skipped: $cachedEventsSkipped ($('{0:N1}%' -f (($cachedEventsSkipped / [Math]::Max($totalEventsProcessed, 1)) * 100)))" "INFO"
Stop-PerformanceTimer "SharePoint RCE Detection"

# 2. CHECK FOR ADDITIONAL EXPLOIT PATTERNS
Write-SecurityLog "Checking for bypass vulnerability indicators..." "INFO"
Start-PerformanceTimer "Bypass Vulnerability Detection"

# REFINED patterns - removing cmd/exec/command as they generate false positives
$ExploitPatterns = @(
    ".*\.aspx.*\.\./.*\.config",           # Path traversal to config files
    ".*__viewstate.*exec.*",               # ViewState manipulation
    ".*ctl00.*shell.*",                    # Control manipulation
    ".*\.aspx.*System\.Web\.Configuration",  # Direct config access
    ".*\.aspx.*MachineKeySection"         # Machine key theft attempts
)

$logCount = 0
$exploitEventsProcessed = 0
$exploitCachedSkipped = 0

foreach ($log in $recentIISLogs) {
    $logCount++
    Write-Progress -Activity "Checking Exploit Patterns" -Status "Processing $($log.Name)" -PercentComplete (($logCount / $recentIISLogs.Count) * 100)

    # Get bookmark for this log
    $bookmark = Get-LogBookmark -LogFile $log.FullName

    # Skip if unchanged
    if ($log.LastWriteTime -le $bookmark.LastReadTime -and $bookmark.FileSize -eq $log.Length) {
        continue
    }

    # OPTIMIZED: Read log once for all exploit patterns
    $matches = Read-LogIncremental -LogPath $log.FullName -Patterns $ExploitPatterns -Bookmark $bookmark

    foreach ($match in $matches) {
        $line = $match.Line
        $pattern = $match.Pattern  # Get which pattern matched
        $exploitEventsProcessed++

        # Create event hash
        $crypto = [System.Security.Cryptography.SHA256]::Create()
        $eventBytes = [System.Text.Encoding]::UTF8.GetBytes($line + $pattern)
        $hashBytes = $crypto.ComputeHash($eventBytes)
        $eventHashString = [BitConverter]::ToString($hashBytes).Replace("-", "")
        $crypto.Dispose()

        # Check if already processed
        if (Test-EventProcessed -EventHash $eventHashString -EventType "Exploit") {
            $exploitCachedSkipped++
            continue
        }

        # Extract IP from log line
        if ($line -match '(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\S+)') {
            $timeValue = "$($Matches[1]) $($Matches[2])"
            $clientIP = $Matches[3]

            # NEW v3.8: Track exploit attempt
            $attackType = switch -Regex ($pattern) {
                "config" { "Path Traversal to Config" }
                "__viewstate" { "ViewState Manipulation" }
                "ctl00" { "Control Manipulation" }
                "System\.Web\.Configuration" { "Direct Config Access" }
                "MachineKeySection" { "Machine Key Theft Attempt" }
                default { "Bypass Vulnerability" }
            }

            $CVEIndicators.AllAttacks += @{
                Type = $attackType
                Time = $timeValue
                AttackerIP = $clientIP
                TargetFile = if ($line -match 'GET\s+([^\s]+)') { $Matches[1] } else { "Unknown" }
                Method = if ($line -match '(GET|POST|PUT|DELETE)') { $Matches[1] } else { "Unknown" }
                Pattern = $pattern
                ThreatActor = "Unknown"
                IsInternal = Test-InternalIPAddress $clientIP
                LogFile = $log.Name
            }

            if (Test-InternalIPAddress $clientIP) {
                # Suspicious internal activity
                if (-not $CVEIndicators.InternalSuspiciousActivity.ContainsKey($clientIP)) {
                    $CVEIndicators.InternalSuspiciousActivity[$clientIP] = @{
                        Time = $timeValue
                        ClientIP = $clientIP
                        Patterns = @()
                        Count = 0
                    }
                }

                $CVEIndicators.InternalSuspiciousActivity[$clientIP].Patterns += @{
                    Pattern = $pattern
                    MatchedString = $line.Substring(0, [Math]::Min($line.Length, 200))
                    Time = $timeValue
                }
                $CVEIndicators.InternalSuspiciousActivity[$clientIP].Count++

                Write-SecurityLog "SUSPICIOUS: Internal IP with exploit pattern - $clientIP" "WARNING"
            } else {
                # External exploit attempt
                $CVEIndicators.ExploitAttempts += @{
                    Time = $timeValue
                    ClientIP = $clientIP
                    Pattern = $pattern
                    Line = $line
                }
                Write-SecurityLog "ALERT: External exploit attempt from $clientIP" "ALERT"
            }

            # Mark as processed
            Add-ProcessedEvent -EventHash $eventHashString -EventType "Exploit"
        }
    }
}

Write-Progress -Activity "Checking Exploit Patterns" -Completed
Write-SecurityLog "  Exploit patterns processed: $exploitEventsProcessed" "INFO"
Write-SecurityLog "  Cached exploits skipped: $exploitCachedSkipped" "INFO"
Stop-PerformanceTimer "Bypass Vulnerability Detection"

# 3. CHECK FOR MACHINE KEY THEFT INDICATORS
Write-SecurityLog "Checking for machine key theft attempts..." "INFO"
Start-PerformanceTimer "Machine Key Theft Detection"

# Check for processes accessing web.config
$suspiciousConfigAccess = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4663  # Object access
    StartTime = (Get-Date).AddHours(-24)
} -ErrorAction SilentlyContinue | Where-Object {
    $_.Message -match "web\.config" -and
    $_.Message -notmatch "iisreset|w3wp\.exe"
}

if ($suspiciousConfigAccess) {
    $CVEIndicators.MachineKeyTheft += $suspiciousConfigAccess
    Write-SecurityLog "WARNING: Suspicious access to web.config detected" "WARNING"

    # NEW v3.8: Track as attack
    foreach ($access in $suspiciousConfigAccess) {
        $CVEIndicators.AllAttacks += @{
            Type = "web.config Access Attempt"
            Time = $access.TimeCreated
            AttackerIP = "Local"
            TargetFile = "web.config"
            Method = "File Access"
            ThreatActor = "Unknown"
            IsInternal = $true
        }
    }
}

# Check for debug_dev.js file (contains stolen web config data)
$debugDevPath = @(
    "C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\15\TEMPLATE\LAYOUTS\debug_dev.js",
    "C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\16\TEMPLATE\LAYOUTS\debug_dev.js"
)

foreach ($path in $debugDevPath) {
    if (Test-Path $path) {
        Write-SecurityLog "CRITICAL: Found debug_dev.js - likely contains stolen MachineKey data!" "ALERT"
        $CVEIndicators.MachineKeyTheft += @{
            Type = "StolenConfigFile"
            Path = $path
            Modified = (Get-Item $path).LastWriteTime
        }

        # NEW v3.8: Track as critical attack
        $CVEIndicators.AllAttacks += @{
            Type = "Machine Key Theft (debug_dev.js)"
            Time = (Get-Item $path).LastWriteTime
            AttackerIP = "Unknown"
            TargetFile = $path
            Method = "Data Exfiltration"
            ThreatActor = "Advanced Threat Actor"
            Severity = "Critical"
        }
    }
}
Stop-PerformanceTimer "Machine Key Theft Detection"

# NEW: 3a. CHECK MICROSOFT DEFENDER STATUS
Write-SecurityLog "Checking Microsoft Defender status and tampering attempts..." "INFO"
Start-PerformanceTimer "Microsoft Defender Status"

# Check if ESET is active first
$esetEnabled = $false
$esetService = Get-Service -Name "ekrn" -ErrorAction SilentlyContinue  # ESET Service
if ($esetService -and $esetService.Status -eq "Running") {
    $esetEnabled = $true
    # Check ESET version
    try {
        $esetProduct = Get-CimInstance -ClassName Win32_Product | Where-Object { $_.Name -match "ESET" }
        if ($esetProduct) {
            Write-SecurityLog "ESET is active - Version: $($esetProduct.Version)" "INFO"
        } else {
            Write-SecurityLog "ESET is active - Microsoft Defender tampering checks skipped" "INFO"
        }
    } catch {
        Write-SecurityLog "ESET is active - Microsoft Defender tampering checks skipped" "INFO"
    }
} else {
    # Check Defender registry keys for modifications
    $defenderRegKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows Defender",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
    )

    foreach ($regKey in $defenderRegKeys) {
        try {
            $key = Get-Item -Path $regKey -ErrorAction SilentlyContinue
            if ($key) {
                # Check for disabled real-time protection
                $realtimeDisabled = (Get-ItemProperty -Path "$regKey\Real-Time Protection" -Name "DisableRealtimeMonitoring" -ErrorAction SilentlyContinue).DisableRealtimeMonitoring
                if ($realtimeDisabled -eq 1) {
                    Write-SecurityLog "CRITICAL: Microsoft Defender Real-Time Protection is DISABLED!" "ALERT"
                    $CVEIndicators.DefenderDisabled += @{
                        Type = "RealTimeProtectionDisabled"
                        Path = "$regKey\Real-Time Protection"
                        Time = Get-Date
                    }

                    # NEW v3.8: Track as attack
                    $CVEIndicators.AllAttacks += @{
                        Type = "Defender Tampering - Real-Time Protection Disabled"
                        Time = Get-Date
                        AttackerIP = "Local"
                        TargetFile = "$regKey\Real-Time Protection"
                        Method = "Registry Modification"
                        ThreatActor = "Unknown"
                        Severity = "Critical"
                    }
                }

                # Check for disabled behavior monitoring
                $behaviorDisabled = (Get-ItemProperty -Path "$regKey\Real-Time Protection" -Name "DisableBehaviorMonitoring" -ErrorAction SilentlyContinue).DisableBehaviorMonitoring
                if ($behaviorDisabled -eq 1) {
                    Write-SecurityLog "WARNING: Microsoft Defender Behavior Monitoring is disabled" "WARNING"
                    $CVEIndicators.DefenderDisabled += @{
                        Type = "BehaviorMonitoringDisabled"
                        Path = "$regKey\Real-Time Protection"
                        Time = Get-Date
                    }
                }
            }
        } catch {
            Write-SecurityLog "Could not check Defender registry key: $regKey" "INFO"
        }
    }

    # Check for recent Defender service tampering
    $defenderTamperEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Windows Defender/Operational'
        ID = 5001, 5010, 5012  # Defender disabled events
        StartTime = (Get-Date).AddDays(-1)
    } -ErrorAction SilentlyContinue

    if ($defenderTamperEvents) {
        Write-SecurityLog "CRITICAL: Microsoft Defender tampering detected!" "ALERT"
        $CVEIndicators.DefenderDisabled += @{
            Type = "DefenderTamperingEvents"
            Events = $defenderTamperEvents.Count
            Time = Get-Date
        }

        # NEW v3.8: Track each tampering event as attack
        foreach ($event in $defenderTamperEvents) {
            $CVEIndicators.AllAttacks += @{
                Type = "Defender Tampering Event"
                Time = $event.TimeCreated
                AttackerIP = "Local"
                TargetFile = "Windows Defender"
                Method = "Service Tampering"
                EventID = $event.Id
                ThreatActor = "Unknown"
                Severity = "High"
            }
        }
    }
}
Stop-PerformanceTimer "Microsoft Defender Status"

# NEW: 3b. CHECK GROUP POLICY MODIFICATIONS
Write-SecurityLog "Checking for recent Group Policy modifications..." "INFO"
Start-PerformanceTimer "Group Policy Monitoring"

$gpoEvents = Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-GroupPolicy/Operational'
    ID = 5136, 5137, 5141  # GPO modification events
    StartTime = (Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue

if ($gpoEvents) {
    # Filter for suspicious GPO changes
    $suspiciousGPO = $gpoEvents | Where-Object {
        $_.Message -match "batch|script|ransomware|lockbit|warlock|scheduled task" -or
        $_.TimeCreated -ge $criticalDateStart
    }

    if ($suspiciousGPO) {
        Write-SecurityLog "WARNING: Suspicious Group Policy modifications detected" "WARNING"
        $CVEIndicators.GPOModifications += @{
            Count = $suspiciousGPO.Count
            Events = $suspiciousGPO | Select-Object -First 5
            Time = Get-Date
        }

        # NEW v3.8: Track GPO changes as attacks
        foreach ($gpo in $suspiciousGPO | Select-Object -First 10) {
            $CVEIndicators.AllAttacks += @{
                Type = "Suspicious GPO Modification"
                Time = $gpo.TimeCreated
                AttackerIP = "Local/Domain"
                TargetFile = "Group Policy"
                Method = "GPO Change"
                ThreatActor = "Potential Ransomware Operator"
                EventID = $gpo.Id
            }
        }
    }
}
Stop-PerformanceTimer "Group Policy Monitoring"

# 4. ENHANCED W3WP.EXE MONITORING WITH POST-EXPLOITATION TOOLS
Write-SecurityLog "Monitoring w3wp.exe process behavior and post-exploitation tools..." "INFO"
Start-PerformanceTimer "W3WP Process Monitoring"

# Get all w3wp processes
$w3wpProcesses = Get-Process -Name w3wp -ErrorAction SilentlyContinue
foreach ($w3wp in $w3wpProcesses) {
    # Check for suspicious child processes using CIM (more efficient)
    $childProcesses = Get-CimInstance Win32_Process -Filter "ParentProcessId=$($w3wp.Id)" |
        Select-Object Name, ProcessId, CommandLine, CreationDate

    foreach ($child in $childProcesses) {
        if ($child.Name -match '^(cmd|powershell|net|certutil|rundll32|wmic|bitsadmin|PsExec|PsExec64)\.exe$') {
            Write-SecurityLog "CRITICAL: w3wp.exe spawned suspicious process: $($child.Name)" "ALERT"

            # Try to get command line
            $commandLine = $child.CommandLine
            if ($commandLine) {
                Write-SecurityLog "  Command line: $commandLine" "ALERT"

                # Check for base64 encoded commands
                if ($commandLine -match '-[Ee]nc(oded)?[Cc]ommand\s+([A-Za-z0-9+/=]+)') {
                    Write-SecurityLog "  Base64 encoded command detected!" "ALERT"
                }

                # Check for Mimikatz patterns
                if ($commandLine -match 'sekurlsa|logonpasswords|privilege::debug|crypto::certificates|lsadump') {
                    Write-SecurityLog "  CRITICAL: Mimikatz credential theft detected!" "ALERT"
                    $CVEIndicators.PostExploitationTools += @{
                        Tool = "Mimikatz"
                        Process = $child.Name
                        CommandLine = $commandLine
                        Time = Get-Date
                    }

                    # NEW v3.8: Track as critical attack
                    $CVEIndicators.AllAttacks += @{
                        Type = "Mimikatz Credential Theft"
                        Time = Get-Date
                        AttackerIP = "Local (w3wp.exe)"
                        TargetFile = "LSASS/Credentials"
                        Method = $child.Name
                        CommandLine = $commandLine
                        ThreatActor = "Advanced Threat Actor"
                        Severity = "Critical"
                    }
                }

                # Check for PsExec
                if ($child.Name -match 'PsExec') {
                    Write-SecurityLog "  CRITICAL: PsExec lateral movement tool detected!" "ALERT"
                    $CVEIndicators.PostExploitationTools += @{
                        Tool = "PsExec"
                        Process = $child.Name
                        CommandLine = $commandLine
                        Time = Get-Date
                    }

                    # NEW v3.8: Track as attack
                    $CVEIndicators.AllAttacks += @{
                        Type = "PsExec Lateral Movement"
                        Time = Get-Date
                        AttackerIP = "Local (w3wp.exe)"
                        TargetFile = if ($commandLine -match '\\\\(\S+)') { "Target: $($Matches[1])" } else { "Unknown Target" }
                        Method = "PsExec"
                        CommandLine = $commandLine
                        ThreatActor = "Unknown"
                        Severity = "High"
                    }
                }
            }
        }
    }
}

# Check for Impacket WMI activity
$wmiEvents = Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-WMI-Activity/Operational'
    ID = 5857, 5858, 5859, 5860, 5861
    StartTime = (Get-Date).AddHours(-24)
} -ErrorAction SilentlyContinue | Where-Object {
    $_.Message -match "WMIC|cmd\.exe.*\/node:|wmiexec"
}

if ($wmiEvents) {
    Write-SecurityLog "WARNING: Potential Impacket WMI activity detected" "WARNING"
    $CVEIndicators.PostExploitationTools += @{
        Tool = "Impacket"
        Type = "WMI Activity"
        Events = $wmiEvents.Count
        Time = Get-Date
    }

    # NEW v3.8: Track WMI attacks
    foreach ($wmiEvent in $wmiEvents | Select-Object -First 5) {
        $CVEIndicators.AllAttacks += @{
            Type = "Impacket WMI Activity"
            Time = $wmiEvent.TimeCreated
            AttackerIP = "Unknown"
            TargetFile = "WMI"
            Method = "WMI Command Execution"
            EventID = $wmiEvent.Id
            ThreatActor = "Unknown"
        }
    }
}
Stop-PerformanceTimer "W3WP Process Monitoring"

# NEW: 4a. CHECK FOR LSASS MEMORY ACCESS
Write-SecurityLog "Checking for LSASS memory access attempts..." "INFO"
Start-PerformanceTimer "LSASS Access Detection"

# Check for LSASS access events (requires Sysmon)
$lsassAccessEvents = @()
$suspiciousLsassEvents = @()

# Define legitimate processes that commonly access LSASS
$legitimateProcesses = @(
    "svchost.exe",
    "services.exe",
    "wininit.exe",
    "lsm.exe",
    "winlogon.exe",
    "csrss.exe",
    "smss.exe",
    "audiodg.exe",
    "searchindexer.exe",
    "taskmgr.exe",
    "mmc.exe",
    "vmtoolsd.exe",     # VMware Tools
    "ekrn.exe",         # ESET
    "egui.exe"          # ESET GUI
)

# Suspicious processes that should NOT access LSASS
$suspiciousProcesses = @(
    "powershell.exe",
    "powershell_ise.exe",
    "pwsh.exe",
    "cmd.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "notepad.exe",
    "calc.exe",
    "mspaint.exe"
)

# Try Sysmon first
$sysmonLog = Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    ID = 10  # Process Access
    StartTime = (Get-Date).AddHours(-24)
} -ErrorAction SilentlyContinue | Where-Object {
    $_.Message -match "TargetImage:.*lsass\.exe"
}

if ($sysmonLog) {
    foreach ($event in $sysmonLog) {
        $sourceProcess = ""
        $targetProcess = ""
        $accessMask = ""

        # Extract process information from Sysmon event
        if ($event.Message -match "SourceImage:\s*([^\r\n]+)") {
            $sourceProcess = [System.IO.Path]::GetFileName($Matches[1])
        }
        if ($event.Message -match "TargetImage:\s*([^\r\n]+)") {
            $targetProcess = [System.IO.Path]::GetFileName($Matches[1])
        }
        if ($event.Message -match "GrantedAccess:\s*([^\r\n]+)") {
            $accessMask = $Matches[1]
        }

        # Check if it's a suspicious access
        $isSuspicious = $false
        $reason = ""

        # Check if source is a suspicious process
        if ($sourceProcess -in $suspiciousProcesses) {
            $isSuspicious = $true
            $reason = "Suspicious process accessing LSASS: $sourceProcess"
        }
        # Check if it's an unknown process (not in legitimate list)
        elseif ($sourceProcess -and $sourceProcess -notin $legitimateProcesses) {
            # Check for specific suspicious access masks
            if ($accessMask -match "0x1410|0x1010|0x1438|0x143a|0x1418") {
                $isSuspicious = $true
                $reason = "Unknown process with memory read access: $sourceProcess"
            }
        }

        if ($isSuspicious) {
            $suspiciousLsassEvents += @{
                Time = $event.TimeCreated
                SourceProcess = $sourceProcess
                AccessMask = $accessMask
                Reason = $reason
                EventData = $event
            }

            # NEW v3.8: Track LSASS access as attack
            $CVEIndicators.AllAttacks += @{
                Type = "LSASS Memory Access"
                Time = $event.TimeCreated
                AttackerIP = "Local"
                TargetFile = "lsass.exe"
                Method = $sourceProcess
                AccessMask = $accessMask
                ThreatActor = "Potential Credential Thief"
                Severity = "Critical"
            }
        }
    }

    $lsassAccessEvents += $sysmonLog
}

# Check Security log for handle access to LSASS
$securityLsassEvents = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4656, 4663  # Handle and object access
    StartTime = (Get-Date).AddHours(-24)
} -ErrorAction SilentlyContinue | Where-Object {
    $_.Message -match "lsass\.exe" -and
    $_.Message -notmatch "Accesses:\s*%%4416" -and  # Exclude ReadControl only
    $_.Message -notmatch "Accesses:\s*%%4417" -and  # Exclude WriteDac only
    $_.Message -notmatch "Accesses:\s*%%4418" -and  # Exclude WriteOwner only
    $_.Message -notmatch "Accesses:\s*%%4423"       # Exclude generic read attributes
}

if ($securityLsassEvents) {
    foreach ($event in $securityLsassEvents) {
        $processName = ""

        # Extract process name from Security event
        if ($event.Message -match "Process Name:\s*([^\r\n]+)") {
            $fullPath = $Matches[1].Trim()
            $processName = [System.IO.Path]::GetFileName($fullPath)
        }

        # Check if suspicious
        if ($processName -in $suspiciousProcesses -or
            ($processName -and $processName -notin $legitimateProcesses)) {

            # Check for specific dangerous access patterns
            if ($event.Message -match "Accesses:.*Process_VM_Read|Process_VM_Write|Process_DUP_HANDLE|Process_Query_Information") {
                $suspiciousLsassEvents += @{
                    Time = $event.TimeCreated
                    SourceProcess = $processName
                    EventID = $event.Id
                    Reason = "Security event: Suspicious process accessing LSASS"
                    EventData = $event
                }

                # NEW v3.8: Track as attack
                $CVEIndicators.AllAttacks += @{
                    Type = "LSASS Access Attempt"
                    Time = $event.TimeCreated
                    AttackerIP = "Local"
                    TargetFile = "lsass.exe"
                    Method = $processName
                    EventID = $event.Id
                    ThreatActor = "Unknown"
                    Severity = "High"
                }
            }
        }
    }

    $lsassAccessEvents += $securityLsassEvents
}

# Additional check: Look for specific credential theft patterns
$credTheftPatterns = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4648, 4624  # Logon events that might indicate credential theft
    StartTime = (Get-Date).AddHours(-24)
} -ErrorAction SilentlyContinue | Where-Object {
    # Look for suspicious logon patterns
    $_.Message -match "Logon Type:\s*9" -or  # NewCredentials (RunAs)
    ($_.Message -match "Logon Type:\s*3" -and $_.Message -match "NTLM")  # Network logon with NTLM
} | Select-Object -First 50  # Limit to prevent too many events

# Analyze results
if ($suspiciousLsassEvents.Count -gt 0) {
    Write-SecurityLog "WARNING: Suspicious LSASS memory access detected!" "WARNING"

    # Group by source process
    $groupedEvents = $suspiciousLsassEvents | Group-Object -Property SourceProcess

    foreach ($group in $groupedEvents) {
        Write-SecurityLog "  Suspicious process: $($group.Name) - $($group.Count) events" "WARNING"

        # Show first few events
        $group.Group | Select-Object -First 3 | ForEach-Object {
            Write-SecurityLog "    Time: $($_.Time), Reason: $($_.Reason)" "WARNING"
        }
    }

$CVEIndicators.LSASSAccess += @{
        Count = $suspiciousLsassEvents.Count
        Events = $suspiciousLsassEvents | Select-Object -First 5
        Time = Get-Date
    }
} elseif ($lsassAccessEvents.Count -gt 0) {
    # Log for debugging but don't alert
    Write-SecurityLog "  Found $($lsassAccessEvents.Count) LSASS access events (all from legitimate processes)" "INFO"
} else {
    Write-SecurityLog "  No LSASS access events found" "INFO"
}

# Check if this is a post-reboot scenario (within 30 minutes of boot)
$bootTime = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
$timeSinceBoot = (Get-Date) - $bootTime

if ($timeSinceBoot.TotalMinutes -lt 30 -and $suspiciousLsassEvents.Count -gt 0) {
    Write-SecurityLog "  Note: System recently rebooted ($([int]$timeSinceBoot.TotalMinutes) minutes ago) - some events might be related to startup" "INFO"
}

Stop-PerformanceTimer "LSASS Access Detection"

# NEW: 4b. CHECK FOR REFLECTIVE DLL INJECTION
Write-SecurityLog "Checking for reflective DLL injection indicators..." "INFO"
Start-PerformanceTimer "Reflective DLL Injection Detection"

# Check for CreateRemoteThread events (requires Sysmon)
$remoteThreadEvents = Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    ID = 8  # CreateRemoteThread
    StartTime = (Get-Date).AddHours(-24)
} -ErrorAction SilentlyContinue

if ($remoteThreadEvents) {
    # Filter for suspicious patterns
    $suspiciousThreads = $remoteThreadEvents | Where-Object {
        $_.Message -match "w3wp\.exe|svchost\.exe|lsass\.exe"
    }

    if ($suspiciousThreads) {
        Write-SecurityLog "WARNING: Potential reflective DLL injection detected" "WARNING"
        $CVEIndicators.ReflectiveInjection += @{
            Count = $suspiciousThreads.Count
            TargetProcesses = @($suspiciousThreads | ForEach-Object {
                if ($_.Message -match "TargetImage:\s*([^\s]+)") { $Matches[1] }
            } | Select-Object -Unique)
            Time = Get-Date
        }

        # NEW v3.8: Track injection attempts
        foreach ($thread in $suspiciousThreads | Select-Object -First 5) {
            $targetProcess = ""
            if ($thread.Message -match "TargetImage:\s*([^\s]+)") {
                $targetProcess = [System.IO.Path]::GetFileName($Matches[1])
            }

            $CVEIndicators.AllAttacks += @{
                Type = "Reflective DLL Injection"
                Time = $thread.TimeCreated
                AttackerIP = "Local"
                TargetFile = $targetProcess
                Method = "CreateRemoteThread"
                EventID = $thread.Id
                ThreatActor = "Unknown"
                Severity = "High"
            }
        }
    }
}
Stop-PerformanceTimer "Reflective DLL Injection Detection"

# NEW: 4c. DLL BASELINE MANAGEMENT
if (($CreateBaseline -or -not $QuickScan) -and -not $ManageTasks) {
    Write-SecurityLog "Managing DLL baseline..." "INFO"
    Start-PerformanceTimer "DLL Baseline Management"

    $baselineFile = "$BaselinePath\DLL_Baseline.json"
    $changeDetected = $false
    $pendingDLLs = @{ PendingDLLs = @() }  # NEW v3.8

    # Load pending DLLs if exists
    if (Test-Path $PendingDLLFile) {
        try {
            $pendingDLLs = Get-Content $PendingDLLFile -Raw | ConvertFrom-Json
        } catch {
            Write-SecurityLog "Could not load pending DLLs file" "INFO"
        }
    }

    # Create new baseline if requested
    if ($CreateBaseline) {
        Write-SecurityLog "Creating new DLL baseline..." "INFO"
        $dllInventory = @{}
        $skippedDuplicates = 0  # NEW v3.9

        $WebPaths = @(
            "C:\inetpub\wwwroot\wss\VirtualDirectories",
            "C:\Windows\Temp",
            "C:\Windows\System32\inetsrv\temp",
            "C:\inetpub\temp",
            "C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\16\TEMPLATE\LAYOUTS",
            "C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\15\TEMPLATE\LAYOUTS",
            "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files"
        )

        foreach ($path in $WebPaths) {
            if (Test-Path $path) {
                Get-ChildItem -Path $path -Filter "*.dll" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                    try {
                        $hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash

                        # NEW v3.9: Check if this hash already exists in inventory
                        $existingEntry = $dllInventory.Values | Where-Object { $_.Hash -eq $hash } | Select-Object -First 1

                        if (-not $existingEntry) {
                            $dllInventory[$_.FullName] = @{
                                Hash = $hash
                                Size = $_.Length
                                Created = $_.CreationTime.ToString("yyyy-MM-dd HH:mm:ss")
                                Modified = $_.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                            }
                        } else {
                            $skippedDuplicates++
                            if ($VerboseDLL) {
                                Write-Host "  [Skip Duplicate] $($_.Name) - Same hash as existing entry" -ForegroundColor Gray
                            }
                        }
                    } catch {
                        Write-SecurityLog "Could not baseline file: $($_.FullName)" "WARNING"
                    }
                }
            }
        }

        # Backup old baseline if exists
        if (Test-Path $baselineFile) {
            Backup-CriticalFile -FilePath $baselineFile
            Write-SecurityLog "Previous baseline backed up" "INFO"
        }

        $dllInventory | ConvertTo-Json -Depth 3 | Out-File $baselineFile -Force
        Write-SecurityLog "DLL baseline created with $($dllInventory.Count) unique files ($skippedDuplicates duplicates skipped)" "SUCCESS"
    }
    # Compare with baseline if exists and not creating new one
    elseif (Test-Path $baselineFile) {
        Write-SecurityLog "Comparing current DLLs with baseline..." "INFO"
        $baselineJson = Get-Content $baselineFile -Raw | ConvertFrom-Json
        $baseline = @{}
        $baselineJson.PSObject.Properties | ForEach-Object { $baseline[$_.Name] = $_.Value }

        $currentDLLs = @{}
        $newDLLs = @()
        $modifiedDLLs = @()
        $deletedDLLs = @()

        # Scan current DLLs
        $WebPaths = @(
            "C:\inetpub\wwwroot\wss\VirtualDirectories",
            "C:\Windows\Temp",
            "C:\Windows\System32\inetsrv\temp",
            "C:\inetpub\temp",
            "C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\16\TEMPLATE\LAYOUTS",
            "C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\15\TEMPLATE\LAYOUTS",
            "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files"
        )

        foreach ($path in $WebPaths) {
            if (Test-Path $path) {
                Get-ChildItem -Path $path -Filter "*.dll" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                    $currentDLLs[$_.FullName] = $_

                    if ($null -eq $baseline[$_.FullName]) {
                        # New DLL found
                        $newDLLs += $_
                        $changeDetected = $true
                    } else {
                        # Check if modified
                        $currentHash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
                        if ($baseline[$_.FullName].Hash -ne $currentHash) {
                            $modifiedDLLs += @{
                                File = $_
                                OldHash = $baseline[$_.FullName].Hash
                                NewHash = $currentHash
                                OldModified = $baseline[$_.FullName].Modified
                            }
                            $changeDetected = $true
                        }
                    }
                }
            }
        }

        # Check for deleted DLLs
        foreach ($baselinePath in $baseline.Keys) {
            if (-not $currentDLLs.ContainsKey($baselinePath)) {
                $deletedDLLs += $baselinePath
                $changeDetected = $true
            }
        }

        # Report findings
        if ($newDLLs.Count -gt 0) {
            Write-SecurityLog "WARNING: $($newDLLs.Count) new DLLs detected since baseline!" "WARNING"
            foreach ($dll in $newDLLs | Select-Object -First 10) {
                # Check if suspicious
                $dllCheck = Test-SuspiciousDLL -File $dll -BasePath $dll.DirectoryName
                if ($dllCheck.IsSuspicious) {
                    Write-SecurityLog "  NEW SUSPICIOUS DLL: $($dll.FullName)" "ALERT"
                    $CVEIndicators.DLLPayloads += @{
                        Path = $dll.FullName
                        Type = "New DLL - " + $dllCheck.Reason
                        Details = $dllCheck.Details
                        Severity = "High"
                        Created = $dll.CreationTime
                        Modified = $dll.LastWriteTime
                        Size = $dll.Length
                        Hash = (Get-FileHash $dll.FullName -Algorithm SHA256).Hash
                    }

                    # NEW v3.8: Track DLL as attack
                    $CVEIndicators.AllAttacks += @{
                        Type = "Suspicious DLL Deployment"
                        Time = $dll.CreationTime
                        AttackerIP = "Unknown"
                        TargetFile = $dll.FullName
                        Method = "File Drop"
                        Details = $dllCheck.Reason
                        Hash = $dllCheck.Hash
                        ThreatActor = "Unknown"
                        Severity = $dllCheck.Severity
                    }

                    # NEW v3.8: Add to pending if can auto-approve
                    if ($dllCheck.CanAutoApprove -and -not $dllCheck.IsApproved) {
                        # Get signature info
                        $sigInfo = $null
                        try {
                            $sig = Get-AuthenticodeSignature $dll.FullName -ErrorAction Stop
                            if ($sig.Status -eq "Valid") {
                                $sigInfo = @{
                                    SignatureStatus = "Valid"
                                    SignerCertificate = $sig.SignerCertificate.Subject
                                }
                            }
                        } catch {}

                        $pendingDLLs.PendingDLLs += @{
                            Name = $dll.Name
                            Path = $dll.FullName
                            Hash = $dllCheck.Hash
                            Size = $dll.Length
                            Created = $dll.CreationTime.ToString("yyyy-MM-dd HH:mm:ss")
                            Modified = $dll.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                            Reason = $dllCheck.Reason
                            CanAutoApprove = $true
                            SignatureStatus = $sigInfo.SignatureStatus
                            SignerCertificate = $sigInfo.SignerCertificate
                        }
                    }
                } else {
                    Write-SecurityLog "  New DLL: $($dll.FullName)" "WARNING"
                }
            }
        }

        if ($modifiedDLLs.Count -gt 0) {
            Write-SecurityLog "ALERT: $($modifiedDLLs.Count) DLLs modified since baseline!" "ALERT"
            foreach ($mod in $modifiedDLLs | Select-Object -First 10) {
                Write-SecurityLog "  MODIFIED: $($mod.File.FullName) (Last modified: $($mod.File.LastWriteTime))" "ALERT"
                # Critical DLLs should never be modified
                if ($mod.File.Name -match "Microsoft\.SharePoint|System\.Web") {
                    Write-SecurityLog "    CRITICAL: Core DLL modification detected!" "ALERT"

                    # NEW v3.8: Track modification as attack
                    $CVEIndicators.AllAttacks += @{
                        Type = "Core DLL Tampering"
                        Time = $mod.File.LastWriteTime
                        AttackerIP = "Unknown"
                        TargetFile = $mod.File.FullName
                        Method = "File Modification"
                        OldHash = $mod.OldHash.Substring(0,16) + "..."
                        NewHash = $mod.NewHash.Substring(0,16) + "..."
                        ThreatActor = "Unknown"
                        Severity = "Critical"
                    }
                }
            }
        }

        if ($deletedDLLs.Count -gt 0) {
            Write-SecurityLog "INFO: $($deletedDLLs.Count) DLLs deleted since baseline" "INFO"
        }

        # NEW v3.9: Store details for report
        $global:SecurityResults.ModifiedDLLDetails = $modifiedDLLs | Select-Object -Property @{
            Name = 'Path'; Expression = { $_.File.FullName }
        }, @{
            Name = 'Name'; Expression = { $_.File.Name }
        }, @{
            Name = 'OldModified'; Expression = { $_.OldModified }
        }, @{
            Name = 'NewModified'; Expression = { $_.File.LastWriteTime }
        }, @{
            Name = 'Size'; Expression = { '{0:N2} KB' -f ($_.File.Length / 1KB) }
        }

        $global:SecurityResults.NewDLLDetails = $newDLLs | Select-Object -Property @{
            Name = 'Path'; Expression = { $_.FullName }
        }, @{
            Name = 'Name'; Expression = { $_.Name }
        }, @{
            Name = 'Created'; Expression = { $_.CreationTime }
        }, @{
            Name = 'Size'; Expression = { '{0:N2} KB' -f ($_.Length / 1KB) }
        }

        # Store statistics
        $global:SecurityResults.Statistics.BaselineNewDLLs = if ($CreateBaseline) { 0 } else { $newDLLs.Count }
        $global:SecurityResults.Statistics.BaselineModifiedDLLs = if ($CreateBaseline) { 0 } else { $modifiedDLLs.Count }
        $global:SecurityResults.Statistics.BaselineDeletedDLLs = if ($CreateBaseline) { 0 } else { $deletedDLLs.Count }
        $global:SecurityResults.Statistics.BaselineChangeDetected = if ($CreateBaseline) { $false } else { $changeDetected }

        # NEW v3.8: Save pending DLLs
        if ($pendingDLLs.PendingDLLs.Count -gt 0) {
            $pendingDLLs | ConvertTo-Json -Depth 3 | Out-File $PendingDLLFile -Force
            Write-SecurityLog "INFO: $($pendingDLLs.PendingDLLs.Count) DLLs added to pending approval list" "INFO"
            Write-SecurityLog "TIP: Run with -ReviewPendingDLLs to review and approve legitimate DLLs" "INFO"
        }
    }
    else {
        # Auto-create baseline if it doesn't exist
        Write-SecurityLog "No DLL baseline found. Creating initial baseline automatically..." "INFO"
        Write-SecurityLog "This is a one-time operation to establish the baseline for future comparisons." "INFO"

        $dllInventory = @{}
        $skippedDuplicates = 0  # NEW v3.9

        $WebPaths = @(
            "C:\inetpub\wwwroot\wss\VirtualDirectories",
            "C:\Windows\Temp",
            "C:\Windows\System32\inetsrv\temp",
            "C:\inetpub\temp",
            "C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\16\TEMPLATE\LAYOUTS",
            "C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\15\TEMPLATE\LAYOUTS",
            "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files"
        )

        foreach ($path in $WebPaths) {
            if (Test-Path $path) {
                Get-ChildItem -Path $path -Filter "*.dll" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                    try {
                        $hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash

                        # NEW v3.9: Check for duplicates
                        $existingEntry = $dllInventory.Values | Where-Object { $_.Hash -eq $hash } | Select-Object -First 1

                        if (-not $existingEntry) {
                            $dllInventory[$_.FullName] = @{
                                Hash = $hash
                                Size = $_.Length
                                Created = $_.CreationTime.ToString("yyyy-MM-dd HH:mm:ss")
                                Modified = $_.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                            }
                        } else {
                            $skippedDuplicates++
                        }
                    } catch {
                        Write-SecurityLog "Could not baseline file: $($_.FullName)" "WARNING"
                    }
                }
            }
        }

        $dllInventory | ConvertTo-Json -Depth 3 | Out-File $baselineFile -Force
        Write-SecurityLog "Initial DLL baseline created automatically with $($dllInventory.Count) unique files ($skippedDuplicates duplicates skipped)" "SUCCESS"
        Write-SecurityLog "Future scans will compare against this baseline to detect changes" "INFO"

        # Set statistics to show this was a baseline creation
        $global:SecurityResults.Statistics.BaselineNewDLLs = 0
        $global:SecurityResults.Statistics.BaselineModifiedDLLs = 0
        $global:SecurityResults.Statistics.BaselineDeletedDLLs = 0
        $global:SecurityResults.Statistics.BaselineChangeDetected = $false
        $global:SecurityResults.Statistics.BaselineAutoCreated = $true
    }

    Stop-PerformanceTimer "DLL Baseline Management"
} else {
    # If not doing baseline check, set values to 0
    $global:SecurityResults.Statistics.BaselineNewDLLs = 0
    $global:SecurityResults.Statistics.BaselineModifiedDLLs = 0
    $global:SecurityResults.Statistics.BaselineDeletedDLLs = 0
    $global:SecurityResults.Statistics.BaselineChangeDetected = $false
}

# NEW: 4d. SHAREPOINT FILE INTEGRITY CHECK
if (($CheckIntegrity -or -not $QuickScan) -and -not $ManageTasks) {
    Write-SecurityLog "Checking SharePoint core file integrity..." "INFO"
    Start-PerformanceTimer "SharePoint Integrity Check"

    # Integrity baseline file
    $integrityFile = "C:\GOLINE\SharePoint_Monitoring\Baselines\SharePoint_Integrity.json"

    # Define critical SharePoint files and their expected hashes
    # NOTE: These hashes should be updated for your specific SharePoint version
    $criticalFiles = @{
        # SharePoint 2019 core files - UPDATE THESE HASHES FOR YOUR ENVIRONMENT
        "Microsoft.SharePoint.dll" = @{
            Path = "C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\16\ISAPI\Microsoft.SharePoint.dll"
            ExpectedHash = ""  # Will be populated on first run
        }
        "Microsoft.SharePoint.Portal.dll" = @{
            Path = "C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\16\ISAPI\Microsoft.SharePoint.Portal.dll"
            ExpectedHash = ""
        }
        "owssvr.dll" = @{
            Path = "C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\16\ISAPI\owssvr.dll"
            ExpectedHash = ""
        }
        "Microsoft.SharePoint.Security.dll" = @{
            Path = "C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\16\ISAPI\Microsoft.SharePoint.Security.dll"
            ExpectedHash = ""
        }
    }

    # Load or create integrity baseline
    if (Test-Path $integrityFile) {
        try {
            Write-SecurityLog "Loading existing integrity baseline from: $integrityFile" "INFO"
            $integrityJson = Get-Content $integrityFile -Raw | ConvertFrom-Json
            $integrityBaseline = @{}

            if ($integrityJson) {
                $integrityJson.PSObject.Properties | ForEach-Object {
                    $integrityBaseline[$_.Name] = $_.Value
                }
                Write-SecurityLog "Loaded $($integrityBaseline.Count) files from integrity baseline" "INFO"
            }
        } catch {
            Write-SecurityLog "Error loading integrity baseline: $_" "WARNING"
            Write-SecurityLog "Creating new SharePoint integrity baseline..." "INFO"
            $integrityBaseline = @{}
        }
    } else {
        Write-SecurityLog "No existing baseline found. Creating SharePoint integrity baseline..." "INFO"
        $integrityBaseline = @{}
    }

    $integrityIssues = @()

    foreach ($fileName in $criticalFiles.Keys) {
        $fileInfo = $criticalFiles[$fileName]

        if (Test-Path $fileInfo.Path) {
            $currentFile = Get-Item $fileInfo.Path
            $currentHash = (Get-FileHash $fileInfo.Path -Algorithm SHA256).Hash

            # Check version info
            $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($fileInfo.Path)

            if ($null -ne $integrityBaseline[$fileName]) {
                # Compare with baseline
                $baseline = $integrityBaseline[$fileName]

                if ($baseline.Hash -ne $currentHash) {
                    $integrityIssues += @{
                        File = $fileName
                        Path = $fileInfo.Path
                        Issue = "Hash mismatch"
                        ExpectedHash = $baseline.Hash
                        CurrentHash = $currentHash
                        LastModified = $currentFile.LastWriteTime
                        Version = $versionInfo.FileVersion
                    }

                    Write-SecurityLog "CRITICAL: SharePoint file tampering detected: $fileName" "ALERT"
                    Write-SecurityLog "  Expected: $($baseline.Hash.Substring(0,16))..." "ALERT"
                    Write-SecurityLog "  Current:  $($currentHash.Substring(0,16))..." "ALERT"
                    Write-SecurityLog "  Modified: $($currentFile.LastWriteTime)" "ALERT"

                    # NEW v3.8: Track as critical attack
                    $CVEIndicators.AllAttacks += @{
                        Type = "SharePoint Core File Tampering"
                        Time = $currentFile.LastWriteTime
                        AttackerIP = "Unknown"
                        TargetFile = $fileInfo.Path
                        Method = "File Modification"
                        OldHash = $baseline.Hash.Substring(0,16) + "..."
                        NewHash = $currentHash.Substring(0,16) + "..."
                        ThreatActor = "Unknown"
                        Severity = "Critical"
                    }
                }
            } else {
                # Add to baseline
                Write-SecurityLog "Adding $fileName to integrity baseline (first time)" "INFO"
                $integrityBaseline[$fileName] = @{
                    Hash = $currentHash
                    Size = $currentFile.Length
                    Modified = $currentFile.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                    Version = $versionInfo.FileVersion
                    Company = $versionInfo.CompanyName
                }
                Write-SecurityLog "Added $fileName to integrity baseline" "INFO"
            }

            # Check if signed by Microsoft
            $signature = Get-AuthenticodeSignature $fileInfo.Path
            if ($signature.Status -ne "Valid" -or $signature.SignerCertificate.Subject -notmatch "Microsoft Corporation") {
                $integrityIssues += @{
                    File = $fileName
                    Path = $fileInfo.Path
                    Issue = "Invalid or missing digital signature"
                    SignatureStatus = $signature.Status
                }
                Write-SecurityLog "WARNING: $fileName has invalid digital signature!" "WARNING"
            }
        } else {
            Write-SecurityLog "WARNING: Critical SharePoint file missing: $($fileInfo.Path)" "WARNING"
            $integrityIssues += @{
                File = $fileName
                Path = $fileInfo.Path
                Issue = "File missing"
            }
        }
    }

    # Save updated baseline
    Backup-CriticalFile -FilePath $integrityFile
    # Verifica che il percorso sia corretto
    if ($integrityFile -match "\.dll\\") {
        # Correggi il percorso se contiene .dll come directory
        $integrityFile = Join-Path "C:\GOLINE\SharePoint_Monitoring\Baselines" "SharePoint_Integrity.json"
    }

    # Crea la directory se non esiste
    $integrityDir = Split-Path $integrityFile -Parent
    if (!(Test-Path $integrityDir)) {
        New-Item -ItemType Directory -Path $integrityDir -Force | Out-Null
    }

    $integrityBaseline | ConvertTo-Json -Depth 3 | Out-File $integrityFile -Force

    # Store results
    $global:SecurityResults.Statistics.IntegrityIssues = $integrityIssues.Count
    if ($integrityIssues.Count -gt 0) {
        $CVEIndicators.ThreatActorActivity += @{
            Actor = "Unknown"
            Type = "SharePoint File Tampering"
            Evidence = "$($integrityIssues.Count) files with integrity issues"
            Time = Get-Date
        }
    }

    Stop-PerformanceTimer "SharePoint Integrity Check"
} else {
    # If not doing integrity check, set to 0
    $global:SecurityResults.Statistics.IntegrityIssues = 0
}

# 5. WEBSHELL AND DLL PAYLOAD DETECTION - ENHANCED WITH INTELLIGENT FILTERING
Write-SecurityLog "Performing comprehensive webshell and DLL payload scan with intelligent filtering..." "INFO"
Start-PerformanceTimer "Webshell and DLL Detection"

$WebPaths = @(
    "C:\inetpub\wwwroot\wss\VirtualDirectories",
    "C:\Windows\Temp",
    "C:\Windows\System32\inetsrv\temp",
    "C:\inetpub\temp",
    "C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\16\TEMPLATE\LAYOUTS",
    "C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\15\TEMPLATE\LAYOUTS",
    "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files"
)

# Enhanced webshell signatures
$WebshellSignatures = @{
    # Known webshell patterns
    "spinstall[0-9]*\.aspx" = "ToolShell Webshell Pattern"
    "info[0-9]+\.aspx" = "ToolShell Info Webshell"
    "System\.Web\.Configuration\.MachineKeySection" = "Machine Key Theft Code"
    "GetApplicationConfig.*ValidationKey" = "Validation Key Extraction"

    # Process execution patterns
    "System\.Diagnostics\.Process\.Start" = "Process Execution"
    "Shell\.Execute|WScript\.Shell" = "Script Shell Execution"

    # Obfuscation patterns
    "FromBase64String.*Invoke" = "Base64 Invoke Pattern"
    "[char]\[\]\s*\+\s*[char]\[\]" = "Char Array Obfuscation"

    # Known webshell signatures
    "c99shell|r57shell|b374k|wso.*shell" = "Known Webshell Signature"
}

# Additional suspicious files to look for
$SuspiciousFiles = @(
    "IIS_Server_dll.dll",
    "SharpHostInfo.x64.exe",
    "xd.exe",
    "debug_dev.js"
)

$totalDLLsScanned = 0
$legitimateDLLsSkipped = 0

foreach ($path in $WebPaths) {
    if (Test-Path $path) {
        Write-SecurityLog "  Scanning: $path" "INFO"

        # Include DLL and EXE files
        $files = Get-ChildItem -Path $path -Recurse -Include "*.aspx","*.asmx","*.ashx","*.asp","*.ps1","*.bat","*.cmd","*.dll","*.exe","*.js" -ErrorAction SilentlyContinue

        foreach ($file in $files) {
            # Skip SharePoint legitimate files
            $isLegitimate = $false
            foreach ($legitPattern in $SharePointLegitimatePatterns) {
                if ($file.FullName -match $legitPattern) {
                    $isLegitimate = $true
                    break
                }
            }

            if ($isLegitimate -and $file.Extension -notin @('.dll', '.exe')) {
                continue
            }

            # Special handling for DLL files with intelligent filtering
            if ($file.Extension -eq '.dll') {
                $totalDLLsScanned++

                # Use intelligent DLL checking
                $dllCheck = Test-SuspiciousDLL -File $file -BasePath $path

                if ($dllCheck.IsSuspicious) {
                    $hash = (Get-FileHash $file.FullName -Algorithm SHA256).Hash

                    $CVEIndicators.DLLPayloads += @{
                        Path = $file.FullName
                        Type = $dllCheck.Reason
                        Details = $dllCheck.Details
                        Severity = $dllCheck.Severity
                        Created = $file.CreationTime
                        Modified = $file.LastWriteTime
                        Size = $file.Length
                        Hash = $hash
                    }

                    # NEW v3.8: Track DLL deployment as attack
                    $CVEIndicators.AllAttacks += @{
                        Type = "Suspicious DLL Found"
                        Time = $file.CreationTime
                        AttackerIP = "Unknown"
                        TargetFile = $file.FullName
                        Method = "DLL Deployment"
                        Details = $dllCheck.Reason
                        Hash = $hash
                        ThreatActor = if ($dllCheck.Details) { "Known Malware" } else { "Unknown" }
                        Severity = $dllCheck.Severity
                    }

                    if ($dllCheck.Severity -eq "Critical") {
                        Write-SecurityLog "CRITICAL: Malicious DLL detected: $($file.FullName) - $($dllCheck.Details)" "ALERT"
                    } else {
                        Write-SecurityLog "SUSPICIOUS: $($dllCheck.Reason): $($file.FullName)" "WARNING"
                    }
                } else {
                    $legitimateDLLsSkipped++
                    if ($dllCheck.IsApproved) {
                        # Already approved, skip silently
                    }
                }

                continue  # Skip further processing for DLLs
            }

            # Check if file name matches suspicious patterns (for non-DLLs)
            if ($file.Name -in $SuspiciousFiles) {
                $hash = (Get-FileHash $file.FullName -Algorithm SHA256).Hash

                Write-SecurityLog "CRITICAL: Suspicious file found: $($file.FullName)" "ALERT"

                if ($file.Name -match "SharpHostInfo|xd\.exe") {
                    $CVEIndicators.PostExploitationTools += @{
                        Tool = $file.Name
                        Path = $file.FullName
                        Hash = $hash
                        Time = $file.CreationTime
                    }

                    # NEW v3.8: Track tool deployment
                    $CVEIndicators.AllAttacks += @{
                        Type = "Attack Tool Deployment"
                        Time = $file.CreationTime
                        AttackerIP = "Unknown"
                        TargetFile = $file.FullName
                        Method = "Tool Drop"
                        Tool = $file.Name
                        Hash = $hash
                        ThreatActor = "Unknown"
                        Severity = "High"
                    }
                } elseif ($file.Name -eq "debug_dev.js") {
                    $CVEIndicators.MachineKeyTheft += @{
                        Type = "StolenConfigFile"
                        Path = $file.FullName
                        Hash = $hash
                        Time = $file.CreationTime
                    }
                }
            }

            # Check file content for patterns (not for DLL/EXE)
            if ($file.Extension -notin @('.dll', '.exe') -and $file.Length -lt 1MB -and $file.Length -gt 50) {
                try {
                    $content = [System.IO.File]::ReadAllText($file.FullName, [System.Text.Encoding]::UTF8)

                    foreach ($pattern in $WebshellSignatures.Keys) {
                        if ($content -match $pattern) {
                            $hash = (Get-FileHash $file.FullName -Algorithm SHA256).Hash

                            $CVEIndicators.WebshellsFound += @{
                                Path = $file.FullName
                                Pattern = $WebshellSignatures[$pattern]
                                Hash = $hash
                                Size = $file.Length
                                Modified = $file.LastWriteTime
                                Created = $file.CreationTime
                            }

                            # NEW v3.8: Track webshell as attack
                            $CVEIndicators.AllAttacks += @{
                                Type = "Webshell Detected"
                                Time = $file.CreationTime
                                AttackerIP = "Unknown"
                                TargetFile = $file.FullName
                                Method = "Webshell Deployment"
                                Pattern = $WebshellSignatures[$pattern]
                                Hash = $hash
                                ThreatActor = "Unknown"
                                Severity = "Critical"
                            }

                            Write-SecurityLog "WEBSHELL DETECTED: $($file.FullName) - $($WebshellSignatures[$pattern])" "ALERT"
                            break
                        }
                    }
                } catch {
                    # Skip files that can't be read
                }
            }
        }
    }
}

Write-SecurityLog "  Total DLLs scanned: $totalDLLsScanned" "INFO"
Write-SecurityLog "  Legitimate DLLs skipped: $legitimateDLLsSkipped" "INFO"
Write-SecurityLog "  Suspicious DLLs found: $($CVEIndicators.DLLPayloads.Count)" "INFO"
Stop-PerformanceTimer "Webshell and DLL Detection"

# 6. RANSOMWARE DETECTION - ENHANCED
Write-SecurityLog "Checking for ransomware indicators..." "INFO"
Start-PerformanceTimer "Ransomware Detection"

$ransomwareExtensions = @(".locked", ".encrypted", ".enc", ".crypt", ".lockbit", ".clop", ".ryuk")
$ransomwareNotes = @("README.txt", "HOW_TO_DECRYPT.txt", "RESTORE_FILES.txt", "!!!READ_ME!!!.txt", "LOCKBIT_README.txt")

# Check common directories for ransomware
$pathsToCheck = @(
    "C:\inetpub\wwwroot",
    "C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions",
    "C:\Users"
)

foreach ($path in $pathsToCheck) {
    if (Test-Path $path) {
        # Check for encrypted files
        foreach ($ext in $ransomwareExtensions) {
            $encryptedFiles = Get-ChildItem -Path $path -Filter "*$ext" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 10
            if ($encryptedFiles) {
                $CVEIndicators.RansomwareIndicators += @{
                    Type = "EncryptedFiles"
                    Extension = $ext
                    SampleFiles = $encryptedFiles.FullName
                    Count = $encryptedFiles.Count
                    ThreatActor = "Unknown Ransomware Group"
                }
                Write-SecurityLog "CRITICAL: Potential ransomware encryption detected! Files with extension $ext found" "ALERT"

                # Track threat actor activity
                $CVEIndicators.ThreatActorActivity += @{
                    Actor = "Ransomware Group"
                    Type = "Ransomware Deployment"
                    Evidence = "Encrypted files with $ext extension"
                    Time = Get-Date
                }

                # NEW v3.8: Track ransomware as critical attack
                foreach ($encFile in $encryptedFiles | Select-Object -First 3) {
                    $CVEIndicators.AllAttacks += @{
                        Type = "Ransomware Encryption"
                        Time = $encFile.LastWriteTime
                        AttackerIP = "Unknown"
                        TargetFile = $encFile.FullName
                        Method = "File Encryption"
                        Extension = $ext
                        ThreatActor = "Ransomware Operator"
                        Severity = "Critical"
                    }
                }
            }
        }

        # Check for ransom notes
        foreach ($note in $ransomwareNotes) {
            $ransomNotes = Get-ChildItem -Path $path -Filter $note -Recurse -ErrorAction SilentlyContinue
            if ($ransomNotes) {
                $CVEIndicators.RansomwareIndicators += @{
                    Type = "RansomNote"
                    FileName = $note
                    Locations = $ransomNotes.FullName
                }
                Write-SecurityLog "CRITICAL: Ransom note found: $note" "ALERT"

                # NEW v3.8: Track ransom note as attack
                foreach ($noteFile in $ransomNotes | Select-Object -First 3) {
                    $CVEIndicators.AllAttacks += @{
                        Type = "Ransomware Note Deployment"
                        Time = $noteFile.CreationTime
                        AttackerIP = "Unknown"
                        TargetFile = $noteFile.FullName
                        Method = "Ransom Note"
                        ThreatActor = "Ransomware Operator"
                        Severity = "Critical"
                    }
                }
            }
        }
    }
}
Stop-PerformanceTimer "Ransomware Detection"

# 7. CHECK ASP.NET MACHINE KEYS STATUS
Write-SecurityLog "Checking ASP.NET machine key configuration..." "INFO"
Start-PerformanceTimer "Machine Key Status Check"

$machineKeyRotated = $false
$machineKeyRotationDate = $null

# Check multiple web.config locations for machine key changes
$webConfigPaths = @()

# Get all SharePoint web.config files dynamically
$virtualDirs = Get-ChildItem "C:\inetpub\wwwroot\wss\VirtualDirectories" -Directory -ErrorAction SilentlyContinue
foreach ($dir in $virtualDirs) {
    $configPath = Join-Path $dir.FullName "web.config"
    if (Test-Path $configPath) {
        $webConfigPaths += $configPath
    }
}

# Add framework configs
$webConfigPaths += @(
    "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config",
    "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\machine.config"
)

foreach ($configPath in $webConfigPaths) {
    if (Test-Path $configPath) {
        $config = Get-Item $configPath

        # Check if config was modified after attack date (using real date)
        if ($config.LastWriteTime -gt (Get-Date "2023-07-01")) {
            # Read the file to check for machineKey section
            try {
                $content = Get-Content $configPath -Raw
                if ($content -match "<machineKey[^>]*validationKey=`"([^`"]+)`"[^>]*decryptionKey=`"([^`"]+)`"") {
                    # Machine key section exists and was modified after attack
                    $machineKeyRotated = $true
                    if ($null -eq $machineKeyRotationDate -or $config.LastWriteTime -gt $machineKeyRotationDate) {
                        $machineKeyRotationDate = $config.LastWriteTime
                    }
                    Write-SecurityLog "Machine keys detected in $configPath (modified: $($config.LastWriteTime))" "INFO"
                }
            } catch {
                Write-SecurityLog "Could not read $configPath for machine key check" "INFO"
            }
        }
    }
}

# Also check IIS lastKeySet in registry
try {
    $iisReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\IIS\Security" -Name "LastKeyRotation" -ErrorAction SilentlyContinue
    if ($iisReg -and $iisReg.LastKeyRotation) {
        $regDate = [DateTime]::Parse($iisReg.LastKeyRotation)
        if ($regDate -gt (Get-Date "2023-07-01")) {
            $machineKeyRotated = $true
            if ($null -eq $machineKeyRotationDate -or $regDate -gt $machineKeyRotationDate) {
                $machineKeyRotationDate = $regDate
            }
        }
    }
} catch {
    # Registry key might not exist
}

if ($machineKeyRotated) {
    Write-SecurityLog "Machine keys were rotated on: $machineKeyRotationDate" "SUCCESS"
} else {
    Write-SecurityLog "WARNING: No evidence of machine key rotation since July 2023" "WARNING"
}
Stop-PerformanceTimer "Machine Key Status Check"

# NEW: 7a. CHECK ADVANCED SECURITY FEATURES
Write-SecurityLog "Checking advanced security features status..." "INFO"
Start-PerformanceTimer "Advanced Security Features"

# Check if ESET is active first
$mdeEnabled = $false
$endpointProtection = "None"

try {
    # First check for ESET
    if ($esetEnabled) {
        $endpointProtection = "ESET"
        Write-SecurityLog "ESET Endpoint Protection is running" "SUCCESS"
    } else {
        # Check for Microsoft Defender for Endpoint
        $mdeService = Get-Service -Name "Sense" -ErrorAction SilentlyContinue
        if ($mdeService -and $mdeService.Status -eq "Running") {
            $mdeEnabled = $true
            $endpointProtection = "Microsoft Defender for Endpoint"
            Write-SecurityLog "Microsoft Defender for Endpoint is running" "SUCCESS"
        } else {
            Write-SecurityLog "WARNING: No endpoint protection service detected (MDE or ESET)" "WARNING"
        }
    }
} catch {
    Write-SecurityLog "Could not check endpoint protection status" "INFO"
}

# If ESET is active, show informational message
if ($esetEnabled) {
    Write-SecurityLog "ESET detected - some Microsoft Defender-specific features will show as 'Protected by ESET'" "INFO"
}

# Check LSA Protection
$lsaProtection = $false
try {
    $lsaReg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
    if ($lsaReg -and $lsaReg.RunAsPPL -eq 1) {
        $lsaProtection = $true
        Write-SecurityLog "LSA Protection is enabled" "SUCCESS"
    } else {
        Write-SecurityLog "WARNING: LSA Protection is not enabled" "WARNING"
    }
} catch {
    Write-SecurityLog "Could not check LSA Protection status" "INFO"
}

# Check Credential Guard
$credentialGuardEnabled = $false
$credentialGuardStatus = "Not Applicable (ESET Active)"
try {
    # Only if not using ESET
    if (-not $esetEnabled) {
        $credGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
        if ($credGuard -and $credGuard.SecurityServicesRunning -contains 1) {
            $credentialGuardEnabled = $true
            $credentialGuardStatus = "Enabled"
            Write-SecurityLog "Credential Guard is enabled" "SUCCESS"
        } else {
            $credentialGuardStatus = "Not Enabled"
            Write-SecurityLog "WARNING: Credential Guard is not enabled" "WARNING"
        }
    } else {
        # With ESET don't generate warning, just info
        Write-SecurityLog "Credential Guard check skipped - ESET provides credential protection" "INFO"
    }
} catch {
    if (-not $esetEnabled) {
        Write-SecurityLog "Could not check Credential Guard status" "INFO"
    }
}

# Check Controlled Folder Access
$controlledFolderAccess = $false
$controlledFolderAccessStatus = "Not Applicable (ESET Active)"
try {
    # Only if not using ESET
    if (-not $esetEnabled) {
        $cfaStatus = Get-MpPreference -ErrorAction SilentlyContinue | Select-Object -ExpandProperty EnableControlledFolderAccess
        if ($cfaStatus -eq 1) {
            $controlledFolderAccess = $true
            $controlledFolderAccessStatus = "Enabled"
            Write-SecurityLog "Controlled Folder Access is enabled" "SUCCESS"
        } else {
            $controlledFolderAccessStatus = "Not Enabled"
            Write-SecurityLog "WARNING: Controlled Folder Access is not enabled" "WARNING"
        }
    } else {
        # With ESET don't generate warning, just info
        Write-SecurityLog "Controlled Folder Access check skipped - ESET provides ransomware protection" "INFO"
    }
} catch {
    if (-not $esetEnabled) {
        Write-SecurityLog "Could not check Controlled Folder Access status" "INFO"
    }
}

# Check Attack Surface Reduction Rules
$asrRulesEnabled = 0
$asrRulesStatus = "Not Applicable (ESET Active)"
try {
    # Only if not using ESET
    if (-not $esetEnabled) {
        $asrRules = Get-MpPreference -ErrorAction SilentlyContinue | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
        if ($asrRules) {
            $asrRulesEnabled = $asrRules.Count
            $asrRulesStatus = "$asrRulesEnabled Rules"
            Write-SecurityLog "Attack Surface Reduction Rules enabled: $asrRulesEnabled" "INFO"
        } else {
            $asrRulesStatus = "None"
            Write-SecurityLog "WARNING: No Attack Surface Reduction Rules are enabled" "WARNING"
        }
    } else {
        # With ESET don't generate warning, just info
        Write-SecurityLog "ASR Rules check skipped - ESET provides exploit protection" "INFO"
    }
} catch {
    if (-not $esetEnabled) {
        Write-SecurityLog "Could not check Attack Surface Reduction Rules" "INFO"
    }
}

# 8. SYSTEM SECURITY CHECKS
Write-SecurityLog "Performing system security checks..." "INFO"

# Check for suspicious scheduled tasks
$legitimateTaskNames = @(
    "Automatic-Device-Join",
    "Recovery-Check",
    "Collection",
    "Configuration",
    "Unistall Adobe Genuine Service"  # Even with the typo
)

$SuspiciousTasks = Get-ScheduledTask | Where-Object {
    # Exclude legitimate tasks
    $_.TaskName -notin $legitimateTaskNames -and
    # Exclude Microsoft and Windows tasks
    $_.TaskPath -notlike "\Microsoft\*" -and
    # Check for suspicious patterns
    (
        $_.TaskName -match "^(temp|test|debug|update\d+)$" -or
        ($_.Actions.Execute -match "powershell|cmd|PsExec|wmic" -and
         $_.Author -notmatch "Microsoft|Adobe|Windows" -and
         $_.TaskName -notlike "*SharePoint*" -and
         $_.TaskName -notlike "*Office*")
    )
} -ErrorAction SilentlyContinue

if ($SuspiciousTasks) {
    Write-SecurityLog "Suspicious scheduled tasks detected!" "WARNING" $SuspiciousTasks

    # NEW v3.8: Track scheduled tasks as persistence
    foreach ($task in $SuspiciousTasks | Select-Object -First 5) {
        $CVEIndicators.AllAttacks += @{
            Type = "Suspicious Scheduled Task"
            Time = if ($task.Date) { $task.Date } else { Get-Date }
            AttackerIP = "Local"
            TargetFile = $task.TaskName
            Method = "Scheduled Task Persistence"
            Command = if ($task.Actions) { $task.Actions[0].Execute } else { "Unknown" }
            ThreatActor = "Unknown"
        }
    }
}
Stop-PerformanceTimer "System Security Checks"

# 9. NETWORK MONITORING WITH KNOWN ATTACKER IPS AND C2 DOMAINS
Write-SecurityLog "Checking network connections..." "INFO"
Start-PerformanceTimer "Network Monitoring"

$ActiveConnections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue

# Check for connections to/from known attacker IPs
$knownAttackerConnections = $ActiveConnections | Where-Object {
    $_.RemoteAddress -in $KnownAttackerIPs
}

if ($knownAttackerConnections) {
    Write-SecurityLog "CRITICAL: Active connections to known attacker IPs!" "ALERT" $knownAttackerConnections

    # Identify threat actors based on IP
    foreach ($conn in $knownAttackerConnections) {
        $actor = "Unknown"
        if ($conn.RemoteAddress -in @("131.226.2.6", "65.38.121.198")) {
            $actor = "Advanced Threat Actor"
        } elseif ($conn.RemoteAddress -in @("134.199.202.205", "188.130.206.168")) {
            $actor = "Known APT Group"
        }

        $CVEIndicators.ThreatActorActivity += @{
            Actor = $actor
            Type = "Active C2 Connection"
            IP = $conn.RemoteAddress
            LocalPort = $conn.LocalPort
            Time = Get-Date
        }

        # NEW v3.8: Track active C2 as critical attack
        $CVEIndicators.AllAttacks += @{
            Type = "Active C2 Connection"
            Time = Get-Date
            AttackerIP = $conn.RemoteAddress
            TargetFile = "Port $($conn.LocalPort)"
            Method = "Network Connection"
            State = "Active"
            ThreatActor = $actor
            Severity = "Critical"
        }
    }
}

# Check for suspicious outbound connections from web processes
$webProcessConnections = $ActiveConnections | Where-Object {
    $_.OwningProcess -in @($w3wpProcesses.Id) -and
    -not (Test-InternalIPAddress $_.RemoteAddress)
}

if ($webProcessConnections) {
    Write-SecurityLog "WARNING: w3wp.exe making external connections" "WARNING" $webProcessConnections

    # NEW v3.8: Track suspicious web connections
    foreach ($webConn in $webProcessConnections | Select-Object -First 5) {
        $CVEIndicators.AllAttacks += @{
            Type = "Suspicious Web Process Connection"
            Time = Get-Date
            AttackerIP = $webConn.RemoteAddress
            TargetFile = "w3wp.exe -> $($webConn.RemoteAddress):$($webConn.RemotePort)"
            Method = "Outbound Connection"
            ThreatActor = "Unknown"
        }
    }
}

# Check DNS cache for C2 domains
$dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue
foreach ($domain in $KnownC2Domains) {
    $c2Entry = $dnsCache | Where-Object { $_.Entry -like "*$domain*" }
    if ($c2Entry) {
        Write-SecurityLog "CRITICAL: C2 domain found in DNS cache: $domain" "ALERT"
        $CVEIndicators.C2Communications += @{
            Type = "DNS Cache"
            Domain = $domain
            Entries = $c2Entry
            Time = Get-Date
        }

        # NEW v3.8: Track C2 domain resolution
        $CVEIndicators.AllAttacks += @{
            Type = "C2 Domain Resolution"
            Time = Get-Date
            AttackerIP = if ($c2Entry.Data) { $c2Entry.Data } else { "Unknown" }
            TargetFile = $domain
            Method = "DNS Lookup"
            ThreatActor = "Unknown"
            Severity = "High"
        }
    }
}

# Check for devtunnels.ms domains
$devTunnelsEntries = $dnsCache | Where-Object { $_.Entry -like "*.devtunnels.ms" }
if ($devTunnelsEntries) {
    Write-SecurityLog "WARNING: DevTunnels domain found in DNS cache (potential C2)" "WARNING"
    foreach ($entry in $devTunnelsEntries) {
        $CVEIndicators.C2Communications += @{
            Type = "DevTunnels DNS"
            Domain = $entry.Entry
            Time = Get-Date
        }

        # NEW v3.8: Track DevTunnels usage
        $CVEIndicators.AllAttacks += @{
            Type = "DevTunnels C2 Domain"
            Time = Get-Date
            AttackerIP = if ($entry.Data) { $entry.Data } else { "Unknown" }
            TargetFile = $entry.Entry
            Method = "DevTunnels Service"
            ThreatActor = "Unknown"
        }
    }
}
Stop-PerformanceTimer "Network Monitoring"

# 10. ANTIMALWARE SCAN INTERFACE (AMSI) CHECK
Write-SecurityLog "Checking AMSI configuration..." "INFO"
Start-PerformanceTimer "AMSI Configuration Check"

# Check if AMSI is enabled for SharePoint
$amsiEnabled = $false
try {
    $amsiReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\AMSI" -ErrorAction SilentlyContinue
    if ($amsiReg) {
        $amsiEnabled = $true
        Write-SecurityLog "AMSI is configured on the system" "INFO"
    } else {
        Write-SecurityLog "WARNING: AMSI not configured - recommended by Microsoft security advisories" "WARNING"
    }
} catch {
    Write-SecurityLog "Could not check AMSI status" "INFO"
}
Stop-PerformanceTimer "AMSI Configuration Check"

# Store statistics
$global:SecurityResults.Statistics = @{
    ToolPaneExploits = $CVEIndicators.ToolPaneExploits.Count
    SignOutExploits = $CVEIndicators.SignOutExploits.Count
    MachineKeyTheftAttempts = $CVEIndicators.MachineKeyTheft.Count
    WebshellsFound = $CVEIndicators.WebshellsFound.Count
    DLLPayloads = $CVEIndicators.DLLPayloads.Count
    RansomwareIndicators = $CVEIndicators.RansomwareIndicators.Count
    ExploitAttempts = $CVEIndicators.ExploitAttempts.Count
    AttackerIPs = $CVEIndicators.AttackerIPs.Count
    InternalSuspiciousIPs = $CVEIndicators.InternalSuspiciousActivity.Count
    InternalSuspiciousEvents = ($CVEIndicators.InternalSuspiciousActivity.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
    CriticalPeriodActivity = $CVEIndicators.CriticalPeriodActivity.Count
    KnownAttackerConnections = @($knownAttackerConnections).Count
    SuspiciousTasks = if($SuspiciousTasks){@($SuspiciousTasks).Count}else{0}
    AMSIEnabled = $amsiEnabled
    MachineKeyRotated = $machineKeyRotated
    MachineKeyRotationDate = $machineKeyRotationDate
    IsEOL = $global:SecurityResults.Statistics.IsEOL
    PostExploitationTools = $CVEIndicators.PostExploitationTools.Count
    C2Communications = $CVEIndicators.C2Communications.Count
    ThreatActorActivity = $CVEIndicators.ThreatActorActivity.Count
    DefenderDisabled = $CVEIndicators.DefenderDisabled.Count  # NEW
    GPOModifications = $CVEIndicators.GPOModifications.Count  # NEW
    LSASSAccess = $CVEIndicators.LSASSAccess.Count  # NEW
    ReflectiveInjection = $CVEIndicators.ReflectiveInjection.Count  # NEW
    InstalledPatches = $installedPatches  # NEW
    MissingPatches = $missingPatches  # NEW
    LSAProtection = $lsaProtection  # NEW
    CredentialGuard = $credentialGuardEnabled  # UPDATED
    CredentialGuardStatus = $credentialGuardStatus  # NEW
    ControlledFolderAccess = $controlledFolderAccess  # UPDATED
    ControlledFolderAccessStatus = $controlledFolderAccessStatus  # NEW
    ASRRulesEnabled = $asrRulesEnabled  # UPDATED
    ASRRulesStatus = $asrRulesStatus  # NEW
    DefenderForEndpoint = $mdeEnabled  # UPDATED
    ESETEnabled = $esetEnabled  # NEW
    EndpointProtection = $endpointProtection  # NEW
    BaselineNewDLLs = if ($global:SecurityResults.Statistics.BaselineNewDLLs) { $global:SecurityResults.Statistics.BaselineNewDLLs } else { 0 }  # NEW
    BaselineModifiedDLLs = if ($global:SecurityResults.Statistics.BaselineModifiedDLLs) { $global:SecurityResults.Statistics.BaselineModifiedDLLs } else { 0 }  # NEW
    BaselineDeletedDLLs = if ($global:SecurityResults.Statistics.BaselineDeletedDLLs) { $global:SecurityResults.Statistics.BaselineDeletedDLLs } else { 0 }  # NEW
    BaselineAutoCreated = if ($global:SecurityResults.Statistics.BaselineAutoCreated) { $global:SecurityResults.Statistics.BaselineAutoCreated } else { $false }  # NEW
    IntegrityIssues = if ($global:SecurityResults.Statistics.IntegrityIssues) { $global:SecurityResults.Statistics.IntegrityIssues } else { 0 }  # NEW
    ExecutionTime = if ($global:MainTimer) { [math]::Round($global:MainTimer.Elapsed.TotalSeconds, 2) } else { 0 }  # NEW
    TotalEventsProcessed = $totalEventsProcessed  # Performance metric
    CachedEventsSkipped = $cachedEventsSkipped    # Performance metric
    AllAttacks = $CVEIndicators.AllAttacks.Count  # NEW v3.8: Total attack count
    PendingDLLApprovals = if (Test-Path $PendingDLLFile) {
        try {
            $pending = Get-Content $PendingDLLFile -Raw | ConvertFrom-Json
            $pending.PendingDLLs.Count
        } catch { 0 }
    } else { 0 }  # NEW v3.8
    ApprovedDLLs = $ApprovedDLLs.Count  # NEW v3.8
}

# 11. GENERATE ENHANCED HTML REPORT WITH THREAT INTELLIGENCE
$global:SecurityResults.EndTime = Get-Date

function Generate-HTMLReport {
    $alertCount = $global:SecurityResults.Alerts.Count
    $warningCount = $global:SecurityResults.Warnings.Count
    $stats = $global:SecurityResults.Statistics

    $hasKnownAttackers = $stats.KnownAttackerConnections -gt 0 -or
                         ($CVEIndicators.ToolPaneExploits | Where-Object {$_.IsKnownAttacker}).Count -gt 0

    $hasThreatActors = $stats.ThreatActorActivity -gt 0

    # Determine colors and status
    if ($hasKnownAttackers -or ($alertCount -gt 0)) {
        $statusColor = "#d32f2f"
        $statusText = if ($hasThreatActors) {
            "CRITICAL - THREAT ACTORS DETECTED"
        } elseif ($hasKnownAttackers) {
            "CRITICAL - KNOWN ATTACKERS DETECTED"
        } else {
            "CRITICAL ALERTS"
        }
    } elseif ($warningCount -gt 0) {
        $statusColor = "#ff9800"
        $statusText = "WARNINGS DETECTED"
    } else {
        $statusColor = "#4caf50"
        $statusText = "SYSTEM SECURE"
    }

    # HTML compatible with Outlook - all inline
    $html = @"
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>SharePoint Security Report</title>
</head>
<body style="margin:0;padding:0;font-family:Arial,sans-serif;font-size:14px;background-color:#f5f5f5;">
<table width="100%" cellpadding="0" cellspacing="0" border="0">
<tr>
<td align="center" bgcolor="#f5f5f5" style="padding:20px;">

<!-- Main Container -->
<table width="700" cellpadding="0" cellspacing="0" border="0" bgcolor="#ffffff">

<!-- Header -->
<tr>
<td bgcolor="#1a237e" style="padding:30px;">
    <table width="100%" cellpadding="0" cellspacing="0" border="0">
    <tr>
        <td style="color:#ffffff;font-size:28px;font-weight:bold;">
            <span style="font-size:32px;">&#x1F6E1;</span> SharePoint Security Report v3.9
        </td>
        <td align="right" style="color:#ffffff;font-size:14px;">
            <span style="font-size:16px;">&#x1F4C5;</span> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        </td>
    </tr>
    </table>
</td>
</tr>

<!-- Status Banner -->
<tr>
<td bgcolor="$statusColor" align="center" style="padding:20px;">
    <span style="color:#ffffff;font-size:22px;font-weight:bold;">
        $(if ($hasThreatActors -or $hasKnownAttackers -or ($alertCount -gt 0)) { '<span style="font-size:28px;">&#x26A0;</span>' } elseif ($warningCount -gt 0) { '<span style="font-size:28px;">&#x26A0;</span>' } else { '<span style="font-size:28px;">&#x2714;</span>' })
        $statusText
    </span>
</td>
</tr>

<!-- Info Bar -->
<tr>
<td style="padding:20px;">
    <table width="100%" cellpadding="10" cellspacing="0" border="1" bordercolor="#e8eaf6" bgcolor="#e8eaf6">
    <tr>
        <td width="25%" align="center">
            <strong style="color:#3949ab;"><span style="font-size:16px;">&#x1F5A5;</span> Server</strong><br />
            $env:COMPUTERNAME
        </td>
        <td width="25%" align="center">
            <strong style="color:#3949ab;"><span style="font-size:16px;">&#x23F1;</span> Duration</strong><br />
            $([math]::Round(($global:SecurityResults.EndTime - $global:SecurityResults.StartTime).TotalMinutes, 2)) min
        </td>
        <td width="25%" align="center">
            <strong style="color:#3949ab;"><span style="font-size:16px;">&#x1F6E1;</span> AMSI</strong><br />
            <span style="color:$(if ($stats.AMSIEnabled) {'#4caf50'} else {'#d32f2f'});">
                $(if ($stats.AMSIEnabled) { '<span style="font-size:14px;">&#x2714;</span> Enabled' } else { '<span style="font-size:14px;">&#x2718;</span> Disabled' })
            </span>
        </td>
        <td width="25%" align="center">
            <strong style="color:#3949ab;"><span style="font-size:16px;">&#x1F511;</span> Keys Rotated</strong><br />
            <span style="color:$(if ($stats.MachineKeyRotated) {'#4caf50'} else {'#d32f2f'});">
                $(if ($stats.MachineKeyRotated) { '<span style="font-size:14px;">&#x2714;</span> Yes' } else { '<span style="font-size:14px;">&#x2718;</span> No' })
            </span>
        </td>
    </tr>
    </table>
</td>
</tr>

<!-- Performance Metrics -->
<tr>
<td style="padding:0 20px 20px 20px;">
    <table width="100%" cellpadding="10" cellspacing="0" border="1" bordercolor="#e3f2fd" bgcolor="#f1f8ff">
    <tr>
        <td>
            <strong style="color:#1565c0;"><span style="font-size:14px;">&#x1F4CA;</span> Performance Metrics:</strong>
            Scan Mode: <strong>$(if ($FullHistoricalScan) { 'Full Historical (30d)' } elseif ($QuickScan) { 'Quick (12h)' } else { "Standard ($MaxDaysToScan" + "d)" })</strong> |
            Events Processed: <strong>$($stats.TotalEventsProcessed)</strong> |
            Cache $(if ($DisableEventCache) { '(Disabled)' } else { 'Hits' }): <strong>$($stats.CachedEventsSkipped) ($('{0:N1}%' -f (($stats.CachedEventsSkipped / [Math]::Max($stats.TotalEventsProcessed, 1)) * 100)))</strong> |
            Execution Time: <strong>$($stats.ExecutionTime)s</strong>
        </td>
    </tr>
    </table>
</td>
</tr>

<!-- EOL Warning if applicable -->
$(if ($stats.IsEOL -eq $true) {
@"
<tr>
<td style="padding:0 20px 20px 20px;">
    <table width="100%" cellpadding="15" cellspacing="0" border="2" bordercolor="#d32f2f" bgcolor="#ffebee">
    <tr>
        <td>
            <h3 style="color:#d32f2f;margin:0;"><span style="font-size:18px;">&#x26A0;</span> CRITICAL: End-of-Life SharePoint Version</h3>
            <p style="margin:10px 0 0 0;">This SharePoint server is running an EOL version that should be disconnected from the internet immediately!</p>
        </td>
    </tr>
    </table>
</td>
</tr>
"@
})

<!-- Patch Status if missing patches -->
$(if ($stats.MissingPatches.Count -gt 0) {
@"
<tr>
<td style="padding:0 20px 20px 20px;">
    <table width="100%" cellpadding="15" cellspacing="0" border="2" bordercolor="#d32f2f" bgcolor="#ffebee">
    <tr>
        <td>
            <h3 style="color:#d32f2f;margin:0;"><span style="font-size:18px;">&#x26A0;</span> CRITICAL: Missing Security Patches</h3>
            <p style="margin:10px 0 0 0;">$(if ($stats.MissingPatches -join '' -match 'SharePoint 2019') {
                "SharePoint 2019 requires December 2023 Cumulative Update or later (minimum build: 16.0.10398.20000)"
            } else {
                "Missing patches: $($stats.MissingPatches -join ', ')"
            })</p>
            <p style="margin:5px 0 0 0;">Apply these patches immediately to protect against CVE-2023-29357 and CVE-2023-33157!</p>
        </td>
    </tr>
    </table>
</td>
</tr>
"@
})

<!-- Executive Summary Title -->
<tr>
<td style="padding:20px 20px 10px 20px;">
    <h2 style="color:#1a237e;font-size:22px;margin:0;padding:0 0 10px 0;border-bottom:2px solid #3949ab;">
        <span style="font-size:20px;">&#x1F4CA;</span> Executive Summary
    </h2>
</td>
</tr>

<!-- Summary Cards Row 1 -->
<tr>
<td style="padding:0 20px;">
    <table width="100%" cellpadding="0" cellspacing="5" border="0">
    <tr>
        <td width="33%" valign="top">
            <table width="100%" cellpadding="15" cellspacing="0" border="0" bgcolor="$(if ($alertCount -gt 0) {'#ffebee'} else {'#e8f5e9'})">
            <tr>
                <td style="border-left:4px solid $(if ($alertCount -gt 0) {'#d32f2f'} else {'#4caf50'});">
                    <div style="color:#666;font-size:14px;"><span style="font-size:16px;">&#x26A0;</span> Critical Alerts</div>
                    <div style="color:$(if ($alertCount -gt 0) {'#d32f2f'} else {'#4caf50'});font-size:32px;font-weight:bold;">$alertCount</div>
                </td>
            </tr>
            </table>
        </td>
        <td width="33%" valign="top">
            <table width="100%" cellpadding="15" cellspacing="0" border="0" bgcolor="$(if ($stats.ToolPaneExploits -gt 0) {'#ffebee'} else {'#e8f5e9'})">
            <tr>
                <td style="border-left:4px solid $(if ($stats.ToolPaneExploits -gt 0) {'#d32f2f'} else {'#4caf50'});">
                    <div style="color:#666;font-size:14px;"><span style="font-size:16px;">&#x1F4A5;</span> ToolPane Exploits</div>
                    <div style="color:$(if ($stats.ToolPaneExploits -gt 0) {'#d32f2f'} else {'#4caf50'});font-size:32px;font-weight:bold;">$($stats.ToolPaneExploits)</div>
                </td>
            </tr>
            </table>
        </td>
        <td width="33%" valign="top">
            <table width="100%" cellpadding="15" cellspacing="0" border="0" bgcolor="$(if ($stats.WebshellsFound -gt 0) {'#ffebee'} else {'#e8f5e9'})">
            <tr>
                <td style="border-left:4px solid $(if ($stats.WebshellsFound -gt 0) {'#d32f2f'} else {'#4caf50'});">
                    <div style="color:#666;font-size:14px;"><span style="font-size:16px;">&#x1F577;</span> Webshells Found</div>
                    <div style="color:$(if ($stats.WebshellsFound -gt 0) {'#d32f2f'} else {'#4caf50'});font-size:32px;font-weight:bold;">$($stats.WebshellsFound)</div>
                </td>
            </tr>
            </table>
        </td>
    </tr>
    </table>
</td>
</tr>

<!-- Summary Cards Row 2 - indicators -->
<tr>
<td style="padding:5px 20px;">
    <table width="100%" cellpadding="0" cellspacing="5" border="0">
    <tr>
        <td width="33%" valign="top">
            <table width="100%" cellpadding="15" cellspacing="0" border="0" bgcolor="$(if ($stats.PostExploitationTools -gt 0) {'#ffebee'} else {'#e8f5e9'})">
            <tr>
                <td style="border-left:4px solid $(if ($stats.PostExploitationTools -gt 0) {'#d32f2f'} else {'#4caf50'});">
                    <div style="color:#666;font-size:14px;"><span style="font-size:16px;">&#x1F528;</span> Attack Tools</div>
                    <div style="color:$(if ($stats.PostExploitationTools -gt 0) {'#d32f2f'} else {'#4caf50'});font-size:32px;font-weight:bold;">$($stats.PostExploitationTools)</div>
                </td>
            </tr>
            </table>
        </td>
        <td width="33%" valign="top">
            <table width="100%" cellpadding="15" cellspacing="0" border="0" bgcolor="$(if ($stats.C2Communications -gt 0) {'#ffebee'} else {'#e8f5e9'})">
            <tr>
                <td style="border-left:4px solid $(if ($stats.C2Communications -gt 0) {'#d32f2f'} else {'#4caf50'});">
                    <div style="color:#666;font-size:14px;"><span style="font-size:16px;">&#x1F4E1;</span> C2 Comms</div>
                    <div style="color:$(if ($stats.C2Communications -gt 0) {'#d32f2f'} else {'#4caf50'});font-size:32px;font-weight:bold;">$($stats.C2Communications)</div>
                </td>
            </tr>
            </table>
        </td>
        <td width="33%" valign="top">
            <table width="100%" cellpadding="15" cellspacing="0" border="0" bgcolor="$(if ($stats.ThreatActorActivity -gt 0) {'#ffebee'} else {'#e8f5e9'})">
            <tr>
                <td style="border-left:4px solid $(if ($stats.ThreatActorActivity -gt 0) {'#d32f2f'} else {'#4caf50'});">
                    <div style="color:#666;font-size:14px;"><span style="font-size:16px;">&#x1F47F;</span> Threat Actors</div>
                    <div style="color:$(if ($stats.ThreatActorActivity -gt 0) {'#d32f2f'} else {'#4caf50'});font-size:32px;font-weight:bold;">$($stats.ThreatActorActivity)</div>
                </td>
            </tr>
            </table>
        </td>
    </tr>
    </table>
</td>
</tr>

<!-- Summary Cards Row 3 -->
<tr>
<td style="padding:5px 20px;">
    <table width="100%" cellpadding="0" cellspacing="5" border="0">
    <tr>
        <td width="33%" valign="top">
            <table width="100%" cellpadding="15" cellspacing="0" border="0" bgcolor="$(if ($stats.DLLPayloads -gt 0) {'#ffebee'} else {'#e8f5e9'})">
            <tr>
                <td style="border-left:4px solid $(if ($stats.DLLPayloads -gt 0) {'#d32f2f'} else {'#4caf50'});">
                    <div style="color:#666;font-size:14px;"><span style="font-size:16px;">&#x1F4BE;</span> DLL Payloads</div>
                    <div style="color:$(if ($stats.DLLPayloads -gt 0) {'#d32f2f'} else {'#4caf50'});font-size:32px;font-weight:bold;">$($stats.DLLPayloads)</div>
                </td>
            </tr>
            </table>
        </td>
        <td width="33%" valign="top">
            <table width="100%" cellpadding="15" cellspacing="0" border="0" bgcolor="$(if ($stats.RansomwareIndicators -gt 0) {'#ffebee'} else {'#e8f5e9'})">
            <tr>
                <td style="border-left:4px solid $(if ($stats.RansomwareIndicators -gt 0) {'#d32f2f'} else {'#4caf50'});">
                    <div style="color:#666;font-size:14px;"><span style="font-size:16px;">&#x1F512;</span> Ransomware Signs</div>
                    <div style="color:$(if ($stats.RansomwareIndicators -gt 0) {'#d32f2f'} else {'#4caf50'});font-size:32px;font-weight:bold;">$($stats.RansomwareIndicators)</div>
                </td>
            </tr>
            </table>
        </td>
        <td width="33%" valign="top">
            <table width="100%" cellpadding="15" cellspacing="0" border="0" bgcolor="$(if ($stats.CriticalPeriodActivity -gt 0) {'#ffebee'} else {'#e8f5e9'})">
            <tr>
                <td style="border-left:4px solid $(if ($stats.CriticalPeriodActivity -gt 0) {'#d32f2f'} else {'#4caf50'});">
                    <div style="color:#666;font-size:14px;"><span style="font-size:16px;">&#x1F4C5;</span> Critical Period</div>
                    <div style="color:$(if ($stats.CriticalPeriodActivity -gt 0) {'#d32f2f'} else {'#4caf50'});font-size:32px;font-weight:bold;">$($stats.CriticalPeriodActivity)</div>
                </td>
            </tr>
            </table>
        </td>
    </tr>
    </table>
</td>
</tr>

<!-- Summary Cards Row 4 - NEW Security Indicators -->
<tr>
<td style="padding:5px 20px 20px 20px;">
    <table width="100%" cellpadding="0" cellspacing="5" border="0">
    <tr>
        <td width="33%" valign="top">
            <table width="100%" cellpadding="15" cellspacing="0" border="0" bgcolor="$(if ($stats.DefenderDisabled -gt 0) {'#ffebee'} else {'#e8f5e9'})">
            <tr>
                <td style="border-left:4px solid $(if ($stats.DefenderDisabled -gt 0) {'#d32f2f'} else {'#4caf50'});">
                    <div style="color:#666;font-size:14px;"><span style="font-size:16px;">&#x1F6AB;</span> Defender Tampering</div>
                    <div style="color:$(if ($stats.DefenderDisabled -gt 0) {'#d32f2f'} else {'#4caf50'});font-size:32px;font-weight:bold;">$($stats.DefenderDisabled)</div>
                </td>
            </tr>
            </table>
        </td>
        <td width="33%" valign="top">
            <table width="100%" cellpadding="15" cellspacing="0" border="0" bgcolor="$(if ($stats.LSASSAccess -gt 0) {'#ffebee'} else {'#e8f5e9'})">
            <tr>
                <td style="border-left:4px solid $(if ($stats.LSASSAccess -gt 0) {'#d32f2f'} else {'#4caf50'});">
                    <div style="color:#666;font-size:14px;"><span style="font-size:16px;">&#x1F511;</span> LSASS Access</div>
                    <div style="color:$(if ($stats.LSASSAccess -gt 0) {'#d32f2f'} else {'#4caf50'});font-size:32px;font-weight:bold;">$($stats.LSASSAccess)</div>
                </td>
            </tr>
            </table>
        </td>
        <td width="33%" valign="top">
            <table width="100%" cellpadding="15" cellspacing="0" border="0" bgcolor="$(if ($stats.GPOModifications -gt 0) {'#ffebee'} else {'#e8f5e9'})">
            <tr>
                <td style="border-left:4px solid $(if ($stats.GPOModifications -gt 0) {'#d32f2f'} else {'#4caf50'});">
                    <div style="color:#666;font-size:14px;"><span style="font-size:16px;">&#x1F4DC;</span> GPO Changes</div>
                    <div style="color:$(if ($stats.GPOModifications -gt 0) {'#d32f2f'} else {'#4caf50'});font-size:32px;font-weight:bold;">$($stats.GPOModifications)</div>
                </td>
            </tr>
            </table>
        </td>
    </tr>
    </table>
</td>
</tr>

<!-- Summary Cards Row 5 - Baseline and Integrity -->
<tr>
<td style="padding:5px 20px 20px 20px;">
    <table width="100%" cellpadding="0" cellspacing="5" border="0">
    <tr>
        <td width="33%" valign="top">
            <table width="100%" cellpadding="15" cellspacing="0" border="0" bgcolor="$(if ($stats.BaselineNewDLLs -gt 0 -or $stats.BaselineModifiedDLLs -gt 0) {'#fff8e1'} else {'#e8f5e9'})">
            <tr>
                <td style="border-left:4px solid $(if ($stats.BaselineNewDLLs -gt 0 -or $stats.BaselineModifiedDLLs -gt 0) {'#ff9800'} else {'#4caf50'});">
                    <div style="color:#666;font-size:14px;"><span style="font-size:16px;">&#x1F4CA;</span> DLL Changes</div>
                    <div style="color:$(if ($stats.BaselineNewDLLs -gt 0 -or $stats.BaselineModifiedDLLs -gt 0) {'#ff9800'} else {'#4caf50'});font-size:24px;font-weight:bold;">
                        +$($stats.BaselineNewDLLs) / ~$($stats.BaselineModifiedDLLs)
                    </div>
                </td>
            </tr>
            </table>
        </td>
        <td width="33%" valign="top">
            <table width="100%" cellpadding="15" cellspacing="0" border="0" bgcolor="$(if ($stats.IntegrityIssues -gt 0) {'#ffebee'} else {'#e8f5e9'})">
            <tr>
                <td style="border-left:4px solid $(if ($stats.IntegrityIssues -gt 0) {'#d32f2f'} else {'#4caf50'});">
                    <div style="color:#666;font-size:14px;"><span style="font-size:16px;">&#x1F50D;</span> Integrity Issues</div>
                    <div style="color:$(if ($stats.IntegrityIssues -gt 0) {'#d32f2f'} else {'#4caf50'});font-size:32px;font-weight:bold;">$($stats.IntegrityIssues)</div>
                </td>
            </tr>
            </table>
        </td>
        <td width="33%" valign="top">
            <table width="100%" cellpadding="15" cellspacing="0" border="0" bgcolor="#e3f2fd">
            <tr>
                <td style="border-left:4px solid #2196f3;">
                    <div style="color:#666;font-size:14px;"><span style="font-size:16px;">&#x23F1;</span> Total Attacks</div>
                    <div style="color:#2196f3;font-size:32px;font-weight:bold;">$($stats.AllAttacks)</div>
                </td>
            </tr>
            </table>
        </td>
    </tr>
    </table>
</td>
</tr>

<!-- DLL Management Info if pending -->
$(if ($stats.PendingDLLApprovals -gt 0) {
@"
<tr>
<td style="padding:0 20px 20px 20px;">
    <table width="100%" cellpadding="15" cellspacing="0" border="2" bordercolor="#ff9800" bgcolor="#fff8e1">
    <tr>
        <td>
            <h3 style="color:#ff9800;margin:0 0 10px 0;"><span style="font-size:18px;">&#x1F4CB;</span> DLL Approval Required</h3>
            <p style="margin:0;">$($stats.PendingDLLApprovals) DLLs are pending review and approval.</p>
            <p style="color:#ff6f00;font-weight:bold;margin:10px 0 0 0;">
                <span style="font-size:16px;">&#x26A0;</span> Run with -ReviewPendingDLLs to approve legitimate DLLs
            </p>
        </td>
    </tr>
    </table>
</td>
</tr>
"@
})

<!-- Threat Intelligence Alert Box - UPDATED -->
<tr>
<td style="padding:0 20px 20px 20px;">
    <table width="100%" cellpadding="15" cellspacing="0" border="2" bordercolor="#3f51b5" bgcolor="#e8eaf6">
    <tr>
        <td>
            <h3 style="color:#3f51b5;margin:0 0 10px 0;"><span style="font-size:18px;">&#x1F6A8;</span> Threat Intelligence Information</h3>
            <table width="100%" cellpadding="0" cellspacing="0" border="0">
            <tr>
                <td width="50%" valign="top">
                    <strong style="color:#3f51b5;"><span style="font-size:14px;">&#x1F47F;</span> Known Threat Indicators:</strong><br />
                    <span style="font-size:14px;">&#x2022;</span> <strong>Advanced persistent threat groups</strong><br />
                    <span style="font-size:14px;">&#x2022;</span> <strong>Nation-state actors</strong><br />
                    <span style="font-size:14px;">&#x2022;</span> <strong>Ransomware operators</strong><br />
                    <br />
                    <strong style="color:#3f51b5;"><span style="font-size:14px;">&#x1F4A3;</span> Actively Exploited CVEs:</strong><br />
                    <span style="font-size:14px;">&#x2022;</span> CVE-2023-29357 (RCE)<br />
                    <span style="font-size:14px;">&#x2022;</span> CVE-2023-33157 (Elevation of Privilege)<br />
                    <span style="font-size:14px;">&#x2022;</span> Additional bypass vulnerabilities
                </td>
                <td width="50%" valign="top">
                    <strong style="color:#3f51b5;"><span style="font-size:14px;">&#x1F528;</span> Attack Tools Observed:</strong><br />
                    <span style="font-size:14px;">&#x2022;</span> Mimikatz (credential theft)<br />
                    <span style="font-size:14px;">&#x2022;</span> Impacket (lateral movement)<br />
                    <span style="font-size:14px;">&#x2022;</span> PsExec (remote execution)<br />
                    <span style="font-size:14px;">&#x2022;</span> IIS backdoors (persistence)<br />
                    <br />
                    <strong style="color:#d32f2f;"><span style="font-size:14px;">&#x1F512;</span> Ransomware:</strong><br />
                    <span style="font-size:14px;">&#x2022;</span> Multiple ransomware families<br />
                    <span style="font-size:14px;">&#x2022;</span> LockBit, Clop, Ryuk variants
                </td>
            </tr>
            </table>
        </td>
    </tr>
    </table>
</td>
</tr>
"@

    # Add Microsoft Defender tampering section if detected AND not using ESET
    if ($CVEIndicators.DefenderDisabled.Count -gt 0 -and -not $stats.ESETEnabled) {
        $html += @"
<!-- Microsoft Defender Tampering -->
<tr>
<td style="padding:0 20px 20px 20px;">
    <table width="100%" cellpadding="15" cellspacing="0" border="2" bordercolor="#d32f2f" bgcolor="#ffebee">
    <tr>
        <td>
            <h3 style="color:#d32f2f;margin:0 0 10px 0;"><span style="font-size:18px;">&#x1F6AB;</span> CRITICAL: Microsoft Defender Tampering Detected</h3>
"@
        foreach ($tampering in $CVEIndicators.DefenderDisabled) {
            $html += @"
            <p style="margin:5px 0;"><strong>$($tampering.Type):</strong> $(if ($tampering.Path) { $tampering.Path } elseif ($tampering.Events) { "$($tampering.Events) events detected" } else { "Detected at $($tampering.Time)" })</p>
"@
        }
        $html += @"
            <p style="color:#d32f2f;font-weight:bold;margin:10px 0 0 0;">
                <span style="font-size:16px;">&#x26A0;</span> IMMEDIATE ACTION: Re-enable Microsoft Defender protections immediately!
            </p>
        </td>
    </tr>
    </table>
</td>
</tr>
"@
    }

    # Add GPO Modifications section if detected
    if ($CVEIndicators.GPOModifications.Count -gt 0) {
        $html += @"
<!-- GPO Modifications -->
<tr>
<td style="padding:0 20px 20px 20px;">
    <table width="100%" cellpadding="15" cellspacing="0" border="2" bordercolor="#ff9800" bgcolor="#fff8e1">
    <tr>
        <td>
            <h3 style="color:#ff9800;margin:0 0 10px 0;"><span style="font-size:18px;">&#x1F4DC;</span> Suspicious Group Policy Modifications</h3>
            <p style="margin:0;">$($CVEIndicators.GPOModifications[0].Count) suspicious GPO modification events detected in the last 7 days.</p>
            <p style="color:#ff6f00;font-weight:bold;margin:10px 0 0 0;">
                <span style="font-size:16px;">&#x26A0;</span> Review GPO changes immediately - ransomware groups use GPO for mass deployment!
            </p>
        </td>
    </tr>
    </table>
</td>
</tr>
"@
    }

    # Add LSASS Access section if detected
    if ($CVEIndicators.LSASSAccess.Count -gt 0) {
        $html += @"
<!-- LSASS Access -->
<tr>
<td style="padding:0 20px 20px 20px;">
    <table width="100%" cellpadding="15" cellspacing="0" border="2" bordercolor="#d32f2f" bgcolor="#ffebee">
    <tr>
        <td>
            <h3 style="color:#d32f2f;margin:0 0 10px 0;"><span style="font-size:18px;">&#x1F511;</span> LSASS Memory Access Detected</h3>
            <p style="margin:0;">$($CVEIndicators.LSASSAccess[0].Count) LSASS access events detected - possible credential theft attempt!</p>
            <p style="color:#d32f2f;font-weight:bold;margin:10px 0 0 0;">
                <span style="font-size:16px;">&#x26A0;</span> Assume credentials are compromised - rotate all passwords immediately!
            </p>
        </td>
    </tr>
    </table>
</td>
</tr>
"@
    }

    # Add Threat Actor Activity section if detected
    if ($CVEIndicators.ThreatActorActivity.Count -gt 0) {
        # Group activities by actor
        $actorGroups = $CVEIndicators.ThreatActorActivity | Group-Object -Property Actor

        $html += @"
<!-- Threat Actor Activity -->
<tr>
<td style="padding:0 20px 20px 20px;">
    <table width="100%" cellpadding="15" cellspacing="0" border="2" bordercolor="#d32f2f" bgcolor="#ffebee">
    <tr>
        <td>
            <h3 style="color:#d32f2f;margin:0 0 10px 0;"><span style="font-size:18px;">&#x1F47F;</span> CRITICAL: Threat Actor Activity Detected</h3>
"@

        foreach ($actorGroup in $actorGroups) {
            $actorName = $actorGroup.Name
            $activities = $actorGroup.Group

            $html += @"
            <h4 style="color:#b71c1c;margin:10px 0 5px 0;">$actorName - $($activities.Count) activities detected</h4>
            <table width="100%" cellpadding="5" cellspacing="0" border="1" bordercolor="#e0e0e0" bgcolor="#ffffff">
            <tr bgcolor="#f5f5f5">
                <th align="left" style="padding:8px;">Activity Type</th>
                <th align="left" style="padding:8px;">Details</th>
                <th align="left" style="padding:8px;">Time</th>
            </tr>
"@
            foreach ($activity in $activities | Select-Object -First 5) {
                $details = ""
                if ($activity.IP) { $details = "IP: $($activity.IP)" }
                elseif ($activity.File) { $details = "File: $($activity.File)" }
                elseif ($activity.Evidence) { $details = $activity.Evidence }

                $html += @"
            <tr bgcolor="#ffcdd2">
                <td style="padding:8px;">$($activity.Activity -replace 'Type', '')</td>
                <td style="padding:8px;">$details</td>
                <td style="padding:8px;">$($activity.Time)</td>
            </tr>
"@
            }
            $html += "</table>"
        }

        $html += @"
            <p style="color:#d32f2f;font-weight:bold;margin:10px 0 0 0;">
                <span style="font-size:16px;">&#x1F6A8;</span> IMMEDIATE ACTION: Active APT groups detected! Initiate incident response immediately!
            </p>
        </td>
    </tr>
    </table>
</td>
</tr>
"@
    }

    # Add Post-Exploitation Tools section if detected
    if ($CVEIndicators.PostExploitationTools.Count -gt 0) {
        $html += @"
<!-- Post-Exploitation Tools -->
<tr>
<td style="padding:0 20px 20px 20px;">
    <table width="100%" cellpadding="15" cellspacing="0" border="2" bordercolor="#d32f2f" bgcolor="#ffebee">
    <tr>
        <td>
            <h3 style="color:#d32f2f;margin:0 0 10px 0;"><span style="font-size:18px;">&#x1F528;</span> POST-EXPLOITATION TOOLS DETECTED</h3>

            <table width="100%" cellpadding="5" cellspacing="0" border="1" bordercolor="#e0e0e0" bgcolor="#ffffff">
            <tr bgcolor="#f5f5f5">
                <th align="left" style="padding:8px;">Tool</th>
                <th align="left" style="padding:8px;">Details</th>
                <th align="left" style="padding:8px;">Time</th>
            </tr>
"@
        foreach ($tool in $CVEIndicators.PostExploitationTools | Select-Object -First 10) {
            $details = ""
            if ($tool.CommandLine) {
                $details = $tool.CommandLine.Substring(0, [Math]::Min($tool.CommandLine.Length, 100)) + "..."
            } elseif ($tool.Path) {
                $details = $tool.Path
            } elseif ($tool.Type) {
                $details = $tool.Type
            }

            $html += @"
            <tr bgcolor="#ffcdd2">
                <td style="padding:8px;font-weight:bold;">$($tool.Tool)</td>
                <td style="padding:8px;font-family:monospace;font-size:11px;">$details</td>
                <td style="padding:8px;">$($tool.Time)</td>
            </tr>
"@
        }
        $html += @"
            </table>
            <p style="color:#d32f2f;font-weight:bold;margin:10px 0 0 0;">
                <span style="font-size:16px;">&#x26A0;</span> Active post-exploitation detected! Assume credentials are compromised!
            </p>
        </td>
    </tr>
    </table>
</td>
</tr>
"@
    }

    # Add C2 Communications section if detected
    if ($CVEIndicators.C2Communications.Count -gt 0) {
        $html += @"
<!-- C2 Communications -->
<tr>
<td style="padding:0 20px 20px 20px;">
    <table width="100%" cellpadding="15" cellspacing="0" border="2" bordercolor="#d32f2f" bgcolor="#ffebee">
    <tr>
        <td>
            <h3 style="color:#d32f2f;margin:0 0 10px 0;"><span style="font-size:18px;">&#x1F4E1;</span> COMMAND & CONTROL COMMUNICATIONS DETECTED</h3>

            <table width="100%" cellpadding="5" cellspacing="0" border="1" bordercolor="#e0e0e0" bgcolor="#ffffff">
            <tr bgcolor="#f5f5f5">
                <th align="left" style="padding:8px;">Type</th>
                <th align="left" style="padding:8px;">Domain/IP</th>
                <th align="left" style="padding:8px;">Details</th>
            </tr>
"@
        foreach ($c2 in $CVEIndicators.C2Communications | Select-Object -First 10) {
            $indicator = if ($c2.Domain) { $c2.Domain } else { $c2.IP }
            $html += @"
            <tr bgcolor="#ffcdd2">
                <td style="padding:8px;">$($c2.Type)</td>
                <td style="padding:8px;font-weight:bold;">$indicator</td>
                <td style="padding:8px;">$(if ($c2.Time) { $c2.Time } else { 'Active' })</td>
            </tr>
"@
        }
        $html += @"
            </table>
            <p style="color:#d32f2f;font-weight:bold;margin:10px 0 0 0;">
                <span style="font-size:16px;">&#x1F6A8;</span> Active C2 channels detected! Isolate affected systems immediately!
            </p>
        </td>
    </tr>
    </table>
</td>
</tr>
"@
    }

    # Add Critical Period Activity details if any
    if ($CVEIndicators.CriticalPeriodActivity.Count -gt 0) {
        $html += @"
<!-- Critical Period Activity -->
<tr>
<td style="padding:0 20px 20px 20px;">
    <table width="100%" cellpadding="15" cellspacing="0" border="2" bordercolor="#d32f2f" bgcolor="#ffebee">
    <tr>
        <td>
            <h3 style="color:#d32f2f;margin:0 0 10px 0;"><span style="font-size:18px;">&#x1F6A8;</span> CRITICAL: Activity During September 2023 Attack Period</h3>
            <p style="margin:0 0 10px 0;">Known exploitation period activity detected:</p>

            <table width="100%" cellpadding="5" cellspacing="0" border="1" bordercolor="#e0e0e0" bgcolor="#ffffff">
            <tr bgcolor="#f5f5f5">
                <th align="left" style="padding:8px;">Type</th>
                <th align="left" style="padding:8px;">Time</th>
                <th align="left" style="padding:8px;">Client IP</th>
                <th align="left" style="padding:8px;">Status</th>
            </tr>
"@
        foreach ($activity in $CVEIndicators.CriticalPeriodActivity | Select-Object -First 10) {
            $html += @"
            <tr bgcolor="#ffcdd2">
                <td style="padding:8px;">$($activity.Type)</td>
                <td style="padding:8px;">$($activity.Time)</td>
                <td style="padding:8px;font-weight:bold;">$($activity.ClientIP)</td>
                <td style="padding:8px;">$($activity.Status)</td>
            </tr>
"@
        }
        $html += @"
            </table>
        </td>
    </tr>
    </table>
</td>
</tr>
"@
    }

    # Add DLL Payload details if any
    if ($CVEIndicators.DLLPayloads.Count -gt 0) {
        # Group by severity
        $criticalDLLs = $CVEIndicators.DLLPayloads | Where-Object { $_.Severity -eq "Critical" }
        $suspiciousDLLs = $CVEIndicators.DLLPayloads | Where-Object { $_.Severity -ne "Critical" }

        $html += @"
<!-- DLL Payloads -->
<tr>
<td style="padding:0 20px 20px 20px;">
    <table width="100%" cellpadding="15" cellspacing="0" border="2" bordercolor="#d32f2f" bgcolor="#ffebee">
    <tr>
        <td>
            <h3 style="color:#d32f2f;margin:0 0 10px 0;"><span style="font-size:18px;">&#x1F4BE;</span> SUSPICIOUS DLL PAYLOADS DETECTED</h3>
"@

        if ($criticalDLLs.Count -gt 0) {
            $html += @"
            <h4 style="color:#b71c1c;margin:10px 0 5px 0;">Critical - Known Malicious DLLs ($($criticalDLLs.Count))</h4>
            <table width="100%" cellpadding="5" cellspacing="0" border="1" bordercolor="#e0e0e0" bgcolor="#ffffff">
            <tr bgcolor="#f5f5f5">
                <th align="left" style="padding:8px;">Type</th>
                <th align="left" style="padding:8px;">File Path</th>
                <th align="left" style="padding:8px;">Details</th>
            </tr>
"@
            foreach ($dll in $criticalDLLs | Select-Object -First 5) {
                $html += @"
            <tr bgcolor="#ffcdd2">
                <td style="padding:8px;font-weight:bold;">$($dll.Type)</td>
                <td style="padding:8px;font-family:monospace;font-size:11px;">$($dll.Path)</td>
                <td style="padding:8px;">$($dll.Details)</td>
            </tr>
"@
            }
            $html += "</table>"
        }

        if ($suspiciousDLLs.Count -gt 0) {
            $html += @"
            <h4 style="color:#ff6f00;margin:10px 0 5px 0;">Suspicious DLLs ($($suspiciousDLLs.Count))</h4>
            <table width="100%" cellpadding="5" cellspacing="0" border="1" bordercolor="#e0e0e0" bgcolor="#ffffff">
            <tr bgcolor="#f5f5f5">
                <th align="left" style="padding:8px;">Type</th>
                <th align="left" style="padding:8px;">File Path</th>
                <th align="left" style="padding:8px;">Created</th>
            </tr>
"@
            foreach ($dll in $suspiciousDLLs | Select-Object -First 5) {
                $html += @"
            <tr bgcolor="#fff3e0">
                <td style="padding:8px;">$($dll.Type)</td>
                <td style="padding:8px;font-family:monospace;font-size:11px;">$($dll.Path)</td>
                <td style="padding:8px;">$($dll.Created)</td>
            </tr>
"@
            }
            $html += "</table>"
        }

        $html += @"
        </td>
    </tr>
    </table>
</td>
</tr>
"@
    }

    # Add Ransomware indicators if any
    if ($CVEIndicators.RansomwareIndicators.Count -gt 0) {
        $html += @"
<!-- Ransomware Indicators -->
<tr>
<td style="padding:0 20px 20px 20px;">
    <table width="100%" cellpadding="15" cellspacing="0" border="2" bordercolor="#d32f2f" bgcolor="#ffebee">
    <tr>
        <td>
            <h3 style="color:#d32f2f;margin:0 0 10px 0;"><span style="font-size:18px;">&#x1F512;</span> RANSOMWARE INDICATORS DETECTED!</h3>
"@
        foreach ($indicator in $CVEIndicators.RansomwareIndicators) {
            if ($indicator.Type -eq "EncryptedFiles") {
                $html += "<p><strong>Encrypted files found with extension: $($indicator.Extension)</strong><br/>Count: $($indicator.Count)<br/>Threat Actor: $(if ($indicator.ThreatActor) { $indicator.ThreatActor } else { 'Unknown' })</p>"
            } elseif ($indicator.Type -eq "RansomNote") {
                $html += "<p><strong>Ransom note found: $($indicator.FileName)</strong><br/>Locations: $($indicator.Locations -join ', ')</p>"
            }
        }
        $html += @"
            <p style="color:#d32f2f;font-weight:bold;margin:10px 0 0 0;">
                <span style="font-size:16px;">&#x1F6A8;</span> IMMEDIATE ACTION: Isolate affected systems and initiate ransomware response!
            </p>
        </td>
    </tr>
    </table>
</td>
</tr>
"@
    }

    # Add ToolPane exploit details if any
    if ($CVEIndicators.ToolPaneExploits.Count -gt 0) {
        $html += @"
<!-- ToolPane Exploits -->
<tr>
<td style="padding:0 20px 20px 20px;">
    <table width="100%" cellpadding="15" cellspacing="0" border="2" bordercolor="#d32f2f" bgcolor="#ffebee">
    <tr>
        <td>
            <h3 style="color:#d32f2f;margin:0 0 10px 0;"><span style="font-size:18px;">&#x1F4A5;</span> CRITICAL: CVE-2023-29357 Exploitation Detected</h3>
            <p style="margin:0 0 10px 0;"><span style="font-size:14px;">&#x26A0;</span> POST requests to /_layouts/15/ToolPane.aspx?DisplayMode=Edit detected:</p>

            <table width="100%" cellpadding="5" cellspacing="0" border="1" bordercolor="#e0e0e0" bgcolor="#ffffff">
            <tr bgcolor="#f5f5f5">
                <th align="left" style="padding:8px;">Time</th>
                <th align="left" style="padding:8px;">Client IP</th>
                <th align="left" style="padding:8px;">Status</th>
                <th align="left" style="padding:8px;">Threat Actor</th>
                <th align="left" style="padding:8px;">Known Attacker</th>
            </tr>
"@
        foreach ($exploit in $CVEIndicators.ToolPaneExploits | Select-Object -First 10) {
            $rowBg = if ($exploit.IsKnownAttacker) { "#ffcdd2" } else { "#ffffff" }
            $ipDisplay = if ($exploit.IsKnownAttacker) {
                "<span style='background-color:#b71c1c;color:#ffffff;padding:2px 6px;font-weight:bold;'>$($exploit.ClientIP)</span>"
            } else {
                $exploit.ClientIP
            }

            $html += @"
            <tr bgcolor="$rowBg">
                <td style="padding:8px;">$($exploit.Time)</td>
                <td style="padding:8px;">$ipDisplay</td>
                <td style="padding:8px;">$($exploit.Status)</td>
                <td style="padding:8px;">$($exploit.ThreatActor)</td>
                <td style="padding:8px;font-weight:bold;color:$(if ($exploit.IsKnownAttacker) {'#d32f2f'} else {'#000000'});">
                    $(if ($exploit.IsKnownAttacker) { "YES" } else { "No" })
                </td>
            </tr>
"@
        }
        $html += @"
            </table>
            <p style="color:#d32f2f;font-weight:bold;margin:10px 0 0 0;">
                <span style="font-size:16px;">&#x1F6A8;</span> IMMEDIATE ACTION REQUIRED: Apply patches, rotate keys, enable AMSI!
            </p>
        </td>
    </tr>
    </table>
</td>
</tr>
"@
    }

    # Add detected webshells section
    if ($CVEIndicators.WebshellsFound.Count -gt 0) {
        $html += @"
<!-- Webshells Detected -->
<tr>
<td style="padding:0 20px 20px 20px;">
    <table width="100%" cellpadding="15" cellspacing="0" border="2" bordercolor="#d32f2f" bgcolor="#ffebee">
    <tr>
        <td>
            <h3 style="color:#d32f2f;margin:0 0 10px 0;"><span style="font-size:18px;">&#x1F577;</span> WEBSHELLS DETECTED</h3>

            <table width="100%" cellpadding="5" cellspacing="0" border="1" bordercolor="#e0e0e0" bgcolor="#ffffff">
            <tr bgcolor="#f5f5f5">
                <th align="left" style="padding:8px;">File Path</th>
                <th align="left" style="padding:8px;">Detection Pattern</th>
                <th align="left" style="padding:8px;">Modified</th>
                <th align="left" style="padding:8px;">Threat Actor</th>
            </tr>
"@
        foreach ($ws in $CVEIndicators.WebshellsFound | Select-Object -First 10) {
            $actor = if ($ws.ThreatActor) { $ws.ThreatActor } else { "Unknown" }
            $html += @"
            <tr bgcolor="#ffcdd2">
                <td style="padding:8px;font-family:monospace;font-size:11px;">$($ws.Path)</td>
                <td style="padding:8px;">$($ws.Pattern)</td>
                <td style="padding:8px;">$($ws.Modified)</td>
                <td style="padding:8px;">$actor</td>
            </tr>
"@
        }
        $html += @"
            </table>
        </td>
    </tr>
    </table>
</td>
</tr>
"@
    }

    # NEW v3.8: Add comprehensive attack summary if attacks detected
    if ($CVEIndicators.AllAttacks.Count -gt 0) {
        # Group attacks by type
        $attacksByType = $CVEIndicators.AllAttacks | Group-Object -Property Type | Sort-Object Count -Descending

        $html += @"
<!-- Comprehensive Attack Summary -->
<tr>
<td style="padding:0 20px 20px 20px;">
    <h2 style="color:#1a237e;font-size:20px;margin:0 0 10px 0;"><span style="font-size:18px;">&#x1F4CA;</span> Detailed Attack Analysis</h2>

    <table width="100%" cellpadding="15" cellspacing="0" border="2" bordercolor="#d32f2f" bgcolor="#ffebee">
    <tr>
        <td>
            <h3 style="color:#d32f2f;margin:0 0 10px 0;"><span style="font-size:18px;">&#x1F6A8;</span> Complete Attack Timeline - $($CVEIndicators.AllAttacks.Count) Total Attacks</h3>

            <h4 style="color:#b71c1c;margin:10px 0 5px 0;">Attack Types Summary:</h4>
            <table width="100%" cellpadding="5" cellspacing="0" border="1" bordercolor="#e0e0e0" bgcolor="#ffffff">
            <tr bgcolor="#f5f5f5">
                <th align="left" style="padding:8px;">Attack Type</th>
                <th align="center" style="padding:8px;">Count</th>
                <th align="center" style="padding:8px;">Percentage</th>
            </tr>
"@
        foreach ($attackType in $attacksByType | Select-Object -First 10) {
            $percentage = [math]::Round(($attackType.Count / $CVEIndicators.AllAttacks.Count) * 100, 1)
            $html += @"
            <tr bgcolor="#fff3e0">
                <td style="padding:8px;font-weight:bold;">$($attackType.Name)</td>
                <td style="padding:8px;text-align:center;">$($attackType.Count)</td>
                <td style="padding:8px;text-align:center;">$percentage%</td>
            </tr>
"@
        }
        $html += @"
            </table>

            <h4 style="color:#b71c1c;margin:15px 0 5px 0;">Recent Attack Details (Last 20):</h4>
            <table width="100%" cellpadding="5" cellspacing="0" border="1" bordercolor="#e0e0e0" bgcolor="#ffffff">
            <tr bgcolor="#f5f5f5">
                <th align="left" style="padding:8px;">Time</th>
                <th align="left" style="padding:8px;">Attack Type</th>
                <th align="left" style="padding:8px;">Attacker IP</th>
                <th align="left" style="padding:8px;">Target</th>
                <th align="left" style="padding:8px;">Method</th>
                <th align="left" style="padding:8px;">Actor</th>
            </tr>
"@

        # Sort attacks by time (newest first) and show last 20
        $sortedAttacks = $CVEIndicators.AllAttacks | Sort-Object {
            if ($_.Time -is [DateTime]) { $_.Time }
            else { [DateTime]::Parse($_.Time) }
        } -Descending | Select-Object -First 20

        foreach ($attack in $sortedAttacks) {
            $rowColor = switch ($attack.Severity) {
                "Critical" { "#ffcdd2" }
                "High" { "#ffe0b2" }
                "Medium" { "#fff3e0" }
                default { "#ffffff" }
            }

            # Ensure we have IP address
            $attackerIP = if ($attack.AttackerIP) {
                $attack.AttackerIP
            } else {
                "Unknown"
            }

            # Ensure we have attack type
            $attackType = if ($attack.Type) {
                $attack.Type
            } else {
                "Unknown Attack"
            }

            $targetDisplay = if ($attack.TargetFile -and $attack.TargetFile.Length -gt 40) {
                "..." + $attack.TargetFile.Substring($attack.TargetFile.Length - 37)
            } elseif ($attack.TargetFile) {
                $attack.TargetFile
            } else {
                "N/A"
            }

            $method = if ($attack.Method) { $attack.Method } else { "Unknown" }
            $actor = if ($attack.ThreatActor) { $attack.ThreatActor } else { "Unknown" }
            $timeDisplay = if ($attack.Time) {
                if ($attack.Time -is [DateTime]) {
                    $attack.Time.ToString("yyyy-MM-dd HH:mm:ss")
                } else {
                    $attack.Time.ToString()
                }
            } else {
                "Unknown"
            }

            $html += @"
            <tr bgcolor="$rowColor">
                <td style="padding:8px;font-size:12px;">$timeDisplay</td>
                <td style="padding:8px;font-size:12px;font-weight:bold;">$attackType</td>
                <td style="padding:8px;font-family:monospace;font-size:12px;">$attackerIP</td>
                <td style="padding:8px;font-family:monospace;font-size:11px;" title="$($attack.TargetFile)">$targetDisplay</td>
                <td style="padding:8px;font-size:12px;">$method</td>
                <td style="padding:8px;font-size:12px;">$actor</td>
            </tr>
"@
        }

        $html += @"
            </table>
            <p style="color:#d32f2f;font-weight:bold;margin:10px 0 0 0;">
                <span style="font-size:16px;">&#x1F6A8;</span> Comprehensive attack analysis shows active compromise. Initiate full incident response immediately!
            </p>
        </td>
    </tr>
    </table>
</td>
</tr>
"@
    }

    # Add internal suspicious activity section
    if ($CVEIndicators.InternalSuspiciousActivity.Count -gt 0) {
        $html += @"
<!-- Internal Suspicious Activity -->
<tr>
<td style="padding:0 20px 20px 20px;">
    <table width="100%" cellpadding="15" cellspacing="0" border="2" bordercolor="#ff9800" bgcolor="#fff8e1">
    <tr>
        <td>
            <h3 style="color:#ff9800;margin:0 0 10px 0;"><span style="font-size:18px;">&#x1F6A8;</span> Internal Suspicious Activity Detected</h3>
            <p style="margin:0 0 10px 0;">Suspicious activity from internal IP addresses - potential lateral movement or compromised systems:</p>

            <table width="100%" cellpadding="5" cellspacing="0" border="1" bordercolor="#e0e0e0" bgcolor="#ffffff">
            <tr bgcolor="#f5f5f5">
                <th align="left" style="padding:8px;">Internal IP</th>
                <th align="left" style="padding:8px;">Activity Count</th>
                <th align="left" style="padding:8px;">Last Activity</th>
                <th align="left" style="padding:8px;">Pattern</th>
            </tr>
"@
        foreach ($ip in $CVEIndicators.InternalSuspiciousActivity.Keys | Select-Object -First 10) {
            $activity = $CVEIndicators.InternalSuspiciousActivity[$ip]
            $html += @"
            <tr bgcolor="#fff3e0">
                <td style="padding:8px;font-weight:bold;">$ip</td>
                <td style="padding:8px;text-align:center;">$($activity.Count)</td>
                <td style="padding:8px;">$($activity.Time)</td>
                <td style="padding:8px;">$($activity.Pattern)</td>
            </tr>
"@
        }
        $html += @"
            </table>
            <p style="color:#ff6f00;font-weight:bold;margin:10px 0 0 0;">
                <span style="font-size:16px;">&#x26A0;</span> Investigate these internal systems for compromise!
            </p>
        </td>
    </tr>
    </table>
</td>
</tr>
"@
    }

    # Add baseline DLL changes section if significant
    if ($stats.BaselineNewDLLs -gt 0 -or $stats.BaselineModifiedDLLs -gt 0) {
        $html += @"
<!-- DLL Baseline Changes -->
<tr>
<td style="padding:0 20px 20px 20px;">
    <table width="100%" cellpadding="15" cellspacing="0" border="2" bordercolor="#ff9800" bgcolor="#fff8e1">
    <tr>
        <td>
            <h3 style="color:#ff9800;margin:0 0 10px 0;"><span style="font-size:18px;">&#x1F4BE;</span> DLL Baseline Changes Detected</h3>
            <p style="margin:0;">
                <strong>New DLLs:</strong> $($stats.BaselineNewDLLs)<br/>
                <strong>Modified DLLs:</strong> $($stats.BaselineModifiedDLLs)<br/>
                <strong>Deleted DLLs:</strong> $($stats.BaselineDeletedDLLs)
            </p>
"@

        # Show modified DLL details if any
        if ($global:SecurityResults.ModifiedDLLDetails.Count -gt 0) {
            $html += @"
            <h4 style="color:#ff6f00;margin:10px 0 5px 0;">Modified DLLs:</h4>
            <table width="100%" cellpadding="5" cellspacing="0" border="1" bordercolor="#e0e0e0" bgcolor="#ffffff">
            <tr bgcolor="#f5f5f5">
                <th align="left" style="padding:8px;">DLL Name</th>
                <th align="left" style="padding:8px;">Path</th>
                <th align="left" style="padding:8px;">Previous Modified</th>
                <th align="left" style="padding:8px;">Current Modified</th>
            </tr>
"@
            foreach ($dll in $global:SecurityResults.ModifiedDLLDetails | Select-Object -First 5) {
                $html += @"
            <tr bgcolor="#fff3e0">
                <td style="padding:8px;font-weight:bold;">$($dll.Name)</td>
                <td style="padding:8px;font-family:monospace;font-size:11px;">$($dll.Path)</td>
                <td style="padding:8px;">$($dll.OldModified)</td>
                <td style="padding:8px;">$($dll.NewModified)</td>
            </tr>
"@
            }
            $html += "</table>"
        }

        # Show new DLL details if any
        if ($global:SecurityResults.NewDLLDetails.Count -gt 0 -and $stats.BaselineNewDLLs -le 20) {
            $html += @"
            <h4 style="color:#ff6f00;margin:10px 0 5px 0;">New DLLs:</h4>
            <table width="100%" cellpadding="5" cellspacing="0" border="1" bordercolor="#e0e0e0" bgcolor="#ffffff">
            <tr bgcolor="#f5f5f5">
                <th align="left" style="padding:8px;">DLL Name</th>
                <th align="left" style="padding:8px;">Path</th>
                <th align="left" style="padding:8px;">Created</th>
                <th align="left" style="padding:8px;">Size</th>
            </tr>
"@
            foreach ($dll in $global:SecurityResults.NewDLLDetails | Select-Object -First 10) {
                $html += @"
            <tr bgcolor="#fff3e0">
                <td style="padding:8px;font-weight:bold;">$($dll.Name)</td>
                <td style="padding:8px;font-family:monospace;font-size:11px;">$($dll.Path)</td>
                <td style="padding:8px;">$($dll.Created)</td>
                <td style="padding:8px;">$($dll.Size)</td>
            </tr>
"@
            }
            $html += "</table>"
        }

        $html += @"
        </td>
    </tr>
    </table>
</td>
</tr>
"@
    }

    # Security Configuration Status
    $html += @"
<!-- Security Configuration Status -->
<tr>
<td style="padding:20px 20px 10px 20px;">
    <h2 style="color:#1a237e;font-size:22px;margin:0;padding:0 0 10px 0;border-bottom:2px solid #3949ab;">
        <span style="font-size:20px;">&#x1F6E1;</span> Security Configuration Status
    </h2>
</td>
</tr>

<tr>
<td style="padding:0 20px 20px 20px;">
    <table width="100%" cellpadding="10" cellspacing="0" border="1" bordercolor="#e0e0e0" bgcolor="#ffffff">
    <tr bgcolor="#f5f5f5">
        <th align="left" style="padding:10px;width:50%;">Security Feature</th>
        <th align="left" style="padding:10px;">Status</th>
    </tr>
    <tr>
        <td style="padding:10px;"><span style="font-size:14px;">&#x1F6E1;</span> <strong>Endpoint Protection</strong></td>
        <td style="padding:10px;color:$(if ($stats.EndpointProtection -ne 'None') {'#4caf50'} else {'#d32f2f'});">
            $(if ($stats.EndpointProtection -ne 'None') { '<span style="font-size:14px;">&#x2714;</span>' } else { '<span style="font-size:14px;">&#x2718;</span>' })
            $($stats.EndpointProtection)
        </td>
    </tr>
    <tr bgcolor="#fafafa">
        <td style="padding:10px;"><span style="font-size:14px;">&#x1F512;</span> <strong>LSA Protection</strong></td>
        <td style="padding:10px;color:$(if ($stats.LSAProtection) {'#4caf50'} else {'#d32f2f'});">
            $(if ($stats.LSAProtection) { '<span style="font-size:14px;">&#x2714;</span> Enabled' } else { '<span style="font-size:14px;">&#x2718;</span> Disabled' })
        </td>
    </tr>
    <tr>
        <td style="padding:10px;"><span style="font-size:14px;">&#x1F6E1;</span> <strong>Credential Guard</strong></td>
        <td style="padding:10px;color:$(if ($stats.CredentialGuardStatus -eq 'Enabled' -or $stats.CredentialGuardStatus -eq 'Not Applicable (ESET Active)') {'#4caf50'} else {'#d32f2f'});">
            $(if ($stats.CredentialGuardStatus -eq 'Enabled') { '<span style="font-size:14px;">&#x2714;</span>' }
              elseif ($stats.CredentialGuardStatus -eq 'Not Applicable (ESET Active)') { '<span style="font-size:14px;">&#x2713;</span>' }
              else { '<span style="font-size:14px;">&#x2718;</span>' })
            $($stats.CredentialGuardStatus)
        </td>
    </tr>
    <tr bgcolor="#fafafa">
        <td style="padding:10px;"><span style="font-size:14px;">&#x1F4C1;</span> <strong>Controlled Folder Access</strong></td>
        <td style="padding:10px;color:$(if ($stats.ControlledFolderAccessStatus -eq 'Enabled' -or $stats.ControlledFolderAccessStatus -eq 'Not Applicable (ESET Active)') {'#4caf50'} else {'#d32f2f'});">
            $(if ($stats.ControlledFolderAccessStatus -eq 'Enabled') { '<span style="font-size:14px;">&#x2714;</span>' }
              elseif ($stats.ControlledFolderAccessStatus -eq 'Not Applicable (ESET Active)') { '<span style="font-size:14px;">&#x2713;</span>' }
              else { '<span style="font-size:14px;">&#x2718;</span>' })
            $($stats.ControlledFolderAccessStatus)
        </td>
    </tr>
    <tr>
        <td style="padding:10px;"><span style="font-size:14px;">&#x1F6E1;</span> <strong>Attack Surface Reduction Rules</strong></td>
        <td style="padding:10px;color:$(if ($stats.ASRRulesStatus -eq 'Not Applicable (ESET Active)' -or $stats.ASRRulesEnabled -gt 0) {'#4caf50'} else {'#ff9800'});">
            $(if ($stats.ASRRulesStatus -eq 'Not Applicable (ESET Active)') { '<span style="font-size:14px;">&#x2713;</span>' }
              elseif ($stats.ASRRulesEnabled -gt 0) { '<span style="font-size:14px;">&#x2714;</span>' }
              else { '<span style="font-size:14px;">&#x26A0;</span>' })
            $($stats.ASRRulesStatus)
        </td>
    </tr>
    <tr bgcolor="#fafafa">
        <td style="padding:10px;"><span style="font-size:14px;">&#x1F527;</span> <strong>AMSI (Antimalware Scan Interface)</strong></td>
        <td style="padding:10px;color:$(if ($stats.AMSIEnabled) {'#4caf50'} else {'#d32f2f'});">
            $(if ($stats.AMSIEnabled) { '<span style="font-size:14px;">&#x2714;</span> Enabled' } else { '<span style="font-size:14px;">&#x2718;</span> Disabled' })
        </td>
    </tr>
    <tr>
        <td style="padding:10px;"><span style="font-size:14px;">&#x1F511;</span> <strong>Machine Keys Rotated</strong></td>
        <td style="padding:10px;color:$(if ($stats.MachineKeyRotated) {'#4caf50'} else {'#d32f2f'});">
            $(if ($stats.MachineKeyRotated) {
                "<span style='font-size:14px;'>&#x2714;</span> Yes - $($stats.MachineKeyRotationDate)"
            } else {
                '<span style="font-size:14px;">&#x2718;</span> No - Keys compromised since July 2023!'
            })
        </td>
    </tr>
    </table>
</td>
</tr>
"@

    # Security patches status
    if ($stats.MissingPatches.Count -gt 0 -or $stats.InstalledPatches.Count -gt 0) {
        $html += @"
<!-- Security Patches Status -->
<tr>
<td style="padding:0 20px 20px 20px;">
    <h3 style="color:#1a237e;margin:0 0 10px 0;"><span style="font-size:18px;">&#x1F6E1;</span> Security Patches Status</h3>

    <table width="100%" cellpadding="10" cellspacing="0" border="1" bordercolor="#e0e0e0" bgcolor="#ffffff">
"@

        if ($stats.InstalledPatches.Count -gt 0) {
            $html += @"
    <tr>
        <td style="padding:10px;background-color:#e8f5e9;">
            <strong style="color:#4caf50;"><span style="font-size:14px;">&#x2714;</span> Installed Patches:</strong><br/>
            $($stats.InstalledPatches -join ', ')
        </td>
    </tr>
"@
        }

        if ($stats.MissingPatches.Count -gt 0) {
            $html += @"
    <tr>
        <td style="padding:10px;background-color:#ffebee;">
            <strong style="color:#d32f2f;"><span style="font-size:14px;">&#x2718;</span> Missing Critical Patches:</strong><br/>
            $($stats.MissingPatches -join ', ')<br/>
            <span style="color:#d32f2f;font-weight:bold;">INSTALL IMMEDIATELY!</span>
        </td>
    </tr>
"@
        }

        $html += @"
    </table>
</td>
</tr>
"@
    }

    # Recommendations section - ENHANCED
    $recommendations = @()
    $criticalRecommendations = @()

    # Critical recommendations based on findings
    if ($stats.MissingPatches.Count -gt 0) {
        if ($stats.MissingPatches -join '' -match 'SharePoint 2019') {
            $criticalRecommendations += "<span style='font-size:14px;'>&#x1F6A8;</span> Install SharePoint 2019 December 2023 CU or later immediately (minimum build: 16.0.10398.20000)"
        } else {
            $criticalRecommendations += "<span style='font-size:14px;'>&#x1F6A8;</span> Install missing security patches immediately: $($stats.MissingPatches -join ', ')"
        }
    }

    if ($stats.ToolPaneExploits -gt 0 -or $stats.ExploitAttempts -gt 0) {
        $criticalRecommendations += "<span style='font-size:14px;'>&#x1F6A8;</span> CRITICAL: Active exploitation detected - initiate incident response immediately"
    }

    if ($stats.ThreatActorActivity -gt 0) {
        $criticalRecommendations += "<span style='font-size:14px;'>&#x1F6A8;</span> CRITICAL: Known threat actors detected - assume breach and engage security team"
    }

    if ($stats.WebshellsFound -gt 0) {
        $criticalRecommendations += "<span style='font-size:14px;'>&#x1F6A8;</span> Remove all detected webshells and perform forensic analysis"
    }

    if ($stats.PostExploitationTools -gt 0) {
        $criticalRecommendations += "<span style='font-size:14px;'>&#x1F6A8;</span> Post-exploitation tools detected - rotate ALL credentials immediately"
    }

    if ($stats.C2Communications -gt 0) {
        $criticalRecommendations += "<span style='font-size:14px;'>&#x1F6A8;</span> Block all C2 domains/IPs at firewall immediately"
    }

    if (-not $stats.MachineKeyRotated) {
        $criticalRecommendations += "<span style='font-size:14px;'>&#x1F511;</span> Rotate ASP.NET machine keys immediately (not rotated since July 2023)"
    }

    if ($stats.DefenderDisabled -gt 0 -and -not $stats.ESETEnabled) {
        $criticalRecommendations += "<span style='font-size:14px;'>&#x1F6AB;</span> Re-enable Microsoft Defender protections immediately"
    }

    if ($stats.LSASSAccess -gt 0) {
        $criticalRecommendations += "<span style='font-size:14px;'>&#x1F511;</span> LSASS access detected - assume credentials compromised, rotate all passwords"
    }

    # Standard recommendations
    if (-not $stats.AMSIEnabled) {
        $recommendations += "<span style='font-size:14px;'>&#x2022;</span> Enable AMSI for SharePoint (strongly recommended by Microsoft)"
    }

    if (-not $stats.LSAProtection) {
        $recommendations += "<span style='font-size:14px;'>&#x2022;</span> Enable LSA Protection (RunAsPPL)"
    }

    if ($stats.CredentialGuardStatus -eq 'Not Enabled' -and -not $stats.ESETEnabled) {
        $recommendations += "<span style='font-size:14px;'>&#x2022;</span> Enable Credential Guard on this server"
    }

    if ($stats.ControlledFolderAccessStatus -eq 'Not Enabled' -and -not $stats.ESETEnabled) {
        $recommendations += "<span style='font-size:14px;'>&#x2022;</span> Enable Controlled Folder Access for ransomware protection"
    }

    if ($stats.ASRRulesEnabled -eq 0 -and -not $stats.ESETEnabled) {
        $recommendations += "<span style='font-size:14px;'>&#x2022;</span> Configure Attack Surface Reduction rules"
    }

    if ($stats.EndpointProtection -eq 'None') {
        $recommendations += "<span style='font-size:14px;'>&#x2022;</span> Deploy endpoint protection (Microsoft Defender for Endpoint or ESET)"
    }

    if ($stats.BaselineNewDLLs -gt 10) {
        $recommendations += "<span style='font-size:14px;'>&#x2022;</span> Review new DLLs detected since baseline - possible persistence mechanisms"
    }

    if ($stats.IntegrityIssues -gt 0) {
        $recommendations += "<span style='font-size:14px;'>&#x2022;</span> Critical SharePoint files have been tampered - reinstall affected components"
    }

    if ($stats.GPOModifications -gt 0) {
        $recommendations += "<span style='font-size:14px;'>&#x2022;</span> Review all Group Policy changes - ransomware groups use GPO for deployment"
    }

    if ($stats.PendingDLLApprovals -gt 0) {
        $recommendations += "<span style='font-size:14px;'>&#x2022;</span> Review pending DLLs: Run script with -ReviewPendingDLLs parameter"
    }

    # Add recommendations section
    if ($criticalRecommendations.Count -gt 0 -or $recommendations.Count -gt 0) {
        $html += @"
<!-- Recommendations -->
<tr>
<td style="padding:20px 20px 10px 20px;">
    <h2 style="color:#1a237e;font-size:22px;margin:0;padding:0 0 10px 0;border-bottom:2px solid #3949ab;">
        <span style="font-size:20px;">&#x1F4CB;</span> Security Recommendations
    </h2>
</td>
</tr>
"@

        if ($criticalRecommendations.Count -gt 0) {
            $html += @"
<tr>
<td style="padding:0 20px 20px 20px;">
    <table width="100%" cellpadding="15" cellspacing="0" border="2" bordercolor="#d32f2f" bgcolor="#ffebee">
    <tr>
        <td>
            <h3 style="color:#d32f2f;margin:0 0 10px 0;">CRITICAL ACTIONS REQUIRED</h3>
"@
            foreach ($rec in $criticalRecommendations) {
                $html += "<p style='margin:5px 0;'>$rec</p>"
            }
            $html += @"
        </td>
    </tr>
    </table>
</td>
</tr>
"@
        }

        if ($recommendations.Count -gt 0) {
            $html += @"
<tr>
<td style="padding:0 20px 20px 20px;">
    <table width="100%" cellpadding="15" cellspacing="0" border="1" bordercolor="#3949ab" bgcolor="#e8eaf6">
    <tr>
        <td>
            <h3 style="color:#3949ab;margin:0 0 10px 0;">Additional Security Improvements</h3>
"@
            foreach ($rec in $recommendations) {
                $html += "<p style='margin:5px 0;'>$rec</p>"
            }
            $html += @"
        </td>
    </tr>
    </table>
</td>
</tr>
"@
        }
    }

    # Footer
    $html += @"
<!-- Footer -->
<tr>
<td bgcolor="#f5f5f5" style="padding:20px;text-align:center;font-size:12px;color:#666;">
    <p style="margin:0;">SharePoint Security Monitor v3.9 - Advanced DLL Validation Edition</p>
    <p style="margin:5px 0 0 0;">Report generated on $env:COMPUTERNAME at $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
    <p style="margin:5px 0 0 0;">For support: soc@goline.ch</p>
</td>
</tr>

</table>
</td>
</tr>
</table>
</body>
</html>
"@

    return $html
}

# Generate report
$report = Generate-HTMLReport

# Save report to file
$reportFile = "$ReportPath\SecurityReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
$report | Out-File $reportFile -Force
Write-SecurityLog "Report saved to: $reportFile" "INFO"

# Clean up old reports (keep last 30)
Get-ChildItem $ReportPath -Filter "SecurityReport_*.html" |
    Sort-Object CreationTime -Descending |
    Select-Object -Skip 30 |
    Remove-Item -Force

# 12. EMAIL ALERT SYSTEM - ENHANCED WITH AUTO EMAIL
$shouldSendEmail = $false
$emailSubject = ""
$emailPriority = "Normal"

# Determine if we should send email based on parameters and findings
if ($ForceAlert) {
    $shouldSendEmail = $true
    $emailSubject = "[FORCED] SharePoint Security Alert - $env:COMPUTERNAME"
    $emailPriority = "High"
    Write-SecurityLog "Force alert parameter set - email will be sent" "INFO"
} elseif ($AlwaysSendReport) {
    $shouldSendEmail = $true
    $emailSubject = "SharePoint Security Report - $env:COMPUTERNAME - $(Get-Date -Format 'yyyy-MM-dd')"
    Write-SecurityLog "Always send report parameter set - email will be sent" "INFO"
} else {
    # Check conditions for automatic email
    $alertCount = $global:SecurityResults.Alerts.Count
    $warningCount = $global:SecurityResults.Warnings.Count
    $stats = $global:SecurityResults.Statistics

    # Critical conditions that always trigger email
    if ($alertCount -gt 0) {
        $shouldSendEmail = $true
        $emailPriority = "High"
        $emailSubject = "[CRITICAL] SharePoint Security Alert - $env:COMPUTERNAME - $alertCount Alerts"
        Write-SecurityLog "Critical alerts detected - email will be sent" "INFO"
    }
    # Warning conditions (unless NoAlertOnWarnings is set)
    elseif ($warningCount -gt 0 -and -not $NoAlertOnWarnings) {
        $shouldSendEmail = $true
        $emailSubject = "[WARNING] SharePoint Security Alert - $env:COMPUTERNAME - $warningCount Warnings"
        Write-SecurityLog "Warnings detected - email will be sent" "INFO"
    }
    # Specific threat conditions
    elseif ($stats.ToolPaneExploits -gt 0 -or $stats.WebshellsFound -gt 0 -or
            $stats.RansomwareIndicators -gt 0 -or $stats.ThreatActorActivity -gt 0 -or
            $stats.PostExploitationTools -gt 0 -or $stats.C2Communications -gt 0) {
        $shouldSendEmail = $true
        $emailPriority = "High"
        $emailSubject = "[THREAT DETECTED] SharePoint Security Alert - $env:COMPUTERNAME"
        Write-SecurityLog "Active threats detected - email will be sent" "INFO"
    }
    # Configuration issues
    elseif ($stats.MissingPatches.Count -gt 0 -or $stats.DefenderDisabled -gt 0 -or
            $stats.IntegrityIssues -gt 0) {
        $shouldSendEmail = $true
        $emailSubject = "[SECURITY ISSUE] SharePoint Security Alert - $env:COMPUTERNAME"
        Write-SecurityLog "Security configuration issues detected - email will be sent" "INFO"
    }
}

# Send daily summary if requested (overrides other conditions)
if ($SendDailySummary) {
    $shouldSendEmail = $true
    $emailSubject = "SharePoint Security Daily Summary - $env:COMPUTERNAME - $(Get-Date -Format 'yyyy-MM-dd')"
    $emailPriority = "Normal"
    Write-SecurityLog "Daily summary requested - email will be sent" "INFO"
}

# Send email if conditions are met
if ($shouldSendEmail) {
    try {
        # Prepare email parameters
        $mailParams = @{
            To = $AlertEmail
            From = $FromEmail
            Subject = $emailSubject
            Body = $report
            BodyAsHtml = $true
            SmtpServer = $SMTPServer
            Priority = $emailPriority
        }

        # Add report as attachment for critical alerts
        if ($emailPriority -eq "High" -or $SendDailySummary -or $AlwaysSendReport) {
            $mailParams.Attachments = $reportFile
        }

        Send-MailMessage @mailParams -ErrorAction Stop

        Write-SecurityLog "Security alert email sent successfully to $AlertEmail" "SUCCESS"
        Write-SecurityLog "Email subject: $emailSubject" "INFO"
    } catch {
        Write-SecurityLog "Failed to send email alert: $_" "ERROR"
        Write-SecurityLog "Please check SMTP settings: Server=$SMTPServer, From=$FromEmail, To=$AlertEmail" "ERROR"
    }
} else {
    if ($NoAlertOnWarnings -and $warningCount -gt 0) {
        Write-SecurityLog "Warnings detected but email suppressed due to -NoAlertOnWarnings parameter" "INFO"
    } else {
        Write-SecurityLog "No critical issues detected - email alert not sent" "INFO"
    }
}

# Stop main timer
$global:MainTimer.Stop()

# 13. SUMMARY OUTPUT
Write-SecurityLog "" "INFO"
Write-SecurityLog "=== SharePoint Security Monitoring Complete ===" "INFO"
Write-SecurityLog "Total Execution Time: $([math]::Round($global:MainTimer.Elapsed.TotalSeconds, 2)) seconds" "INFO"
Write-SecurityLog "" "INFO"
Write-SecurityLog "SUMMARY:" "INFO"
Write-SecurityLog "- Critical Alerts: $($global:SecurityResults.Alerts.Count)" $(if ($global:SecurityResults.Alerts.Count -gt 0) { "ALERT" } else { "SUCCESS" })
Write-SecurityLog "- Warnings: $($global:SecurityResults.Warnings.Count)" $(if ($global:SecurityResults.Warnings.Count -gt 0) { "WARNING" } else { "SUCCESS" })
Write-SecurityLog "- ToolPane Exploits: $($global:SecurityResults.Statistics.ToolPaneExploits)" $(if ($global:SecurityResults.Statistics.ToolPaneExploits -gt 0) { "ALERT" } else { "SUCCESS" })
Write-SecurityLog "- Webshells Found: $($global:SecurityResults.Statistics.WebshellsFound)" $(if ($global:SecurityResults.Statistics.WebshellsFound -gt 0) { "ALERT" } else { "SUCCESS" })
Write-SecurityLog "- Suspicious DLLs: $($global:SecurityResults.Statistics.DLLPayloads)" $(if ($global:SecurityResults.Statistics.DLLPayloads -gt 0) { "ALERT" } else { "SUCCESS" })
Write-SecurityLog "- Post-Exploitation Tools: $($global:SecurityResults.Statistics.PostExploitationTools)" $(if ($global:SecurityResults.Statistics.PostExploitationTools -gt 0) { "ALERT" } else { "SUCCESS" })
Write-SecurityLog "- Threat Actor Activity: $($global:SecurityResults.Statistics.ThreatActorActivity)" $(if ($global:SecurityResults.Statistics.ThreatActorActivity -gt 0) { "ALERT" } else { "SUCCESS" })
Write-SecurityLog "- Total Attacks Detected: $($global:SecurityResults.Statistics.AllAttacks)" $(if ($global:SecurityResults.Statistics.AllAttacks -gt 0) { "ALERT" } else { "SUCCESS" })

if ($global:SecurityResults.Statistics.PendingDLLApprovals -gt 0) {
    Write-SecurityLog "" "INFO"
    Write-SecurityLog "ACTION REQUIRED: $($global:SecurityResults.Statistics.PendingDLLApprovals) DLLs pending approval" "WARNING"
    Write-SecurityLog "Run with -ReviewPendingDLLs to review and approve legitimate DLLs" "WARNING"
}

Write-SecurityLog "" "INFO"
Write-SecurityLog "Report Location: $reportFile" "INFO"
Write-SecurityLog "Email Status: $(if ($shouldSendEmail) { 'Sent' } else { 'Not required' })" "INFO"

# Exit with appropriate code
if ($global:SecurityResults.Alerts.Count -gt 0) {
    exit 2  # Critical
} elseif ($global:SecurityResults.Warnings.Count -gt 0) {
    exit 1  # Warning
} else {
    exit 0  # Success
}

# END OF SCRIPT

