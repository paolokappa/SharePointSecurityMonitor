#Requires -Version 5.1
<#
.SYNOPSIS
    Demonstration script for the Enhanced SharePoint Security Monitor
    
.DESCRIPTION
    This script demonstrates the capabilities of the enhanced SharePoint Security Monitor
    showing the modular architecture, improved performance, and advanced features.
    
.EXAMPLE
    .\Demo-EnhancedScript.ps1
    
.NOTES
    This is a demonstration of the enhanced PowerShell solution
#>

[CmdletBinding()]
param(
    [switch]$ShowModules,
    [switch]$CreateSampleData,
    [switch]$RunDemo
)

Write-Host "Enhanced SharePoint Security Monitor v4.0 - Demonstration" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green

if ($ShowModules) {
    Write-Host "`nModular Architecture:" -ForegroundColor Yellow
    Write-Host "--------------------" -ForegroundColor Yellow
    
    $ModuleFiles = Get-ChildItem -Path ".\Modules\*.psm1" -ErrorAction SilentlyContinue
    
    if ($ModuleFiles.Count -gt 0) {
        foreach ($Module in $ModuleFiles) {
            $ModuleName = [System.IO.Path]::GetFileNameWithoutExtension($Module.Name)
            Write-Host "✓ $ModuleName" -ForegroundColor Green
            
            # Show module functions
            try {
                $ModuleContent = Get-Content $Module.FullName -Raw
                if ($ModuleContent -match "Export-ModuleMember -Function @\((.*?)\)") {
                    $Functions = $Matches[1] -replace "'|`"" -split ",\s*" | ForEach-Object { $_.Trim() }
                    foreach ($Function in $Functions) {
                        if ($Function) {
                            Write-Host "   - $Function" -ForegroundColor Cyan
                        }
                    }
                }
            } catch {
                Write-Host "   - (Unable to parse module functions)" -ForegroundColor Gray
            }
            Write-Host ""
        }
    } else {
        Write-Host "No module files found in .\Modules\" -ForegroundColor Red
    }
}

if ($CreateSampleData) {
    Write-Host "`nCreating Sample Data Structure:" -ForegroundColor Yellow
    Write-Host "-------------------------------" -ForegroundColor Yellow
    
    # Create directories
    $Directories = @("Data", "Logs", "Reports", "Config\Environment", "Config\Secure", "Templates")
    
    foreach ($Dir in $Directories) {
        if (!(Test-Path $Dir)) {
            New-Item -ItemType Directory -Path $Dir -Force | Out-Null
            Write-Host "✓ Created directory: $Dir" -ForegroundColor Green
        } else {
            Write-Host "✓ Directory exists: $Dir" -ForegroundColor Cyan
        }
    }
    
    # Create sample data files
    $SampleBaseline = @{
        CreatedDate = Get-Date
        Version = "1.0"
        DLLs = @{
            "ABC123DEF456" = @{
                FilePath = "C:\Program Files\Microsoft\SharePoint\bin\Microsoft.SharePoint.dll"
                FileName = "Microsoft.SharePoint.dll"
                FileSize = 2048576
                CreationTime = Get-Date
                LastWriteTime = Get-Date
            }
        }
    }
    
    $BaselinePath = ".\Data\DLLBaseline.json"
    if (!(Test-Path $BaselinePath)) {
        $SampleBaseline | ConvertTo-Json -Depth 3 | Out-File -FilePath $BaselinePath -Encoding UTF8
        Write-Host "✓ Created sample DLL baseline: $BaselinePath" -ForegroundColor Green
    }
    
    # Create sample threat signatures
    $SampleThreatSignatures = @{
        "MALICIOUS_HASH_1" = @{
            Description = "Known malicious DLL"
            ThreatLevel = "Critical"
            FirstSeen = Get-Date
        }
    }
    
    $ThreatSigPath = ".\Data\ThreatSignatures.json"
    if (!(Test-Path $ThreatSigPath)) {
        $SampleThreatSignatures | ConvertTo-Json -Depth 3 | Out-File -FilePath $ThreatSigPath -Encoding UTF8
        Write-Host "✓ Created sample threat signatures: $ThreatSigPath" -ForegroundColor Green
    }
    
    # Create environment-specific config
    $DevConfig = @{
        LoggingSettings = @{
            LogLevel = "DEBUG"
        }
        ScanSettings = @{
            MaxDaysToScan = 1
        }
    }
    
    $DevConfigPath = ".\Config\Environment\Development.json"
    if (!(Test-Path $DevConfigPath)) {
        $DevConfig | ConvertTo-Json -Depth 3 | Out-File -FilePath $DevConfigPath -Encoding UTF8
        Write-Host "✓ Created development config: $DevConfigPath" -ForegroundColor Green
    }
}

if ($RunDemo) {
    Write-Host "`nRunning Enhanced Script Demonstration:" -ForegroundColor Yellow
    Write-Host "--------------------------------------" -ForegroundColor Yellow
    
    # Test if main script exists
    if (Test-Path ".\Enhanced-SharePoint-Security-Monitor.ps1") {
        Write-Host "✓ Enhanced script found" -ForegroundColor Green
        
        # Show help
        Write-Host "`nShowing script help:" -ForegroundColor Cyan
        try {
            Get-Help ".\Enhanced-SharePoint-Security-Monitor.ps1" -ErrorAction Stop
        } catch {
            Write-Host "Help information not available (script may need to be loaded)" -ForegroundColor Yellow
        }
        
        # Demonstrate configuration loading
        Write-Host "`nTesting configuration loading:" -ForegroundColor Cyan
        if (Test-Path ".\SharePointSecurityConfig.json") {
            try {
                $Config = Get-Content ".\SharePointSecurityConfig.json" -Raw | ConvertFrom-Json
                Write-Host "✓ Configuration loaded successfully" -ForegroundColor Green
                Write-Host "  Environment: $($Config.Environment)" -ForegroundColor Cyan
                Write-Host "  Log Level: $($Config.LoggingSettings.LogLevel)" -ForegroundColor Cyan
                Write-Host "  DLL Analysis: $($Config.DLLAnalysisSettings.EnableDLLAnalysis)" -ForegroundColor Cyan
            } catch {
                Write-Host "✗ Failed to load configuration: $_" -ForegroundColor Red
            }
        } else {
            Write-Host "✗ Configuration file not found" -ForegroundColor Red
        }
        
        # Show available parameters
        Write-Host "`nAvailable script parameters:" -ForegroundColor Cyan
        Write-Host "- Standard Scan: .\Enhanced-SharePoint-Security-Monitor.ps1" -ForegroundColor White
        Write-Host "- Quick Scan: .\Enhanced-SharePoint-Security-Monitor.ps1 -QuickScan" -ForegroundColor White
        Write-Host "- Create Baseline: .\Enhanced-SharePoint-Security-Monitor.ps1 -CreateBaseline" -ForegroundColor White
        Write-Host "- Review DLLs: .\Enhanced-SharePoint-Security-Monitor.ps1 -ReviewPendingDLLs" -ForegroundColor White
        Write-Host "- Manage Tasks: .\Enhanced-SharePoint-Security-Monitor.ps1 -ManageTasks -TaskAction Install" -ForegroundColor White
        
    } else {
        Write-Host "✗ Enhanced script not found: .\Enhanced-SharePoint-Security-Monitor.ps1" -ForegroundColor Red
    }
}

Write-Host "`nEnhancement Summary:" -ForegroundColor Yellow
Write-Host "-------------------" -ForegroundColor Yellow
Write-Host "✓ Modular Architecture: Separated into 5 specialized modules" -ForegroundColor Green
Write-Host "✓ Enhanced DLL Analysis: ML-based detection with behavioral analysis" -ForegroundColor Green
Write-Host "✓ Advanced Threat Detection: Pattern correlation and threat intelligence" -ForegroundColor Green
Write-Host "✓ Centralized Configuration: JSON-based config with environment support" -ForegroundColor Green
Write-Host "✓ Comprehensive Reporting: HTML reports with charts and visualizations" -ForegroundColor Green
Write-Host "✓ Improved Performance: Caching, parallel processing, and optimization" -ForegroundColor Green
Write-Host "✓ Better Error Handling: Structured logging and recovery mechanisms" -ForegroundColor Green

Write-Host "`nKey Improvements over v3.9:" -ForegroundColor Yellow
Write-Host "---------------------------" -ForegroundColor Yellow
Write-Host "• Reduced from 5,519 lines to modular components" -ForegroundColor Cyan
Write-Host "• Added ML-based DLL threat scoring" -ForegroundColor Cyan
Write-Host "• Implemented threat correlation analysis" -ForegroundColor Cyan
Write-Host "• Added comprehensive configuration management" -ForegroundColor Cyan
Write-Host "• Enhanced reporting with HTML and charts" -ForegroundColor Cyan
Write-Host "• Improved performance with caching and parallel processing" -ForegroundColor Cyan
Write-Host "• Added SIEM integration capabilities" -ForegroundColor Cyan
Write-Host "• Implemented secure credential handling" -ForegroundColor Cyan

Write-Host "`nNext Steps:" -ForegroundColor Yellow
Write-Host "----------" -ForegroundColor Yellow
Write-Host "1. Review and customize SharePointSecurityConfig.json for your environment" -ForegroundColor White
Write-Host "2. Run: .\Demo-EnhancedScript.ps1 -CreateSampleData to set up data structure" -ForegroundColor White
Write-Host "3. Execute: .\Enhanced-SharePoint-Security-Monitor.ps1 -CreateBaseline to establish baseline" -ForegroundColor White
Write-Host "4. Set up scheduled tasks: .\Enhanced-SharePoint-Security-Monitor.ps1 -ManageTasks -TaskAction Install" -ForegroundColor White
Write-Host "5. Monitor with: .\Enhanced-SharePoint-Security-Monitor.ps1 for regular scans" -ForegroundColor White

Write-Host "`nDemo completed successfully!" -ForegroundColor Green