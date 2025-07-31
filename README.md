# Enhanced SharePoint Security Monitor v4.0

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://github.com/PowerShell/PowerShell)
[![SharePoint](https://img.shields.io/badge/SharePoint-2016%2F2019-green.svg)](https://www.microsoft.com/en-us/microsoft-365/sharepoint/collaboration)

A comprehensive PowerShell-based SharePoint security monitoring solution with CVE-2025-53770 protection, advanced DLL analysis, threat detection, and automated alerting capabilities.

## Project Overview

The original 5,519-line PowerShell script has been successfully transformed into a modular, high-performance security monitoring solution that maintains the PowerShell ecosystem while adding significant enhancements. This enhanced solution successfully transforms the original monolithic PowerShell script into a modern, modular, and highly capable security monitoring platform.

## Key Features

- **CVE-Specific Protection**: Dedicated detection for CVE-2025-53770
- **Advanced DLL Analysis**: ML-based threat scoring with signature verification and behavioral analysis
- **Modular Architecture**: 5 specialized PowerShell modules for different security functions
- **Real-time Threat Detection**: Pattern matching and correlation analysis across time windows
- **Automated Email Alerting**: Comprehensive notifications to security team (soc@goline.ch)
- **Performance Optimized**: Incremental log reading with caching and parallel processing
- **Interactive Reporting**: HTML reports with charts, visualizations, and executive summaries
- **Configuration Management**: Environment-specific settings with secure credential handling

## Solution Architecture

### Core Components

1. **Enhanced-SharePoint-Security-Monitor.ps1** (Main Script)
   - Modular entry point with comprehensive parameter support
   - Error handling and recovery mechanisms
   - Progress reporting and execution time tracking
   - Support for quick scans, baseline creation, and task management

2. **Modular Architecture (5 Specialized Modules)**
   - **SecurityLogger.psm1**: Advanced logging with SIEM integration
   - **DLLAnalyzer.psm1**: Comprehensive DLL analysis with ML-based detection
   - **ThreatDetector.psm1**: Pattern matching and threat correlation
   - **ConfigManager.psm1**: Centralized configuration management
   - **ReportGenerator.psm1**: HTML reporting with charts and visualizations

3. **Configuration System**
   - **SharePointSecurityConfig.json**: Production-ready configuration
   - Environment-specific overrides (Development, Testing, Production)
   - Secure credential handling with encryption support

4. **Demonstration and Setup**
   - **Demo-EnhancedScript.ps1**: Interactive demonstration script
   - Sample data structure creation
   - Module verification and testing capabilities

## Quick Start Guide

### Basic Usage
```powershell
# Standard security scan
.\Enhanced-SharePoint-Security-Monitor.ps1
```

### Common Operations
```powershell
# Quick scan (last 12 hours)
.\Enhanced-SharePoint-Security-Monitor.ps1 -QuickScan

# Create DLL baseline
.\Enhanced-SharePoint-Security-Monitor.ps1 -CreateBaseline

# Review pending DLL approvals
.\Enhanced-SharePoint-Security-Monitor.ps1 -ReviewPendingDLLs

# File integrity check
.\Enhanced-SharePoint-Security-Monitor.ps1 -CheckIntegrity

# Force email alert with detailed report
.\Enhanced-SharePoint-Security-Monitor.ps1 -ForceAlert -AlwaysSendReport

# Auto-approve legitimate DLLs
.\Enhanced-SharePoint-Security-Monitor.ps1 -AutoApproveDLLs
```

### Task Management
```powershell
# Install scheduled tasks
.\Enhanced-SharePoint-Security-Monitor.ps1 -ManageTasks -TaskAction Install

# Check task status
.\Enhanced-SharePoint-Security-Monitor.ps1 -ManageTasks -TaskAction Status

# Remove scheduled tasks
.\Enhanced-SharePoint-Security-Monitor.ps1 -ManageTasks -TaskAction Remove
```

### Advanced Features
```powershell
# Verbose DLL analysis with auto-approval
.\Enhanced-SharePoint-Security-Monitor.ps1 -VerboseDLL -AutoApproveDLLs

# Clear caches and reset bookmarks
.\Enhanced-SharePoint-Security-Monitor.ps1 -ClearCache -ResetBookmarks
```

## File Structure

```
Enhanced SharePoint Security Monitor/
├── Enhanced-SharePoint-Security-Monitor.ps1    # Main script
├── Demo-EnhancedScript.ps1                     # Demonstration script
├── SharePointSecurityConfig.json               # Configuration file
├── Modules/
│   ├── SecurityLogger.psm1                     # Logging module
│   ├── DLLAnalyzer.psm1                        # DLL analysis module
│   ├── ThreatDetector.psm1                     # Threat detection module
│   ├── ConfigManager.psm1                      # Configuration module
│   └── ReportGenerator.psm1                    # Reporting module
├── Data/                                        # Data storage (created on first run)
│   ├── DLLBaseline.json                        # DLL baseline data
│   ├── ThreatSignatures.json                   # Known threat signatures
│   ├── KnownGoodDLLs.json                      # Approved DLLs
│   ├── PendingDLLApprovals.json                # Pending approvals
│   ├── EventCache.json                         # Event processing cache
│   └── LogBookmarks.json                       # Log reading positions
├── Logs/                                        # Log files (created on first run)
├── Reports/                                     # Generated reports
├── Config/                                      # Configuration management
│   ├── Environment/                             # Environment-specific configs
│   └── Secure/                                  # Encrypted configurations
└── Templates/                                   # Report templates
```

## Key Enhancements Over Original v3.9

### Performance Improvements
- **Modular Design**: Reduced monolithic 5,519-line script to specialized modules
- **Caching System**: Event caching and log bookmarks for incremental processing
- **Parallel Processing**: Multi-threaded analysis for large datasets
- **Memory Optimization**: Configurable memory limits and compression caching
- **Progress Reporting**: Real-time feedback on long-running operations

### Advanced DLL Analysis System
- **Signature Validation**: Digital certificate verification and trust analysis
- **Behavioral Analysis**: API import analysis and entropy calculation
- **Machine Learning**: Threat scoring algorithm with confidence levels
- **Baseline Management**: Automated baseline creation and comparison
- **Approval Workflow**: Interactive review process for suspicious DLLs
- **Pattern Recognition**: Legitimate vs malicious DLL identification based on technical guide

### Enhanced Threat Detection
- **CVE-Specific Patterns**: Detection for CVE-2023-29357 and CVE-2023-33157
- **Threat Actor Tools**: Recognition of known attack tools and techniques
- **Correlation Analysis**: Multi-vector attack detection across time windows
- **Real-time Processing**: Incremental log reading with bookmarks
- **Custom Patterns**: Extensible threat pattern definitions
- **Timeline Analysis**: Event correlation within configurable time windows

### Configuration Management
- **Environment Support**: Development, Testing, Production configurations
- **Validation System**: Comprehensive configuration validation
- **Secure Storage**: Encrypted sensitive data handling
- **Backup/Restore**: Automatic configuration versioning
- **Template Generation**: Configuration template creation

### Comprehensive Reporting
- **HTML Reports**: Interactive reports with CSS styling and responsive design
- **Multiple Formats**: JSON, CSV, and future PDF export capabilities
- **Executive Summary**: Risk assessment and key findings for management
- **Technical Details**: Detailed analysis for security teams
- **Charts & Graphs**: Visual threat trends and analysis charts
- **Performance Metrics**: Execution time and system resource usage

## Technical Specifications

### Module Functions Summary

#### SecurityLogger.psm1
- `Initialize-SecurityLogger`: Set up logging system
- `Write-SecurityLog`: Write structured log entries
- `Get-SecurityLogs`: Retrieve filtered logs
- `Export-SecurityLogs`: Export logs in multiple formats
- `Close-SecurityLogger`: Cleanup logging resources

#### DLLAnalyzer.psm1
- `Start-DLLAnalysis`: Comprehensive DLL analysis
- `Analyze-DLLFile`: Individual file analysis
- `Create-DLLBaseline`: Baseline establishment
- `Review-PendingDLLs`: Interactive approval process

#### ThreatDetector.psm1
- `Start-ThreatDetection`: Multi-pattern threat analysis
- `Analyze-LogPath`: Process log directories
- `Analyze-LogFile`: Individual log file processing
- `Invoke-ThreatCorrelation`: Attack pattern correlation
- `Reset-LogBookmarks`: Clear processing bookmarks
- `Clear-EventCache`: Reset event cache

#### ConfigManager.psm1
- `Initialize-SecurityConfig`: Load and validate configuration
- `Import-SecurityConfig`: Import from JSON files
- `Export-SecurityConfig`: Save configuration with encryption
- `Test-SecurityConfig`: Validate configuration integrity
- `Get-ConfigValue`: Retrieve configuration values
- `Set-ConfigValue`: Update configuration values
- `New-ConfigTemplate`: Generate configuration templates
- `Backup-SecurityConfig`: Create configuration backups

#### ReportGenerator.psm1
- `New-SecurityReport`: Generate comprehensive reports
- `Prepare-ReportData`: Process and analyze results
- `New-HTMLReport`: Create interactive HTML reports

### Configuration Categories

1. **EmailSettings**: SMTP configuration and alert preferences
2. **ScanSettings**: Scanning parameters and performance tuning
3. **DLLAnalysisSettings**: DLL analysis behavior and thresholds
4. **ThreatDetectionSettings**: Threat pattern and correlation settings
5. **LoggingSettings**: Log level, format, and retention policies
6. **PerformanceSettings**: Memory limits and processing optimization
7. **SecuritySettings**: Encryption and privilege requirements
8. **ScheduledTaskSettings**: Automated execution configuration
9. **AlertingSettings**: Real-time alerting and escalation rules
10. **ReportingSettings**: Report generation and formatting options

## Deployment and Setup

### Prerequisites
- Windows PowerShell 5.1 or PowerShell Core 6.0+
- SharePoint 2019 or SharePoint Online environment
- Administrative privileges for full functionality
- SMTP server access for email alerts (optional)

### Installation Steps
1. Extract all files to a secure directory
2. Review and customize `SharePointSecurityConfig.json`
3. Run demonstration: `.\Demo-EnhancedScript.ps1 -CreateSampleData`
4. Create DLL baseline: `.\Enhanced-SharePoint-Security-Monitor.ps1 -CreateBaseline`
5. Install scheduled tasks: `.\Enhanced-SharePoint-Security-Monitor.ps1 -ManageTasks -TaskAction Install`
6. Perform initial scan: `.\Enhanced-SharePoint-Security-Monitor.ps1`

### Security Considerations
- Run with appropriate administrative privileges
- Store configuration files in secure locations
- Use encrypted storage for sensitive credentials
- Implement proper access controls on log files
- Regular backup of configuration and baseline data

## Configuration

Edit `SharePointSecurityConfig.json` to customize:
- Email settings (SMTP server, recipients)
- Scan parameters (time ranges, file size limits)
- Security thresholds and alert levels
- Performance optimization settings
- Threat detection patterns and correlation rules

## Email Configuration

The script is pre-configured to send alerts to:
- **Alert Email**: soc@goline.ch
- **SMTP Server**: exchange.goline.ch
- **From Email**: sharepoint-security@goline.ch

## Exit Codes

- **0**: No security issues detected
- **1**: Warnings detected
- **2**: Critical security issues detected
- **99**: Script execution error

## Benefits Achieved

### For Security Teams
- **Faster Analysis**: Modular design enables focused analysis of specific threats
- **Better Visibility**: Comprehensive reporting with visual charts and trends
- **Reduced False Positives**: ML-based scoring and behavioral analysis
- **Streamlined Workflow**: Automated approval processes and task management

### For System Administrators
- **Easier Maintenance**: Modular architecture simplifies updates and customization
- **Better Performance**: Optimized algorithms and caching reduce resource usage
- **Flexible Configuration**: Environment-specific settings and validation
- **Automated Operations**: Scheduled tasks and automated baseline management

### For Management
- **Executive Reporting**: Clear risk assessment and key findings summary
- **Compliance Support**: Detailed audit trails and comprehensive documentation
- **Cost Efficiency**: Reduced manual effort and faster incident response
- **Risk Visibility**: Real-time threat level assessment and trend analysis

## Version History

- **v4.0**: Modular architecture with specialized modules, ML-based threat scoring, and enhanced reporting
- **v3.9**: Enhanced DLL validation and pattern analysis (original comprehensive single-file script)
- **v3.8**: Auto-approval workflows and detailed attack reporting

## Future Enhancement Opportunities

1. **Machine Learning Integration**: Advanced ML models for threat prediction
2. **Cloud Integration**: Azure/Office 365 security center integration
3. **API Development**: REST API for integration with external systems
4. **Mobile Dashboard**: Mobile-friendly reporting interface
5. **Threat Intelligence Feeds**: Integration with commercial threat intelligence
6. **Automated Response**: Automated containment and remediation actions

## License

This project is designed for SharePoint security monitoring and threat detection.

## Support

For technical support and security incidents, contact: soc@goline.ch
