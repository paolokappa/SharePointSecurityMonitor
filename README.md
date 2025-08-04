# 🛡️ SharePoint Security Monitor v5.0

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://github.com/PowerShell/PowerShell)
[![SharePoint](https://img.shields.io/badge/SharePoint-2016%2F2019-green.svg)](https://www.microsoft.com/en-us/microsoft-365/sharepoint/collaboration)

> 🚀 A comprehensive PowerShell-based SharePoint security monitoring solution with CVE-2023-29357 and CVE-2023-33157 protection, intelligent DLL management, advanced threat detection, and automated alerting capabilities.

## 📋 Table of Contents

- [🌟 Project Overview](#-project-overview)
- [✨ Key Features](#-key-features)
- [🏗️ Solution Architecture](#-solution-architecture)
- [🚀 Quick Start Guide](#-quick-start-guide)
- [📁 File Structure](#-file-structure)
- [🆕 Key Enhancements](#-key-enhancements-over-original-v39)
- [⚙️ Technical Specifications](#-technical-specifications)
- [🔧 Deployment and Setup](#-deployment-and-setup)
- [📧 Email Configuration](#-email-configuration)
- [🎯 Benefits Achieved](#-benefits-achieved)
- [📅 Version History](#-version-history)
- [🔮 Future Enhancements](#-future-enhancements)
- [📄 License](#-license)
- [💬 Support](#-support)

## 🌟 Project Overview

The original 5,519-line PowerShell script has been successfully transformed into a **modular**, **high-performance** security monitoring solution that maintains the PowerShell ecosystem while adding significant enhancements. This enhanced solution successfully transforms the original monolithic PowerShell script into a modern, modular, and highly capable security monitoring platform.

## ✨ Key Features

### 🛡️ Security Features
- **🔍 CVE-Specific Protection**: Dedicated detection for CVE-2023-29357 and CVE-2023-33157
- **🧬 Intelligent DLL Management**: Auto-approval system with pending review queue
- **🎯 Real-time Threat Detection**: Advanced threat actor identification and tracking
- **📊 Comprehensive Attack Tracking**: Unified attack timeline with 20+ attack types
- **🔐 LSASS Memory Protection**: Detection of credential theft attempts
- **�️ Defender Tampering Detection**: Monitoring for security software disabling
- **📋 GPO Monitoring**: Detection of suspicious Group Policy modifications
- **🔄 Reflective DLL Injection Detection**: Advanced memory injection detection
- **🚨 Ransomware Detection**: Multiple ransomware family identification
- **🌐 C2 Communication Detection**: Known C2 domains and IPs monitoring

### 🏗️ Architecture Features
- **📦 Enhanced Architecture**: Single optimized script with modular functions
- **⚡ Performance Optimized**: Incremental log reading with smart bookmarks
- **🔄 Event Caching**: Efficient duplicate event filtering
- **💾 Smart Caching**: Daily cache files with automatic cleanup
- **📊 Baseline Management**: DLL and file integrity baseline systems
- **🔒 Multi-Layer Security**: ESET and Microsoft Defender compatibility

### 📢 Monitoring & Alerting
- **📧 Smart Email Alerting**: Configurable alerts with -NoAlertOnWarnings option
- **📈 Enhanced HTML Reports**: Comprehensive attack timeline and statistics
- **⚙️ Scheduled Task Management**: Automated hourly, daily, and startup scans
- **🔐 Detailed Attack Analysis**: IP-based threat actor identification
- **📊 Performance Metrics**: Execution time tracking and cache hit rates
- **🎯 Pending DLL Management**: Review and approval workflow for DLLs

## 🏗️ Solution Architecture

### 🔧 Core Components

#### 1️⃣ **SharePoint-Security-Monitor.ps1** (Main Script)
- 🎯 Modular entry point with comprehensive parameter support
- 🛡️ Error handling and recovery mechanisms
- 📊 Progress reporting and execution time tracking
- ⚡ Support for quick scans, baseline creation, and task management

#### 2️⃣ **Core Functionality** (Integrated Functions)
- 📝 **Advanced Logging**: Performance tracking with timer functions
- 🔬 **DLL Analysis**: Intelligent Test-SuspiciousDLL with auto-approval
- 🎯 **Threat Detection**: Real-time pattern matching and correlation
- ⚙️ **Configuration**: JSON-based configuration with secure handling
- 📊 **Report Generation**: Comprehensive HTML reports with attack timeline

#### 3️⃣ **Configuration System**
- 📋 **SharePointSecurityConfig.json**: Production-ready configuration
- 🌍 Environment-specific overrides (Development, Testing, Production)
- 🔐 Secure credential handling with encryption support

#### 4️⃣ **Demonstration and Setup**
- 🎮 **Demo-EnhancedScript.ps1**: Interactive demonstration script
- 📊 Sample data structure creation
- ✅ Module verification and testing capabilities

## 🚀 Quick Start Guide

### 📌 Basic Usage
```powershell
# Standard security scan with email on alerts/warnings
.\SharePoint-Security-Monitor.ps1

# Standard scan with custom max days
.\SharePoint-Security-Monitor.ps1 -MaxDaysToScan 7
```

### 🎯 Common Operations
```powershell
# ⚡ Quick scan (last 12 hours)
.\SharePoint-Security-Monitor.ps1 -QuickScan

# 📐 Create DLL baseline
.\SharePoint-Security-Monitor.ps1 -CreateBaseline

# 👁️ Review and approve pending DLLs
.\SharePoint-Security-Monitor.ps1 -ReviewPendingDLLs

# 🤖 Auto-approve legitimate DLLs
.\SharePoint-Security-Monitor.ps1 -AutoApproveDLLs

# 🔍 Check SharePoint file integrity
.\SharePoint-Security-Monitor.ps1 -CheckIntegrity

# 📧 Force email alert
.\SharePoint-Security-Monitor.ps1 -ForceAlert

# 📊 Always send report regardless of findings
.\SharePoint-Security-Monitor.ps1 -AlwaysSendReport

# 🔕 Only alert on critical issues (not warnings)
.\SharePoint-Security-Monitor.ps1 -NoAlertOnWarnings

# 🗓️ Full historical scan (30 days)
.\SharePoint-Security-Monitor.ps1 -FullHistoricalScan

# 🔄 Reset log reading bookmarks
.\SharePoint-Security-Monitor.ps1 -ResetBookmarks

# 🗑️ Clear event cache
.\SharePoint-Security-Monitor.ps1 -ClearCache

# ⚙️ Manage scheduled tasks
.\SharePoint-Security-Monitor.ps1 -ManageTasks -TaskAction Install
.\SharePoint-Security-Monitor.ps1 -ManageTasks -TaskAction Status
.\SharePoint-Security-Monitor.ps1 -ManageTasks -TaskAction Remove

# 🚫 Disable event caching for debugging
.\SharePoint-Security-Monitor.ps1 -DisableEventCache

# 📏 Process larger log files (default 250MB)
.\SharePoint-Security-Monitor.ps1 -MaxLogSizeMB 500

# ✅ Auto-approve legitimate DLLs
.\SharePoint-Security-Monitor.ps1 -AutoApproveDLLs
```

### 📅 Task Management
```powershell
# 📥 Install scheduled tasks
.\SharePoint-Security-Monitor.ps1 -ManageTasks -TaskAction Install

# 📊 Check task status
.\SharePoint-Security-Monitor.ps1 -ManageTasks -TaskAction Status

# 🗑️ Remove scheduled tasks
.\SharePoint-Security-Monitor.ps1 -ManageTasks -TaskAction Remove
```

### 🔬 Advanced Features
```powershell
# 🔍 Verbose DLL analysis with auto-approval
.\SharePoint-Security-Monitor.ps1 -VerboseDLL -AutoApproveDLLs

# 🧹 Clear caches and reset bookmarks
.\SharePoint-Security-Monitor.ps1 -ClearCache -ResetBookmarks
```

## 📁 File Structure

```
📂 SharePoint Security Monitor/
├── 📄 SharePoint-Security-Monitor.ps1              # Main monitoring script
├── 🎮 Demo-EnhancedScript.ps1                     # Demonstration script
├── ⚙️  SharePointSecurityConfig.json               # Configuration file
├── 📋 README.md                                    # Documentation
├── 📄 changelog-file.md                            # Version history
└── 📋 contributing-guide.md                        # Contribution guidelines

📂 Runtime Directories (auto-created)
├── Logs/                                        # Security logs
│   └── SecurityMonitor_YYYYMMDD.log               # Daily log files
├── Reports/                                     # HTML reports
│   └── SecurityReport_YYYYMMDD_HHMMSS.html        # Timestamped reports
├── Baselines/                                   # Baseline data
│   ├── DLL_Baseline.json                          # DLL inventory baseline
│   ├── SharePoint_Integrity.json                  # File integrity baseline
│   ├── PendingDLLApproval.json                   # DLLs awaiting approval
│   └── ApprovedDLLs.json                          # Whitelisted DLLs
├── Bookmarks/                                   # Log reading positions
│   └── LogReadingBookmarks.json                   # Incremental read tracking
└── Cache/                                       # Event processing cache
    └── ProcessedEvents_YYYYMMDD.json              # Daily event cache
```

## 🆕 What's New in Version 5.0

### 🛡️ Enhanced Security Detection
- **🔍 Real CVE Protection**: Updated to detect CVE-2023-29357 and CVE-2023-33157 (real vulnerabilities)
- **🎯 Advanced Threat Actor Tracking**: Identifies known APT groups and ransomware operators
- **🔐 Credential Theft Detection**: LSASS memory access monitoring with intelligent process filtering
- **🛡️ Security Software Monitoring**: Detects Microsoft Defender and GPO tampering
- **💉 Reflective DLL Injection Detection**: Monitors CreateRemoteThread events
- **🏷️ Comprehensive Attack Tracking**: Unified timeline of all security events

### 🧬 Intelligent DLL Management
- **🤖 Auto-Approval System**: Automatically approves legitimate Microsoft-signed DLLs
- **📋 Pending Review Queue**: DLLs requiring manual review are queued for approval
- **✅ SharePoint Component Recognition**: Smart detection of legitimate SharePoint ASP.NET components
- **🔍 Enhanced Filtering**: Reduced false positives with intelligent pattern matching
- **📊 Approval Workflow**: Interactive review process with hash-based tracking

### ⚡ Performance Optimizations
- **📚 Incremental Log Reading**: Bookmark system tracks last read position in logs
- **💾 Event Caching**: Daily cache files prevent duplicate event processing
- **� Smart Skip Logic**: Unchanged logs are automatically skipped
- **📊 Cache Hit Tracking**: Performance metrics show cache efficiency
- **🧹 Automatic Cleanup**: Old cache and log files are automatically removed

### 📊 Enhanced Reporting
- **📈 Attack Timeline**: Complete chronological view of all attacks
- **🎯 Attack Type Analysis**: Statistical breakdown by attack category
- **🌐 IP-Based Analysis**: Detailed attacker IP tracking and correlation
- **📊 Executive Dashboard**: At-a-glance security metrics
- **🔍 Detailed Drill-Down**: Comprehensive attack details with threat actor attribution

### 🔧 Operational Features
- **📅 Automated Task Management**: Built-in scheduled task installation and management
- **🔄 Flexible Scan Modes**: Quick (12h), Standard (configurable), Full Historical (30d)
- **📧 Smart Email Alerts**: Configurable alerting with -NoAlertOnWarnings option
- **🧪 ESET Compatibility**: Intelligent detection of ESET vs Microsoft Defender
- **🔒 Baseline Systems**: DLL baseline and SharePoint file integrity checking

## 🆕 Key Enhancements Over Original v3.9

### ⚡ Performance Improvements
- **📦 Optimized Design**: Enhanced 4,823-line script with modular functions
- **💾 Caching System**: Event caching and log bookmarks for incremental processing
- **🔄 Parallel Processing**: Multi-threaded analysis for large datasets
- **🧠 Memory Optimization**: Configurable memory limits and compression caching
- **📊 Progress Reporting**: Real-time feedback on long-running operations

### 🔬 Advanced DLL Analysis System
- **✍️ Signature Validation**: Digital certificate verification and trust analysis
- **🧬 Behavioral Analysis**: API import analysis and entropy calculation
- **🤖 Machine Learning**: Threat scoring algorithm with confidence levels
- **📐 Baseline Management**: Automated baseline creation and comparison
- **✅ Approval Workflow**: Interactive review process for suspicious DLLs
- **🎯 Pattern Recognition**: Legitimate vs malicious DLL identification

### 🛡️ Enhanced Threat Detection
- **🔍 CVE-Specific Patterns**: Detection for CVE-2025-53770 and bypass vulnerabilities
- **👤 Threat Actor Tools**: Recognition of known attack tools and techniques
- **🔗 Correlation Analysis**: Multi-vector attack detection across time windows
- **⚡ Real-time Processing**: Incremental log reading with bookmarks
- **🎨 Custom Patterns**: Extensible threat pattern definitions
- **⏰ Timeline Analysis**: Event correlation within configurable time windows

### ⚙️ Configuration Management
- **🌍 Environment Support**: Development, Testing, Production configurations
- **✅ Validation System**: Comprehensive configuration validation
- **🔐 Secure Storage**: Encrypted sensitive data handling
- **💾 Backup/Restore**: Automatic configuration versioning
- **📋 Template Generation**: Configuration template creation

### 📊 Comprehensive Reporting
- **🌐 HTML Reports**: Interactive reports with CSS styling and responsive design
- **📄 Multiple Formats**: JSON, CSV, and future PDF export capabilities
- **👔 Executive Summary**: Risk assessment and key findings for management
- **🔧 Technical Details**: Detailed analysis for security teams
- **📈 Charts & Graphs**: Visual threat trends and analysis charts
- **⚡ Performance Metrics**: Execution time and system resource usage

## ⚙️ Technical Specifications

### 📦 Module Functions Summary

#### 📝 SecurityLogger.psm1
- `Initialize-SecurityLogger`: Set up logging system
- `Write-SecurityLog`: Write structured log entries
- `Get-SecurityLogs`: Retrieve filtered logs
- `Export-SecurityLogs`: Export logs in multiple formats
- `Close-SecurityLogger`: Cleanup logging resources

#### 🔬 DLLAnalyzer.psm1
- `Start-DLLAnalysis`: Comprehensive DLL analysis
- `Analyze-DLLFile`: Individual file analysis
- `Create-DLLBaseline`: Baseline establishment
- `Review-PendingDLLs`: Interactive approval process

#### 🎯 ThreatDetector.psm1
- `Start-ThreatDetection`: Multi-pattern threat analysis
- `Analyze-LogPath`: Process log directories
- `Analyze-LogFile`: Individual log file processing
- `Invoke-ThreatCorrelation`: Attack pattern correlation
- `Reset-LogBookmarks`: Clear processing bookmarks
- `Clear-EventCache`: Reset event cache

#### ⚙️ ConfigManager.psm1
- `Initialize-SecurityConfig`: Load and validate configuration
- `Import-SecurityConfig`: Import from JSON files
- `Export-SecurityConfig`: Save configuration with encryption
- `Test-SecurityConfig`: Validate configuration integrity
- `Get-ConfigValue`: Retrieve configuration values
- `Set-ConfigValue`: Update configuration values
- `New-ConfigTemplate`: Generate configuration templates
- `Backup-SecurityConfig`: Create configuration backups

#### 📊 ReportGenerator.psm1
- `New-SecurityReport`: Generate comprehensive reports
- `Prepare-ReportData`: Process and analyze results
- `New-HTMLReport`: Create interactive HTML reports

### ⚙️ Configuration Categories

1. **📧 EmailSettings**: SMTP configuration and alert preferences
2. **🔍 ScanSettings**: Scanning parameters and performance tuning
3. **🔬 DLLAnalysisSettings**: DLL analysis behavior and thresholds
4. **🎯 ThreatDetectionSettings**: Threat pattern and correlation settings
5. **📝 LoggingSettings**: Log level, format, and retention policies
6. **⚡ PerformanceSettings**: Memory limits and processing optimization
7. **🔐 SecuritySettings**: Encryption and privilege requirements
8. **📅 ScheduledTaskSettings**: Automated execution configuration
9. **🚨 AlertingSettings**: Real-time alerting and escalation rules
10. **📊 ReportingSettings**: Report generation and formatting options

## 🔧 Deployment and Setup

### 📋 Prerequisites
- ✅ Windows PowerShell 5.1 or PowerShell Core 6.0+
- ✅ SharePoint 2019 or SharePoint Online environment
- ✅ Administrative privileges for full functionality
- ✅ SMTP server access for email alerts (optional)

### 📥 Installation Steps
1. 📂 Extract all files to a secure directory
2. ⚙️ Review and customize `SharePointSecurityConfig.json`
3. 🎮 Run demonstration: `.\Demo-EnhancedScript.ps1 -CreateSampleData`
4. 📐 Create DLL baseline: `.\SharePoint-Security-Monitor.ps1 -CreateBaseline`
5. 📅 Install scheduled tasks: `.\SharePoint-Security-Monitor.ps1 -ManageTasks -TaskAction Install`
6. 🔍 Perform initial scan: `.\SharePoint-Security-Monitor.ps1`

### 🔐 Security Considerations
- 👤 Run with appropriate administrative privileges
- 🔒 Store configuration files in secure locations
- 🔐 Use encrypted storage for sensitive credentials
- 🛡️ Implement proper access controls on log files
- 💾 Regular backup of configuration and baseline data

## ⚙️ Configuration

Edit `SharePointSecurityConfig.json` to customize:
- 📧 Email settings (SMTP server, recipients)
- 🔍 Scan parameters (time ranges, file size limits)
- 🎯 Security thresholds and alert levels
- ⚡ Performance optimization settings
- 🛡️ Threat detection patterns and correlation rules

## 📧 Email Configuration

The script is pre-configured to send alerts to:
- **📬 Alert Email**: soc@goline.ch
- **📮 SMTP Server**: exchange.goline.ch
- **📤 From Email**: sharepoint-security@goline.ch

## 🚪 Exit Codes

- **✅ 0**: No security issues detected
- **⚠️ 1**: Warnings detected
- **🚨 2**: Critical security issues detected
- **❌ 99**: Script execution error

## 🎯 Benefits Achieved

### 👥 For Security Teams
- **⚡ Faster Analysis**: Modular design enables focused analysis of specific threats
- **👁️ Better Visibility**: Comprehensive reporting with visual charts and trends
- **🎯 Reduced False Positives**: ML-based scoring and behavioral analysis
- **🔄 Streamlined Workflow**: Automated approval processes and task management

### 🔧 For System Administrators
- **🛠️ Easier Maintenance**: Modular architecture simplifies updates and customization
- **⚡ Better Performance**: Optimized algorithms and caching reduce resource usage
- **⚙️ Flexible Configuration**: Environment-specific settings and validation
- **🤖 Automated Operations**: Scheduled tasks and automated baseline management

### 👔 For Management
- **📊 Executive Reporting**: Clear risk assessment and key findings summary
- **✅ Compliance Support**: Detailed audit trails and comprehensive documentation
- **💰 Cost Efficiency**: Reduced manual effort and faster incident response
- **📈 Risk Visibility**: Real-time threat level assessment and trend analysis

## 📅 Version History

- **🆕 v4.0**: Modular architecture with specialized modules, ML-based threat scoring, and enhanced reporting
- **📦 v3.9**: Enhanced DLL validation and pattern analysis (original comprehensive single-file script)
- **🔄 v3.8**: Auto-approval workflows and detailed attack reporting

## 🔮 Future Enhancement Opportunities

1. **🤖 Machine Learning Integration**: Advanced ML models for threat prediction
2. **☁️ Cloud Integration**: Azure/Office 365 security center integration
3. **🔌 API Development**: REST API for integration with external systems
4. **📱 Mobile Dashboard**: Mobile-friendly reporting interface
5. **🌐 Threat Intelligence Feeds**: Integration with commercial threat intelligence
6. **🤖 Automated Response**: Automated containment and remediation actions

## 📄 License

This project is designed for SharePoint security monitoring and threat detection.

## 💬 Support

For technical support and security incidents, contact: **soc@goline.ch**

---

<div align="center">

**🛡️ Protecting SharePoint Environments Since 2024 🛡️**

Made with ❤️ by the Security Operations Center

</div>

</div>
