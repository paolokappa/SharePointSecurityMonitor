# SharePoint Security Monitor

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://github.com/PowerShell/PowerShell)
[![SharePoint](https://img.shields.io/badge/SharePoint-2016%2F2019-green.svg)](https://www.microsoft.com/en-us/microsoft-365/sharepoint/collaboration)

A comprehensive security monitoring solution for SharePoint Server with specific protection against CVE-2025-53770 and other threats. Features unified HTML reporting, automated threat detection, and real-time email alerts.

## 🚀 Features

### Core Security Monitoring
- **CVE-2025-53770 Protection**: Specific detection patterns for known exploit attempts
- **Webshell Detection**: 15+ signature patterns for common webshells
- **File Integrity Monitoring**: Baseline comparison and change detection
- **Failed Login Analysis**: Tracks and alerts on suspicious authentication attempts
- **Process Monitoring**: Detects suspicious processes (mimikatz, psexec, etc.)
- **Service Monitoring**: Identifies potentially malicious services
- **Network Analysis**: Monitors external connections and known malicious IPs

### Reporting & Alerts
- **Unified HTML Reports**: Single comprehensive email with visual dashboard
- **Real-time Alerts**: Immediate notifications for critical security events
- **Daily Summaries**: Scheduled reports at 8 AM with system status
- **Local Report Storage**: All reports saved as HTML for audit trail

### Management Features
- **Baseline System**: Creates and maintains security baselines
- **Management Console**: Simple PowerShell interface for administration
- **Scheduled Tasks**: Automated hourly monitoring and daily reports
- **Email Testing**: Built-in email configuration verification

## 📋 Requirements

- Windows Server 2012 R2 or later
- SharePoint Server 2016/2019
- PowerShell 5.1 or later
- SMTP server for email alerts
- Administrative privileges

## 🔧 Installation

### Quick Install

1. Download the repository to your SharePoint server
2. Open PowerShell as Administrator
3. Navigate to the installation directory
4. Run:

```powershell
.\Install-SharePointSecurityMonitor.ps1
```

### Manual Install

1. Clone the repository:
```bash
git clone https://github.com/paolokappa/SharePointSecurityMonitor.git
```

2. Copy to your SharePoint server at `C:\GOLINE`

3. Run the installation script:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
.\Install-SharePointSecurityMonitor.ps1
```

### Configuration

During installation, you'll be prompted for:
- **Email recipient**: Default `soc@yourdomain.com`
- **SMTP server**: Default `smtp.yourdomain.com`
- **From address**: Default `sharepoint-security@yourdomain.com`

Or provide parameters:
```powershell
.\Install-SharePointSecurityMonitor.ps1 -AlertEmail "security@company.com" -SMTPServer "mail.company.com"
```

## 📖 Usage

### Management Console

The management console provides easy access to all features:

```powershell
# Check monitoring status
.\Manage-Monitoring.ps1 -Action Status

# Run immediate security scan with forced alert
.\Manage-Monitoring.ps1 -Action Test

# Test email configuration
.\Manage-Monitoring.ps1 -Action Email

# Reinitialize security baseline
.\Manage-Monitoring.ps1 -Action Baseline

# View recent alerts from logs
.\Manage-Monitoring.ps1 -Action Logs

# Open latest HTML report
.\Manage-Monitoring.ps1 -Action Report
```

### Manual Monitoring

Run a manual security scan:
```powershell
.\SharePoint-Monitor.ps1
```

Force an alert email (for testing):
```powershell
.\SharePoint-Monitor.ps1 -ForceAlert
```

Send daily summary immediately:
```powershell
.\SharePoint-Monitor.ps1 -SendDailySummary
```

## 📊 Report Structure

The unified HTML report includes:

### Executive Summary
- Critical alerts count
- Warnings count
- System status (SECURE/WARNING/CRITICAL)

### Security Metrics Dashboard
- Webshells found
- Exploit attempts
- Failed logins
- New web files
- Modified files
- Suspicious processes/services

### System Health
- CPU usage
- Memory usage
- Disk space
- Performance metrics

### Detailed Findings
- Alert details with timestamps
- Warning descriptions
- CVE-2025-53770 specific analysis
- Recommendations

## 🗂️ File Structure

```
C:\GOLINE\
├── SharePoint-Monitor.ps1           # Main monitoring script
├── Install-SharePointSecurityMonitor.ps1  # Installation script
├── Initialize-Baseline.ps1          # Baseline creation script
├── Test-Email.ps1                   # Email testing utility
├── Manage-Monitoring.ps1            # Management console
└── SharePoint_Monitoring\
    ├── Logs\                        # Daily log files
    ├── Reports\                     # HTML reports
    └── Baselines\                   # Security baselines
```

## ⚙️ Scheduled Tasks

The installer creates two scheduled tasks:

1. **SharePoint Security Monitor**
   - Runs every hour
   - Performs full security scan
   - Sends alerts if threats detected

2. **SharePoint Daily Security Report**
   - Runs daily at 8:00 AM
   - Sends comprehensive summary
   - Includes all events from past 24 hours

## 🔍 Detection Patterns

### CVE-2025-53770 Specific
- Upload exploit attempts in IIS logs
- Malformed ASPX requests
- ViewState manipulation attempts
- Path traversal patterns

### Webshell Signatures
- Code evaluation functions
- Base64 encoding/decoding
- Process execution methods
- Network operations
- File system manipulation
- Known webshell names

### Suspicious Processes
- nc, ncat, netcat
- mimikatz
- procdump
- psexec
- wmic
- certutil
- bitsadmin

## 📧 Email Alerts

### Alert Triggers
- Any webshell detection
- Failed logins > 5 per hour
- New ASPX/ASMX files created
- File modifications detected
- Suspicious processes running
- CVE exploit attempts

### Email Format
- HTML formatted with responsive design
- Color-coded status indicators
- Detailed tables for findings
- Direct links to affected resources
- Timestamp and server information

## 🛠️ Troubleshooting

### Email Not Sending
1. Test email configuration:
   ```powershell
   .\Test-Email.ps1
   ```
2. Check SMTP server connectivity
3. Verify sender address is authorized
4. Check spam filters

### Performance Issues
- Reduce scan frequency in scheduled task
- Limit paths in webshell detection
- Adjust log retention period

### False Positives
- Review and update baseline
- Adjust detection thresholds in script
- Add exclusions for known safe files

## 🔐 Security Considerations

- Run with minimum required privileges
- Secure the installation directory
- Regularly review and update baselines
- Monitor the monitoring system logs
- Keep detection patterns updated

## 📝 Configuration Options

Edit `SharePoint-Monitor.ps1` to customize:

```powershell
# Thresholds
$FailedLoginThreshold = 5    # Trigger alert after X failed logins

# Paths to monitor
$WebPaths = @(
    "C:\inetpub\wwwroot\wss\VirtualDirectories",
    "C:\custom\path"
)

# Known malicious IPs
$KnownBadIPs = @(
    "192.168.1.100",
    "10.0.0.50"
)
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

### Adding Detection Patterns

To add new webshell signatures:
```powershell
$WebshellSignatures = @{
    "your_pattern_regex" = "Pattern Description"
}
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- SharePoint security community
- OWASP for webshell research
- Microsoft Security Response Center

## 📞 Support

- Create an issue for bugs
- Submit PRs for enhancements
- Check wiki for documentation

## ⚡ Quick Start Guide

1. **Install**: `.\Install-SharePointSecurityMonitor.ps1`
2. **Verify**: `.\Test-Email.ps1`
3. **Check Status**: `.\Manage-Monitoring.ps1 -Action Status`
4. **View Report**: `.\Manage-Monitoring.ps1 -Action Report`

---

**Note**: This tool is provided as-is for security monitoring purposes. Always test in a non-production environment first.
