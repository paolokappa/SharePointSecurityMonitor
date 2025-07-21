# Changelog

All notable changes to SharePoint Security Monitor will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2024-07-21

### Added
- Unified HTML email reporting with visual dashboard
- CVE-2025-53770 specific detection patterns
- Comprehensive webshell detection with 15+ signatures
- File integrity monitoring with baseline comparison
- Process and service monitoring for suspicious activity
- Network connection analysis with external IP tracking
- SharePoint-specific security configuration checks
- Management console for easy administration
- Automated baseline creation and updates
- Local HTML report storage for audit trails
- System health monitoring (CPU, Memory, Disk)
- Color-coded status indicators in reports
- Detailed recommendations based on findings

### Changed
- Replaced multiple alert emails with single unified report
- Improved detection accuracy with refined patterns
- Enhanced performance with optimized scanning
- Updated email templates with responsive HTML design
- Simplified installation process with parameter support

### Fixed
- Email delivery issues with alternative SMTP methods
- False positives in webshell detection
- Scheduled task creation errors
- Baseline comparison performance

## [1.5.0] - 2024-06-15

### Added
- Initial CVE-2025-53770 detection capabilities
- Basic webshell scanning
- Failed login monitoring
- Email alert system

### Changed
- Improved logging system
- Enhanced error handling

### Fixed
- PowerShell compatibility issues
- SMTP authentication problems

## [1.0.0] - 2024-05-01

### Added
- Initial release
- Basic security monitoring
- Scheduled task creation
- Email notifications
- Simple reporting

[2.0.0]: https://github.com/yourusername/sharepoint-security-monitor/compare/v1.5.0...v2.0.0
[1.5.0]: https://github.com/yourusername/sharepoint-security-monitor/compare/v1.0.0...v1.5.0
[1.0.0]: https://github.com/yourusername/sharepoint-security-monitor/releases/tag/v1.0.0