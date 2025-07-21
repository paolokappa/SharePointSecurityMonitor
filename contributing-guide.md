# Contributing to SharePoint Security Monitor

First off, thank you for considering contributing to SharePoint Security Monitor! It's people like you that make this tool better for everyone.

## Code of Conduct

This project and everyone participating in it is governed by our Code of Conduct. By participating, you are expected to uphold this code.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues as you might find out that you don't need to create one. When you are creating a bug report, please include as many details as possible:

* **Use a clear and descriptive title**
* **Describe the exact steps to reproduce the problem**
* **Provide specific examples to demonstrate the steps**
* **Describe the behavior you observed and expected**
* **Include logs and screenshots if possible**
* **Include your environment details**:
  - SharePoint version
  - Windows Server version
  - PowerShell version
  - Email server type

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, please include:

* **Use a clear and descriptive title**
* **Provide a detailed description of the proposed enhancement**
* **Explain why this enhancement would be useful**
* **List any alternative solutions you've considered**

### Pull Requests

1. Fork the repo and create your branch from `main`
2. If you've added code that should be tested, add tests
3. Ensure your code follows the existing style
4. Make sure your code lints
5. Issue that pull request!

## Adding New Detection Patterns

### Webshell Signatures

To add a new webshell signature:

1. Edit `SharePoint-Monitor.ps1`
2. Find the `$WebshellSignatures` hashtable
3. Add your pattern:

```powershell
$WebshellSignatures = @{
    # ... existing patterns ...
    "your_regex_pattern" = "Description of what this detects"
}
```

### CVE Detection Patterns

For new CVE-specific patterns:

1. Add to the `$ExploitPatterns` array
2. Document the CVE number and description
3. Include example log entries if possible

### Testing Your Patterns

1. Create a test file with the malicious pattern
2. Run the monitor in test mode
3. Verify detection and no false positives
4. Clean up test files

## Development Setup

1. Clone the repository
```bash
git clone https://github.com/yourusername/sharepoint-security-monitor.git
cd sharepoint-security-monitor
```

2. Create a test environment
```powershell
# Create test directory structure
New-Item -ItemType Directory -Path "C:\TestSharePoint" -Force
```

3. Run tests
```powershell
# Run with test configuration
.\Install-SharePointSecurityMonitor.ps1 -InstallPath "C:\TestSharePoint" -SkipEmailTest
```

## Style Guide

### PowerShell Style

* Use PascalCase for function names
* Use camelCase for variable names
* Always include comment-based help for functions
* Use proper indentation (4 spaces)
* Include error handling with try/catch blocks

Example:
```powershell
function Get-SecurityStatus {
    <#
    .SYNOPSIS
        Gets the current security status
    
    .DESCRIPTION
        Detailed description here
    
    .PARAMETER ComputerName
        The computer to check
    
    .EXAMPLE
        Get-SecurityStatus -ComputerName "SERVER01"
    #>
    param(
        [string]$ComputerName = $env:COMPUTERNAME
    )
    
    try {
        # Your code here
    }
    catch {
        Write-Error "Failed to get security status: $_"
    }
}
```

### Commit Messages

* Use the present tense ("Add feature" not "Added feature")
* Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
* Limit the first line to 72 characters or less
* Reference issues and pull requests liberally after the first line

### Documentation

* Update README.md with any new features
* Update CHANGELOG.md following [Keep a Changelog](https://keepachangelog.com/)
* Include inline comments for complex logic
* Update help documentation in scripts

## Testing

### Manual Testing

1. Install in a test environment
2. Create test conditions (failed logins, new files, etc.)
3. Verify alerts are sent correctly
4. Check for false positives
5. Test all management commands

### Automated Testing

We're working on automated tests. If you'd like to help, please let us know!

## Releasing

1. Update version in all scripts
2. Update CHANGELOG.md
3. Create a pull request
4. After merge, create a release on GitHub
5. Upload release artifacts

## Recognition

Contributors will be recognized in:
* The README.md file
* Release notes
* Annual contributor spotlight (if applicable)

## Questions?

Feel free to open an issue with the label "question" if you have any questions about contributing.

Thank you for contributing! 🎉