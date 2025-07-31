# SharePoint Security Monitor

## Overview

A comprehensive PowerShell-based SharePoint security monitoring solution with CVE-2023-29357 and CVE-2023-33157 protection, DLL analysis, threat detection, and email alerting capabilities.

**Project Focus**: Pure PowerShell security monitoring solution (cleaned up - web files removed)

## User Preferences

- Preferred communication style: Simple, everyday language
- Project type: PowerShell scripts only (no web interface needed)
- Keep only essential files for server deployment

## Recent Changes

- **2025-07-31**: Removed unnecessary files (ENHANCED_SOLUTION_SUMMARY.md, attached_assets/) 
- **2025-07-31**: Merged ENHANCED_SOLUTION_SUMMARY.md into README.md for comprehensive documentation
- **2025-07-31**: Created complete technical documentation with all architectural details
- **2025-01-30**: Cleaned up project - removed all web development files
- **2025-01-30**: Kept only essential PowerShell components for server deployment
- **2025-01-30**: SharePoint-Security-Monitor.ps1 is the main working script (238KB, 5,519 lines)
- **2025-01-30**: Project now contains only PowerShell security monitoring components

## System Architecture

### PowerShell Solution Structure
- **Enhanced-SharePoint-Security-Monitor.ps1**: Main modular script (v4.0) with module system
- **SharePoint_Security_Monitoring.ps1**: Original comprehensive single-file script (v3.9)
- **Modules/**: 5 specialized PowerShell modules for different security functions
- **Configuration**: JSON-based configuration with environment-specific settings
- **Performance**: Caching, parallel processing, and memory optimization
- **Reporting**: HTML reports with charts and comprehensive security analysis

### Module Architecture
- **SecurityLogger**: Advanced logging with SIEM integration and structured output
- **DLLAnalyzer**: Comprehensive DLL analysis with behavioral detection
- **ThreatDetector**: Pattern matching and threat correlation analysis
- **ConfigManager**: Centralized configuration with environment support
- **ReportGenerator**: HTML reporting with charts and visualizations

## Key Components

### Enhanced DLL Analysis System
- **Signature Validation**: Digital signature verification and certificate analysis
- **Behavioral Analysis**: API import analysis and entropy calculation
- **Pattern Recognition**: Legitimate vs malicious DLL identification based on technical guide
- **Baseline Management**: Automated baseline creation and comparison
- **Approval Workflow**: Interactive review and approval process for suspicious DLLs
- **Machine Learning**: Threat scoring algorithm with confidence levels

### Advanced Threat Detection
- **CVE Pattern Detection**: Specific patterns for CVE-2023-29357 and CVE-2023-33157
- **Threat Actor Identification**: Known tool and technique detection
- **Correlation Analysis**: Multi-vector attack detection across time windows
- **Real-time Processing**: Incremental log reading with bookmarks and caching
- **Custom Patterns**: Extensible threat pattern definitions

### Configuration Management System
- **Environment-Specific**: Development, Testing, Production configurations
- **Secure Storage**: Encrypted sensitive data handling
- **Validation**: Comprehensive configuration validation and error reporting
- **Backup/Restore**: Automatic configuration backup and versioning

### Comprehensive Reporting
- **HTML Reports**: Interactive reports with CSS styling and responsive design
- **Multiple Formats**: JSON, CSV, and PDF export capabilities
- **Charts & Graphs**: Visual threat trends and analysis charts
- **Executive Summary**: Risk assessment and key findings for management
- **Technical Details**: Detailed analysis for security teams

## Data Flow

1. **Security Events**: Real-time events are captured and stored in the database
2. **DLL Analysis**: Files are analyzed and results stored with approval workflows
3. **Dashboard Metrics**: Aggregated data is calculated and displayed in real-time
4. **Reports**: Data is processed and formatted into structured reports
5. **Configuration**: Settings control system behavior and monitoring parameters

## External Dependencies

### Frontend Dependencies
- **UI Components**: Extensive Radix UI component library
- **Forms**: React Hook Form with Zod validation
- **Date Handling**: date-fns for date manipulation
- **Charts**: Recharts for data visualization
- **Styling**: Tailwind CSS with class variance authority

### Backend Dependencies
- **Database**: Drizzle ORM with PostgreSQL dialect
- **Validation**: Zod schemas for data validation
- **Sessions**: connect-pg-simple for PostgreSQL session storage
- **Development**: tsx for TypeScript execution

### Development Tools
- **Build**: Vite for frontend bundling, esbuild for backend bundling
- **Development**: Replit-specific plugins for enhanced development experience
- **Type Safety**: Comprehensive TypeScript configuration

## Deployment Strategy

### Build Process
1. **Frontend**: Vite builds the React application to `dist/public`
2. **Backend**: esbuild bundles the Express server to `dist/index.js`
3. **Database**: Drizzle migrations are applied via `drizzle-kit push`

### Production Setup
- **Server**: Node.js application serving both API and static files
- **Database**: PostgreSQL database (configured for Neon Database)
- **Environment**: Production mode with optimized builds
- **Static Assets**: Frontend served from Express server

### Development Workflow
- **Hot Reload**: Vite provides hot module replacement for frontend
- **Auto Restart**: tsx watches for backend changes
- **Database Sync**: Drizzle schema changes can be pushed directly
- **Integrated Development**: Single command starts both frontend and backend

The application is designed as a monorepo with shared TypeScript types and schemas, enabling type safety across the full stack. The architecture supports real-time security monitoring with a focus on SharePoint-specific threats and DLL analysis workflows.