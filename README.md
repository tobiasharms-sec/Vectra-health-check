# Vectra Health Check Script

A comprehensive Python script for monitoring and reporting on the health status of Vectra AI platform deployments. This tool provides detailed insights into system performance, connector status, EDR configurations, and overall platform health.

## Features

- **System Information**: Uptime, version, serial number, and model details
- **External Connectors**: Status, authentication, and configuration details for all connectors
- **EDR Configuration**: Health and status of endpoint detection and response integrations
- **Network Brain Status**: Connection health and latency to Vectra's cloud services
- **System Resources**: Memory and CPU usage monitoring
- **Network Information**: Interface status, traffic statistics, and VLAN information
- **Disk Usage**: Filesystem utilization and RAID status
- **Detection Health**: Status of AI detection models
- **Vectra Match**: Status of threat intelligence matching capabilities
- **Metrics Summary**: Prioritized hosts, entities with detections, and lockdown status

## Requirements

- Python 3.6 or higher
- Required Python packages (install via `pip install -r requirements.txt`):
  - `requests`
  - `python-dotenv`
  - `colorama`
  - `tabulate` (optional, for better table formatting)

## Installation

1. Clone this repository:
```bash
git clone https://github.com/yourusername/vectra-health-check.git
cd vectra-health-check
```

2. Install required dependencies:
```bash
pip install -r requirements.txt
```

3. Create your credentials file:
```bash
cp cred.env.example cred.env
```

4. Edit `cred.env` with your Vectra platform credentials:
```env
CLIENT_ID=your_client_id_here
CLIENT_SECRET=your_client_secret_here
VECTRA_URL=https://your-vectra-instance.com/
```

## Usage

### Basic Usage

Run the health check with default settings:
```bash
python vectra-health-check.py
```

### Command Line Options

```bash
python vectra-health-check.py [OPTIONS]

Options:
  --host HOST           Vectra platform hostname or IP (overrides config file)
  --env-file FILE       Environment file with credentials (default: cred.env)
  --output FILE, -o FILE Output file to save the health check results
  --no-details          Skip detailed information for connectors and EDR
  --debug               Enable debug mode with verbose error messages
  --help, -h            Show help message
```

### Examples

1. **Basic health check**:
```bash
python vectra-health-check.py
```

2. **Save output to file**:
```bash
python vectra-health-check.py --output health-report.txt
```

3. **Quick check without detailed connector/EDR info**:
```bash
python vectra-health-check.py --no-details
```

4. **Override hostname from command line**:
```bash
python vectra-health-check.py --host vectra.example.com
```

5. **Debug mode for troubleshooting**:
```bash
python vectra-health-check.py --debug
```

## Configuration

### Environment Variables

Create a `cred.env` file in the same directory as the script with the following variables:

```env
# Vectra API Credentials
CLIENT_ID=your_oauth2_client_id
CLIENT_SECRET=your_oauth2_client_secret
VECTRA_URL=https://your-vectra-instance.com/

# Optional: Custom token file location
TOKEN_FILE=vectra_token.json
```

### OAuth2 Credentials

To obtain OAuth2 credentials for your Vectra platform:

1. Log in to your Vectra platform as an administrator
2. Navigate to **Settings** > **API Clients**
3. Create a new API client with appropriate permissions
4. Copy the Client ID and Client Secret to your `cred.env` file

### Required Permissions

The API client needs the following permissions:
- `health:read` - For system health information
- `entities:read` - For entity and detection counts
- `lockdown:read` - For lockdown status
- `vectra-match:read` - For Vectra Match status (if available)

## Output Format

The script generates a comprehensive report including:

```
================================================================================
VECTRA HEALTH CHECK REPORT - your-vectra-instance.com
Date: 2024-01-15 10:30:45
Data collection completed in 2.45 seconds
================================================================================

===== SYSTEM INFORMATION =====
Serial Number    ABC123456789
Model           X-Series Sensor
Version         8.5.2
Uptime          15 days, 3h 45m 22s
Last Update     2024-01-10

===== NETWORK BRAIN STATUS =====
Status          connected
Latency         12ms

===== EXTERNAL CONNECTORS =====
┌─────────────────┬─────────┬──────────────┬─────────────────────────────────┐
│ Connector       │ Status  │ Authentication│ Details                         │
├─────────────────┼─────────┼──────────────┼─────────────────────────────────┤
│ Active Directory│ enabled │ authenticated │ Domain: example.com             │
│ Splunk          │ enabled │ authenticated │ Index: vectra_logs              │
└─────────────────┴─────────┴──────────────┴─────────────────────────────────┘

[Additional sections...]
```

## Authentication

The script uses OAuth2 authentication with automatic token management:

- Tokens are automatically cached in `vectra_token.json`
- Expired tokens are automatically refreshed
- Refresh tokens are used when available to minimize API calls

## Error Handling

The script includes comprehensive error handling:

- Network connectivity issues
- Authentication failures
- API endpoint unavailability
- Malformed responses
- Permission errors

Use the `--debug` flag for detailed error information during troubleshooting.

## Modules

### `vectra-health-check.py`
Main script that orchestrates the health check process and generates the report.

### `vectra_auth.py`
Authentication module that handles OAuth2 token management and API requests. This module can be imported by other scripts that need to interact with the Vectra API.

Key functions:
- `get_token()` - Obtain and manage OAuth2 tokens
- `make_api_request()` - Make authenticated API requests
- `load_config()` - Load configuration from environment files

## Troubleshooting

### Common Issues

1. **Authentication Failed**
   - Verify your CLIENT_ID and CLIENT_SECRET in `cred.env`
   - Ensure the API client has sufficient permissions
   - Check that the VECTRA_URL is correct and accessible

2. **SSL Certificate Errors**
   - The script disables SSL verification by default for self-signed certificates
   - For production use, consider implementing proper certificate validation

3. **Network Connectivity**
   - Ensure the Vectra platform is accessible from your network
   - Check firewall rules and proxy settings

4. **Missing Data Sections**
   - Some sections may not appear if the feature is not configured or available
   - Use `--debug` to see detailed error messages

### Debug Mode

Enable debug mode for verbose error messages:
```bash
python vectra-health-check.py --debug
```

This will show:
- Full stack traces for errors
- Detailed API response information
- Step-by-step execution flow

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is provided as-is for educational and operational purposes. Please ensure compliance with your organization's security policies and Vectra's terms of service.

## Author

**Tobias Harms**

## Support

For issues and questions:
- Check the [troubleshooting section](#troubleshooting)
- Review the Vectra API documentation

## Author

**Tobias Harms**

---

*This tool is not officially supported by Vectra AI. Use at your own risk and ensure compliance with your organization's security policies.*
