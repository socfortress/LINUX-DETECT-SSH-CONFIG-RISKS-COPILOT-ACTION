## Detect SSH Config Risks

This script scans for risky SSH configuration files, such as world-writable files or hidden `.ssh` files outside the `/home` directory, providing a JSON-formatted output for integration with security tools like OSSEC/Wazuh.

### Overview

The `Detect-SSHConfig-Risks` script identifies potential security risks in SSH configuration files by analyzing their permissions and locations. It outputs results in a standardized JSON format suitable for active response workflows.

### Script Details

#### Core Features

1. **World-Writable File Detection**: Identifies SSH configuration files (`config`, `authorized_keys`) with world-writable permissions.
2. **Hidden File Detection**: Detects `.ssh` files located outside the `/home` directory.
3. **JSON Output**: Generates a structured JSON report for integration with security tools.
4. **Logging Framework**: Provides detailed logs for script execution and findings.
5. **Log Rotation**: Implements automatic log rotation to manage log file size.

### How the Script Works

#### Command Line Execution
```bash
./Detect-SSHConfig-Risks
```

#### Parameters

| Parameter | Type | Default Value | Description |
|-----------|------|---------------|-------------|
| `LOG`     | string | `/var/ossec/active-response/active-responses.log` | Path for active response JSON output |
| `LogPath` | string | `/tmp/Detect-SSHConfig-Risks.log` | Path for detailed execution logs |
| `LogMaxKB` | int | 100 | Maximum log file size in KB before rotation |
| `LogKeep` | int | 5 | Number of rotated log files to retain |

#### Example Invocation

```bash
# Run the script
./Detect-SSHConfig-Risks
```

### Script Execution Flow

#### 1. Initialization Phase
- Clears the active response log file.
- Rotates the detailed log file if it exceeds the size limit.
- Logs the start of the script execution.

#### 2. Risk Detection
- **World-Writable File Check**: Scans `/home/*/.ssh/` for files with world-writable permissions.
- **Hidden File Check**: Scans the entire filesystem for `.ssh` files outside `/home`.

#### 3. JSON Output Generation
- Formats findings into a JSON array.
- Writes the JSON result to the active response log.

#### 4. Completion Phase
- Logs the duration of the script execution.
- Outputs the final JSON result.

### JSON Output Format

#### Risky Files Found
```json
{
  "timestamp": "2025-07-18T10:30:45.123Z",
  "host": "HOSTNAME",
  "action": "Detect-SSHConfig-Risks",
  "status": "risky",
  "reason": "Risky SSH config files found",
  "results": [
    {
      "path": "/home/user/.ssh/config",
      "issue": "world_writable"
    },
    {
      "path": "/etc/.ssh/authorized_keys",
      "issue": "hidden_outside_home"
    }
  ],
  "copilot_soar": true
}
```

#### No Risky Files Found
```json
{
  "timestamp": "2025-07-18T10:30:45.123Z",
  "host": "HOSTNAME",
  "action": "Detect-SSHConfig-Risks",
  "status": "ok",
  "reason": "No risky SSH config files found",
  "results": [],
  "copilot_soar": true
}
```

### Implementation Guidelines

#### Best Practices
- Run the script with appropriate permissions to access SSH configuration files.
- Validate the JSON output for compatibility with your security tools.
- Test the script in isolated environments before production use.

#### Security Considerations
- Ensure the script runs with minimal privileges.
- Validate all input paths to prevent injection attacks.
- Protect the active response log file from unauthorized access.

### Troubleshooting

#### Common Issues
1. **Permission Errors**: Ensure the script has read access to SSH configuration files.
2. **Empty Results**: Verify that the directories being scanned contain valid SSH configuration files.
3. **Log File Issues**: Check write permissions for the log paths.

#### Debugging
Enable verbose logging by reviewing the script's log output:
```bash
./Detect-SSHConfig-Risks
```

### Contributing

When modifying this script:
1. Maintain the core logging, JSON output, and log rotation structure.
2. Follow Bash scripting best practices.
3. Document any additional functionality or parameters.
4. Test thoroughly in isolated environments.
