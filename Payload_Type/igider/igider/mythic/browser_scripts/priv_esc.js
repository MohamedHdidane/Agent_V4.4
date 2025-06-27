function(task, responses) {
    // Initialize output and state
    let output = "";
    const linuxChecks = [
        "system_info", "sudo_privileges", "privileged_groups", "file_permissions",
        "suid_sgid_binaries", "capabilities", "kernel_version", "dirty_cow",
        "kernel_vulnerabilities", "cron_permissions", "environment_vars",
        "root_processes", "network_services", "world_writable", "ssh_keys",
        "docker_socket", "mounts"
    ];
    const windowsChecks = [
        "admin_check",
        "uac_status",
        "user_privileges",
        "dangerous_privileges",
        "privileged_groups",
        "unquoted_service_paths",
        "registry_permissions",
        "service_permissions",
        "windows_version",
        "windows_version_detailed",
        "scheduled_tasks",
        "network_shares",
        "listening_ports",
        "vulnerable_software",
        "total_installed_software",
        "total_services",
        "writable_drive_root",
        "writable_task_folder",
        "writable_registry_keys",
        "writable_autorun_locations",
        "writable_path_directories",
        "writable_interesting_locations",
        "firewall_status",
        "accessible_drives",
        "high_privilege_tasks",
        "writable_program_files",
        "services",
        "autorun_locations",
        "dll_hijacking",
        "network_configuration",
        "installed_software"

    ];

    let progressDisplayed = false;

    // Handle error state
    if (task.status.includes("error")) {
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return { plaintext: `Task error: ${combined}` };
    }

    // Determine platform
    let platform = "unknown";
    let relevantChecks = [...new Set([...linuxChecks, ...windowsChecks])];

    // Try to infer platform from responses
    if (responses && responses.length > 0) {
        try {
            const data = JSON.parse(responses[0]);
            if (data.results) {
                for (const result of data.results) {
                    if (result.check === "kernel_version" && result.result.includes("Kernel version")) {
                        platform = "linux";
                        break;
                    } else if (result.check === "windows_version") {
                        platform = "windows";
                        break;
                    }
                }
            }
        } catch (error) {
            // If parsing fails, continue with unknown platform
        }
    }

    // Set relevant checks based on platform
    if (platform === "linux") {
        relevantChecks = linuxChecks;
    } else if (platform === "windows") {
        relevantChecks = windowsChecks;
    }

    // Handle pending state
    if (!task.completed) {
        output = "Starting privilege escalation enumeration...\n";
        if (platform === "unknown") {
            output += "  Detecting platform...\n";
        } else {
            for (const check of relevantChecks) {
                output += `  Checking ${check.replace(/_/g, ' ')}...\n`;
            }
        }
        return { plaintext: output };
    }


    // Handle completed state
    try {
        // Parse JSON response
        const data = JSON.parse(responses[0]);
        if (data.status !== "completed" || !data.results) {
            throw new Error("Invalid response format");
        }

        // Extract system metadata
        let targetUser = "unknown";
        let system = "unknown";
        let isAdmin = "unknown";
        let latestTimestamp = null;

        for (const result of data.results) {
            // Extract user info
            if (result.check === "system_info") {
                const userMatch = result.result.match(/User: (\w+)/);
                if (userMatch) targetUser = userMatch[1];
            } else if (result.check === "admin_check") {
                targetUser = result.user || "unknown";
                isAdmin = result.result.includes("Administrator") ? "Yes" : "No";
            }
            // Extract system info
            if (result.check === "kernel_version" && result.result.includes("Kernel version")) {
                const kernelMatch = result.result.match(/Kernel\s*version:\s*([\w\.\-]+)/i);
                if (kernelMatch) system = `Linux ${kernelMatch[1]}`;
            } else if (result.check === "windows_version") {
                const versionMatch = result.result.match(/Windows\s*version:\s*([\w\s\-\.]+)/i);
                if (versionMatch) system = versionMatch[1];
            }
            // Update latest timestamp
            if (result.timestamp) {
                try {
                    const timestamp = new Date(result.timestamp);
                    if (!latestTimestamp || timestamp > new Date(latestTimestamp)) {
                        latestTimestamp = result.timestamp;
                    }
                } catch (error) {
                    // Skip invalid timestamps
                    continue;
                }
            }
        }

        // Get performed checks
        const performedChecks = [...new Set(data.results.map(r => r.check))].filter(check => relevantChecks.includes(check));

        // Group findings by severity
        const severityGroups = {
            critical: [],
            high: [],
            medium: [],
            low: [],
            info: [],
            error: []
        };

        for (const result of data.results) {
            if (result.severity && result.check && relevantChecks.includes(result.check)) {
                severityGroups[result.severity.toLowerCase()].push(result);
            }
        }

        // Build report
        output = "";
        output += "Starting privilege escalation enumeration...\n";
        for (const check of performedChecks) {
            output += `  Checking ${check.replace(/_/g, ' ')}... [DONE]\n`;
        }
        output += "=".repeat(80) + "\n";
        output += "PRIVILEGE ESCALATION REPORT\n";
        output += "=".repeat(80) + "\n";
        output += `Scan Date: ${latestTimestamp || "unknown"}`;
        output += `\nTarget User: ${targetUser}\n`;
        output += `System: ${system}\n`;
        if (isAdmin !== "unknown") {
            output += `Administrator: ${isAdmin}\n`;
        }
        output += "=".repeat(80) + "\n\n";

        // Display findings by severity
        const severityOrder = ["critical", "high", "medium", "low", "info", "error"];
        const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0, error: 0 };
        let totalFindings = 0;

        for (const severity of severityOrder) {
            const findings = severityGroups[severity];
            if (findings.length > 0) {
                severityCounts[severity] = findings.length;
                totalFindings += findings.length;
                output += `[${severity.toUpperCase()}] FINDINGS (${findings.length}):\n`;
                output += "-".repeat(50) + "\n";
                for (const finding of findings) {
                    output += `Check: ${finding.check.replace(/_/g, ' ')}\n`;
                    output += `Result: ${finding.result}\n`;
                    output += `Time: ${finding.timestamp}\n\n`;
                }
            }
        }

        // Summary
        output += "=".repeat(80) + "\n";
        output += "SUMMARY:\n";
        output += `Total findings: ${totalFindings}\n`;
        for (const severity of severityOrder) {
            if (severityCounts[severity] > 0) {
                output += `${severity.charAt(0).toUpperCase() + severity.slice(1)}: ${severityCounts[severity]}\n`;
            }
        }

        return { plaintext: output };
    } catch (error) {
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return { plaintext: `Error processing response: ${error.message}\n${combined}` };
    }
}