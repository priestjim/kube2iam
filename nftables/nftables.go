package nftables

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// AddRule adds the required rule to the host's nat table using nftables.
func AddRule(appPort, metadataAddress, hostInterface, hostIP string) error {

	if err := checkInterfaceExists(hostInterface); err != nil {
		return err
	}
	actualHostInterface := massageHostInterface(hostInterface)

	if hostIP == "" {
		return errors.New("--host-ip must be set")
	}

	// Check if nft command is available
	if _, err := exec.LookPath("nft"); err != nil {
		return fmt.Errorf("nft command not found: %w", err)
	}

	// Create table if it doesn't exist
	if err := runNftCommand("add", "table", "ip", "kube2iam"); err != nil {
		return fmt.Errorf("failed to create nftables table: %w", err)
	}

	// Create prerouting chain if it doesn't exist
	if err := runNftCommand("add", "chain", "ip", "kube2iam", "prerouting",
		"{", "type", "nat", "hook", "prerouting", "priority", "-100", ";", "}"); err != nil {
		return fmt.Errorf("failed to create prerouting chain: %w", err)
	}

	// Add the DNAT rule
	// nft add rule ip kube2iam prerouting ip daddr <metadataAddress> tcp dport 80 iifname <hostInterface> dnat to <hostIP>:<appPort>
	rule := fmt.Sprintf("ip daddr %s tcp dport 80 iifname %s dnat to %s:%s",
		metadataAddress, actualHostInterface, hostIP, appPort)

	// Check if rule already exists
	exists, err := ruleExists("kube2iam", "prerouting", rule)
	if err != nil {
		return fmt.Errorf("failed to check if rule exists: %w", err)
	}

	if !exists {
		if err := runNftCommand("add", "rule", "ip", "kube2iam", "prerouting", rule); err != nil {
			return fmt.Errorf("failed to add nftables rule: %w", err)
		}
	}

	return nil
}

// runNftCommand executes an nft command with the given arguments
func runNftCommand(args ...string) error {
	cmd := exec.Command("nft", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft command failed: %s (output: %s)", err, string(output))
	}
	return nil
}

// ruleExists checks if a rule already exists in the specified chain
func ruleExists(table, chain, rule string) (bool, error) {
	cmd := exec.Command("nft", "list", "chain", "ip", table, chain)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Chain might not exist yet
		if strings.Contains(string(output), "No such file or directory") ||
			strings.Contains(string(output), "does not exist") {
			return false, nil
		}
		return false, fmt.Errorf("failed to list chain: %w (output: %s)", err, string(output))
	}

	return strings.Contains(string(output), rule), nil
}

// massageHostInterface replaces + with * in the host interface, this is necessary because nftables does not support + in the interface name.
func massageHostInterface(hostInterface string) string {
	return strings.Replace(hostInterface, "+", "*", -1)
}

// checkInterfaceExists validates the interface passed exists for the given system.
// checkInterfaceExists ignores wildcard networks.
func checkInterfaceExists(hostInterface string) error {

	if strings.Contains(hostInterface, "+") {
		// wildcard networks ignored
		return nil
	}

	_, err := net.InterfaceByName(hostInterface)
	return err
}
