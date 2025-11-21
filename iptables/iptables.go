package iptables

import (
	"errors"
	"net"
	"strings"

	"github.com/coreos/go-iptables/iptables"
)

// AddRule adds the required rule to the host's nat table.
func AddRule(appPort, metadataAddress, hostInterface, hostIP string) error {

	if err := checkInterfaceExists(hostInterface); err != nil {
		return err
	}

	if hostIP == "" {
		return errors.New("--host-ip must be set")
	}

	ipt, err := iptables.New()
	if err != nil {
		return err
	}

	return ipt.AppendUnique(
		"nat", "PREROUTING", "-p", "tcp", "-d", metadataAddress, "--dport", "80",
		"-j", "DNAT", "--to-destination", hostIP+":"+appPort, "-i", hostInterface,
	)
}

// RemoveRule removes the iptables rule added by kube2iam.
func RemoveRule(appPort, metadataAddress, hostInterface, hostIP string) error {
	if err := checkInterfaceExists(hostInterface); err != nil {
		return err
	}

	if hostIP == "" {
		return errors.New("--host-ip must be set")
	}

	ipt, err := iptables.New()
	if err != nil {
		return err
	}

	// Try to delete the rule. If it doesn't exist, iptables will return an error
	// but we can safely ignore it during cleanup
	err = ipt.Delete(
		"nat", "PREROUTING", "-p", "tcp", "-d", metadataAddress, "--dport", "80",
		"-j", "DNAT", "--to-destination", hostIP+":"+appPort, "-i", hostInterface,
	)

	if err != nil {
		// Check if the error is because the rule doesn't exist
		exists, checkErr := ipt.Exists(
			"nat", "PREROUTING", "-p", "tcp", "-d", metadataAddress, "--dport", "80",
			"-j", "DNAT", "--to-destination", hostIP+":"+appPort, "-i", hostInterface,
		)
		if checkErr != nil {
			return checkErr
		}
		if !exists {
			// Rule doesn't exist, nothing to clean up
			return nil
		}
		return err
	}

	return nil
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
