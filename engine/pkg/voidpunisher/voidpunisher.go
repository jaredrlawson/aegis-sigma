package voidpunisher

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/aegis-sigma/engine/internal/config"
)

func DeployIPTablesDrop(ip string) bool {
	if ip == "" || ip == "127.0.0.1" || ip == "::1" || strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "172.") {
		return false
	}

	result, _ := exec.Command("iptables", "-L", config.IptablesChain, "-n").CombinedOutput()
	if !strings.Contains(string(result), config.IptablesChain) {
		exec.Command("iptables", "-N", config.IptablesChain).Run()
		exec.Command("iptables", "-I", "INPUT", "1", "-j", config.IptablesChain).Run()
		exec.Command("iptables", "-I", "OUTPUT", "1", "-j", config.IptablesChain).Run()
	}

	if strings.Contains(string(result), ip) {
		return true
	}

	exec.Command("iptables", "-A", config.IptablesChain, "-s", ip, "-j", "DROP").Run()
	exec.Command("iptables", "-A", config.IptablesChain, "-d", ip, "-j", "DROP").Run()
	fmt.Printf("[VOID] iptables DROP deployed for %s\n", ip)
	return true
}

func RemoveIPTablesDrop(ip string) bool {
	exec.Command("iptables", "-D", config.IptablesChain, "-s", ip, "-j", "DROP").Run()
	exec.Command("iptables", "-D", config.IptablesChain, "-d", ip, "-j", "DROP").Run()
	return true
}

func GetBlockedIPs() []string {
	result, err := exec.Command("iptables", "-L", config.IptablesChain, "-n").CombinedOutput()
	if err != nil {
		return nil
	}
	var ips []string
	seen := map[string]bool{}
	for _, line := range strings.Split(string(result), "\n") {
		if strings.Contains(line, "DROP") {
			parts := strings.Fields(line)
			for _, p := range parts {
				if strings.Contains(p, ".") && p != "0.0.0.0/0" && p != "0.0.0.0" && !seen[p] {
					ips = append(ips, p)
					seen[p] = true
					break
				}
			}
		}
	}
	return ips
}
