package utils

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ParseIPOrCIDR parses a string input and returns an array of valid IP addresses.
func ParseIPOrCIDR(input string) ([]string, error) {
	if strings.Contains(input, "-") {
		return parseIPRange(input)
	}

	ip := net.ParseIP(input)
	if ip != nil {
		return []string{ip.String()}, nil
	}

	_, ipNet, err := net.ParseCIDR(input)
	if err != nil {
		return nil, fmt.Errorf("invalid IP, CIDR, or range format: %s", input)
	}

	var ips []string
	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
		if isNetworkOrBroadcast(ip, ipNet) {
			continue
		}
		ips = append(ips, ip.String())
	}

	return ips, nil
}

// parseIPRange handles IP range inputs like "192.168.0.1-10"
func parseIPRange(input string) ([]string, error) {
	parts := strings.Split(input, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid range format: %s", input)
	}

	baseIP := net.ParseIP(parts[0])
	if baseIP == nil {
		return nil, fmt.Errorf("invalid IP address in range: %s", parts[0])
	}

	lastOctet, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid range end: %s", parts[1])
	}

	octets := strings.Split(parts[0], ".")
	if len(octets) != 4 {
		return nil, fmt.Errorf("invalid IPv4 format: %s", parts[0])
	}

	startOctet, err := strconv.Atoi(octets[3])
	if err != nil {
		return nil, fmt.Errorf("invalid start octet: %s", octets[3])
	}

	if lastOctet < startOctet || lastOctet > 255 {
		return nil, fmt.Errorf("invalid range: %d-%d", startOctet, lastOctet)
	}

	var ips []string
	for i := startOctet; i <= lastOctet; i++ {
		octets[3] = strconv.Itoa(i)
		ips = append(ips, strings.Join(octets, "."))
	}

	return ips, nil
}

// incrementIP increases the IP address by one.
func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] != 0 {
			break
		}
	}
}

// isNetworkOrBroadcast checks if an IP is a network or broadcast address.
func isNetworkOrBroadcast(ip net.IP, ipNet *net.IPNet) bool {
	if ip.Equal(ipNet.IP) {
		return true // Network address
	}

	broadcast := make(net.IP, len(ip))
	copy(broadcast, ipNet.IP)
	for i := range broadcast {
		broadcast[i] |= ^ipNet.Mask[i]
	}

	if ip.Equal(broadcast) {
		return true // Broadcast address
	}

	return false
}
