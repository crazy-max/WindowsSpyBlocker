package netu

import (
	"bytes"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/cavaliergopher/grab/v3"
)

// GetCIDRFromIPRange converts IP range to CIDR
func GetCIDRFromIPRange(ipRange string) (string, error) {
	if strings.Contains(ipRange, "-") {
		ipRangeS := strings.SplitN(ipRange, "-", 2)
		if len(ipRangeS) != 2 {
			return "", fmt.Errorf("Invalid IP range %s", ipRange)
		}
		ipA := net.ParseIP(ipRangeS[0])
		ipB := net.ParseIP(ipRangeS[1])
		maxLen := 32
		for l := maxLen; l >= 0; l-- {
			mask := net.CIDRMask(l, maxLen)
			na := ipA.Mask(mask)
			n := net.IPNet{IP: na, Mask: mask}
			if n.Contains(ipB) {
				return fmt.Sprintf("%v/%v", na, l), nil
			}
		}
	}
	return "", fmt.Errorf("Invalid IP range %s", ipRange)
}

// GetIPRangeFromCIDR converts CIDR to IP range
func GetIPRangeFromCIDR(cidr string) (string, error) {
	ips, err := GetIpsFromCIDR(cidr)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s-%s", ips[0], ips[len(ips)-1]), nil
}

// GetIpsFromCIDR gets IPs list from CIDR
func GetIpsFromCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		ips = append(ips, ip.String())
	}

	return ips, nil
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// GetIpsFromIPRange gets IPs list from range
func GetIpsFromIPRange(ipRange string) ([]string, error) {
	cidr, err := GetCIDRFromIPRange(ipRange)
	if err != nil {
		return nil, err
	}
	return GetIpsFromCIDR(cidr)
}

// DownloadFile downloads a file and display status
func DownloadFile(filename string, url string) error {
	client := grab.NewClient()
	req, err := grab.NewRequest(filename, url)
	if err != nil {
		return err
	}

	resp := client.Do(req)
	t := time.NewTicker(200 * time.Millisecond)
	defer t.Stop()

Loop:
	for {
		select {
		case <-t.C:
			fmt.Print(".")
		case <-resp.Done:
			break Loop
		}
	}

	if err := resp.Err(); err != nil {
		return err
	}

	return nil
}

// IsValidIPv4 validates an IPv4
func IsValidIPv4(ipAddress string) bool {
	ipAddress = strings.Trim(ipAddress, " ")
	re, _ := regexp.Compile(`^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$`)
	if re.MatchString(ipAddress) {
		return true
	}
	return false
}

// GetIPFromReverse returns IP address from a reverse domain address
func GetIPFromReverse(domain string) string {
	re := regexp.MustCompile(`(?i)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`)
	matches := re.FindStringSubmatch(domain)
	if len(matches) == 2 && IsValidIPv4(matches[1]) {
		return matches[1]
	}
	return ""
}

// IsValidIpv4Range validates an IPv4 range
func IsValidIpv4Range(ipRange string) bool {
	if strings.Contains(ipRange, "-") {
		ipRangeS := strings.SplitN(ipRange, "-", 2)
		if len(ipRangeS) != 2 {
			return false
		}
		if !IsValidIPv4(ipRangeS[0]) || !IsValidIPv4(ipRangeS[1]) {
			return false
		}
		return true
	}
	return false
}

// IsPrivateIp validates an IP in a private network
func IsPrivateIp(ipStr string) bool {
	privateIps := []string{
		"127.0.0.1",
		"10.0.0.0-10.255.255.255",
		"172.16.0.0–172.31.255.255",
		"192.168.0.0–192.168.255.255",
	}

	ip := net.ParseIP(ipStr)
	if ip.To4() == nil {
		return false
	}

	for _, privateIp := range privateIps {
		if strings.Contains(privateIp, "-") {
			ipRange := strings.SplitN(privateIp, "-", 2)
			if len(ipRange) != 2 {
				return false
			}
			ipRange0 := net.ParseIP(ipRange[0])
			ipRange1 := net.ParseIP(ipRange[1])
			if ipRange0.To4() == nil || ipRange1.To4() == nil {
				return false
			}
			if bytes.Compare(ip, ipRange0) >= 0 && bytes.Compare(ip, ipRange1) <= 0 {
				return true
			}
		} else if privateIp == ipStr {
			return true
		}
	}

	return false
}
