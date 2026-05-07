package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type Config struct {
	LocalPublicIP  string `json:"local_public_ip"`
	RemotePublicIP string `json:"remote_public_ip"`
	LocalSubnet    string `json:"local_subnet"`
	RemoteSubnet   string `json:"remote_subnet"`
	PSK            string `json:"psk"`
	ConnectionName string `json:"connection_name"`
	IKE            string `json:"ike"`
	ESP            string `json:"esp"`
	KeyExchange    string `json:"key_exchange"`
	Auto           string `json:"auto"`
	OutputDir      string `json:"output_dir"`
	RestartIPsec   bool   `json:"restart_ipsec"`
}

func defaultConfig() Config {
	return Config{
		ConnectionName: "tunnel",
		IKE:            "aes256-sha2",
		ESP:            "aes256-sha2",
		KeyExchange:    "ikev2",
		Auto:           "start",
		OutputDir:      ".",
	}
}

func validateIPv4(ip string) error {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil || parsed.To4() == nil {
		return fmt.Errorf("invalid IPv4 address: %s", ip)
	}
	return nil
}

func validateCIDR(cidr string) error {
	_, _, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return fmt.Errorf("invalid CIDR: %s", cidr)
	}
	return nil
}

func validatePSK(psk string) error {
	if len(strings.TrimSpace(psk)) < 8 {
		return errors.New("PSK must be at least 8 characters")
	}
	return nil
}

func validateName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("connection name cannot be empty")
	}
	for _, r := range name {
		if !(r == '-' || r == '_' || r == '.' ||
			(r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9')) {
			return fmt.Errorf("invalid character in connection name: %q", r)
		}
	}
	return nil
}

func validateConfig(cfg Config) error {
	if err := validateIPv4(cfg.LocalPublicIP); err != nil {
		return err
	}
	if err := validateIPv4(cfg.RemotePublicIP); err != nil {
		return err
	}
	if err := validateCIDR(cfg.LocalSubnet); err != nil {
		return err
	}
	if err := validateCIDR(cfg.RemoteSubnet); err != nil {
		return err
	}
	if err := validatePSK(cfg.PSK); err != nil {
		return err
	}
	if err := validateName(cfg.ConnectionName); err != nil {
		return err
	}
	if strings.TrimSpace(cfg.IKE) == "" {
		return errors.New("IKE setting cannot be empty")
	}
	if strings.TrimSpace(cfg.ESP) == "" {
		return errors.New("ESP setting cannot be empty")
	}
	if strings.TrimSpace(cfg.KeyExchange) == "" {
		return errors.New("key exchange cannot be empty")
	}
	if strings.TrimSpace(cfg.Auto) == "" {
		return errors.New("auto cannot be empty")
	}
	if strings.TrimSpace(cfg.OutputDir) == "" {
		return errors.New("output directory cannot be empty")
	}
	return nil
}

func buildIPSecConf(cfg Config) string {
	var b strings.Builder
	b.WriteString("config setup\n")
	b.WriteString("    protostack=netkey\n\n")
	b.WriteString("conn ")
	b.WriteString(cfg.ConnectionName)
	b.WriteString("\n")
	b.WriteString("    auto=")
	b.WriteString(cfg.Auto)
	b.WriteString("\n")
	b.WriteString("    left=")
	b.WriteString(cfg.LocalPublicIP)
	b.WriteString("\n")
	b.WriteString("    leftsubnet=")
	b.WriteString(cfg.LocalSubnet)
	b.WriteString("\n")
	b.WriteString("    right=")
	b.WriteString(cfg.RemotePublicIP)
	b.WriteString("\n")
	b.WriteString("    rightsubnet=")
	b.WriteString(cfg.RemoteSubnet)
	b.WriteString("\n")
	b.WriteString("    authby=secret\n")
	b.WriteString("    ike=")
	b.WriteString(cfg.IKE)
	b.WriteString("\n")
	b.WriteString("    esp=")
	b.WriteString(cfg.ESP)
	b.WriteString("\n")
	b.WriteString("    keyexchange=")
	b.WriteString(cfg.KeyExchange)
	b.WriteString("\n")
	return b.String()
}

func buildIPSecSecrets(cfg Config) string {
	return fmt.Sprintf("%s %s : PSK %q\n", cfg.LocalPublicIP, cfg.RemotePublicIP, cfg.PSK)
}

func ensureDir(path string) error {
	info, err := os.Stat(path)
	if err == nil {
		if !info.IsDir() {
			return fmt.Errorf("path exists but is not a directory: %s", path)
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}
	return os.MkdirAll(path, 0755)
}

func testWritePermission(dir string) error {
	testFile := filepath.Join(dir, ".write_test")
	if err := os.WriteFile(testFile, []byte{}, 0644); err != nil {
		return fmt.Errorf("no write permission for directory %s: %v", dir, err)
	}
	return os.Remove(testFile)
}

func backupFile(path string) error {
	if _, err := os.Stat(path); err == nil {
		backupPath := path + ".backup"
		return os.Rename(path, backupPath)
	}
	return nil
}

func writeFileAtomic(path string, data string, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(data), mode); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err == nil {
		return nil
	}
	if err := os.WriteFile(path, []byte(data), mode); err != nil {
		return err
	}
	return os.Remove(tmp)
}

func restartIPsec() error {
	cmd := exec.Command("systemctl", "restart", "ipsec")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func printUsage() {
	fmt.Println("Usage:")
	fmt.Println("  ipsecgen --local-public-ip 10.0.0.1 --remote-public-ip 10.0.0.2 --local-subnet 192.168.10.0/24 --remote-subnet 192.168.20.0/24 --psk supersecretkey")
	fmt.Println()
	fmt.Println("Optional:")
	fmt.Println("  --connection-name tunnel")
	fmt.Println("  --ike aes256-sha2")
	fmt.Println("  --esp aes256-sha2")
	fmt.Println("  --key-exchange ikev2")
	fmt.Println("  --auto start")
	fmt.Println("  --output-dir /etc")
	fmt.Println("  --restart-ipsec")
	fmt.Println("  --print-json")
	fmt.Println("  --version")
}

func main() {
	cfg := defaultConfig()

	localPublicIP := flag.String("local-public-ip", "", "Local public IP address (required)")
	remotePublicIP := flag.String("remote-public-ip", "", "Remote public IP address (required)")
	localSubnet := flag.String("local-subnet", "", "Local subnet in CIDR format (required)")
	remoteSubnet := flag.String("remote-subnet", "", "Remote subnet in CIDR format (required)")
	psk := flag.String("psk", "", "Pre-shared key, min 8 chars (required)")
	connectionName := flag.String("connection-name", cfg.ConnectionName, "Connection name (default: tunnel)")
	ike := flag.String("ike", cfg.IKE, "IKE encryption algorithm (default: aes256-sha2)")
	esp := flag.String("esp", cfg.ESP, "ESP encryption algorithm (default: aes256-sha2)")
	keyExchange := flag.String("key-exchange", cfg.KeyExchange, "Key exchange protocol (default: ikev2)")
	auto := flag.String("auto", cfg.Auto, "Auto-start option (default: start)")
	outputDir := flag.String("output-dir", cfg.OutputDir, "Output directory for config files (default: .)")
	restart := flag.Bool("restart-ipsec", false, "Restart ipsec service after generation")
	printJSON := flag.Bool("print-json", false, "Output results in JSON format")
	version := flag.Bool("version", false, "Show version")
	flag.Parse()

	if *version {
		fmt.Println("ipsecgen version 1.0.0")
		os.Exit(0)
	}

	if *localPublicIP == "" || *remotePublicIP == "" || *localSubnet == "" || *remoteSubnet == "" || *psk == "" {
		printUsage()
		os.Exit(2)
	}

	cfg.LocalPublicIP = *localPublicIP
	cfg.RemotePublicIP = *remotePublicIP
	cfg.LocalSubnet = *localSubnet
	cfg.RemoteSubnet = *remoteSubnet
	cfg.PSK = *psk
	cfg.ConnectionName = *connectionName
	cfg.IKE = *ike
	cfg.ESP = *esp
	cfg.KeyExchange = *keyExchange
	cfg.Auto = *auto
	cfg.OutputDir = *outputDir
	cfg.RestartIPsec = *restart

	if err := validateConfig(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "validation error: %v\n", err)
		os.Exit(1)
	}

	if err := ensureDir(cfg.OutputDir); err != nil {
		fmt.Fprintf(os.Stderr, "directory error: %v\n", err)
		os.Exit(1)
	}

	if err := testWritePermission(cfg.OutputDir); err != nil {
		fmt.Fprintf(os.Stderr, "permission error: %v\n", err)
		os.Exit(1)
	}

	confPath := filepath.Join(cfg.OutputDir, "ipsec.conf")
	secretsPath := filepath.Join(cfg.OutputDir, "ipsec.secrets")

	if err := backupFile(confPath); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to backup %s: %v\n", confPath, err)
	}

	if err := backupFile(secretsPath); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to backup %s: %v\n", secretsPath, err)
	}

	confContent := buildIPSecConf(cfg)
	secretsContent := buildIPSecSecrets(cfg)

	if err := writeFileAtomic(confPath, confContent, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write %s: %v\n", confPath, err)
		os.Exit(1)
	}

	if err := writeFileAtomic(secretsPath, secretsContent, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write %s: %v\n", secretsPath, err)
		os.Exit(1)
	}

	if *printJSON {
		safeCfg := cfg
		safeCfg.PSK = "***REDACTED***"
		out := map[string]any{
			"ok":           true,
			"ipsec_conf":   confPath,
			"ipsec_secret": secretsPath,
			"config":       safeCfg,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			fmt.Fprintf(os.Stderr, "failed to encode JSON: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Printf("Generated %s\n", confPath)
		fmt.Printf("Generated %s\n", secretsPath)
	}

	if cfg.RestartIPsec {
		if err := restartIPsec(); err != nil {
			fmt.Fprintf(os.Stderr, "failed to restart ipsec: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Restarted ipsec service")
	}
}
