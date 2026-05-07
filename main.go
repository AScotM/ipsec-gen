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
	"time"
)

type Config struct {
	LocalPublicIP   string `json:"local_public_ip"`
	RemotePublicIP  string `json:"remote_public_ip"`
	LocalSubnet     string `json:"local_subnet"`
	RemoteSubnet    string `json:"remote_subnet"`
	PSK             string `json:"psk"`
	ConnectionName  string `json:"connection_name"`
	IKE             string `json:"ike"`
	ESP             string `json:"esp"`
	KeyExchange     string `json:"key_exchange"`
	Auto            string `json:"auto"`
	OutputDir       string `json:"output_dir"`
	RestartIPsec    bool   `json:"restart_ipsec"`
	DryRun          bool   `json:"dry_run"`
	SkipBackup      bool   `json:"skip_backup"`
	MinPSKLength    int    `json:"min_psk_length"`
}

func defaultConfig() Config {
	return Config{
		ConnectionName: "tunnel",
		IKE:            "aes256-sha2",
		ESP:            "aes256-sha2",
		KeyExchange:    "ikev2",
		Auto:           "start",
		OutputDir:      ".",
		MinPSKLength:   16,
	}
}

func validateIPv4(ip string) error {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil || parsed.To4() == nil {
		return fmt.Errorf("invalid IPv4 address: %s", ip)
	}
	return nil
}

func validateIPv4CIDR(cidr string) error {
	parsed, _, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return fmt.Errorf("invalid IPv4 CIDR: %s", cidr)
	}
	if parsed.To4() == nil {
		return fmt.Errorf("CIDR must be IPv4: %s", cidr)
	}
	return nil
}

func validatePSK(psk string, minLength int) error {
	if minLength < 8 {
		return errors.New("minimum PSK length cannot be less than 8")
	}
	if len(strings.TrimSpace(psk)) < minLength {
		return fmt.Errorf("PSK must be at least %d characters", minLength)
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

func validateChoice(name string, value string, allowed map[string]struct{}) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("%s cannot be empty", name)
	}
	if _, ok := allowed[value]; !ok {
		return fmt.Errorf("invalid %s: %s", name, value)
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
	if err := validateIPv4CIDR(cfg.LocalSubnet); err != nil {
		return err
	}
	if err := validateIPv4CIDR(cfg.RemoteSubnet); err != nil {
		return err
	}
	if err := validatePSK(cfg.PSK, cfg.MinPSKLength); err != nil {
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
	if err := validateChoice("key exchange", cfg.KeyExchange, map[string]struct{}{
		"ikev1": {},
		"ikev2": {},
	}); err != nil {
		return err
	}
	if err := validateChoice("auto", cfg.Auto, map[string]struct{}{
		"add":    {},
		"route":  {},
		"start":  {},
		"ignore": {},
	}); err != nil {
		return err
	}
	if strings.TrimSpace(cfg.OutputDir) == "" {
		return errors.New("output directory cannot be empty")
	}
	return nil
}

func normalizeConfig(cfg Config) Config {
	cfg.LocalPublicIP = strings.TrimSpace(cfg.LocalPublicIP)
	cfg.RemotePublicIP = strings.TrimSpace(cfg.RemotePublicIP)
	cfg.LocalSubnet = strings.TrimSpace(cfg.LocalSubnet)
	cfg.RemoteSubnet = strings.TrimSpace(cfg.RemoteSubnet)
	cfg.PSK = strings.TrimSpace(cfg.PSK)
	cfg.ConnectionName = strings.TrimSpace(cfg.ConnectionName)
	cfg.IKE = strings.TrimSpace(cfg.IKE)
	cfg.ESP = strings.TrimSpace(cfg.ESP)
	cfg.KeyExchange = strings.TrimSpace(cfg.KeyExchange)
	cfg.Auto = strings.TrimSpace(cfg.Auto)
	cfg.OutputDir = filepath.Clean(strings.TrimSpace(cfg.OutputDir))
	return cfg
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
	file, err := os.CreateTemp(dir, ".write-test-*")
	if err != nil {
		return fmt.Errorf("no write permission for directory %s: %v", dir, err)
	}
	name := file.Name()
	if closeErr := file.Close(); closeErr != nil {
		_ = os.Remove(name)
		return closeErr
	}
	return os.Remove(name)
}

func backupFile(path string) (string, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}

	backupPath := fmt.Sprintf("%s.backup.%s", path, time.Now().Format("20060102-150405"))
	if err := os.Rename(path, backupPath); err != nil {
		return "", err
	}
	return backupPath, nil
}

func writeFileAtomic(path string, data string, mode os.FileMode) error {
	dir := filepath.Dir(path)
	base := filepath.Base(path)

	tmp, err := os.CreateTemp(dir, "."+base+".tmp-*")
	if err != nil {
		return err
	}

	tmpName := tmp.Name()
	removeTmp := true

	defer func() {
		if removeTmp {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.WriteString(data); err != nil {
		_ = tmp.Close()
		return err
	}

	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}

	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}

	if err := tmp.Close(); err != nil {
		return err
	}

	if err := os.Rename(tmpName, path); err != nil {
		return err
	}

	removeTmp = false
	return nil
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
	fmt.Println("  --dry-run")
	fmt.Println("  --skip-backup")
	fmt.Println("  --min-psk-length 16")
	fmt.Println("  --print-json")
	fmt.Println("  --version")
}

func main() {
	cfg := defaultConfig()

	localPublicIP := flag.String("local-public-ip", "", "Local public IPv4 address required")
	remotePublicIP := flag.String("remote-public-ip", "", "Remote public IPv4 address required")
	localSubnet := flag.String("local-subnet", "", "Local IPv4 subnet in CIDR format required")
	remoteSubnet := flag.String("remote-subnet", "", "Remote IPv4 subnet in CIDR format required")
	psk := flag.String("psk", "", "Pre-shared key required")
	connectionName := flag.String("connection-name", cfg.ConnectionName, "Connection name")
	ike := flag.String("ike", cfg.IKE, "IKE encryption algorithm")
	esp := flag.String("esp", cfg.ESP, "ESP encryption algorithm")
	keyExchange := flag.String("key-exchange", cfg.KeyExchange, "Key exchange protocol")
	auto := flag.String("auto", cfg.Auto, "Auto-start option")
	outputDir := flag.String("output-dir", cfg.OutputDir, "Output directory for config files")
	restart := flag.Bool("restart-ipsec", false, "Restart ipsec service after generation")
	dryRun := flag.Bool("dry-run", false, "Print generated files without writing")
	skipBackup := flag.Bool("skip-backup", false, "Do not backup existing files")
	minPSKLength := flag.Int("min-psk-length", cfg.MinPSKLength, "Minimum PSK length")
	printJSON := flag.Bool("print-json", false, "Output results in JSON format")
	version := flag.Bool("version", false, "Show version")

	flag.Parse()

	if *version {
		fmt.Println("ipsecgen version 1.1.0")
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
	cfg.DryRun = *dryRun
	cfg.SkipBackup = *skipBackup
	cfg.MinPSKLength = *minPSKLength

	cfg = normalizeConfig(cfg)

	if err := validateConfig(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "validation error: %v\n", err)
		os.Exit(1)
	}

	confPath := filepath.Join(cfg.OutputDir, "ipsec.conf")
	secretsPath := filepath.Join(cfg.OutputDir, "ipsec.secrets")

	confContent := buildIPSecConf(cfg)
	secretsContent := buildIPSecSecrets(cfg)

	if cfg.DryRun {
		if *printJSON {
			safeCfg := cfg
			safeCfg.PSK = "***REDACTED***"
			out := map[string]any{
				"ok":            true,
				"dry_run":       true,
				"ipsec_conf":    confPath,
				"ipsec_secrets": secretsPath,
				"config":        safeCfg,
				"conf_content":  confContent,
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(out); err != nil {
				fmt.Fprintf(os.Stderr, "failed to encode JSON: %v\n", err)
				os.Exit(1)
			}
		} else {
			fmt.Printf("Would write %s:\n\n%s\n", confPath, confContent)
			fmt.Printf("Would write %s:\n\n%s", secretsPath, "***REDACTED***\n")
		}
		os.Exit(0)
	}

	if err := ensureDir(cfg.OutputDir); err != nil {
		fmt.Fprintf(os.Stderr, "directory error: %v\n", err)
		os.Exit(1)
	}

	if err := testWritePermission(cfg.OutputDir); err != nil {
		fmt.Fprintf(os.Stderr, "permission error: %v\n", err)
		os.Exit(1)
	}

	backups := make(map[string]string)

	if !cfg.SkipBackup {
		if backupPath, err := backupFile(confPath); err != nil {
			fmt.Fprintf(os.Stderr, "failed to backup %s: %v\n", confPath, err)
			os.Exit(1)
		} else if backupPath != "" {
			backups[confPath] = backupPath
		}

		if backupPath, err := backupFile(secretsPath); err != nil {
			fmt.Fprintf(os.Stderr, "failed to backup %s: %v\n", secretsPath, err)
			os.Exit(1)
		} else if backupPath != "" {
			backups[secretsPath] = backupPath
		}
	}

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
			"ok":            true,
			"ipsec_conf":    confPath,
			"ipsec_secrets": secretsPath,
			"backups":       backups,
			"config":        safeCfg,
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

		for original, backup := range backups {
			fmt.Printf("Backed up %s to %s\n", original, backup)
		}
	}

	if cfg.RestartIPsec {
		if err := restartIPsec(); err != nil {
			fmt.Fprintf(os.Stderr, "failed to restart ipsec: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Restarted ipsec service")
	}
}
