package main

import (
	"fmt"
	"os"
	"sync"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	RISK_LOW      = "LOW"
	RISK_MEDIUM   = "MEDIUM"
	RISK_HIGH     = "HIGH"
	RISK_CRITICAL = "CRITICAL"
)

// Configuration holds all customizable settings for security checks
type Configuration struct {
	SensitiveMounts        []string          `yaml:"sensitiveMounts"`
	CriticalPaths          []string          `yaml:"criticalPaths"`
	SuspiciousCommands     []string          `yaml:"suspiciousCommands"`
	MinerProcesses         []string          `yaml:"minerProcesses"`
	CloudCredentialEnvVars []string          `yaml:"cloudCredentialEnvVars"`
	DangerousCapabilities  map[string]string `yaml:"dangerousCapabilities"` // capability name -> risk level
	DangerousPermissions   []RBACPermission  `yaml:"dangerousPermissions"`
	SensitivePatterns      map[string]string `yaml:"sensitivePatterns"` // pattern name -> regex
}

// RBACPermission defines a dangerous RBAC permission to check for
type RBACPermission struct {
	Resource string `yaml:"resource"`
	Verb     string `yaml:"verb"`
	Risk     string `yaml:"risk"`
}

type Finding struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Risk        string `json:"risk"`
	Mitigation  string `json:"mitigation"`
}

type Report struct {
	ContainerName string         `json:"container_name"`
	PodName       string         `json:"pod_name"`
	Namespace     string         `json:"namespace"`
	ScanTime      string         `json:"scan_time"`
	RiskSummary   map[string]int `json:"risk_summary"`
	Findings      []Finding      `json:"findings"`
	WorkloadType  string         `json:"workload_type,omitempty"` // Deployment, StatefulSet, DaemonSet, etc.
}

type ContainerSecurityTester struct {
	clientset                *kubernetes.Clientset
	config                   *rest.Config
	namespace                string
	pod                      string
	container                string
	verbose                  bool
	findings                 []Finding
	risks                    map[string]int
	workloadType             string
	scanAllContainers        bool
	podSecurityContext       *corev1.PodSecurityContext
	containerSecurityContext *corev1.SecurityContext
	cfg                      Configuration // Use this for all configurations
	mutex                    sync.Mutex    // Mutex to protect concurrent access to findings and risks
}

// DefaultConfig returns the default configuration
func DefaultConfig() Configuration {
	return Configuration{
		SensitiveMounts: []string{
			"/proc", "/sys", "/var/run/docker.sock", "/etc/shadow",
			"/root", "/var/lib/docker", "/var/run",
			"/etc/kubernetes", "/boot", "/dev", "/var/lib/kubelet", "/run/secrets",
			"/sys/fs/bpf",
		},
		CriticalPaths: []string{
			"/etc/", "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/lib/", "/lib64/",
			"/opt/app/", "/var/lib/", "/usr/local/bin/",
		},
		SuspiciousCommands: []string{
			"nmap", "nc", "netcat", "tcpdump", "wget", "curl", "ssh", "scp",
			"socat", "tshark", "hping", "masscan",
			"bpftrace", "bpftool", "bcc-tools",
		},
		MinerProcesses: []string{
			"xmrig", "cgminer", "cryptonight", "stratum+tcp", "minerd", "ethminer",
			"monero", "cpuminer", "nicehash", "bminer",
		},
		CloudCredentialEnvVars: []string{
			"AWS_ACCESS_KEY", "AWS_SECRET_KEY", "AWS_SECRET_ACCESS_KEY", "AZURE_CLIENT_ID",
			"AZURE_TENANT_ID", "AZURE_CLIENT_SECRET", "GOOGLE_APPLICATION_CREDENTIALS",
			"GOOGLE_CLOUD_PROJECT", "DO_AUTH_TOKEN", "DIGITALOCEAN_ACCESS_TOKEN",
			"ALICLOUD_ACCESS_KEY", "IBM_CLOUD_API_KEY", "RACKSPACE_API_KEY",
		},
		DangerousCapabilities: map[string]string{
			"CAP_CHOWN":        RISK_MEDIUM,
			"CAP_DAC_OVERRIDE": RISK_HIGH,
			"CAP_SETUID":       RISK_HIGH,
			"CAP_SYS_ADMIN":    RISK_CRITICAL,
			"CAP_NET_ADMIN":    RISK_HIGH,
			"CAP_SYS_PTRACE":   RISK_HIGH,
			"CAP_SYS_MODULE":   RISK_CRITICAL,
			"CAP_SYS_BOOT":     RISK_HIGH,
			"CAP_BPF":          RISK_HIGH,
		},
		DangerousPermissions: []RBACPermission{
			{Resource: "pods", Verb: "create", Risk: RISK_HIGH},
			{Resource: "pods", Verb: "delete", Risk: RISK_HIGH},
			{Resource: "pods", Verb: "exec", Risk: RISK_HIGH},
			{Resource: "pods", Verb: "attach", Risk: RISK_HIGH},
			{Resource: "pods", Verb: "portforward", Risk: RISK_HIGH},
			{Resource: "secrets", Verb: "get", Risk: RISK_HIGH},
			{Resource: "secrets", Verb: "list", Risk: RISK_HIGH},
			{Resource: "secrets", Verb: "create", Risk: RISK_HIGH},
			{Resource: "deployments", Verb: "create", Risk: RISK_HIGH},
			{Resource: "deployments", Verb: "delete", Risk: RISK_HIGH},
			{Resource: "daemonsets", Verb: "create", Risk: RISK_HIGH},
			{Resource: "clusterroles", Verb: "bind", Risk: RISK_HIGH},
			{Resource: "clusterroles", Verb: "escalate", Risk: RISK_CRITICAL},
			{Resource: "nodes", Verb: "get", Risk: RISK_HIGH},
			{Resource: "nodes", Verb: "list", Risk: RISK_HIGH},
		},
		SensitivePatterns: map[string]string{
			"AWS Key":             `(?i)(aws_access_key|aws_secret_key|aws_session_token)`,
			"Password":            `(?i)(password|passwd|pass)`,
			"API Key":             `(?i)(api[_-]?key|apikey|api[_-]?token|token)`,
			"Certificate":         `(?i)(ssl|tls|cert|certificate|key)`,
			"OAuth":               `(?i)(oauth|auth[_-]?token)`,
			"Database":            `(?i)(database|db)[_-]?(password|passwd|pwd)`,
			"Secret":              `(?i)secret`,
			"Credentials":         `(?i)cred(ential)?s?`,
			"API Token":           `(?i)(auth[_-]?token|access[_-]?token)`,
			"Private Key":         `(?i)-----BEGIN(.*?)PRIVATE KEY-----`,
			"SSH Key":             `(?i)(ssh-rsa|ssh-dss|ecdsa-sha2-nistp256)`,
			"JWT":                 `(?i)[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+`,
			"GitHub Token":        `(?i)ghp_[A-Za-z0-9]{36}`,
			"GitLab Token":        `(?i)glpat-[A-Za-z0-9]{20,}`,
			"Slack Token":         `(?i)xox[baprs]-[0-9]{12}-[0-9]{12}-[A-Za-z0-9]{24}`,
			"Google API Key":      `(?i)AIza[0-9A-Za-z\\-_]{35}`,
			"Stripe Secret":       `(?i)sk_(live|test)_[0-9a-zA-Z]{24}`,
			"Heroku API Key":      `(?i)[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`,
			"PGP Private Key":     `(?i)-----BEGIN PGP PRIVATE KEY BLOCK-----`,
			"OpenSSH Private Key": `(?i)-----BEGIN OPENSSH PRIVATE KEY-----`,
		},
	}
}

// LoadConfig loads configuration from file or returns defaults if file doesn't exist
func LoadConfig(configPath string) (Configuration, error) {
	config := DefaultConfig()

	// If no config file specified, return defaults
	if configPath == "" {
		log.Info("No configuration file specified, using default configuration")
		return config, nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Infof("No configuration file found at %s, using defaults", configPath)
			return config, nil
		}
		return config, fmt.Errorf("error reading config file: %v", err)
	}

	log.Infof("Using custom configuration from %s", configPath)
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return config, fmt.Errorf("error parsing config file: %v", err)
	}

	return config, nil
}
