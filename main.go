package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/client-go/util/homedir"
)

const (
	RISK_LOW      = "LOW"
	RISK_MEDIUM   = "MEDIUM"
	RISK_HIGH     = "HIGH"
	RISK_CRITICAL = "CRITICAL"
)

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
}

type ContainerSecurityTester struct {
	clientset *kubernetes.Clientset
	config    *rest.Config
	namespace string
	pod       string
	container string
	verbose   bool
	findings  []Finding
	risks     map[string]int
}

// newSecurityTester creates and returns a ContainerSecurityTester using either in-cluster config or a kubeconfig file.
func newSecurityTester(namespace, pod, container string, verbose bool) (*ContainerSecurityTester, error) {
	var kubeconfig string
	var config *rest.Config
	var err error

	// Try in-cluster config first.
	config, err = rest.InClusterConfig()
	if err != nil {
		// Fall back to kubeconfig file.
		if home := homedir.HomeDir(); home != "" {
			kubeconfig = filepath.Join(home, ".kube", "config")
		}
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create K8s config: %v", err)
		}
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create K8s client: %v", err)
	}

	return &ContainerSecurityTester{
		clientset: clientset,
		config:    config,
		namespace: namespace,
		pod:       pod,
		container: container,
		verbose:   verbose,
		findings:  []Finding{},
		risks:     map[string]int{RISK_LOW: 0, RISK_MEDIUM: 0, RISK_HIGH: 0, RISK_CRITICAL: 0},
	}, nil
}

// log logs messages using Logrus if verbose mode is enabled.
func (t *ContainerSecurityTester) log(message string) {
	if t.verbose {
		log.Infof("%s", message)
	}
}

// addFinding appends a security finding and updates risk counts.
func (t *ContainerSecurityTester) addFinding(title, description, risk, mitigation string) {
	finding := Finding{
		Title:       title,
		Description: description,
		Risk:        risk,
		Mitigation:  mitigation,
	}
	t.findings = append(t.findings, finding)
	t.risks[risk]++
}

// execInContainerWithTimeout runs a command in the container with a specified timeout.
func (t *ContainerSecurityTester) execInContainerWithTimeout(command []string, timeout time.Duration) (string, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req := t.clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(t.pod).
		Namespace(t.namespace).
		SubResource("exec")
	req.VersionedParams(&corev1.PodExecOptions{
		Container: t.container,
		Command:   command,
		Stdin:     false,
		Stdout:    true,
		Stderr:    true,
		TTY:       false,
	}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(t.config, "POST", req.URL())
	if err != nil {
		return "", "", fmt.Errorf("error creating executor: %v", err)
	}

	var stdout, stderr bytes.Buffer
	errChan := make(chan error, 1)
	go func() {
		errChan <- exec.Stream(remotecommand.StreamOptions{
			Stdout: &stdout,
			Stderr: &stderr,
		})
	}()

	select {
	case <-ctx.Done():
		return stdout.String(), stderr.String(), fmt.Errorf("command timed out")
	case err := <-errChan:
		return stdout.String(), stderr.String(), err
	}
}

// checkContainerCapabilities verifies dangerous Linux capabilities.
func (t *ContainerSecurityTester) checkContainerCapabilities() {
	t.log("Checking container capabilities...")
	stdout, _, err := t.execInContainerWithTimeout([]string{"cat", "/proc/self/status"}, 10*time.Second)
	if err != nil {
		t.log(fmt.Sprintf("Error checking capabilities: %v", err))
		return
	}

	lines := strings.Split(stdout, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "CapEff:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				capsHex := parts[1]
				var caps int64
				fmt.Sscanf(capsHex, "%x", &caps)

				if caps&(1<<0) != 0 { // CAP_CHOWN
					t.addFinding(
						"CAP_CHOWN enabled",
						"Container has CAP_CHOWN capability which allows changing file ownership",
						RISK_MEDIUM,
						"Remove CAP_CHOWN capability if not required",
					)
				}
				if caps&(1<<2) != 0 { // CAP_DAC_OVERRIDE
					t.addFinding(
						"CAP_DAC_OVERRIDE enabled",
						"Container can bypass file permission checks",
						RISK_HIGH,
						"Remove CAP_DAC_OVERRIDE capability if not required",
					)
				}
				if caps&(1<<7) != 0 { // CAP_SETUID
					t.addFinding(
						"CAP_SETUID enabled",
						"Container can perform arbitrary setuid calls",
						RISK_HIGH,
						"Remove CAP_SETUID capability if not required",
					)
				}
				if caps&(1<<21) != 0 { // CAP_SYS_ADMIN
					t.addFinding(
						"CAP_SYS_ADMIN enabled",
						"Container has administrative capabilities that may allow container escape",
						RISK_CRITICAL,
						"Remove CAP_SYS_ADMIN capability",
					)
				}
			}
		}
	}
}

// checkSensitiveMounts looks for sensitive host path mounts.
func (t *ContainerSecurityTester) checkSensitiveMounts() {
	t.log("Checking for sensitive mounts...")
	stdout, _, err := t.execInContainerWithTimeout([]string{"cat", "/proc/mounts"}, 10*time.Second)
	if err != nil {
		t.log(fmt.Sprintf("Error checking mounts: %v", err))
		return
	}

	sensitivePathPrefixes := []string{
		"/proc", "/sys", "/var/run/docker.sock", "/etc/shadow",
		"/root", "/var/lib/docker", "/var/run",
	}
	lines := strings.Split(stdout, "\n")
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			mountPoint := parts[1]
			for _, sensitive := range sensitivePathPrefixes {
				if mountPoint == sensitive || strings.HasPrefix(mountPoint, sensitive+"/") {
					t.addFinding(
						fmt.Sprintf("Sensitive path mounted: %s", mountPoint),
						fmt.Sprintf("Container has access to sensitive host path %s which may allow container escape", mountPoint),
						RISK_CRITICAL,
						fmt.Sprintf("Remove mount for %s", mountPoint),
					)
				}
			}
		}
	}

	// Check specifically for the Docker socket.
	_, _, err = t.execInContainerWithTimeout([]string{"ls", "/var/run/docker.sock"}, 5*time.Second)
	if err == nil {
		t.addFinding(
			"Docker socket mounted",
			"Docker socket is mounted into container allowing complete control of the Docker daemon",
			RISK_CRITICAL,
			"Remove the Docker socket mount from the container",
		)
	}
}

// checkPrivilegedMode verifies if the container runs with elevated privileges.
func (t *ContainerSecurityTester) checkPrivilegedMode() {
	t.log("Checking for privileged mode...")
	devMemExists := false
	devKmsgExists := false
	procSysWritable := false

	_, _, err := t.execInContainerWithTimeout([]string{"ls", "/dev/mem"}, 5*time.Second)
	if err == nil {
		devMemExists = true
	}
	_, _, err = t.execInContainerWithTimeout([]string{"ls", "/dev/kmsg"}, 5*time.Second)
	if err == nil {
		devKmsgExists = true
	}
	stdout, _, _ := t.execInContainerWithTimeout([]string{"touch", "/proc/sys/kernel/test"}, 5*time.Second)
	if !strings.Contains(stdout, "Permission denied") && !strings.Contains(stdout, "Read-only file system") {
		procSysWritable = true
	}
	if devMemExists || devKmsgExists || procSysWritable {
		t.addFinding(
			"Container running in privileged mode",
			"Container has full access to host devices which may allow container escape",
			RISK_CRITICAL,
			"Remove privileged: true from the container security context",
		)
	}
}

// checkCgroupEscapes looks for writable cgroup paths.
func (t *ContainerSecurityTester) checkCgroupEscapes() {
	t.log("Checking for cgroup escape vectors...")
	stdout, _, err := t.execInContainerWithTimeout([]string{"cat", "/proc/self/cgroup"}, 10*time.Second)
	if err != nil {
		t.log(fmt.Sprintf("Error checking cgroups: %v", err))
		return
	}
	if strings.Contains(stdout, "docker") || strings.Contains(stdout, "kubepods") {
		cgroupPaths := []string{
			"/sys/fs/cgroup/release_agent",
			"/sys/fs/cgroup/notify_on_release",
		}
		for _, path := range cgroupPaths {
			_, _, err := t.execInContainerWithTimeout([]string{"test", "-w", path}, 5*time.Second)
			if err == nil {
				t.addFinding(
					"Potential cgroup escape vector",
					fmt.Sprintf("Container can write to %s which may be exploitable for container escape", path),
					RISK_CRITICAL,
					"Ensure proper isolation of cgroup filesystem",
				)
			}
		}
	}
}

// checkKernelModules tests if module loading interfaces are writable.
func (t *ContainerSecurityTester) checkKernelModules() {
	t.log("Checking ability to load kernel modules...")
	moduleInterfaces := []string{
		"/proc/sys/kernel/modules_disabled",
		"/sys/module",
	}
	for _, path := range moduleInterfaces {
		_, _, err := t.execInContainerWithTimeout([]string{"test", "-w", path}, 5*time.Second)
		if err == nil {
			t.addFinding(
				"Kernel module loading possible",
				"Container appears able to load kernel modules which may lead to privileged code execution",
				RISK_CRITICAL,
				"Run container without CAP_SYS_MODULE capability",
			)
			return
		}
	}
}

// checkNamespaceIsolation compares container and host user namespaces.
func (t *ContainerSecurityTester) checkNamespaceIsolation() {
	t.log("Checking namespace isolation...")
	stdout1, _, err1 := t.execInContainerWithTimeout([]string{"readlink", "/proc/self/ns/user"}, 5*time.Second)
	stdout2, _, err2 := t.execInContainerWithTimeout([]string{"readlink", "/proc/1/ns/user"}, 5*time.Second)
	if err1 == nil && err2 == nil && strings.TrimSpace(stdout1) == strings.TrimSpace(stdout2) {
		t.addFinding(
			"Shared user namespace with host",
			"Container shares user namespace with host which may allow privilege escalation",
			RISK_HIGH,
			"Ensure container uses its own user namespace",
		)
	}
}

// checkContainerRuntime detects the container runtime and checks related issues.
func (t *ContainerSecurityTester) checkContainerRuntime() {
	t.log("Checking container runtime...")
	runtime := "Unknown"
	_, _, err := t.execInContainerWithTimeout([]string{"ls", "/.dockerenv"}, 5*time.Second)
	if err == nil {
		runtime = "Docker"
	} else if _, _, err := t.execInContainerWithTimeout([]string{"printenv", "KUBERNETES_SERVICE_HOST"}, 5*time.Second); err == nil {
		runtime = "Kubernetes"
	}
	if runtime == "Docker" {
		t.log("Detected Docker runtime, checking for Docker-specific issues...")
		stdout, _, _ := t.execInContainerWithTimeout([]string{"cat", "/proc/self/status"}, 10*time.Second)
		if !strings.Contains(stdout, "apparmor") && !strings.Contains(stdout, "selinux") {
			t.addFinding(
				"No AppArmor/SELinux profiles detected",
				"Container is running without additional mandatory access control systems",
				RISK_MEDIUM,
				"Enable AppArmor or SELinux profiles for the container",
			)
		}
	} else if runtime == "Kubernetes" {
		t.log("Detected Kubernetes runtime, checking for Kubernetes-specific issues...")
		_, _, err := t.execInContainerWithTimeout([]string{"ls", "/var/run/secrets/kubernetes.io/serviceaccount/token"}, 5*time.Second)
		if err == nil {
			t.addFinding(
				"Default service account token mounted",
				"Container has access to Kubernetes service account token which may allow cluster escape",
				RISK_HIGH,
				"Use automountServiceAccountToken: false or a limited role binding",
			)
		}
	}
}

// checkSeccompProfile tests for an effective seccomp profile.
func (t *ContainerSecurityTester) checkSeccompProfile() {
	t.log("Checking seccomp profile...")
	_, stderr, _ := t.execInContainerWithTimeout([]string{"unshare", "--map-root-user", "--user", "echo", "test"}, 10*time.Second)
	if !strings.Contains(stderr, "Operation not permitted") && !strings.Contains(stderr, "command not found") {
		t.addFinding(
			"No effective seccomp profile",
			"Container can execute dangerous syscalls like unshare, which may assist in container escape",
			RISK_HIGH,
			"Enable a seccomp profile that restricts dangerous syscalls",
		)
	}
}

// checkHostNetwork verifies if the pod uses the host network.
func (t *ContainerSecurityTester) checkHostNetwork() {
	t.log("Checking if container uses host network...")
	stdout, _, _ := t.execInContainerWithTimeout([]string{"cat", "/proc/net/dev"}, 5*time.Second)
	if strings.Contains(stdout, "eth0") && strings.Contains(stdout, "lo") {
		pod, err := t.clientset.CoreV1().Pods(t.namespace).Get(context.TODO(), t.pod, metav1.GetOptions{})
		if err == nil && pod.Spec.HostNetwork {
			t.addFinding(
				"Container using host network namespace",
				"Container has full access to host network interfaces and can sniff traffic",
				RISK_HIGH,
				"Remove hostNetwork: true from pod specification",
			)
		}
	}
}

// checkContainerResources verifies that CPU and memory limits are set.
func (t *ContainerSecurityTester) checkContainerResources() {
	t.log("Checking container resource limits...")
	pod, err := t.clientset.CoreV1().Pods(t.namespace).Get(context.TODO(), t.pod, metav1.GetOptions{})
	if err != nil {
		t.log(fmt.Sprintf("Error getting pod details: %v", err))
		return
	}

	var container *corev1.Container
	for i := range pod.Spec.Containers {
		if pod.Spec.Containers[i].Name == t.container {
			container = &pod.Spec.Containers[i]
			break
		}
	}
	if container == nil {
		t.log("Container not found in pod spec")
		return
	}
	if container.Resources.Limits.Cpu().IsZero() {
		t.addFinding(
			"No CPU limits set",
			"Container has no CPU limits which could lead to resource exhaustion",
			RISK_MEDIUM,
			"Set appropriate CPU limits for the container",
		)
	}
	if container.Resources.Limits.Memory().IsZero() {
		t.addFinding(
			"No memory limits set",
			"Container has no memory limits which could lead to resource exhaustion",
			RISK_MEDIUM,
			"Set appropriate memory limits for the container",
		)
	}
}

// checkNonRootUser verifies that the container is not running as root.
func (t *ContainerSecurityTester) checkNonRootUser() {
	t.log("Checking if container is running as non-root user...")
	stdout, _, err := t.execInContainerWithTimeout([]string{"id", "-u"}, 5*time.Second)
	if err != nil {
		t.log(fmt.Sprintf("Error checking user: %v", err))
		return
	}
	if strings.TrimSpace(stdout) == "0" {
		t.addFinding(
			"Container running as root",
			"Container process is running as root which increases the risk of privilege escalation",
			RISK_HIGH,
			"Run container as a non-root user",
		)
	}
}

// checkReadOnlyFilesystem tests if the container filesystem is read-only.
func (t *ContainerSecurityTester) checkReadOnlyFilesystem() {
	t.log("Checking if container filesystem is read-only...")
	// Try to create a file in /tmp; if successful, the filesystem is writable.
	_, stderr, err := t.execInContainerWithTimeout([]string{"sh", "-c", "touch /tmp/testfile && rm /tmp/testfile"}, 5*time.Second)
	if err == nil {
		t.addFinding(
			"Writable filesystem",
			"Container filesystem is writable which may allow an attacker to modify files",
			RISK_MEDIUM,
			"Set container filesystem to read-only if possible",
		)
	} else {
		if strings.Contains(stderr, "Read-only file system") {
			t.log("Filesystem is read-only")
		}
	}
}

// runAllChecks executes all security tests concurrently.
func (t *ContainerSecurityTester) runAllChecks() {
	t.log("Starting container security tests...")
	var wg sync.WaitGroup
	checks := []func(){
		t.checkContainerCapabilities,
		t.checkSensitiveMounts,
		t.checkPrivilegedMode,
		t.checkCgroupEscapes,
		t.checkKernelModules,
		t.checkNamespaceIsolation,
		t.checkContainerRuntime,
		t.checkSeccompProfile,
		t.checkHostNetwork,
		t.checkContainerResources,
		t.checkNonRootUser,
		t.checkReadOnlyFilesystem,
	}

	for _, check := range checks {
		wg.Add(1)
		go func(chk func()) {
			defer wg.Done()
			chk()
		}(check)
	}

	wg.Wait()
	t.log("All tests completed.")
}

// generateReport creates a summary report of the scan.
func (t *ContainerSecurityTester) generateReport() Report {
	return Report{
		ContainerName: t.container,
		PodName:       t.pod,
		Namespace:     t.namespace,
		ScanTime:      time.Now().Format(time.RFC3339),
		RiskSummary:   t.risks,
		Findings:      t.findings,
	}
}

func main() {
	// Initialize Logrus for structured logging.
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})

	var namespace, pod, container, outputFile string
	var verbose bool

	// Command-line flag parsing.
	flag.StringVar(&namespace, "namespace", "", "Namespace of the target pod")
	flag.StringVar(&namespace, "n", "", "Namespace of the target pod (shorthand)")
	flag.StringVar(&pod, "pod", "", "Name of the target pod")
	flag.StringVar(&pod, "p", "", "Name of the target pod (shorthand)")
	flag.StringVar(&container, "container", "", "Name of the target container")
	flag.StringVar(&container, "c", "", "Name of the target container (shorthand)")
	flag.StringVar(&outputFile, "output", "", "Output file for JSON report")
	flag.StringVar(&outputFile, "o", "", "Output file for JSON report (shorthand)")
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose output")
	flag.BoolVar(&verbose, "v", false, "Enable verbose output (shorthand)")
	flag.Parse()

	// Print banner.
	fmt.Println(`
╔═══════════════════════════════════════════════════╗
║          kubectl-tricorder - Container Security   ║
║          For authorized security testing only.    ║
╚═══════════════════════════════════════════════════╝
`)

	// Validate required flags.
	if namespace == "" || pod == "" {
		fmt.Println("Error: namespace and pod name are required")
		flag.Usage()
		os.Exit(1)
	}

	// If no output file is specified, ask for user confirmation.
	if outputFile == "" {
		fmt.Print("Do you have permission to test this container? (y/n): ")
		var confirm string
		fmt.Scanln(&confirm)
		if strings.ToLower(confirm) != "y" {
			fmt.Println("Exiting without testing.")
			os.Exit(0)
		}
	}

	// If container not specified, try to get the first container in the pod.
	if container == "" {
		fmt.Println("Container name not specified, trying to get the first container in the pod...")
		var kubeconfig string
		if home := homedir.HomeDir(); home != "" {
			kubeconfig = filepath.Join(home, ".kube", "config")
		}
		config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			fmt.Printf("Error building kubeconfig: %v\n", err)
			os.Exit(1)
		}
		clientset, err := kubernetes.NewForConfig(config)
		if err != nil {
			fmt.Printf("Error creating Kubernetes client: %v\n", err)
			os.Exit(1)
		}
		podInfo, err := clientset.CoreV1().Pods(namespace).Get(context.TODO(), pod, metav1.GetOptions{})
		if err != nil {
			fmt.Printf("Error getting pod details: %v\n", err)
			os.Exit(1)
		}
		if len(podInfo.Spec.Containers) > 0 {
			container = podInfo.Spec.Containers[0].Name
			fmt.Printf("Using container: %s\n", container)
		} else {
			fmt.Println("No containers found in the pod")
			os.Exit(1)
		}
	}

	// Create and run the security tester.
	tester, err := newSecurityTester(namespace, pod, container, verbose)
	if err != nil {
		fmt.Printf("Error initializing security tester: %v\n", err)
		os.Exit(1)
	}

	tester.runAllChecks()
	report := tester.generateReport()

	// Print summary.
	fmt.Println("\n=== Security Scan Results ===")
	fmt.Printf("Pod: %s\n", report.PodName)
	fmt.Printf("Container: %s\n", report.ContainerName)
	fmt.Printf("Namespace: %s\n", report.Namespace)
	fmt.Printf("%s: %d\n", color.RedString("Critical issues"), report.RiskSummary[RISK_CRITICAL])
	fmt.Printf("%s: %d\n", color.YellowString("High risk issues"), report.RiskSummary[RISK_HIGH])
	fmt.Printf("%s: %d\n", color.CyanString("Medium risk issues"), report.RiskSummary[RISK_MEDIUM])
	fmt.Printf("%s: %d\n", color.GreenString("Low risk issues"), report.RiskSummary[RISK_LOW])

	// Output detailed findings either to a file or to the console.
	if outputFile != "" {
		jsonData, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Printf("Error creating JSON report: %v\n", err)
			os.Exit(1)
		}
		err = os.WriteFile(outputFile, jsonData, 0644)
		if err != nil {
			fmt.Printf("Error writing to file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("\nDetailed report saved to %s\n", outputFile)
	} else {
		fmt.Println("\n=== Detailed Findings ===")
		for _, finding := range report.Findings {
			var riskColor func(format string, a ...interface{}) string
			switch finding.Risk {
			case RISK_CRITICAL:
				riskColor = color.RedString
			case RISK_HIGH:
				riskColor = color.YellowString
			case RISK_MEDIUM:
				riskColor = color.CyanString
			case RISK_LOW:
				riskColor = color.GreenString
			}
			fmt.Printf("\n[%s] %s\n", riskColor("%s", finding.Risk), finding.Title)
			fmt.Printf("Description: %s\n", finding.Description)
			fmt.Printf("Mitigation: %s\n", finding.Mitigation)
		}
	}
}
