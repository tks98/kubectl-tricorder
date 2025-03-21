package main

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	authv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/client-go/util/homedir"
)

// newSecurityTester creates and returns a ContainerSecurityTester using either in-cluster config or a kubeconfig file.
func newSecurityTester(namespace, pod, container string, verbose bool, cfg Configuration) (*ContainerSecurityTester, error) {
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

	tester := &ContainerSecurityTester{
		clientset:         clientset,
		config:            config,
		namespace:         namespace,
		pod:               pod,
		container:         container,
		verbose:           verbose,
		findings:          []Finding{},
		risks:             map[string]int{RISK_LOW: 0, RISK_MEDIUM: 0, RISK_HIGH: 0, RISK_CRITICAL: 0},
		scanAllContainers: false,
		cfg:               cfg,
	}

	// Fetch initial pod info to get security context
	tester.fetchPodDetails()

	return tester, nil
}

// fetchPodDetails gets initial pod and container information
func (t *ContainerSecurityTester) fetchPodDetails() {
	pod, err := t.clientset.CoreV1().Pods(t.namespace).Get(context.TODO(), t.pod, metav1.GetOptions{})
	if err != nil {
		t.log(fmt.Sprintf("Error getting pod details: %v", err))
		return
	}

	// Store pod security context
	t.podSecurityContext = pod.Spec.SecurityContext

	// Store workload information if available
	if len(pod.OwnerReferences) > 0 {
		t.workloadType = pod.OwnerReferences[0].Kind
	}

	// Find our container and store information
	for i := range pod.Spec.Containers {
		if pod.Spec.Containers[i].Name == t.container {
			// Store container security context
			t.containerSecurityContext = pod.Spec.Containers[i].SecurityContext
			break
		}
	}
}

// log logs messages using Logrus if verbose mode is enabled.
func (t *ContainerSecurityTester) log(message string) {
	if t.verbose {
		log.Infof("%s", message)
	}
}

// addFinding appends a security finding and updates risk counts.
func (t *ContainerSecurityTester) addFinding(title, description, risk, mitigation string) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

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

				// Map of capability bit position to name
				capMap := map[int]string{
					0:  "CAP_CHOWN",
					1:  "CAP_DAC_OVERRIDE",
					2:  "CAP_DAC_READ_SEARCH",
					3:  "CAP_FOWNER",
					4:  "CAP_FSETID",
					5:  "CAP_KILL",
					6:  "CAP_SETGID",
					7:  "CAP_SETUID",
					8:  "CAP_SETPCAP",
					9:  "CAP_LINUX_IMMUTABLE",
					10: "CAP_NET_BIND_SERVICE",
					11: "CAP_NET_BROADCAST",
					12: "CAP_NET_ADMIN",
					13: "CAP_NET_RAW",
					14: "CAP_IPC_LOCK",
					15: "CAP_IPC_OWNER",
					16: "CAP_SYS_MODULE",
					17: "CAP_SYS_RAWIO",
					18: "CAP_SYS_CHROOT",
					19: "CAP_SYS_PTRACE",
					20: "CAP_SYS_PACCT",
					21: "CAP_SYS_ADMIN",
					22: "CAP_SYS_BOOT",
					23: "CAP_SYS_NICE",
					24: "CAP_SYS_RESOURCE",
					25: "CAP_SYS_TIME",
					26: "CAP_SYS_TTY_CONFIG",
					27: "CAP_MKNOD",
					28: "CAP_LEASE",
					29: "CAP_AUDIT_WRITE",
					30: "CAP_AUDIT_CONTROL",
					31: "CAP_SETFCAP",
					32: "CAP_MAC_OVERRIDE",
					33: "CAP_MAC_ADMIN",
					34: "CAP_SYSLOG",
					35: "CAP_WAKE_ALARM",
					36: "CAP_BLOCK_SUSPEND",
					37: "CAP_AUDIT_READ",
					38: "CAP_PERFMON",
					39: "CAP_BPF",
					40: "CAP_CHECKPOINT_RESTORE",
				}

				// Check each bit up to the highest known capability
				for bit := 0; bit <= 40; bit++ {
					if caps&(1<<bit) != 0 {
						capName := capMap[bit]
						if risk, exists := t.cfg.DangerousCapabilities[capName]; exists {
							var description, mitigation string

							switch capName {
							case "CAP_CHOWN":
								description = "Container has CAP_CHOWN capability which allows changing file ownership"
								mitigation = "Remove CAP_CHOWN capability if not required"
							case "CAP_DAC_OVERRIDE":
								description = "Container can bypass file permission checks"
								mitigation = "Remove CAP_DAC_OVERRIDE capability if not required"
							case "CAP_SETUID":
								description = "Container can perform arbitrary setuid calls"
								mitigation = "Remove CAP_SETUID capability if not required"
							case "CAP_SYS_ADMIN":
								description = "Container has administrative capabilities that may allow container escape"
								mitigation = "Remove CAP_SYS_ADMIN capability"
							case "CAP_NET_ADMIN":
								description = "Container can modify network settings and interfaces"
								mitigation = "Remove CAP_NET_ADMIN capability if not required"
							case "CAP_SYS_MODULE":
								description = "Container can load kernel modules"
								mitigation = "Remove CAP_SYS_MODULE capability"
							case "CAP_SYS_PTRACE":
								description = "Container can use ptrace to inspect processes"
								mitigation = "Remove CAP_SYS_PTRACE capability"
							case "CAP_BPF":
								description = "Container can create and load eBPF programs which could be used for kernel-level access"
								mitigation = "Remove CAP_BPF capability unless absolutely necessary"
							default:
								description = fmt.Sprintf("Container has %s capability which may be dangerous", capName)
								mitigation = fmt.Sprintf("Remove %s capability if not required", capName)
							}

							t.addFinding(
								fmt.Sprintf("%s enabled", capName),
								description,
								risk,
								mitigation,
							)
						}
					}
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

	// Map to track sensitive paths by parent directory
	sensitivePathsByParent := make(map[string][]string)

	lines := strings.Split(stdout, "\n")
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			mountPoint := parts[1]
			for _, sensitive := range t.cfg.SensitiveMounts {
				if mountPoint == sensitive || strings.HasPrefix(mountPoint, sensitive+"/") {
					// Group by the sensitive parent path
					sensitivePathsByParent[sensitive] = append(sensitivePathsByParent[sensitive], mountPoint)
					break // Found a match, no need to check other sensitive paths
				}
			}
		}
	}

	// Define patterns for paths that should be consolidated
	pathPatterns := map[string]*regexp.Regexp{
		"Docker overlay":    regexp.MustCompile(`/var/lib/docker/overlay2/[0-9a-f]{64}/merged`),
		"Docker container":  regexp.MustCompile(`/var/lib/docker/containers/[0-9a-f]{64}/.*`),
		"Docker volume":     regexp.MustCompile(`/var/lib/docker/volumes/[0-9a-f]{64}.*`),
		"Kubernetes volume": regexp.MustCompile(`/var/lib/kubelet/pods/[0-9a-f-]{36}/volumes/.*`),
		"Container ID path": regexp.MustCompile(`.*/[0-9a-f]{32,}/.*`),
		"UUID path":         regexp.MustCompile(`.*/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/.*`),
	}

	// Process each sensitive parent directory
	for sensitive, paths := range sensitivePathsByParent {
		// Map to store grouped paths by pattern
		groupedPaths := make(map[string][]string)
		ungroupedPaths := []string{}

		// First attempt to group paths by known patterns
		for _, path := range paths {
			matched := false
			for patternName, pattern := range pathPatterns {
				if pattern.MatchString(path) {
					groupedPaths[patternName] = append(groupedPaths[patternName], path)
					matched = true
					break
				}
			}
			if !matched {
				ungroupedPaths = append(ungroupedPaths, path)
			}
		}

		// Process grouped paths
		for patternName, matchedPaths := range groupedPaths {
			if len(matchedPaths) > 3 {
				// Report as a group if we have many paths of the same pattern
				t.addFinding(
					fmt.Sprintf("Multiple %s paths mounted", patternName),
					fmt.Sprintf("Container has access to %d %s paths which may allow container escape",
						len(matchedPaths), patternName),
					RISK_CRITICAL,
					fmt.Sprintf("Remove mounts for %s paths", patternName),
				)

				// Log a few examples at verbose level
				examples := matchedPaths
				if len(examples) > 3 {
					examples = examples[:3]
				}
				t.log(fmt.Sprintf("Examples of %s paths: %s, and %d more",
					patternName, strings.Join(examples, ", "), len(matchedPaths)-len(examples)))
			} else {
				// Report individual paths if only a few
				for _, path := range matchedPaths {
					t.addFinding(
						fmt.Sprintf("%s path mounted: %s", patternName, path),
						fmt.Sprintf("Container has access to %s path which may allow container escape", patternName),
						RISK_CRITICAL,
						fmt.Sprintf("Remove mount for %s", path),
					)
				}
			}
		}

		// Process remaining ungrouped paths
		// Further consolidate paths with common prefixes if they're too numerous
		if len(ungroupedPaths) > 10 {
			// Group by common path prefixes (first 3 components)
			prefixGroups := make(map[string][]string)
			for _, path := range ungroupedPaths {
				parts := strings.Split(path, "/")
				prefix := ""
				// Use at most first 3 path components for grouping
				depth := min(4, len(parts))
				if depth > 0 {
					prefix = strings.Join(parts[:depth], "/")
				}
				prefixGroups[prefix] = append(prefixGroups[prefix], path)
			}

			// Report each prefix group
			for prefix, prefixPaths := range prefixGroups {
				if len(prefixPaths) > 3 {
					t.addFinding(
						fmt.Sprintf("Multiple sensitive paths under %s", prefix),
						fmt.Sprintf("Container has access to %d sensitive paths under %s which may allow container escape",
							len(prefixPaths), prefix),
						RISK_CRITICAL,
						fmt.Sprintf("Remove mounts for paths under %s", prefix),
					)
					t.log(fmt.Sprintf("First few paths: %s, and %d more",
						strings.Join(prefixPaths[:min(3, len(prefixPaths))], ", "), len(prefixPaths)-min(3, len(prefixPaths))))
				} else {
					// Just report the individual paths if only a few
					for _, path := range prefixPaths {
						t.addFinding(
							fmt.Sprintf("Sensitive path mounted: %s", path),
							fmt.Sprintf("Container has access to sensitive host path %s which may allow container escape", path),
							RISK_CRITICAL,
							fmt.Sprintf("Remove mount for %s", path),
						)
					}
				}
			}
		} else if len(ungroupedPaths) > 1 {
			// Handle case where there are multiple paths but not too many
			t.addFinding(
				fmt.Sprintf("Multiple sensitive paths under %s", sensitive),
				fmt.Sprintf("Container has access to %d sensitive paths under %s which may allow container escape",
					len(ungroupedPaths), sensitive),
				RISK_CRITICAL,
				fmt.Sprintf("Remove mounts for paths under %s", sensitive),
			)
			t.log(fmt.Sprintf("Sensitive paths under %s: %s", sensitive, strings.Join(ungroupedPaths, ", ")))
		} else if len(ungroupedPaths) == 1 {
			// Single path case
			t.addFinding(
				fmt.Sprintf("Sensitive path mounted: %s", ungroupedPaths[0]),
				fmt.Sprintf("Container has access to sensitive host path %s which may allow container escape", ungroupedPaths[0]),
				RISK_CRITICAL,
				fmt.Sprintf("Remove mount for %s", ungroupedPaths[0]),
			)
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

// min returns the smaller of x or y.
func min(x, y int) int {
	if x < y {
		return x
	}
	return y
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

// checkSecretsInEnvVars searches for potential secrets in environment variables.
func (t *ContainerSecurityTester) checkSecretsInEnvVars() {
	t.log("Checking for secrets in environment variables...")

	// Get pod details to check environment variables
	pod, err := t.clientset.CoreV1().Pods(t.namespace).Get(context.TODO(), t.pod, metav1.GetOptions{})
	if err != nil {
		t.log(fmt.Sprintf("Error getting pod details: %v", err))
		return
	}

	// Find our container
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

	// Compile all patterns
	sensitivePatterns := make(map[string]*regexp.Regexp)
	for patternName, patternStr := range t.cfg.SensitivePatterns {
		sensitivePatterns[patternName] = regexp.MustCompile(patternStr)
	}

	// Check environment variables
	for _, env := range container.Env {
		// Skip if value is coming from a Secret reference
		if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
			continue // This is OK as it's using Kubernetes Secrets
		}

		// Check for sensitive patterns in variable names
		for patternName, pattern := range sensitivePatterns {
			if pattern.MatchString(env.Name) {
				t.addFinding(
					fmt.Sprintf("Potentially sensitive data in environment variable: %s", env.Name),
					fmt.Sprintf("Environment variable name matches %s pattern", patternName),
					RISK_HIGH,
					"Store sensitive data in Kubernetes Secrets and reference them instead of using plain environment variables",
				)
				break
			}
		}
	}

	// Check for secrets from ConfigMaps
	for _, envFrom := range container.EnvFrom {
		if envFrom.ConfigMapRef != nil {
			cm, err := t.clientset.CoreV1().ConfigMaps(t.namespace).Get(context.TODO(), envFrom.ConfigMapRef.Name, metav1.GetOptions{})
			if err != nil {
				t.log(fmt.Sprintf("Error getting ConfigMap: %v", err))
				continue
			}

			for key := range cm.Data {
				// Check for sensitive patterns in ConfigMap keys
				for patternName, pattern := range sensitivePatterns {
					if pattern.MatchString(key) {
						t.addFinding(
							fmt.Sprintf("Potentially sensitive data in ConfigMap: %s", envFrom.ConfigMapRef.Name),
							fmt.Sprintf("ConfigMap key '%s' matches %s pattern", key, patternName),
							RISK_HIGH,
							"Store sensitive data in Kubernetes Secrets instead of ConfigMaps",
						)
						break
					}
				}
			}
		}
	}
}

// checkSUIDBindaries checks for SUID binaries that could be used for privilege escalation
func (t *ContainerSecurityTester) checkSUIDBindaries() {
	t.log("Checking for SUID binaries...")
	stdout, _, err := t.execInContainerWithTimeout([]string{"find", "/", "-perm", "-4000", "-type", "f", "-exec", "ls", "-la", "{}", "\\;", "2>/dev/null"}, 30*time.Second)
	if err == nil && stdout != "" {
		t.addFinding(
			"SUID binaries found",
			fmt.Sprintf("Container contains SUID binaries which could be used for privilege escalation: %s", stdout),
			RISK_HIGH,
			"Remove unnecessary SUID binaries or use a distroless container image",
		)
	}
}

// checkCloudCredentials checks for cloud provider credentials in the environment
func (t *ContainerSecurityTester) checkCloudCredentials() {
	t.log("Checking for cloud provider credentials...")

	stdout, _, _ := t.execInContainerWithTimeout([]string{"printenv"}, 5*time.Second)
	for _, pattern := range t.cfg.CloudCredentialEnvVars {
		if strings.Contains(stdout, pattern) {
			t.addFinding(
				"Cloud provider credentials found",
				fmt.Sprintf("Container has access to cloud credentials matching pattern: %s", pattern),
				RISK_CRITICAL,
				"Remove cloud credentials from container environment and use a secret store",
			)
		}
	}
}

// checkNetworkPolicies checks if network policies exist for the namespace
func (t *ContainerSecurityTester) checkNetworkPolicies() {
	t.log("Checking for network policies...")

	// Check if network policies exist for this namespace
	policies, err := t.clientset.NetworkingV1().NetworkPolicies(t.namespace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		t.log(fmt.Sprintf("Error checking network policies: %v", err))
		return
	}

	if len(policies.Items) == 0 {
		t.addFinding(
			"No network policies in namespace",
			"No Kubernetes NetworkPolicies found in this namespace, allowing unrestricted pod communication",
			RISK_HIGH,
			"Implement NetworkPolicies to restrict pod-to-pod communication",
		)
	}
}

// checkSuspiciousProcesses checks for suspicious processes and potential crypto miners
func (t *ContainerSecurityTester) checkSuspiciousProcesses() {
	t.log("Checking for suspicious processes and tools...")

	for _, cmd := range t.cfg.SuspiciousCommands {
		_, _, err := t.execInContainerWithTimeout([]string{"which", cmd}, 5*time.Second)
		if err == nil {
			t.addFinding(
				fmt.Sprintf("Network tool found: %s", cmd),
				fmt.Sprintf("Container contains network reconnaissance tool '%s' which could be used for lateral movement", cmd),
				RISK_MEDIUM,
				fmt.Sprintf("Remove %s from container image or use a minimal base image", cmd),
			)
		}
	}

	// Check for cryptocurrency miners
	stdout, _, _ := t.execInContainerWithTimeout([]string{"ps", "aux"}, 10*time.Second)

	for _, process := range t.cfg.MinerProcesses {
		if strings.Contains(strings.ToLower(stdout), process) {
			t.addFinding(
				"Potential cryptocurrency miner detected",
				fmt.Sprintf("Process matching crypto mining signature detected: %s", process),
				RISK_CRITICAL,
				"Investigate and remove unauthorized processes",
			)
		}
	}
}

// checkWriteablePaths checks if critical system paths are writable
func (t *ContainerSecurityTester) checkWriteablePaths() {
	t.log("Checking for writable critical paths...")

	for _, path := range t.cfg.CriticalPaths {
		_, _, err := t.execInContainerWithTimeout([]string{"test", "-w", path}, 5*time.Second)
		if err == nil {
			t.addFinding(
				fmt.Sprintf("Critical path is writable: %s", path),
				"Container can write to critical system paths which could allow for persistence",
				RISK_HIGH,
				"Make critical paths read-only using a readOnlyRootFilesystem securityContext",
			)
		}
	}
}

// checkHostPathVolumes checks for sensitive host path volumes mounted in the pod
func (t *ContainerSecurityTester) checkHostPathVolumes() {
	t.log("Checking for sensitive hostPath volumes...")
	pod, err := t.clientset.CoreV1().Pods(t.namespace).Get(context.TODO(), t.pod, metav1.GetOptions{})
	if err != nil {
		t.log(fmt.Sprintf("Error getting pod details: %v", err))
		return
	}

	for _, volume := range pod.Spec.Volumes {
		if volume.HostPath != nil {
			hostPath := volume.HostPath.Path
			if hostPath == "/" || hostPath == "/etc" || hostPath == "/var" ||
				strings.HasPrefix(hostPath, "/proc") || strings.HasPrefix(hostPath, "/sys") {
				t.addFinding(
					fmt.Sprintf("Critical hostPath volume mounted: %s", hostPath),
					"Pod has access to sensitive host filesystem paths which enables container escape",
					RISK_CRITICAL,
					"Remove hostPath volume mounts for sensitive paths",
				)
			}
		}
	}
}

// checkRBACPermissions checks for dangerous RBAC permissions assigned to the pod's service account
func (t *ContainerSecurityTester) checkRBACPermissions() {
	t.log("Checking service account RBAC permissions...")

	// Get service account name
	pod, err := t.clientset.CoreV1().Pods(t.namespace).Get(context.TODO(), t.pod, metav1.GetOptions{})
	if err != nil {
		t.log(fmt.Sprintf("Error getting pod details: %v", err))
		return
	}

	saName := "default"
	if pod.Spec.ServiceAccountName != "" {
		saName = pod.Spec.ServiceAccountName
	}

	for _, perm := range t.cfg.DangerousPermissions {
		sar := &authv1.SelfSubjectAccessReview{
			Spec: authv1.SelfSubjectAccessReviewSpec{
				ResourceAttributes: &authv1.ResourceAttributes{
					Namespace: t.namespace,
					Verb:      perm.Verb,
					Resource:  perm.Resource,
				},
			},
		}

		review, err := t.clientset.AuthorizationV1().SelfSubjectAccessReviews().Create(context.TODO(), sar, metav1.CreateOptions{})
		if err != nil {
			t.log(fmt.Sprintf("Error checking RBAC permissions: %v", err))
			continue
		}

		if review.Status.Allowed {
			t.addFinding(
				fmt.Sprintf("Excessive RBAC permission: %s %s", perm.Verb, perm.Resource),
				fmt.Sprintf("Service account '%s' has permission to %s %s which could be used for privilege escalation",
					saName, perm.Verb, perm.Resource),
				perm.Risk,
				"Implement least privilege RBAC policies",
			)
		}
	}
}

// checkServiceAccountToken checks for access to and permissions of the service account token
func (t *ContainerSecurityTester) checkServiceAccountToken() {
	t.log("Checking service account token...")

	// Check if token is accessible
	tokenPath := "/var/run/secrets/kubernetes.io/serviceaccount/token"
	_, _, err := t.execInContainerWithTimeout([]string{"cat", tokenPath}, 5*time.Second)
	if err == nil {
		// Token is accessible, check if it's automounted
		pod, err := t.clientset.CoreV1().Pods(t.namespace).Get(context.TODO(), t.pod, metav1.GetOptions{})
		if err != nil {
			t.log(fmt.Sprintf("Error getting pod details: %v", err))
			return
		}

		if pod.Spec.AutomountServiceAccountToken == nil || *pod.Spec.AutomountServiceAccountToken {
			t.addFinding(
				"Service account token automatically mounted",
				"The pod has a service account token automatically mounted, which could be used for lateral movement",
				RISK_HIGH,
				"Set automountServiceAccountToken: false in pod spec unless the token is required",
			)
		}
	}
}

// checkEbpfAccess checks for potential eBPF access that could be used for container escape
func (t *ContainerSecurityTester) checkEbpfAccess() {
	t.log("Checking for eBPF access...")

	// Check if BPF syscalls are restricted with seccomp
	stdout, _, err := t.execInContainerWithTimeout([]string{"grep", "bpf", "/proc/self/status"}, 5*time.Second)
	if err == nil && !strings.Contains(stdout, "0-0:allow") {
		t.addFinding(
			"Unrestricted BPF syscall access",
			"Container can use BPF syscalls which could be used for container escape or unauthorized monitoring",
			RISK_HIGH,
			"Apply a seccomp profile that restricts BPF syscalls",
		)
	}

	// Check for write access to the BPF filesystem
	_, _, err = t.execInContainerWithTimeout([]string{"test", "-w", "/sys/fs/bpf"}, 5*time.Second)
	if err == nil {
		t.addFinding(
			"Writable BPF filesystem",
			"Container can write to /sys/fs/bpf which may allow loading unauthorized eBPF programs",
			RISK_HIGH,
			"Mount /sys/fs/bpf as read-only or remove the mount entirely",
		)
	}

	// Check for existing eBPF programs
	stdout, _, err = t.execInContainerWithTimeout([]string{"ls", "-la", "/sys/fs/bpf"}, 5*time.Second)
	if err == nil && len(stdout) > 0 && !strings.Contains(stdout, "No such file") {
		t.addFinding(
			"eBPF programs detected",
			"Found existing eBPF programs or maps that may indicate container monitoring or potential escape vectors",
			RISK_MEDIUM,
			"Investigate eBPF usage and restrict container capabilities",
		)
	}

	// Check for common eBPF development tools
	for _, tool := range []string{"bpftool", "bpftrace", "bcc"} {
		_, _, err := t.execInContainerWithTimeout([]string{"which", tool}, 5*time.Second)
		if err == nil {
			t.addFinding(
				fmt.Sprintf("eBPF tool found: %s", tool),
				fmt.Sprintf("Container contains eBPF development tool %s which could be used for kernel-level access", tool),
				RISK_HIGH,
				fmt.Sprintf("Remove %s from container image", tool),
			)
		}
	}

	// Check if the process is being traced by eBPF
	stdout, _, err = t.execInContainerWithTimeout([]string{"cat", "/proc/self/environ"}, 5*time.Second)
	if err == nil && strings.Contains(stdout, "BPF_") {
		t.addFinding(
			"Process being traced by eBPF",
			"Container processes appear to be traced by eBPF programs which may indicate unauthorized monitoring",
			RISK_MEDIUM,
			"Investigate eBPF traces and ensure they are authorized",
		)
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
		t.checkSecretsInEnvVars,
		// New checks
		t.checkSUIDBindaries,
		t.checkCloudCredentials,
		t.checkNetworkPolicies,
		t.checkSuspiciousProcesses,
		t.checkWriteablePaths,
		t.checkHostPathVolumes,
		t.checkRBACPermissions,
		t.checkServiceAccountToken,
		t.checkEbpfAccess,
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
		WorkloadType:  t.workloadType,
	}
}
