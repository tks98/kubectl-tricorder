# kubectl-tricorder
A kubectl plugin that detects container vulnerabilities, privileges risks, and escape vectors in your pods.

## Features

- Identifies security vulnerabilities in running containers
- Detects potential container escape vectors
- Checks for excessive privileges and capabilities
- Identifies sensitive mounts and paths
- Reports on RBAC permissions and service account issues
- Customizable security checks through configuration files
- Detects eBPF security risks and access vectors

## Usage

```bash
kubectl tricorder -n <namespace> -p <pod-name> [-c <container-name>] [-o output.json] [-v] [-a] [--config config.yaml]
```

Options:
- `-n, --namespace`: Target namespace (required)
- `-p, --pod`: Target pod name (required)
- `-c, --container`: Target container name (defaults to first container)
- `-o, --output`: JSON output file
- `-v, --verbose`: Enable verbose logging
- `-a, --all-containers`: Scan all containers in the pod
- `--config`: Path to configuration file

## Configuration

You can customize the security checks by providing a YAML configuration file:

```bash
kubectl tricorder -n monitoring -p prometheus-server --config custom-checks.yaml
```

The configuration file allows you to define:
- Custom sensitive paths and mounts to check
- Critical paths that shouldn't be writable
- Suspicious commands to look for
- Regex patterns for sensitive data
- Customized risk levels for different findings
- Dangerous Linux capabilities
- eBPF access risks to detect

See [config-example.yaml](config-example.yaml) for a complete example of the configuration format.

### Configuration Options

| Section | Description |
|---------|-------------|
| `sensitiveMounts` | Paths that are dangerous when mounted from host, including eBPF filesystems |
| `criticalPaths` | System paths that shouldn't be writable |
| `suspiciousCommands` | Binaries that shouldn't be in containers, including eBPF tools |
| `minerProcesses` | Cryptocurrency mining process patterns |
| `cloudCredentialEnvVars` | Environment variable patterns for cloud credentials |
| `dangerousCapabilities` | Linux capabilities with assigned risk levels, including eBPF capabilities |
| `dangerousPermissions` | RBAC permissions with assigned risk levels |
| `sensitivePatterns` | Regex patterns for identifying sensitive data |

## Example

```bash
# Scan a specific container and output to a file
kubectl tricorder -n production -p web-server -c app -o results.json

# Scan all containers in a pod with custom checks
kubectl tricorder -n database -p postgres --all-containers --config db-checks.yaml
```

## Security Checks

Kubectl-tricorder performs various security checks including:

### Container Security
- Privileged container detection
- Root user usage
- Writable critical filesystems
- Sensitive environment variables
- Excessive capabilities

### Kubernetes Configuration
- RBAC permission analysis
- Service account token mounts
- Network policy enforcement
- Excessive hostPath mounts
- Privileged pod settings

### Escape Vectors
- Docker socket access
- Host namespace usage (PID, Network, IPC)
- Sensitive mount points
- Kernel module loading
- cgroup manipulation

### eBPF Security
- CAP_BPF capability detection
- BPF filesystem access
- BPF syscall restrictions
- eBPF program presence detection
- eBPF tools presence

## Installation

### Using Krew (Recommended)

The easiest way to install kubectl-tricorder is via [Krew](https://krew.sigs.k8s.io/), the kubectl plugin manager:

```bash
# First install Krew if you don't have it
# See https://krew.sigs.k8s.io/docs/user-guide/setup/install/

# Then install tricorder plugin
kubectl krew install --manifest-url https://github.com/tks98/kubectl-tricorder/releases/download/vX.Y.Z/kubectl-tricorder.yaml
```

### Manual Download

You can download pre-built binaries for your platform:

```bash
# For Linux (x86_64)
curl -L https://github.com/tks98/kubectl-tricorder/releases/latest/download/kubectl-tricorder_vX.Y.Z_linux_amd64.tar.gz -o kubectl-tricorder.tar.gz

# For macOS (Intel)
curl -L https://github.com/tks98/kubectl-tricorder/releases/latest/download/kubectl-tricorder_vX.Y.Z_darwin_amd64.tar.gz -o kubectl-tricorder.tar.gz

# For macOS (Apple Silicon)
curl -L https://github.com/tks98/kubectl-tricorder/releases/latest/download/kubectl-tricorder_vX.Y.Z_darwin_arm64.tar.gz -o kubectl-tricorder.tar.gz

# Then for any platform
tar -xzf kubectl-tricorder.tar.gz
chmod +x kubectl-tricorder
sudo mv kubectl-tricorder /usr/local/bin/
```

Replace `vX.Y.Z` with the specific version you want to install, like `v0.1.0`.

### Build from Source

If you prefer to build from source:

```bash
git clone https://github.com/tks98/kubectl-tricorder.git
cd kubectl-tricorder
go build -o kubectl-tricorder
sudo mv kubectl-tricorder /usr/local/bin/
```

### Verify Installation

To verify the installation:

```bash
kubectl tricorder --help
```

You should see the command help output with all available options.

## Test Examples

The repository includes files to help you understand container security risks and see how kubectl-tricorder works:

### Test Pod Configuration

A deliberately insecure test pod configuration is provided in `test/test-pod.yaml`. This file contains numerous security issues including:

- Privileged container settings
- Excessive capabilities (SYS_ADMIN, NET_ADMIN, etc.)
- Sensitive host path mounts
- Cloud provider credentials in environment variables
- Exposed sensitive information in ConfigMaps
- Excessive RBAC permissions
- eBPF access risks
- Cryptocurrency mining simulation

You can use this file to safely test kubectl-tricorder in a lab environment:

```bash
# Apply the test configuration (do NOT use in production clusters)
kubectl apply -f test/test-pod.yaml

# Scan the test pod
kubectl tricorder -n default -p security-test-pod-insecure
```

### Example Output

An example of kubectl-tricorder's output when scanning the test pod is provided in `test/example-output.txt`. This shows:

- Critical, high, medium, and low-risk findings
- Detailed descriptions of each security issue
- Recommended mitigations for each finding
- Detection of cloud credentials, sensitive data, and risky configurations
- Identification of container escape vectors

These files are valuable for:
- Security training and education
- Testing your security scanning tools
- Understanding container security risks
- Demonstrating the capabilities of kubectl-tricorder

**WARNING:** The test pod configuration contains deliberate security risks and should only be deployed in isolated test environments, never in production clusters.
