# kubectl-tricorder
A kubectl plugin for scanning and analyzing Kubernetes container security posture. Like a Star Trek tricorder for your clusters - identifies vulnerabilities, capability issues, and escape vectors in your pods.

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

Download the latest release binary and place it in your PATH:

```bash
curl -L https://github.com/yourusername/kubectl-tricorder/releases/latest/download/kubectl-tricorder -o kubectl-tricorder
chmod +x kubectl-tricorder
sudo mv kubectl-tricorder /usr/local/bin/
```

Or build from source:

```bash
git clone https://github.com/yourusername/kubectl-tricorder.git
cd kubectl-tricorder
go build -o kubectl-tricorder
sudo mv kubectl-tricorder /usr/local/bin/
```
