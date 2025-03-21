# kubectl-tricorder
A kubectl plugin that helps identify security risks in your Kubernetes pods by examining container configurations, privileges, and potential escape vectors.

## Features

- Detects container security issues including privilege escalations and escape vectors
- Examines mounted volumes, capabilities, and security contexts
- Analyzes RBAC permissions and service account configurations
- Identifies sensitive data exposure and risky configurations
- Detects specialized threats like eBPF security risks
- Allows customization via configuration files

## How It Works

kubectl-tricorder connects to your Kubernetes cluster and analyzes pod configurations through a combination of API queries and container inspection commands.

The tool works in several phases:

1. **API Analysis**: Gathers pod specifications and configuration data from the Kubernetes API
   
2. **Container Inspection**: Executes diagnostic commands inside containers using the Kubernetes exec API to check:
   - File permissions and sensitive paths
   - Running processes
   - Environment variables
   - Capabilities and privilege settings
   - System configurations

3. **Boundary Analysis**: Identifies potential container escape vectors by examining mount points, namespaces, and host access

4. **RBAC Evaluation**: Analyzes service account permissions available to the container

While the tool uses non-destructive read-only operations, **exercise caution in production environments**. The commands executed through the Kubernetes exec API could potentially impact sensitive applications or add load to production workloads. Consider testing in staging environments first or limiting scans to non-critical pods during maintenance windows.

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

The configuration file allows you to define custom security checks including sensitive paths, critical files, suspicious processes, and more. See [config-example.yaml](config-example.yaml) for a complete example.

### Configuration Options

| Section | Description |
|---------|-------------|
| `sensitiveMounts` | Paths that are dangerous when mounted from host |
| `criticalPaths` | System paths that shouldn't be writable |
| `suspiciousCommands` | Binaries that shouldn't be in containers |
| `minerProcesses` | Cryptocurrency mining process patterns |
| `cloudCredentialEnvVars` | Environment variable patterns for cloud credentials |
| `dangerousCapabilities` | Linux capabilities with assigned risk levels |
| `dangerousPermissions` | RBAC permissions with assigned risk levels |
| `sensitivePatterns` | Regex patterns for identifying sensitive data |

## Security Checks

kubectl-tricorder examines numerous security aspects including:

### Container Security
- Privileged containers and root usage
- Critical filesystem permissions
- Sensitive data exposure
- Excessive capabilities

### Kubernetes Configuration
- RBAC permissions
- Service account tokens
- Network policies
- hostPath mounts

### Escape Vectors
- Docker socket access
- Host namespace usage
- Sensitive mount points
- Kernel module access

### eBPF Security
- BPF capability and filesystem access
- Syscall restrictions
- eBPF tools and programs

## Installation

### Using Krew (Recommended)

```bash
# First install Krew if you don't have it
# See https://krew.sigs.k8s.io/docs/user-guide/setup/install/

# Then install tricorder plugin
kubectl krew install --manifest-url https://github.com/tks98/kubectl-tricorder/releases/download/vX.Y.Z/kubectl-tricorder.yaml
```

### Manual Download

Download pre-built binaries for your platform:

```bash
# For Linux (x86_64)
curl -L https://github.com/tks98/kubectl-tricorder/releases/latest/download/kubectl-tricorder_vX.Y.Z_linux_amd64.tar.gz -o kubectl-tricorder.tar.gz

# For macOS (Intel)
curl -L https://github.com/tks98/kubectl-tricorder/releases/latest/download/kubectl-tricorder_vX.Y.Z_darwin_amd64.tar.gz -o kubectl-tricorder.tar.gz

# For macOS (Apple Silicon)
curl -L https://github.com/tks98/kubectl-tricorder/releases/latest/download/kubectl-tricorder_vX.Y.Z_darwin_arm64.tar.gz -o kubectl-tricorder.tar.gz

# Extract and install
tar -xzf kubectl-tricorder.tar.gz
chmod +x kubectl-tricorder
sudo mv kubectl-tricorder /usr/local/bin/
```

Replace `vX.Y.Z` with the specific version you want to install, like `v0.1.0`.

### Build from Source

```bash
git clone https://github.com/tks98/kubectl-tricorder.git
cd kubectl-tricorder
go build -o kubectl-tricorder
sudo mv kubectl-tricorder /usr/local/bin/
```

Verify the installation with `kubectl tricorder --help`

## Testing and Examples

Provided is a deliberately insecure test pod configuration in `test/test-pod.yaml` to help you understand container security risks and see how kubectl-tricorder works. This pod contains numerous security issues including privileged settings, excessive capabilities, sensitive mounts, and more.

```bash
# Apply the test configuration (do NOT use in production clusters)
kubectl apply -f test/test-pod.yaml

# Scan the test pod
kubectl tricorder -n default -p security-test-pod-insecure
```

Check `test/example-output.txt` to see sample results that highlight various security issues and recommended mitigations.

**WARNING:** The test pod contains deliberate security risks and should only be deployed in isolated test environments.