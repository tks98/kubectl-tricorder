package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	log "github.com/sirupsen/logrus"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

// Version information - will be set during build
var (
	Version = "dev" // This will be overridden during build
)

func main() {
	// Initialize Logrus for structured logging.
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})

	var namespace, pod, container, outputFile, configFile string
	var verbose, scanAllContainers, showVersion bool

	// Command-line flag parsing.
	flag.StringVar(&namespace, "namespace", "", "Namespace of the target pod")
	flag.StringVar(&namespace, "n", "", "Namespace of the target pod (shorthand)")
	flag.StringVar(&pod, "pod", "", "Name of the target pod")
	flag.StringVar(&pod, "p", "", "Name of the target pod (shorthand)")
	flag.StringVar(&container, "container", "", "Name of the target container")
	flag.StringVar(&container, "c", "", "Name of the target container (shorthand)")
	flag.StringVar(&outputFile, "output", "", "Output file for JSON report")
	flag.StringVar(&outputFile, "o", "", "Output file for JSON report (shorthand)")
	flag.StringVar(&configFile, "config", "", "Path to configuration file")
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose output")
	flag.BoolVar(&verbose, "v", false, "Enable verbose output (shorthand)")
	flag.BoolVar(&scanAllContainers, "all-containers", false, "Scan all containers in the pod")
	flag.BoolVar(&scanAllContainers, "a", false, "Scan all containers in the pod (shorthand)")
	flag.BoolVar(&showVersion, "version", false, "Show version information and exit")
	flag.BoolVar(&showVersion, "V", false, "Show version information and exit (shorthand)")
	flag.Parse()

	// Handle version flag first
	if showVersion {
		fmt.Printf("kubectl-tricorder version %s\n", Version)
		os.Exit(0)
	}

	// Print banner.
	fmt.Println(`
╔═══════════════════════════════════════════════════╗
║          kubectl-tricorder - Container Security   ║
║        "I'm a scanner, not a miracle worker!"     ║
║        Making your clusters secure, Captain       ║
║          For authorized security testing only.    ║
╚═══════════════════════════════════════════════════╝
`)

	// Validate required flags.
	if namespace == "" || pod == "" {
		fmt.Println("Error: namespace and pod name are required")
		flag.Usage()
		os.Exit(1)
	}

	// Load configuration
	cfg, err := LoadConfig(configFile)
	if err != nil {
		fmt.Printf("Error loading configuration: %v\n", err)
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

	// Setup kubernetes client
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

	// Get pod details
	podInfo, err := clientset.CoreV1().Pods(namespace).Get(context.TODO(), pod, metav1.GetOptions{})
	if err != nil {
		fmt.Printf("Error getting pod details: %v\n", err)
		os.Exit(1)
	}

	// Determine which containers to scan
	containersToScan := []string{}
	if container != "" {
		// Scan the specified container
		containerExists := false
		for _, c := range podInfo.Spec.Containers {
			if c.Name == container {
				containerExists = true
				break
			}
		}
		if !containerExists {
			fmt.Printf("Error: container '%s' not found in pod\n", container)
			os.Exit(1)
		}
		containersToScan = append(containersToScan, container)
	} else if scanAllContainers {
		// Scan all containers in the pod
		for _, c := range podInfo.Spec.Containers {
			containersToScan = append(containersToScan, c.Name)
		}
		fmt.Printf("Scanning all %d containers in pod\n", len(containersToScan))
	} else {
		// Default: scan the first container
		if len(podInfo.Spec.Containers) > 0 {
			container = podInfo.Spec.Containers[0].Name
			containersToScan = append(containersToScan, container)
			fmt.Printf("Using container: %s\n", container)
		} else {
			fmt.Println("No containers found in the pod")
			os.Exit(1)
		}
	}

	// Results for all containers
	allFindings := []Finding{}
	allRisks := map[string]int{RISK_LOW: 0, RISK_MEDIUM: 0, RISK_HIGH: 0, RISK_CRITICAL: 0}
	var allReports []Report

	// Scan each container
	for _, containerName := range containersToScan {
		fmt.Printf("\nScanning container: %s\n", containerName)

		// Create and run the security tester for this container
		tester, err := newSecurityTester(namespace, pod, containerName, verbose, cfg)
		if err != nil {
			fmt.Printf("Error initializing security tester for container %s: %v\n", containerName, err)
			continue
		}
		tester.scanAllContainers = scanAllContainers

		tester.runAllChecks()
		report := tester.generateReport()
		allReports = append(allReports, report)

		// Aggregate findings and risks
		allFindings = append(allFindings, report.Findings...)
		for risk, count := range report.RiskSummary {
			allRisks[risk] += count
		}

		// Print container summary
		fmt.Printf("\n=== Container Security Results: %s ===\n", containerName)
		fmt.Printf("%s: %d\n", color.RedString("Critical issues"), report.RiskSummary[RISK_CRITICAL])
		fmt.Printf("%s: %d\n", color.YellowString("High risk issues"), report.RiskSummary[RISK_HIGH])
		fmt.Printf("%s: %d\n", color.CyanString("Medium risk issues"), report.RiskSummary[RISK_MEDIUM])
		fmt.Printf("%s: %d\n", color.GreenString("Low risk issues"), report.RiskSummary[RISK_LOW])
	}

	// Print overall summary if scanning multiple containers
	if len(containersToScan) > 1 {
		fmt.Printf("\n=== Overall Pod Security Results ===\n")
		fmt.Printf("Pod: %s\n", pod)
		fmt.Printf("Namespace: %s\n", namespace)
		fmt.Printf("Containers scanned: %d\n", len(containersToScan))
		fmt.Printf("%s: %d\n", color.RedString("Critical issues"), allRisks[RISK_CRITICAL])
		fmt.Printf("%s: %d\n", color.YellowString("High risk issues"), allRisks[RISK_HIGH])
		fmt.Printf("%s: %d\n", color.CyanString("Medium risk issues"), allRisks[RISK_MEDIUM])
		fmt.Printf("%s: %d\n", color.GreenString("Low risk issues"), allRisks[RISK_LOW])
	}

	// Output detailed findings either to a file or to the console.
	if outputFile != "" {
		var outputData interface{}
		if len(containersToScan) > 1 {
			// Create a combined report for all containers
			combinedReport := struct {
				PodName          string         `json:"pod_name"`
				Namespace        string         `json:"namespace"`
				ScanTime         string         `json:"scan_time"`
				RiskSummary      map[string]int `json:"risk_summary"`
				ContainerReports []Report       `json:"container_reports"`
			}{
				PodName:          pod,
				Namespace:        namespace,
				ScanTime:         time.Now().Format(time.RFC3339),
				RiskSummary:      allRisks,
				ContainerReports: allReports,
			}
			outputData = combinedReport
		} else if len(allReports) > 0 {
			// Just use the single container report
			outputData = allReports[0]
		}

		jsonData, err := json.MarshalIndent(outputData, "", "  ")
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
	} else if len(allFindings) > 0 {
		// Print detailed findings to console
		fmt.Println("\n=== Detailed Findings ===")
		for _, finding := range allFindings {
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
