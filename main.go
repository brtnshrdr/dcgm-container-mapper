package main

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/protobuf/proto"
)

var (
	logLevel       string
	reexportDCGM   bool
	dcgmPort       string
	port           string
	listenAddress  string
	updateInterval time.Duration
	gpuInfo        map[string]*GPUInfo // Static GPU information, initialized once at startup (UUID -> GPU details)
	activeGPUs     map[string]*ContainerMapping
	processes      []GPUProcess
	mutex          sync.RWMutex
	logger         *zap.SugaredLogger

	containerMappingMetric = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dcgm_container_mapping",
			Help: "Mapping between GPU ID and container and process name",
		},
		[]string{"gpu", "modelName", "UUID", "container", "process"},
	)

	registry = prometheus.NewRegistry()
)

func init() {
	// Register the metric with our registry instead of the default one
	registry.MustRegister(containerMappingMetric)
}

// initLogger initializes the zap logger with the specified level
func initLogger(level string) {
	// Parse log level
	var zapLevel zapcore.Level
	if err := zapLevel.UnmarshalText([]byte(level)); err != nil {
		log.Fatalf("Invalid log level %q: %v", level, err)
	}

	// Create logger configuration
	config := zap.Config{
		Level:            zap.NewAtomicLevelAt(zapLevel),
		Development:      false,
		Encoding:         "console",
		EncoderConfig:    zap.NewProductionEncoderConfig(),
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
	}

	// Customize time format
	config.EncoderConfig.EncodeTime = zapcore.TimeEncoderOfLayout("2006-01-02 15:04:05.000")
	config.EncoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder

	// Create logger
	baseLogger, err := config.Build()
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	logger = baseLogger.Sugar()
}

// DCGMMetric represents a single metric from DCGM exporter
type DCGMMetric struct {
	// Labels is a key-value map of the metric's labels (e.g., "UUID", "name")
	Labels    map[string]string `json:"labels"`
	Value     float64           `json:"value"`
	Timestamp int64             `json:"timestamp"`
}

// GPUInfo contains GPU details retrieved at startup (index, UUID, model name).
type GPUInfo struct {
	// Index is the numeric index from nvidia-smi (e.g., "0", "1").
	Index string
	UUID  string
	Name  string // GPU model name (e.g. "Tesla V100")
}

// GPUProcess describes a process on a GPU, including PID and process name.
type GPUProcess struct {
	GPUUUID     string
	PID         string
	ProcessName string
}

// ContainerMapping links a GPU to an associated Docker container.
type ContainerMapping struct {
	ContainerID   string
	ContainerName string
	GPUIndex      string
	GPUName       string
}

// String returns the Prometheus format string representation of the metric
func (m DCGMMetric) String() string {
	// Build labels string
	var labels []string
	for k, v := range m.Labels {
		labels = append(labels, fmt.Sprintf("%s=\"%s\"", k, v))
	}
	labelStr := strings.Join(labels, ",")

	// Format the metric line
	if m.Timestamp > 0 {
		return fmt.Sprintf("%s{%s} %g %d", m.Labels["__name__"], labelStr, m.Value, m.Timestamp)
	}
	return fmt.Sprintf("%s{%s} %g", m.Labels["__name__"], labelStr, m.Value)
}

func initGPUMapping() error {
	logger.Debug("Initializing GPU information")
	cmd := exec.Command("nvidia-smi", "--query-gpu=index,uuid,name", "--format=csv,noheader")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to execute nvidia-smi --query-gpu: %v", err)
	}
	logger.Debug("nvidia-smi GPU query output: %s", string(output))

	gpuInfo = make(map[string]*GPUInfo)
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, ", ")
		if len(fields) == 3 {
			gpuInfo[fields[1]] = &GPUInfo{
				Index: fields[0],
				UUID:  fields[1],
				Name:  fields[2],
			}
			logger.Debugf("Found GPU: Index=%s, UUID=%s, Name=%s", fields[0], fields[1], fields[2])
		}
	}

	if len(gpuInfo) == 0 {
		return fmt.Errorf("no GPUs found in nvidia-smi output")
	}
	logger.Infof("Found %d GPUs", len(gpuInfo))
	return nil
}

func getGPUProcesses() ([]GPUProcess, error) {
	logger.Debug("Executing nvidia-smi command")
	cmd := exec.Command("nvidia-smi", "--query-compute-apps=gpu_uuid,gpu_name,pid,name", "--format=csv,noheader")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to execute nvidia-smi: %v, output: %s", err, string(output))
	}
	logger.Debug("nvidia-smi raw output: %s", string(output))

	var processes []GPUProcess
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		logger.Debugf("Processing line: %s", line)
		fields := strings.Split(line, ", ")
		logger.Debugf("Split into %d fields: %v", len(fields), fields)
		if len(fields) == 4 {
			uuid := fields[0]
			if _, ok := gpuInfo[uuid]; !ok {
				logger.Warnf("No GPU info found for UUID %s", uuid)
				continue
			}

			process := GPUProcess{
				GPUUUID:     uuid,
				PID:         fields[2],
				ProcessName: fields[3],
			}
			logger.Debugf("Created process entry: %+v", process)
			processes = append(processes, process)
		} else {
			logger.Debug("Skipping line due to incorrect field count")
		}
	}

	return processes, nil
}

func getContainerIDFromPID(pid string) (string, error) {
	cgroupPath := fmt.Sprintf("/proc/%s/cgroup", pid)
	logger.Debugf("Reading cgroup file: %s", cgroupPath)
	content, err := os.ReadFile(cgroupPath)
	if err != nil {
		return "", fmt.Errorf("failed to read cgroup file: %v", err)
	}
	content = bytes.TrimSpace(content)
	logger.Debugf("Cgroup content: %s", string(content))

	// Matches cgroup path like "0::/system.slice/docker-<64-character-hex>.scope"
	re := regexp.MustCompile(`^0::/system\.slice/docker-([a-f0-9]{64})\.scope$`)
	matches := re.FindStringSubmatch(string(content))

	if len(matches) > 1 {
		logger.Debugf("Found container ID: %s", matches[1])
		return matches[1], nil
	}

	return "", fmt.Errorf("no container ID found for PID %s", pid)
}

func getContainerName(containerID string) (string, error) {
	logger.Debugf("Getting container name for ID: %s", containerID)
	cmd := exec.Command("docker", "inspect", "--format", "{{.Name}}", containerID)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get container name: %v", err)
	}

	name := strings.TrimSpace(string(output))
	name = strings.TrimPrefix(name, "/")
	logger.Debugf("Container name: %s", name)
	return name, nil
}

func getDCGMMetrics() (map[string]*dto.MetricFamily, error) {
	dcgmURL := fmt.Sprintf("http://localhost:%s/metrics", dcgmPort)
	logger.Debugf("Fetching DCGM metrics from %s", dcgmURL)

	resp, err := http.Get(dcgmURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch DCGM metrics: %v", err)
	}
	defer resp.Body.Close()

	var parser expfmt.TextParser
	metricFamilies, err := parser.TextToMetricFamilies(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse metrics: %v", err)
	}

	return metricFamilies, nil
}

func getGPUProcessContainerMapping() (map[string]*ContainerMapping, []GPUProcess, error) {
	processes, err := getGPUProcesses()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get GPU processes: %v", err)
	}

	// Build UUID to container mapping
	activeGPUs := make(map[string]*ContainerMapping)
	for _, process := range processes {
		containerID, err := getContainerIDFromPID(process.PID)
		if err != nil {
			logger.Warnf("Could not get container ID for PID %s: %v", process.PID, err)
			continue
		}

		containerName, err := getContainerName(containerID)
		if err != nil {
			logger.Warnf("Could not get container name for ID %s: %v", containerID, err)
			continue
		}

		gpu := gpuInfo[process.GPUUUID]
		activeGPUs[process.GPUUUID] = &ContainerMapping{
			ContainerID:   containerID,
			ContainerName: containerName,
			GPUIndex:      gpu.Index,
			GPUName:       gpu.Name,
		}
	}

	return activeGPUs, processes, nil
}

func updateGPUInfo(ctx context.Context) {
	ticker := time.NewTicker(updateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			newActiveGPUs, newProcesses, err := getGPUProcessContainerMapping()
			if err != nil {
				logger.Errorf("Error updating GPU information: %v", err)
				continue
			}

			mutex.Lock()
			activeGPUs = newActiveGPUs
			processes = newProcesses
			mutex.Unlock()

			logger.Debugf("Updated GPU information: %d active GPUs, %d processes", len(activeGPUs), len(processes))
		}
	}
}

func metricsHandler(w http.ResponseWriter, r *http.Request) {
	// The primary handler for our /metrics endpoint.
	logger.Debugf("Request for /metrics from %s", r.RemoteAddr)

	if reexportDCGM {
		// We fetch raw DCGM metrics, then append our container labels before serving them back out.
		metricFamilies, err := getDCGMMetrics()
		if err != nil {
			logger.Errorf("Error getting DCGM metrics: %v", err)
			http.Error(w, fmt.Sprintf("Failed to get DCGM metrics: %v", err), http.StatusInternalServerError)
			return
		}

		// Create an encoder that will write the metrics in text format
		contentType := expfmt.Negotiate(r.Header)
		encoder := expfmt.NewEncoder(w, contentType)

		mutex.RLock()
		localActiveGPUs := activeGPUs
		mutex.RUnlock()

		// Process each metric family
		for _, mf := range metricFamilies {
			// For each metric in the family
			for _, metric := range mf.GetMetric() {
				// Check if this metric has a GPU UUID label
				var uuid string
				for _, label := range metric.GetLabel() {
					if label.GetName() == "UUID" {
						uuid = label.GetValue()
						break
					}
				}

				// Always add our custom labels, using container info if available
				containerName := ""
				if containerInfo, ok := localActiveGPUs[uuid]; ok {
					containerName = containerInfo.ContainerName
				}

				metric.Label = append(metric.Label,
					&dto.LabelPair{
						Name:  proto.String("exported_pod"),
						Value: proto.String(containerName),
					},
					&dto.LabelPair{
						Name:  proto.String("exported_container"),
						Value: proto.String(containerName),
					},
					&dto.LabelPair{
						Name:  proto.String("exported_namespace"),
						Value: proto.String("docker"),
					},
				)
			}

			// Encode the metric family
			if err := encoder.Encode(mf); err != nil {
				logger.Errorf("Error encoding metric family: %v", err)
				http.Error(w, fmt.Sprintf("Failed to encode metrics: %v", err), http.StatusInternalServerError)
				return
			}
		}
		return
	}

	mutex.RLock()
	localProcesses := processes
	localActiveGPUs := activeGPUs
	mutex.RUnlock()

	logger.Debugf("Found %d GPU processes", len(localProcesses))

	// Create metrics for each GPU: one base metric for the GPU itself and additional metrics for any running processes
	for uuid, gpu := range gpuInfo {
		containerMappingMetric.With(prometheus.Labels{
			"gpu":       gpu.Index,
			"modelName": gpu.Name,
			"UUID":      uuid,
			"container": "",
			"process":   "",
		}).Set(0)

		for _, process := range localProcesses {
			if process.GPUUUID == uuid {
				containerName := ""
				if containerInfo, ok := localActiveGPUs[uuid]; ok {
					containerName = containerInfo.ContainerName
				}
				containerMappingMetric.With(prometheus.Labels{
					"gpu":       gpu.Index,
					"modelName": gpu.Name,
					"UUID":      uuid,
					"container": containerName,
					"process":   process.ProcessName,
				}).Set(0)
			}
		}
	}

	metricFamilies, err := registry.Gather()
	if err != nil {
		logger.Errorf("Error gathering metrics: %v", err)
		http.Error(w, fmt.Sprintf("Failed to gather metrics: %v", err), http.StatusInternalServerError)
		return
	}

	contentType := expfmt.Negotiate(r.Header)
	encoder := expfmt.NewEncoder(w, contentType)

	for _, mf := range metricFamilies {
		if err := encoder.Encode(mf); err != nil {
			logger.Errorf("Error encoding metric family: %v", err)
			http.Error(w, fmt.Sprintf("Failed to encode metrics: %v", err), http.StatusInternalServerError)
			return
		}
	}

	logger.Debug("Finished writing metrics")
}

func main() {
	// Parse command line flags
	flag.StringVar(&logLevel, "log-level", "info", "Logging level (debug, info, warn, error)")
	flag.BoolVar(&reexportDCGM, "reexport-dcgm", false, "Enable re-exporting DCGM metrics")
	flag.StringVar(&dcgmPort, "dcgm-port", "9400", "DCGM exporter port (default: 9400)")
	flag.StringVar(&port, "port", "9100", "Port to listen on (default: 9100)")
	flag.StringVar(&listenAddress, "listen-address", "localhost", "Address to listen on (default: localhost)")
	flag.DurationVar(&updateInterval, "update-interval", 5*time.Second, "Interval to update GPU information (default: 5s)")
	flag.Parse()

	// Initialize logger
	initLogger(logLevel)
	defer logger.Sync()

	// Initialize GPU UUID to ID mapping
	if err := initGPUMapping(); err != nil {
		logger.Fatalf("Failed to initialize GPU mapping: %v", err)
	}

	// Initialize active GPUs and processes
	var err error
	activeGPUs, processes, err = getGPUProcessContainerMapping()
	if err != nil {
		logger.Fatalf("Failed to initialize GPU process mapping: %v", err)
	}

	// Start background GPU information update
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go updateGPUInfo(ctx)

	// Register metrics handler
	http.HandleFunc("/metrics", metricsHandler)

	logger.Infof("Starting metrics server on %s", port)
	logger.Infof("Metrics available at http://%s:%s/metrics", listenAddress, port)
	logger.Infof("Updating GPU information every %v", updateInterval)
	if reexportDCGM {
		logger.Infof("Re-exporting DCGM metrics from port %s", dcgmPort)
	}

	if err := http.ListenAndServe(listenAddress+":"+port, nil); err != nil {
		logger.Fatalf("Failed to start server: %v", err)
	}
}
