# GPU to Docker Container Metrics Exporter

A Prometheus exporter that enhances DCGM (Data Center GPU Manager) metrics with Docker container mapping information. This exporter is designed to work alongside DCGM Exporter, enriching its metrics with container-level information to provide better observability of GPU usage in containerized environments.

## Features

- Re-exports DCGM metrics with added container information (primary use case)
- Maps GPU metrics to Docker container names
- Adds container name information to DCGM metrics
- Real-time monitoring of GPU processes and their container associations
- Configurable update intervals and logging levels

## Prerequisites

- Go 1.x or higher
- NVIDIA GPU(s)
- NVIDIA drivers installed
- DCGM Exporter running in your environment
- `nvidia-smi` command-line tool
- Docker runtime

## Installation

### Pre-built Binaries

You can download pre-built binaries for Linux (AMD64 and ARM64) from the [releases page](../../releases).

```bash
# Download the latest release for your architecture
# For AMD64:
curl -L -o gpu-metrics-exporter "https://github.com/brtnshrdr/dcgm-container-mapper/releases/latest/download/gpu-metrics-exporter-linux-amd64"
# For ARM64:
curl -L -o gpu-metrics-exporter "https://github.com/brtnshrdr/dcgm-container-mapper/releases/latest/download/gpu-metrics-exporter-linux-arm64"

# Make it executable
chmod +x gpu-metrics-exporter
```

### Building from Source

```bash
# Clone the repository
git clone https://github.com/brtnshrdr/dcgm-container-mapper.git
cd dcgm-container-mapper

# Install dependencies
go mod tidy

# Build the binary
go build -o gpu-metrics-exporter main.go
# On MacOS, use the following command to build for Linux
GOOS=linux GOARCH=amd64 go build -o gpu-metrics-exporter main.go
```

## Usage

The most common usage is with DCGM re-export enabled:

```bash
./gpu-metrics-exporter --reexport-dcgm --dcgm-port 9400
```

This mode is recommended because:
1. It preserves all valuable DCGM metrics (GPU utilization, memory usage, temperature, etc.)
2. Adds container context to these metrics (container name, pod name, namespace)
3. Maintains compatibility with existing DCGM-based dashboards while adding container visibility
4. Enables better correlation between GPU metrics and container performance

### Command Line Flags

- `--reexport-dcgm`: Enable re-exporting of DCGM metrics [default: false] (Recommended to enable)
- `--dcgm-port`: DCGM exporter port to read from [default: "9400"]
- `--port`: Port to listen on [default: "9100"]
- `--listen-address`: Address to listen on [default: "localhost"]
- `--update-interval`: Interval to update GPU information [default: 5s]
- `--log-level`: Set logging level (debug, info, warn, error) [default: "info"]

## Metrics

The exporter provides metrics in two modes:

### Re-export Mode (Recommended)
When running with `--reexport-dcgm`, all DCGM metrics are re-exported with additional container context labels:
- `exported_pod`
- `exported_container`
- `exported_namespace`

exported_pod will always equal exported_container, and exported_namespace will always be "docker". This is to align with "Kubernetes mode" (DCGM_EXPORTER_KUBERNETES=true) of the DCGM exporter.

This enriches the standard DCGM metrics with container information, making it easier to track GPU usage per container/pod.

### Basic Mode (Limited)
Without `--reexport-dcgm`, only basic GPU-to-container mapping is provided:
```
# HELP gpu_container_mapping Mapping between GPU ID and container and process name
# TYPE gpu_container_mapping gauge
```

Metric format:
```
gpu_container_mapping{gpu="0",modelName="Tesla V100",UUID="GPU-xxx",container="container_name",process="process_name"} 0
```

## Example

1. Start the exporter:
```bash
./gpu-metrics-exporter --port 9100 --log-level debug
```

2. Access metrics:
```bash
curl http://localhost:9100/metrics
```

## Monitoring Setup

### Prometheus Configuration

Add the following to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'gpu-metrics'
    static_configs:
      - targets: ['localhost:9100']
```

## Development

### Building from Source

```bash
go build -o gpu-metrics-exporter main.go
```