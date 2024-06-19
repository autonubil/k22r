# k22r - Kubernetes IPFIX Exporter

k22r is a Kubernetes IPFIX Exporter that facilitates the collection and export of network flow information from a Kubernetes cluster using IPFIX (IP Flow Information Export) protocol.



[![GitHub license](https://img.shields.io/github/license/xanzy/go-gitlab.svg)](https://github.com/autonubil/k22r/blob/master/LICENSE)
[![Sourcegraph](https://sourcegraph.com/github.com/autonubil/go-wazuh/-/badge.svg)](https://sourcegraph.com/github.com/autonubil/k22r?badge)
[![GoDoc](https://godoc.org/github.com/autonubil/go-wazuh?status.svg)](https://godoc.org/github.com/autonubil/k22r)

## Table of Contents
   
- [k22r - Kubernetes IPFIX Exporter](#k22r---kubernetes-ipfix-exporter)
  - [Table of Contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Features](#features)
  - [Installation](#installation)
  - [Configuration](#configuration)
  - [Parameters and Environment Variables](#parameters-and-environment-variables)
    - [Parameters](#parameters)
    - [Environment Variables](#environment-variables)
  - [Usage](#usage)
  - [Contributing](#contributing)
  - [License](#license)

## Introduction

k22r is designed to gather network flow data within a Kubernetes environment and export it using the IPFIX protocol. This helps in monitoring and analyzing network traffic for performance, security, and auditing purposes.

## Features

- Collects network flow data from Kubernetes nodes
- Exports data using IPFIX protocol
- Easy deployment via Kubernetes DaemonSet

## Installation

To deploy k22r in your Kubernetes cluster, follow these steps:

1. Clone the repository:
    ```bash
    git clone https://github.com/autonubil/k22r.git
    cd k22r
    ```

2. Apply the DaemonSet configuration:
    ```bash
    kubectl apply -f deploy/daemonset.yaml
    ```

3. (Optional) Configure the firewall on your nodes:
    ```bash
    cp deploy/k22r.xml /usr/lib/firewalld/services/k22r.xml
    firewall-cmd --reload
    firewall-cmd --add-service k22r --zone <zone> --permanent
    ```

## Configuration

The configuration for k22r can be modified within the `deploy/daemonset.yaml` file. Key parameters include:

- **IPFIX collector address**: The IP address and port of the IPFIX collector
- **Sampling rate**: The rate at which packets are sampled

Adjust these settings according to your monitoring requirements.


## Parameters and Environment Variables

k22r uses the following parameters and environment variables:

### Parameters

- `--collector`, `-t`: Specifies the IPFIX target collector address.
- `--observationDomainId`, `-i`: Sets the observation domain identifier.
- `--observationDomainName`, `-n`: Sets the observation domain name.
- `--groupName`, `-g`: Sets the group name, useful for distinguishing clusters.
- `--exporterIp`, `-e`: Sets the exporter IP address.
- `--activeTimeout`: Specifies the active flow timeout duration in seconds.
- `--idleTimeout`: Specifies the idle flow timeout duration in seconds.
- `--cpuprofile`: Writes CPU profile to the specified file.
- `--memprofile`: Writes memory profile to the specified file.
- `--blockprofile`: Enables blocking profile.
- `--prometheus-port`: Sets the port for Prometheus metrics (default: 9943).
- `--prometheus-enabled`: Enables Prometheus metrics export (default: true).
- `--prometheus-dump`: Dumps Prometheus metrics after execution.

Example:
```bash
k22r --collector "192.168.1.100:4739" --observationDomainId 1234 --observationDomainName "domain1" --groupName "cluster1" --exporterIp "10.0.0.1" --activeTimeout 300 --idleTimeout 60 --prometheus-port 9090 --prometheus-enabled true
```

### Environment Variables

- `K22R_COLLECTOR`: Can be used to set the IPFIX target collector address.
- `K22R_OBSERVATION_DOMAIN_NAME`: Can be used to set the observation domain name.
- `K22R_GROUP_NAME`: Can be used to set the group name.
- `K22R_EXPORTER_IP`: Can be used to set the exporter IP address.
- `K22R_IDLE_TIMEOUT`: Can be used to set the flow idle timeout.
- `K22R_ACTIVE_TIMEOUT`: Can be used to set the flow active timeout.

Example:
```bash
export K22R_IDLE_TIMEOUT=360
export K22R_ACTIVE_TIMEOUT=60
export K22R_COLLECTOR="192.168.1.100:4739"
export K22R_OBSERVATION_DOMAIN_NAME="domain1"
export K22R_GROUP_NAME="cluster1"
export K22R_EXPORTER_IP="10.0.0.1"
k22r
```


## Usage

Once deployed, k22r will automatically start collecting and exporting network flow data from all nodes in your Kubernetes cluster. The data can be analyzed using an IPFIX collector tool.

## Contributing

We welcome contributions to the k22r project. If you want to contribute, please follow these steps:

1. Fork the repository
2. Create a new branch (`git checkout -b feature-branch`)
3. Commit your changes (`git commit -am 'Add new feature'`)
4. Push to the branch (`git push origin feature-branch`)
5. Create a new Pull Request

Please ensure your code adheres to our coding standards and includes appropriate tests.

## License

This project is licensed under the BSD 3-Clause License. See the [LICENSE](LICENSE) file for details.
 
