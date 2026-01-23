# Benchmark Environment Notes

results for the paper were gathered on a single VM.

## System Specifications

**OS:** Ubuntu 22.04.5 LTS (Jammy)

**CPU:** AMD EPYC 8224P 24-Core Processor
- 48 CPUs (24 cores × 2 threads)
- 1 socket

**Memory:** 188 GB total, 180 GB available

**GPU:** NVIDIA L4
- 23 GB VRAM
- Driver: 570.195.03
- CUDA Version: 12.8

## What I had to setup

**NVIDIA Container Toolkit** - Required for Docker GPU access
   ```bash
   # Add repository
   distribution=$(. /etc/os-release;echo $ID$VERSION_ID)
   curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey | sudo gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg
   curl -s -L https://nvidia.github.io/libnvidia-container/$distribution/libnvidia-container.list | sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' | sudo tee /etc/apt/sources.list.d/nvidia-container-toolkit.list
   
   # Install
   sudo apt-get update
   sudo apt-get install -y nvidia-container-toolkit
   
   # Configure Docker
   sudo nvidia-ctk runtime configure --runtime=docker
   sudo systemctl restart docker
   ```