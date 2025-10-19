Storj.Cloud Dashboard Agent

This repository contains the official client-side agent for the Storj.Cloud dashboard. The agent is composed of two services:

API Poller: Collects real-time performance and statistical data from your Storj node's local API.

Log Interpreter: Watches your Storj node's log file, parses important events, and sends them to the dashboard for analysis.

Features

Automated Setup: A single script handles installation, dependency checks, and service creation.

Automatic Node Detection: Automatically finds Storj nodes running in Docker containers on your system.

Seamless Registration: Automatically registers your detected nodes with your Storj.Cloud dashboard account.

Multi-Node Support: Natively supports monitoring multiple nodes running on a single machine.

Resilient Services: Runs as systemd services, ensuring they automatically start on boot and restart if they fail.

Quick Install

To install the agent, simply download the install.sh script and run it with sudo.

# Download the installer
wget https://your-public-repo-url/install.sh

# Make it executable
chmod +x install.sh

# Run the automated setup
sudo ./install.sh


The script will guide you through the entire process, including logging into your Storj.Cloud account. Once complete, your nodes will be configured, and data will begin appearing on your dashboard.

Requirements

A Linux system with systemd.

Docker installed and running.

curl, jq, and python3-venv must be installed. The script will attempt to install these for you if they are missing.