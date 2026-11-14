# CCP Captive Portal 

While going from hostel to college and from college to hostel, there's always a problem with laptops connecting to Wi-Fi and opening captive portals.

**ccp** is a lightweight, zero-lag CLI tool that stores your login details, dynamically discovers the local gateway using Firefox CaptiveDetect probe (<20ms), and automatically authenticates you across subnets.

## Installation

### Linux, macOS & WSL

Install in one command using `curl`:

```bash
curl -fsSL https://raw.githubusercontent.com/garvittsingla/ccp/main/install.sh | bash
```

### Windows (Native PowerShell)

Install natively in Windows without WSL using PowerShell:

```powershell
irm https://raw.githubusercontent.com/garvittsingla/ccp/main/install.ps1 | iex
```

## Usage

### 1. Set Credentials
Save your captive portal username and password:
```bash
ccp set
```

### 2. Authenticate
Run `ccp` anytime you connect to Wi-Fi:
```bash
ccp
```
