# CCP Captive Portal 

While going from hostel to college and from college to hostel, there's always problem with my laptop connecting to wifi and opening captative portal, this is the same experienced by my fellow classmates and hostelmates.

So i thought why not fixing it with a simple cli tool which just saves your login details and automatically connect you with wifi and authenticate your captative portal.

## Installation

Install in one command using `curl`:

```bash
curl -fsSL https://raw.githubusercontent.com/garvittsingla/ccp/main/install.sh | bash
```

> Works seamlessly on **macOS** (Apple Silicon & Intel), **Linux**, and **WSL**.

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



