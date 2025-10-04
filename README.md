
# PowerDNS AdGuard Shim

The main goal of this shim is to enable the use of the PowerDNS plugin in Proxmox SDN with AdGuard, allowing AdGuard to manage DNS records for guests in Proxmox SDN zones. This adapter bridges PowerDNS and AdGuard, so that DNS records for virtual machines and containers managed by Proxmox SDN can be automatically handled by AdGuard.

It is designed to be run as a service, typically using Docker.

## Features
- Acts as a bridge between PowerDNS and AdGuard
- Simple configuration via environment variables
- Docker support for easy deployment

## Requirements
- Python 3.12+
- See `requirements.txt` for Python dependencies
- Docker (optional, for containerized deployment)

## Usage

### 1. Clone the repository
```bash
git clone https://github.com/simoncaron/powerdns-adguard-shim
cd powerdns-adguard-shim
```

### 2. Configure Environment
Copy the example environment file and edit as needed:
```bash
cp .env.example .env
# Edit .env to match your configuration
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the Shim
```bash
python powerdns_adguard_shim.py
```

Or with Docker:
```bash
docker-compose up --build
```

## Configuration
All configuration is done via environment variables. See `.env.example` for available options.

## License
MIT License
