#!/usr/bin/env python3
"""
PowerDNS to AdGuard Home API Shim
Translates PowerDNS API calls to AdGuard Home API calls
Compatible with Proxmox SDN PowerDNS Plugin
"""

from flask import Flask, request, jsonify
import requests
from requests.auth import HTTPBasicAuth
import ipaddress
import re
import logging

# Configuration from environment variables (Docker-friendly)
import os

ADGUARD_URL = os.getenv("ADGUARD_URL", "http://localhost:3000")
ADGUARD_USER = os.getenv("ADGUARD_USER", "admin")
ADGUARD_PASS = os.getenv("ADGUARD_PASS", "password")
POWERDNS_API_KEY = os.getenv("POWERDNS_API_KEY", "your-api-key-here")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

app = Flask(__name__)
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

class AdGuardClient:
    """Client for AdGuard Home API"""
    
    def __init__(self, url, username, password):
        self.url = url.rstrip('/')
        self.auth = HTTPBasicAuth(username, password)
    
    def list_rewrites(self):
        """Get all DNS rewrites from AdGuard"""
        resp = requests.get(
            f"{self.url}/control/rewrite/list",
            auth=self.auth
        )
        resp.raise_for_status()
        return resp.json()
    
    def add_rewrite(self, domain, answer):
        """Add a DNS rewrite to AdGuard"""
        data = {
            "domain": domain,
            "answer": answer
        }
        resp = requests.post(
            f"{self.url}/control/rewrite/add",
            json=data,
            auth=self.auth
        )
        resp.raise_for_status()
        return resp.status_code
    
    def delete_rewrite(self, domain, answer):
        """Delete a DNS rewrite from AdGuard"""
        data = {
            "domain": domain,
            "answer": answer
        }
        resp = requests.post(
            f"{self.url}/control/rewrite/delete",
            json=data,
            auth=self.auth
        )
        resp.raise_for_status()
        return resp.status_code

adguard = AdGuardClient(ADGUARD_URL, ADGUARD_USER, ADGUARD_PASS)

def check_auth():
    """Verify PowerDNS API key"""
    api_key = request.headers.get('X-API-Key')
    if api_key != POWERDNS_API_KEY:
        app.logger.warning("Invalid API key")
        return False
    return True

def is_ipv6(ip):
    """Check if IP is IPv6"""
    try:
        return ipaddress.ip_address(ip).version == 6
    except:
        return False

def normalize_domain(domain):
    """Remove trailing dot from FQDN if present"""
    return domain.rstrip('.')

def get_record_type(answer):
    """Determine DNS record type from answer"""
    if is_ipv6(answer):
        return "AAAA"
    elif re.match(r'^\d+\.\d+\.\d+\.\d+$', answer):
        return "A"
    else:
        return "CNAME"

def delete_rewrites_by_type(domain, record_type):
    """Delete all AdGuard rewrites for a domain that match the record type"""
    existing_rewrites = adguard.list_rewrites()
    deleted_count = 0
    
    for rewrite in existing_rewrites:
        if normalize_domain(rewrite.get('domain', '')) == normalize_domain(domain):
            answer = rewrite.get('answer', '')
            if get_record_type(answer) == record_type:
                try:
                    adguard.delete_rewrite(normalize_domain(domain), answer)
                    deleted_count += 1
                    app.logger.info(f"Deleted {domain} -> {answer}")
                except Exception as e:
                    app.logger.error(f"Failed to delete {domain} -> {answer}: {e}")
    
    return deleted_count

def convert_rewrites_to_rrsets(rewrites, zone):
    """Convert AdGuard rewrites to PowerDNS rrsets format"""
    rrsets = []
    zone_suffix = f".{zone}."
    
    # Group rewrites by domain and type
    records_by_name = {}
    
    for rewrite in rewrites:
        domain = rewrite.get('domain', '')
        answer = rewrite.get('answer', '')
        
        # Skip if not in this zone
        # Accept both "hostname.zone" and "hostname.zone."
        normalized_domain = normalize_domain(domain)
        normalized_zone = normalize_domain(zone)
        
        if not (normalized_domain.endswith(normalized_zone) or 
                normalized_domain.endswith(f".{normalized_zone}")):
            # Also check if domain is exactly the zone
            if normalized_domain != normalized_zone:
                continue
        
        # Ensure FQDN format (with trailing dot)
        fqdn = domain if domain.endswith('.') else f"{domain}."
        
        # Determine record type
        record_type = get_record_type(answer)
        
        key = (fqdn, record_type)
        if key not in records_by_name:
            records_by_name[key] = []
        
        records_by_name[key].append({
            "content": answer,
            "disabled": False
        })
    
    # Convert to rrsets format
    for (name, rtype), records in records_by_name.items():
        rrsets.append({
            "name": name,
            "type": rtype,
            "ttl": 14400,
            "records": records
        })
    
    return rrsets

@app.route('/')
def index():
    """Root endpoint - PowerDNS plugin calls this to verify API is working"""
    if not check_auth():
        return jsonify({"error": "Unauthorized"}), 401
    
    return jsonify({
        "server": "PowerDNS-to-AdGuard Shim",
        "version": "1.0"
    })

@app.route('/healthz')
def healthz():
    """Healthcheck endpoint (no authentication)"""
    return jsonify({"status": "ok"}), 200

@app.route('/zones/<zone>', methods=['GET'])
def get_zone(zone):
    """
    Get zone information (translates to AdGuard rewrite list)
    
    Proxmox plugin calls this in two ways:
    1. GET /zones/{zone}?rrsets=false - just verify zone exists (verify_zone)
    2. GET /zones/{zone} - get full zone with rrsets (get_zone_content)
    """
    if not check_auth():
        return jsonify({"error": "Unauthorized"}), 401
    
    try:
        # Check if this is just a zone verification (rrsets=false)
        rrsets_param = request.args.get('rrsets', 'true').lower()
        
        if rrsets_param == 'false':
            # Simple zone verification - just return basic zone info
            return jsonify({
                "id": zone,
                "name": f"{zone}.",
                "type": "Zone",
                "kind": "Native"
            })
        
        # Full zone request - get all rewrites from AdGuard
        rewrites = adguard.list_rewrites()
        
        # Convert to PowerDNS zone format
        rrsets = convert_rewrites_to_rrsets(rewrites, zone)
        
        # Return PowerDNS-compatible response
        return jsonify({
            "id": zone,
            "name": f"{zone}.",
            "type": "Zone",
            "kind": "Native",
            "serial": 1,
            "notified_serial": 1,
            "masters": [],
            "dnssec": False,
            "rrsets": rrsets
        })
    
    except Exception as e:
        app.logger.error(f"Error in get_zone: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/zones/<zone>', methods=['PATCH'])
def patch_zone(zone):
    """
    Update zone records (translates to AdGuard rewrite add/delete)
    
    The Proxmox plugin sends rrsets with REPLACE or DELETE changetype.
    CRITICAL: Must handle record types separately (don't delete AAAA when updating A)
    """
    if not check_auth():
        return jsonify({"error": "Unauthorized"}), 401
    
    try:
        data = request.json
        rrsets = data.get('rrsets', [])
        
        app.logger.info(f"PATCH /zones/{zone} with {len(rrsets)} rrsets")
        
        for rrset in rrsets:
            name = rrset['name']  # Already has trailing dot from plugin
            name_normalized = normalize_domain(name)
            record_type = rrset['type']
            changetype = rrset.get('changetype', 'REPLACE')
            records = rrset.get('records', [])
            
            app.logger.info(f"Processing {changetype} for {name} ({record_type})")
            
            # Skip PTR records - AdGuard doesn't handle reverse DNS rewrites
            # The plugin will try to add these but we can't support them
            if record_type == 'PTR':
                app.logger.warning(f"Skipping PTR record for {name} - AdGuard doesn't support reverse DNS rewrites")
                continue
            
            # Skip non-A/AAAA/CNAME records
            if record_type not in ['A', 'AAAA', 'CNAME']:
                app.logger.warning(f"Skipping unsupported record type {record_type} for {name}")
                continue
            
            if changetype == 'DELETE':
                # Delete all rewrites of this TYPE for this domain
                # IMPORTANT: Only delete records matching this type
                deleted = delete_rewrites_by_type(name_normalized, record_type)
                app.logger.info(f"Deleted {deleted} {record_type} records for {name}")
            
            elif changetype == 'REPLACE':
                # REPLACE means: delete all records of this type, then add the new ones
                # This preserves records of other types (e.g., keep AAAA when updating A)
                
                # First, delete existing rewrites of this type only
                deleted = delete_rewrites_by_type(name_normalized, record_type)
                app.logger.info(f"Deleted {deleted} existing {record_type} records for {name}")
                
                # Then add new records
                added = 0
                for record in records:
                    content = record.get('content')
                    if content:
                        try:
                            adguard.add_rewrite(name_normalized, content)
                            added += 1
                            app.logger.info(f"Added {name_normalized} -> {content}")
                        except Exception as e:
                            app.logger.error(f"Failed to add rewrite {name_normalized} -> {content}: {e}")
                            # Continue processing other records even if one fails
                
                app.logger.info(f"Added {added} new {record_type} records for {name}")
        
        return jsonify({"status": "ok"})
    
    except Exception as e:
        app.logger.error(f"Error in patch_zone: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

@app.errorhandler(404)
def not_found(e):
    """Handle 404 errors"""
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(500)
def internal_error(e):
    """Handle 500 errors"""
    app.logger.error(f"Internal error: {e}")
    return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    print("="*60)
    print("PowerDNS to AdGuard Home API Shim")
    print("="*60)
    print(f"AdGuard URL: {ADGUARD_URL}")
    print(f"Listening on: http://0.0.0.0:8081")
    print("="*60)
    print("\nIMPORTANT: Configure Proxmox SDN DNS plugin with:")
    print(f"  URL: http://<this-host>:8081")
    print(f"  API Key: {POWERDNS_API_KEY}")
    print("\nLIMITATIONS:")
    print("  - PTR (reverse DNS) records are NOT supported")
    print("  - AdGuard doesn't have 'zones' - all records are global")
    print("="*60)
    
    # Run on port 8081 (or whatever you prefer)
    # In production, use a proper WSGI server like gunicorn
    app.run(host='0.0.0.0', port=8081, debug=True)
