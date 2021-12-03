from flask import Blueprint, render_template, request, flash, jsonify, redirect, url_for
import re
from bson import ObjectId
from . import db

domain_re = "(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]" 
ip_re = "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
cidr_range_re = "^([0-9]{1,3}\.){3}[0-9]{1,3}(\/([0-9]|[1-2][0-9]|3[0-2]))?$"
explicit_range_re = "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?) +((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
# could be improved
port_list_re = "(([1-9][0-9]*),)+([1-9][0-9]*)$"

def process_scan_form(form:dict, case_id:ObjectId):
    # DON'T KNOW WHERE BUT SOMEWHERE IN IN HERE HACKER'S GONNA COME FOR YOU KNECAPS
    # add more length checks up in this bitch <------------
    if not preprocess_form(form, case_id):
        return False
    # choose appropriate scan_type 
    if form['scan_type'] == 0:
        # subdomain scan
        settings = process_subdomian_scan(form)
    elif form['scan_type'] == 1:
        # domain/ip OSINT scan
        settings = process_domian_ip_osint_scan(form)
    elif form['scan_type'] == 2:
        # http screen shot scan
        settings = process_http_screen_shot_scan(form)
    elif form['scan_type'] == 3:
        # ip range scan
        settings = process_ip_range_scan(form)
    else:
        flash(f"Unrecognised scan type.", category="error")
        return False
    if settings:
        print(form['scan_type'])
        db.create_scan(case_id, form['scan-name'], form['scan_type'], form['scope'], settings)
        return True
    else:
        return False

def preprocess_form(form:dict, case_id:ObjectId) -> bool:
    if 'scan-name' in form and form['scan-name']:
        if not db.is_scan_name_unique(form['scan-name'], case_id):
            flash(f"Scan Name is not unique.", category="error")
            return False
    else:
        flash(f"Invalid Scan Name.", category="error")
        return False

    form['scope'] = [target.strip() for target in form['scope'].split('\r\n') if target]
    if not all(list(map(lambda line : (re.match(ip_re,line) or re.match(domain_re,line) or re.match(cidr_range_re,line) or re.match(explicit_range_re,line)), form['scope']))):
        print(form['scope'])
        print(list(map(lambda line : (bool(re.match(ip_re,line)) or bool(re.match(domain_re,line))), form['scope'])))
        flash(f"Invalid Scope.", category="error")
        return False
    # premptive type conversion, could likely be refactored away somehow
    if 'scan_type' in form:
        try:
            form['scan_type'] = int(form['scan_type'])
        except ValueError:
            flash(f"Invalid Scan type. Hacker? Friend? :)", category="error")
            return False
    return True

def process_subdomian_scan(form:dict):
    if 'threads' in form:
        try:
            form['threads'] = int(form['threads'])
        except ValueError:
            flash(f"Number of threads must be between 1 and 999.", category="error")
            return None 
    if 'scan_length' not in form or form['scan_length'] not in {'short', 'long', 'brute'}:
        flash(f"Scan length invalid.", category="error")
        return None 
    elif 'threads' not in form or form['threads'] < 1 or form['threads'] > 999:
        flash(f"Number of threads must be between 1 and 999.", category="error")
        return None 
    else:
        settings = {'scan_length':form['scan_length'],'threads':form['threads']} 
        return settings

def process_domian_ip_osint_scan(form:dict):
    if not ('whois' in form or 'rev-dns' in form or 'dns-history' in form):
        flash(f"Must select at least one sub-scan type.", category="error")
        return None
    else:
        settings = { 'whois':1 if 'whois' in form else 0,
                     'rev-dns':1 if 'rev-dns' in form else 0,
                     'dns-history':1 if 'dns-history' in form else 0,
                     'recursive':1 if 'recursive' in form else 0 } 
        return settings

def process_http_screen_shot_scan(form:dict) -> dict:
    if not re.match(port_list_re,form['http-ports']):
        flash(f"Port list invalid.", category="error")
        return None
    else:
        settings = { 'ports':[int(port.strip()) for port in form['http-ports'].split(',') if port],
                     'host_check':1 if 'host_check' in form else 0 }
        return settings

def process_ip_range_scan(form:dict) -> dict:
    if 'ip-range-scans' not in form or form['ip-range-scans'] not in {'host-detection', 'port-scanning'}:
        flash(f"Unrecognised scan type.", category="error")
        return None
    if not re.match(port_list_re,form['ports']) and form['ports']:
        flash(f"Port list invalid.", category="error")
        return None
    else:
        settings = {}
        if form['ip-range-scans'] == 'port-scanning':
            settings['ports'] = [int(port.strip()) for port in form['ports'].split(',') if port]
        settings['ip-range-scan-type'] = 0 if form['ip-range-scans'] == 'host-detection' else 1
        return settings

