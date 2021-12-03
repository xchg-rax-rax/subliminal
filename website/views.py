from flask import Blueprint, render_template, request, flash, jsonify, redirect, url_for
from flask_login import login_required, current_user
import json
import re
from bson import ObjectId 
from bson.errors import InvalidId
from . import db
from .ScanManager import ScanManager
from .FormProcessing import process_scan_form

scan_manager = ScanManager()
# blueprints allow us to split up our views across multiple files
views = Blueprint('views', __name__)

domain_re = "(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]" 
ip_re = "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
cidr_range_re = "^([0-9]{1,3}\.){3}[0-9]{1,3}(\/([0-9]|[1-2][0-9]|3[0-2]))?$"
explicit_range_re = "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?) +((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
# could be improved
port_list_re = "(([1-9][0-9]*),)+([1-9][0-9]*)$"


# This decorator defines a URL rule which tells flask to run the following function
# web someone visits the specified path. The html returned will be show to the user.
@views.route('/', methods=['GET','POST'])
@views.route('/dashboard', methods=['GET','POST'])
@login_required
def dashboard():
    if request.method == "POST":
        data = request.form.get('data')
    user = db.read_user(username=current_user.username)
    cases = [db.read_case(case_id) for case_id in user['cases']]
    return render_template("dashboard.html", user=current_user, cases=cases)

@views.route('/case/<case_id>', methods=['GET','POST'])
@login_required
def case(case_id):
    if request.method == "GET":
        try:
            case_id = ObjectId(case_id)
        except InvalidId:
            case_id = ""
        user = db.read_user(user_id=ObjectId(current_user.id))
        print(case_id)
        print(user['cases'])
        if (not case_id) or (case_id not in user['cases']):
            flash(f"Case ID {case_id} is not valid.", category="error")
            return redirect(url_for('views.dashboard'))
    if request.method == "POST":
        pass
    case = db.read_case(ObjectId(case_id))
    #preformat case dictionary for template
    case['tags'] = ['#'+tag for tag in case['tags']]
    case['scans'] = [db.read_scan(ObjectId(scan_id)) for scan_id in case['scans']]
    return render_template("case.html", user=current_user,case=case)

@views.route('/create_case', methods=['GET','POST'])
@login_required
def new_case():
    if request.method == "POST":
        case_name = request.form.get('case_name')
        tags = request.form.get('tags').split(',')
        summary = request.form.get('summary')
        # input validation
        if len(case_name) < 1:
            flash("Please enter case name.", category="error")
        elif len(case_name) > 100:
            flash("Case name can be no more than 100 characters in length.", category="error")
        elif max([len(tag) for tag in tags]) > 25:
            flash("Each tag can be no more than 25 characters in length.", category="error")
        elif len(tags)>25:
            flash("Each case can have no more than 25 tags.", category="error")
        elif len(summary) > 10000:
            flash("Case summary can be no more than 10,000 characters in length.", category="error")
        else:
            case_id = db.create_case(ObjectId(current_user.id), case_name, tags, summary)
            if case_id:
                flash("Created Case", category="success")
                return redirect(url_for('views.case',case_id=case_id))
            else:
                flash("Could not create case", category="error")
    return render_template("create_case.html", user=current_user)

@views.route('/create_scan', methods=['GET','POST'])
@login_required
def create_scan():
    # case ID validation
    if request.method == "POST":
        case_id = request.form.get('case_id')
    elif request.method == "GET":
        case_id = request.args.get('case_id')
    print(case_id)
    try:
        case_id = ObjectId(case_id)
    except InvalidId:
        case_id = ""
    user = db.read_user(user_id=ObjectId(current_user.id))
    if (not case_id) or (case_id not in user['cases']):
        flash(f"Case ID {case_id} is not valid.", category="error")
        return redirect(url_for('views.dashboard'))
    if request.method == "POST":
        if process_scan_form(request.form.to_dict(), case_id):
            return redirect(url_for('views.case',case_id=case_id))
        else:
            return redirect(url_for('views.create_scan')+"?case_id="+str(case_id))
    else:
        return render_template("create_scan.html", user=current_user, case_id=case_id)
"""
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
"""
@views.route('/case_results', methods=['GET','POST'])
@login_required
def case_results():
    if request.method == "POST":
        data = request.form.get('data')
    return render_template(".html", user=current_user)

@views.route('/scan_results/<scan_id>', methods=['GET'])
@login_required
def scan_results(scan_id:ObjectId):
    scan = db.read_scan(ObjectId(scan_id)) 
    artefacts = [db.read_artefact(artefact_id) for artefact_id in scan['artefacts']]
    if scan['scan_type'] == 1:
        for i in range(len(artefacts)):
            if artefacts[i]['artefact_type'] == "whois":
                artefacts[i]['raw_content'][1] = artefacts[i]['raw_content'][1].split("\n")
    return render_template("scan_results.html", user=current_user, scan=scan, artefacts=artefacts)

@views.route('/scan_delete/<scan_id>', methods=['GET'])
@login_required
def scan_delete(scan_id):
    if not scan_id:
        flash("No scan ID sent.", status="error")
        return redirect(url_for('views.dashboard'))
    scan = db.read_scan(ObjectId(scan_id))
    case = db.read_case(scan['case_id'])
    if not scan:
        flash(f"Scan with ID {scan_id} not found.", category="error")
        return redirect(url_for('views.dashboard'))
    elif case['owner_id'] != ObjectId(current_user.id):
        flash(f"You do not have permission to edit scan with ID {scan_id}.", category="error")
        return redirect(url_for('views.dashboard'))
    else:
        if db.delete_scan(ObjectId(scan_id)):
            flash(f"Scan deleted.", category="success")
        else:
            flash(f"Failed to delete scan.", category="success")
        return redirect(url_for('views.case',case_id=scan['case_id']))

@views.route('/case_delete/<case_id>', methods=['GET'])
@login_required
def case_delete(case_id):
    if not case_id:
        flash("No case ID sent.", status="error")
        return redirect(url_for('views.dashboard'))
    case = db.read_case(ObjectId(case_id))
    if not case:
        flash(f"Case with ID {case_id} not found.", category="error")
    elif case['owner_id'] != ObjectId(current_user.id):
        flash(f"You do not have permission to edit case with ID {case_id}.", category="error")
    else:
        if db.delete_case(ObjectId(case_id)):
            flash(f"Case deleted.", category="success")
        else:
            flash(f"Failed to delete case.", category="error")
    return redirect(url_for('views.dashboard'))

@views.route('/scan_copy/<scan_id>', methods=['GET'])
@login_required
def scan_copy(scan_id):
    if not scan_id:
        flash("No scan ID sent.", status="error")
        return redirect(url_for('views.dashboard'))
    scan = db.read_scan(ObjectId(scan_id))
    case = db.read_case(scan['case_id'])
    if not scan:
        flash(f"Scan with ID {scan_id} not found.", category="error")
        return redirect(url_for('views.dashboard'))
    elif case['owner_id'] != ObjectId(current_user.id):
        flash(f"You do not have permission to edit scan with ID {scan_id}.", category="error")
        return redirect(url_for('views.dashboard'))
    else:
        if db.copy_scan(ObjectId(scan_id)):
            flash(f"Scan Copied.", category="success")
            return redirect(url_for('views.case', case_id=scan['case_id']))
        else:
            flash(f"Failed to copy scan.", category="success")
            return redirect(url_for('views.case', case_id=scan['case_id']))

@views.route('/scan_start/<scan_id>', methods=['GET'])
@login_required
def scan_start(scan_id):
    # the permission validation is use lots elsewhere and should be 
    # refactored into and independent function.
    if not scan_id:
        flash("No scan ID sent.", status="error")
        return redirect(url_for('views.dashboard'))
    scan = db.read_scan(ObjectId(scan_id))
    case = db.read_case(scan['case_id'])
    if not scan:
        flash(f"Scan with ID {scan_id} not found.", category="error")
        return redirect(url_for('views.dashboard'))
    elif case['owner_id'] != ObjectId(current_user.id):
        flash(f"You do not have permission to edit scan with ID {scan_id}.", category="error")
        return redirect(url_for('views.dashboard'))
    else:
        if scan_manager.scan_start(scan):
            flash("Scan failed to start.", status="error")
        return redirect(url_for('views.case', case_id=scan['case_id']))
