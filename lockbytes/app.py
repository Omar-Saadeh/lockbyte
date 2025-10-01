from flask import Flask, render_template, redirect, request, url_for, session, flash
import socket
import ast
import threading
from flask_moment import Moment
# Make sure LoginManager and UserMixin are imported
from flask_login import LoginManager, login_required, current_user, UserMixin, login_user, logout_user
# ... other imports ...
import requests
import re
import os
from urllib.parse import urljoin, urlparse
import mysql.connector
import bcrypt
from functools import wraps
from datetime import datetime
import base64
import hashlib
import time
import string
import random
import email
from email import policy
from email.parser import Parser
from dotenv import load_dotenv
import feedparser # For news feed
from functools import wraps # Make sure this is here
from datetime import datetime # Make sure this is here
# import sqlite3 # Not directly used with MySQL, but kept for context if you had it.

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__, static_folder='static', template_folder='Templates')
app.secret_key = os.getenv('SECRET_KEY', 'a_very_secret_default_key_if_env_not_set')

# --- Flask-Login Setup ---
login_manager = LoginManager()
login_manager.init_app(app) # <--- ADD THIS LINE!
login_manager.login_view = 'login' # This tells Flask-Login what endpoint to redirect to for unauthorized access.

# User model for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, email, role):
        self.id = id
        self.username = username
        self.email = email
        self.role = role # Assuming 'role' is part of your user schema

    def get_id(self):
        return str(self.id) # Flask-Login requires the ID to be a string

# User loader callback for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    """
    This function is called by Flask-Login to reload the user object
    from the user ID stored in the session.
    """
    conn = None
    user_data = None
    try:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT id, username, email, role FROM users WHERE id = %s", (int(user_id),))
            user_data = cursor.fetchone()
    except mysql.connector.Error as err:
        print(f"❌ Error loading user for Flask-Login: {err}")
    finally:
        if conn:
            conn.close()
    
    if user_data:
        return User(user_data['id'], user_data['username'], user_data['email'], user_data['role'])
    return None

# MySQL DB config
def get_db_connection():
    """Establishes and returns a connection to the MySQL database."""
    try:
        conn = mysql.connector.connect(
            host=os.getenv('DB_HOST', 'localhost'),
            user=os.getenv('DB_USER', 'root'),
            password=os.getenv('DB_PASSWORD', ''),
            database=os.getenv('DB_NAME', 'lockbytes')
        )
        print("✅ Database connection successful!")
        return conn
    except mysql.connector.Error as err:
        print(f"❌ Error connecting to database: {err}")
        flash(f"Database connection error: {err}", "danger")
        return None

# Decorator to restrict admin routes (can now use Flask-Login's current_user.is_authenticated and current_user.role)
# You can update this to use current_user.is_authenticated as well
def admin_required(f):
    """Decorator to ensure only admin users can access a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash("Admin access required", "danger")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- Helper function for logging user actions ---
def log_user_action(user_id, username, action, details=None, ip_address=None):
    """
    Logs a user action to the 'user_logs' table in the database.
    """
    conn = None
    try:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            query = "INSERT INTO user_logs (user_id, username, action, details, ip_address) VALUES (%s, %s, %s, %s, %s)"
            cursor.execute(query, (user_id, username, action, details, ip_address))
            conn.commit()
            print(f"User log recorded: User ID {user_id}, Action '{action}'")
    except mysql.connector.Error as err:
        print(f"❌ Error logging user action to database: {err}")
    finally:
        if conn:
            conn.close()

moment = Moment(app) 
# --- Routes ---

@app.route('/newpage')
def newpage():
    return render_template('newpage.html')

@app.route('/')
@app.route('/home')
def home():
    """Renders the home page."""
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    if current_user.is_authenticated:
        return redirect(url_for('profile')) # Redirect if already logged in

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        user_data = None # Renamed to avoid conflict with Flask-Login's `user` variable
        if conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            user_data = cursor.fetchone()
            conn.close()

        if user_data and bcrypt.checkpw(password.encode(), user_data['password'].encode()):
            user_obj = User(user_data['id'], user_data['username'], user_data['email'], user_data['role'])
            login_user(user_obj) # <--- Use Flask-Login's login_user function

            flash("Login successful!", "success")

            # Log successful login
            log_user_action(
                user_id=user_data['id'],
                username=user_data['username'],
                action='login',
                details='Successful login',
                ip_address=request.remote_addr
            )
            next_page = request.args.get('next') # Redirect to 'next' if available
            return redirect(next_page or url_for('profile'))
        else:
            flash("Invalid email or password", "danger")
            # Log failed login attempt
            log_user_action(
                user_id=None, # User ID not known for failed attempts
                username=email, # Log the email attempted
                action='failed_login',
                details='Invalid credentials provided',
                ip_address=request.remote_addr
            )

    return render_template('login.html')

@app.route('/logout')
@login_required # Protect the logout route with Flask-Login
def logout():
    """Handles user logout."""
    user_id = current_user.id # Get user ID from Flask-Login
    username = current_user.username # Get username from Flask-Login

    # Log logout
    log_user_action(
        user_id=user_id,
        username=username,
        action='logout',
        details='User logged out',
        ip_address=request.remote_addr
    )

    logout_user() # <--- Use Flask-Login's logout_user function
    flash("You have been logged out.", "info")
    return redirect(url_for('home'))

@app.route('/interactive-learning')
def interactive_learning():
    """Renders the interactive learning page, displaying videos from the database."""
    conn = get_db_connection()
    videos = []
    if conn:
        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM learning_videos ORDER BY created_at DESC")
            videos = cursor.fetchall()
        except mysql.connector.Error as err:
            flash(f"Error fetching learning videos: {err}", "danger")
            print(f"Error fetching learning videos: {err}")
        finally:
            if conn:
                conn.close()
    return render_template('interactive-learning.html', videos=videos) # Pass videos to the template

@app.route('/profile')
@login_required # <--- Protect the profile page
def profile():
    """Renders the user profile page."""
    # With Flask-Login, current_user holds the User object if authenticated
    user_data = {
        "username": current_user.username,
        "email": current_user.email,
        "role": current_user.role,
        # "joined": current_user.joined # If you add 'joined' to your User model
    }
    return render_template('profile.html', user=user_data)

@app.route('/contact')
def contact():
    """Renders the contact page."""
    return render_template('contact.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Handles user registration."""
    if current_user.is_authenticated:
        return redirect(url_for('profile')) # Redirect if already logged in

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash("Passwords do not match", "danger")
            return redirect(url_for('signup'))

        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

        try:
            conn = get_db_connection()
            if conn:
                cursor = conn.cursor()
                # Default role to 'user' for new signups
                cursor.execute("INSERT INTO users (username, email, password, role) VALUES (%s, %s, %s, %s)",
                               (username, email, hashed_password, 'user')) 
                conn.commit()
                conn.close()
                flash("Account created successfully. You can now log in.", "success")
                # Log successful signup
                log_user_action(
                    user_id=None, # User ID not available at this point, will be on next login
                    username=username,
                    action='signup',
                    details='New user registered successfully',
                    ip_address=request.remote_addr
                )
                return redirect(url_for('login'))
        except mysql.connector.IntegrityError:
            flash("Username or email already exists", "warning")
            # Log failed signup
            log_user_action(
                user_id=None,
                username=username,
                action='signup_failed',
                details='Username or email already exists',
                ip_address=request.remote_addr
            )
            return redirect(url_for('signup'))
        except Exception as e:
            flash(f"An unexpected error occurred during signup: {e}", "danger")
            log_user_action(
                user_id=None,
                username=username,
                action='signup_error',
                details=f'Unexpected error: {e}',
                ip_address=request.remote_addr
            )

    return render_template('signUp.html')

@app.route('/tools')
def tools():
    """Renders the tools overview page."""
    return render_template('tools.html')

@app.route('/privacy')
def privacy():
    """Renders the privacy policy page."""
    return render_template('privacy.html')

@app.route('/terms')
def terms():
    """Renders the terms and conditions page."""
    return render_template('terms.html')

# =================== Encryption Tool ===================

def encryptionProcess(plainText, key):
    """Performs a Caesar cipher-like encryption."""
    letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$^&*()_+-?<>"
    num_letters = len(letters)
    cipherText = ''
    for letter in plainText:
        if letter != ' ':
            index = letters.find(letter)
            if index == -1:
                cipherText += letter
            else:
                newIndex = (index + key) % num_letters
                cipherText += letters[newIndex]
        else:
            cipherText += letter
    return cipherText

def decryptionProcess(cipherText, key):
    """Performs a Caesar cipher-like decryption."""
    letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$^&*()_+-?<>"
    num_letters = len(letters)
    plainText = ''
    for letter in cipherText:
        if letter != ' ':
            index = letters.find(letter)
            if index == -1:
                plainText += letter
            else:
                newIndex = (index - key) % num_letters
                if newIndex < 0: newIndex += num_letters # Ensure positive index for negative results
                plainText += letters[newIndex]
        else:
            plainText += letter
    return plainText

@app.route('/EncryptionTool', methods=['GET', 'POST'])
def EncryptionPro():
    """Handles encryption and decryption requests."""
    result = None
    # Use current_user from Flask-Login
    user_id = current_user.id if current_user.is_authenticated else None
    username = current_user.username if current_user.is_authenticated else 'Guest'

    if request.method == 'POST' and 'mode' in request.form and 'key' in request.form and 'text' in request.form:
        mode = request.form['mode']
        text = request.form['text']
        
        try:
            key = int(request.form['key'])
        except ValueError:
            result = "Invalid key. Please enter a number."
            log_user_action(user_id, username, 'encryption_tool_error', 'Invalid key type provided', request.remote_addr)
            return render_template('EncryptionProgramme.html', result=result)

        if 1 <= key <= 77:
            if mode == 'e':
                result = encryptionProcess(text, key)
                log_user_action(user_id, username, 'encryption_tool_encrypt', f'Text length: {len(text)}, Key: {key}', request.remote_addr)
            elif mode == 'd':
                result = decryptionProcess(text, key)
                log_user_action(user_id, username, 'encryption_tool_decrypt', f'Text length: {len(text)}, Key: {key}', request.remote_addr)
            else:
                result = "Invalid mode. Please choose 'e' or 'd'."
                log_user_action(user_id, username, 'encryption_tool_error', 'Invalid mode selected', request.remote_addr)
        else:
            result = "Invalid key. Please enter a number between 1 and 77."
            log_user_action(user_id, username, 'encryption_tool_error', f'Key out of range: {key}', request.remote_addr)

    return render_template('EncryptionProgramme.html', result=result)

# =================== News =================== 

# Multiple news sources for the news feed
NEWS_SOURCES = {
    "thn": "https://feeds.feedburner.com/TheHackersNews",
    "krebs": "https://krebsonsecurity.com/feed/",
    "naked": "https://nakedsecurity.sophos.com/feed/",
    "threatpost": "https://threatpost.com/feed/"
}

# Cache setup (Placeholder - actual caching would need more robust implementation for MySQL)
CACHE_DURATION = 3600    # 1 hour cache

@app.route("/news")
def news():
    """Fetches and displays cybersecurity news from various RSS feeds."""
    # Use current_user from Flask-Login
    user_id = current_user.id if current_user.is_authenticated else None
    username = current_user.username if current_user.is_authenticated else 'Guest'
    
    all_news = []
    
    # In a real scenario, you'd fetch from your MySQL cache here to reduce API calls
    cached_news = None # Placeholder for get_cached_news()
    if cached_news:
        log_user_action(user_id, username, 'news_view', 'Fetched from cache', request.remote_addr)
        return render_template("news.html", news_data=cached_news)
    
    # If no cache or cache expired, fetch fresh news
    for source_name, source_url in NEWS_SOURCES.items():
        try:
            feed = feedparser.parse(source_url)
            for entry in feed.entries[:5]:  # Get top 5 articles per source
                # Standardize date format; handle potential missing 'published'
                pub_date = datetime.strptime(entry.published, '%a, %d %b %Y %H:%M:%S %z') if 'published' in entry else datetime.now()
                
                all_news.append({
                    "title": entry.title,
                    "summary": clean_summary(entry.summary),
                    "link": entry.link,
                    "date": pub_date.strftime('%b %d, %Y'),
                    "readTime": estimate_read_time(entry.summary),
                    "category": source_name,
                    "source": source_name.upper(),
                    "image": extract_image(entry)
                })
        except Exception as e:
            print(f"Error fetching {source_name}: {e}")
            log_user_action(user_id, username, 'news_fetch_error', f'Error fetching {source_name}: {e}', request.remote_addr)
            continue
    
    # Sort by date (newest first)
    all_news.sort(key=lambda x: x['date'], reverse=True)
    
    # Cache the results (placeholder - actual caching would need MySQL integration)
    # cache_news(all_news)
    log_user_action(user_id, username, 'news_view', f'Fetched fresh news from {len(NEWS_SOURCES)} sources', request.remote_addr)
    
    return render_template("news.html", news_data=all_news[:20])  # Limit to 20 articles for display

def clean_summary(summary):
    """Removes HTML tags from summary and truncates it."""
    clean = re.sub('<[^<]+?>', '', summary)
    return clean[:200] + '...' if len(clean) > 200 else clean

def estimate_read_time(text):
    """Estimates reading time based on word count (200 words per minute)."""
    word_count = len(text.split())
    minutes = max(1, round(word_count / 200))
    return f"{minutes} min read"

def extract_image(entry):
    """Attempts to extract an image URL from a news entry."""
    if 'media_content' in entry and entry.media_content:
        return entry.media_content[0]['url']
    elif 'image' in entry and entry.image:
        return entry.image.href
    return url_for('static', filename='images/default-news.jpg')

def cache_news(news_data):
    """Placeholder function for caching news data to the database."""
    # In a full implementation, you would insert/update news articles in a dedicated DB table here.
    pass

def get_cached_news():
    """Placeholder function for retrieving cached news data from the database."""
    # In a full implementation, you would query your news articles table here.
    return None

# =================== Port Scanner ===================

@app.route('/tools/PortScanner', methods=['GET', 'POST'])
def PortScannerGUI():
    """Handles port scanning requests."""
    result = None
    # Use current_user from Flask-Login
    user_id = current_user.id if current_user.is_authenticated else None
    username = current_user.username if current_user.is_authenticated else 'Guest'

    if request.method == 'POST':
        host_address = request.form.get('host_address')
        ports_input = request.form.get('ports')

        if not host_address or not ports_input:
            flash("Please provide both a host address and ports.", "warning")
            log_user_action(user_id, username, 'port_scan_failed', 'Missing host or ports input', request.remote_addr)
            return render_template('PortScannerGUI.html', result=None)

        try:
            # Safely evaluate the ports input as a list
            ports = ast.literal_eval(ports_input)
            if not isinstance(ports, list):
                raise ValueError("Ports input must be a list (e.g., [80, 443]).")
            for port in ports:
                if not isinstance(port, int) or not (0 <= port <= 65535):
                    raise ValueError("Ports must be integers between 0 and 65535.")
        except (ValueError, SyntaxError) as e:
            flash(f"Invalid ports input: {e}", "danger")
            log_user_action(user_id, username, 'port_scan_failed', f'Invalid ports format: {e}', request.remote_addr)
            return render_template('PortScannerGUI.html', result=None)

        scan_results = [] # Renamed from 'results' to avoid conflict with global Flask 'results'
        try:
            host_ip = socket.gethostbyname(host_address)
        except socket.gaierror:
            flash("Invalid host address. Could not resolve hostname.", "danger")
            log_user_action(user_id, username, 'port_scan_failed', f'Invalid host address: {host_address}', request.remote_addr)
            return render_template('PortScannerGUI.html', result=None)

        def scan_port(port):
            """Internal function to scan a single port."""
            try:
                clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                clientSocket.settimeout(1) # Shorter timeout for faster feedback
                response = clientSocket.connect_ex((host_ip, port))
                if response == 0:
                    scan_results.append(f"[*] Port {port} : open")
                else:
                    scan_results.append(f"[*] Port {port} : closed")
                clientSocket.close()
            except socket.error as e:
                scan_results.append(f"[*] Port {port} : Error - {e}")

        threads = []
        for port in ports:
            thread = threading.Thread(target=scan_port, args=(port,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join() # Wait for all threads to complete

        scan_results.sort() # Sort results for consistent display
        result = scan_results
        log_user_action(user_id, username, 'port_scan_success', f'Scanned {host_address} on {len(ports)} ports', request.remote_addr)

    return render_template('PortScannerGUI.html', result=result)

# =================== Malware Scanner (VirusTotal v3) ===================
VT_API_KEY = '34262a3c3b4aeddc6c75955427ed36ae79803b7cf19c3a1c54852442f2bbe456' # Keep this secure
VT_BASE_URL = 'https://www.virustotal.com/api/v3'
headers = {'x-apikey': VT_API_KEY}


@app.template_filter('datetimeformat')
def datetimeformat(value, format_str='%Y-%m-%d %H:%M:%S'):
    """Jinja2 filter to format Unix timestamps to human-readable dates."""
    if value is None:
        return 'N/A'
    try:
        dt_object = datetime.utcfromtimestamp(int(value))
        return dt_object.strftime(format_str)
    except (ValueError, TypeError):
        return str(value)

@app.route('/malware-scan/')
def index():
    """Renders the malware scan input page."""
    return render_template('malware-scan.html')

@app.route('/scan-url', methods=['POST'])
def scan_url():
    """Handles URL scanning via VirusTotal."""
    url = request.form.get('url')
    # Use current_user from Flask-Login
    user_id = current_user.id if current_user.is_authenticated else None
    username = current_user.username if current_user.is_authenticated else 'Guest'

    if not url:
        flash('Please provide a URL to scan.', 'warning')
        log_user_action(user_id, username, 'url_scan_failed', 'No URL provided', request.remote_addr)
        return redirect(url_for('index'))

    scan_payload = {'url': url}
    try:
        # Submit URL for analysis
        resp = requests.post(f"{VT_BASE_URL}/urls", headers=headers, data=scan_payload, timeout=10)
        resp.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)
    except requests.exceptions.RequestException as e:
        flash(f'Error submitting URL for scanning: {e}', 'danger')
        log_user_action(user_id, username, 'url_scan_error', f'Failed to submit URL {url}: {e}', request.remote_addr)
        print(f"URL submission error: {e}")
        return redirect(url_for('index'))

    # VirusTotal documentation states that the URL ID for a report is the base64-encoded URL.
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    # Wait briefly for analysis to propagate if it was a fresh scan.
    time.sleep(5) # Give VT a moment if it's a new scan

    try:
        # Retrieve the analysis report
        report_resp = requests.get(f"{VT_BASE_URL}/urls/{url_id}", headers=headers, timeout=20)
        report_resp.raise_for_status() # Raise an exception for HTTP errors
    except requests.exceptions.RequestException as e:
        flash(f'Error retrieving URL report: {e}', 'danger')
        log_user_action(user_id, username, 'url_scan_error', f'Failed to retrieve report for URL {url}: {e}', request.remote_addr)
        print(f"URL report retrieval error: {e}")
        return redirect(url_for('index'))

    report = report_resp.json()
    log_user_action(user_id, username, 'url_scan_success', f'Scanned URL: {url}', request.remote_addr)
    return render_template('result.html', result=report, scan_type='url')


@app.route('/scan-file', methods=['POST'])
def scan_file():
    """Handles file scanning via VirusTotal."""
    uploaded_file = request.files.get('file')
    # Use current_user from Flask-Login
    user_id = current_user.id if current_user.is_authenticated else None
    username = current_user.username if current_user.is_authenticated else 'Guest'

    if not uploaded_file or not uploaded_file.filename:
        flash('Please select a file to scan.', 'warning')
        log_user_action(user_id, username, 'file_scan_failed', 'No file uploaded', request.remote_addr)
        return redirect(url_for('index'))

    original_filename = uploaded_file.filename
    print(f"✅ Received file: {original_filename}")

    file_content = uploaded_file.read()
    uploaded_file.close() # Close the file stream

    print(f"📦 File size: {len(file_content) / 1024:.2f} KB")

    if len(file_content) == 0:
        flash('Uploaded file is empty.', 'warning')
        log_user_action(user_id, username, 'file_scan_failed', 'Empty file uploaded', request.remote_addr)
        return redirect(url_for('index'))

    # Calculate SHA256 Hash of the uploaded file
    sha256_hash = hashlib.sha256(file_content).hexdigest()
    print(f"Calculated SHA256: {sha256_hash}")

    log_user_action(user_id, username, 'file_scan_attempt', f'Filename: {original_filename}, SHA256: {sha256_hash}', request.remote_addr)

    # --- Step 1: Attempt to retrieve report by hash first ---
    try:
        report_resp = requests.get(f"{VT_BASE_URL}/files/{sha256_hash}", headers=headers, timeout=20)
        report_resp.raise_for_status() # This will raise an exception for 4xx/5xx responses
        
        report = report_resp.json()
        if 'data' in report and 'attributes' in report['data']:
            flash(f'File report found via hash lookup for {original_filename}.', 'success')
            log_user_action(user_id, username, 'file_scan_success', f'Report found via hash for {original_filename} ({sha256_hash})', request.remote_addr)
            return render_template('result.html', result=report, scan_type='file')
        else:
            # This case means 200 OK but data structure is not as expected for a valid report
            print("Hash lookup returned 200, but data structure was unexpected. Falling through to upload.")
            pass # Continue to the upload section if the response isn't a proper file report
            
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            print(f"Hash {sha256_hash} not found in VirusTotal database. Proceeding to upload.")
            pass # Continue to the upload section
        else:
            flash(f'Error retrieving report by hash: {e}', 'danger')
            log_user_action(user_id, username, 'file_scan_error', f'Error during hash lookup for {sha256_hash}: {e}', request.remote_addr)
            print(f"Error during hash lookup: {e}")
            return redirect(url_for('index'))
    except requests.exceptions.RequestException as e:
        flash(f'Network error during hash lookup: {e}', 'danger')
        log_user_action(user_id, username, 'file_scan_error', f'Network error during hash lookup for {sha256_hash}: {e}', request.remote_addr)
        print(f"Network error during hash lookup: {e}")
        return redirect(url_for('index'))
    # --- End Step 1 ---

    # --- Step 2: If hash lookup failed (e.g., 404), upload the file for a new scan ---
    print("Hash lookup did not yield a result. Uploading file for analysis.")
    
    if len(file_content) > 32 * 1024 * 1024: # VirusTotal public API direct upload limit is 32MB
        flash('File is too large for direct upload (max 32MB). The hash was not found in VT database. Please consider scanning its hash directly if you obtain it, or using a premium VT API.', 'warning')
        log_user_action(user_id, username, 'file_scan_failed', 'File too large for direct upload', request.remote_addr)
        return redirect(url_for('index'))

    files_payload = {'file': (original_filename, file_content)}
    
    try:
        resp = requests.post(f"{VT_BASE_URL}/files", headers=headers, files=files_payload, timeout=60) # Increased timeout for upload
        resp.raise_for_status()
        print(f"🔁 VirusTotal upload response {resp.status_code}: {resp.text}")
    except requests.exceptions.RequestException as e:
        flash(f'Error submitting file for scanning: {e}', 'danger')
        log_user_action(user_id, username, 'file_scan_error', f'Error submitting file {original_filename} for scan: {e}', request.remote_addr)
        print(f"File submission error: {e}")
        return redirect(url_for('index'))

    analysis_id = resp.json().get('data', {}).get('id')
    if not analysis_id:
        flash('Could not retrieve analysis ID from VirusTotal response after upload.', 'danger')
        log_user_action(user_id, username, 'file_scan_error', 'Could not get analysis ID after upload', request.remote_addr)
        print("Could not retrieve analysis ID after upload.")
        return redirect(url_for('index'))

    print(f"🔍 Analysis ID (for new scan): {analysis_id}")

    # --- Step 3: Poll for analysis completion for the newly submitted file ---
    max_retries = 20 # Increased retries to allow more time for new scans
    retry_delay = 10 # seconds
    
    analysis_completed = False
    for attempt in range(max_retries):
        print(f"Attempt {attempt + 1}/{max_retries} to fetch analysis status for {analysis_id}")
        time.sleep(retry_delay)
        try:
            analysis_status_resp = requests.get(f"{VT_BASE_URL}/analyses/{analysis_id}", headers=headers, timeout=20)
            analysis_status_resp.raise_for_status()
            
            analysis_data = analysis_status_resp.json().get('data', {})
            status = analysis_data.get('attributes', {}).get('status')
            
            print(f"Current analysis status: {status}")

            if status == 'completed':
                analysis_completed = True
                break # Analysis is complete, exit polling loop
            elif status in ['queued', 'running', 'in-progress']: # Common statuses during processing
                continue # Keep polling
            else:
                flash(f'File analysis stopped with unexpected status: {status}. The report might become available later.', 'danger')
                log_user_action(user_id, username, 'file_scan_error', f'Unexpected analysis status for {original_filename}: {status}', request.remote_addr)
                return redirect(url_for('index'))
        except requests.exceptions.RequestException as e:
            print(f"Error polling analysis status: {e}")
            if attempt < max_retries - 1:
                continue # Retry on network/server error
            else:
                flash(f'Failed to poll analysis status after multiple attempts: {e}', 'danger')
                log_user_action(user_id, username, 'file_scan_error', f'Failed to poll status for {original_filename}: {e}', request.remote_addr)
                return redirect(url_for('index'))
    
    if not analysis_completed:
        flash('File analysis did not complete within the expected time. The report might become available later by scanning its hash.', 'warning')
        log_user_action(user_id, username, 'file_scan_timeout', f'Analysis timed out for {original_filename}', request.remote_addr)
        return redirect(url_for('index'))

    # --- Step 4: Analysis is complete, now fetch the detailed file report using its SHA256 hash ---
    print(f"Analysis completed. Now fetching detailed report for SHA256: {sha256_hash}")
    try:
        final_report_resp = requests.get(f"{VT_BASE_URL}/files/{sha256_hash}", headers=headers, timeout=20)
        final_report_resp.raise_for_status()
        
        final_report = final_report_resp.json()
        print(f"📊 Detailed file report fetched successfully for SHA256: {sha256_hash}")
        # Ensure the report has the expected structure before passing
        if 'data' not in final_report or 'attributes' not in final_report['data']:
            flash('Detailed file report fetched, but its structure was invalid.', 'danger')
            log_user_action(user_id, username, 'file_scan_error', f'Invalid report structure for {original_filename}', request.remote_addr)
            return redirect(url_for('index'))

        log_user_action(user_id, username, 'file_scan_success', f'Scanned file: {original_filename} (SHA256: {sha256_hash})', request.remote_addr)
        return render_template('result.html', result=final_report, scan_type='file')
    except requests.exceptions.RequestException as e:
        flash(f'Error retrieving detailed file report after analysis completion: {e}', 'danger')
        log_user_action(user_id, username, 'file_scan_error', f'Error getting final report for {original_filename}: {e}', request.remote_addr)
        print(f"Detailed file report retrieval error: {e}")
        return redirect(url_for('index'))


@app.route('/scan-hash', methods=['POST'])
def scan_hash():
    file_hash = request.form.get('hash')
    if not file_hash:
        flash('Please provide a hash to scan.', 'warning')
        return redirect(url_for('index'))

    try:
        resp = requests.get(f"{VT_BASE_URL}/files/{file_hash}", headers=headers)
        resp.raise_for_status()
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            flash(f'Hash "{file_hash}" not found in VirusTotal database.', 'info')
        else:
            flash(f'Error retrieving report for hash: {e}', 'danger')
        print(f"Hash scan error: {e}")
        return redirect(url_for('index'))
    except requests.exceptions.RequestException as e:
        flash(f'Network or request error for hash scan: {e}', 'danger')
        print(f"Hash scan network error: {e}")
        return redirect(url_for('index'))

    report = resp.json()
    if 'data' not in report or 'attributes' not in report['data']:
        flash('Invalid response structure from VirusTotal for hash scan.', 'danger')
        return redirect(url_for('index'))

    return render_template('result.html', result=report, scan_type='hash')

# =================== Password Tool ===================

@app.route('/password-tool', methods=['GET', 'POST'])
def password_tool():
    """Handles password generation and strength checking."""
    generated_password = None
    strength_result = None
    password_checked = None
    
    user_id = session.get('user_id')
    username = session.get('username', 'Guest')
    
    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'generate':
            try:
                length = int(request.form.get('length', 12))
                if not (6 <= length <= 128): # Reasonable password length limits
                    flash("Password length must be between 6 and 128 characters.", "danger")
                    log_user_action(user_id, username, 'password_generation_failed', 'Invalid length provided', request.remote_addr)
                    return render_template('password-tool.html')

                include_upper = 'include_upper' in request.form
                include_lower = 'include_lower' in request.form
                include_digits = 'include_digits' in request.form
                include_symbols = 'include_symbols' in request.form

                char_pool = ''
                if include_upper:
                    char_pool += string.ascii_uppercase
                if include_lower:
                    char_pool += string.ascii_lowercase
                if include_digits:
                    char_pool += string.digits
                if include_symbols:
                    char_pool += string.punctuation

                if not char_pool:
                    strength_result = "❌ Please select at least one character type."
                    log_user_action(user_id, username, 'password_generation_failed', 'No character types selected', request.remote_addr)
                else:
                    generated_password = ''.join(random.choices(char_pool, k=length))
                    strength_result = evaluate_strength(generated_password)
                    log_user_action(user_id, username, 'password_generated', f'Length: {length}, Strength: {strength_result[:50]}', request.remote_addr)

            except ValueError:
                strength_result = "❌ Please enter a valid number for length."
                log_user_action(user_id, username, 'password_generation_failed', 'Invalid length format', request.remote_addr)

        elif action == 'check':
            password_checked = request.form.get('password_input')
            if password_checked:
                strength_result = evaluate_strength(password_checked)
                # Log only a portion of the result to avoid logging potentially sensitive info
                log_user_action(user_id, username, 'password_strength_checked', f'Result: {strength_result[:100]}', request.remote_addr)
            else:
                strength_result = "❌ Please enter a password to evaluate."
                log_user_action(user_id, username, 'password_strength_check_failed', 'No password provided for check', request.remote_addr)

    return render_template(
        'password-tool.html',
        generated_password=generated_password,
        strength_result=strength_result,
        password_checked=password_checked
    )

def evaluate_strength(password):
    """Evaluates the strength of a given password."""
    score = 0
    feedback = []

    if len(password) < 8:
        feedback.append("At least 8 characters recommended.")
    elif len(password) >= 12:
        score += 1
        feedback.append("Good length.")
    
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)

    char_type_count = sum([has_upper, has_lower, has_digit, has_special])

    if char_type_count < 3:
        feedback.append("Include a mix of uppercase, lowercase, digits, and symbols.")
    else:
        score += char_type_count - 2 # Add points for variety based on character types

    if score >= 3 and len(password) >= 10:
        return "✅ Strong: Excellent mix of characters and good length."
    elif score >= 2 and len(password) >= 8:
        return "⚠ Moderate: Consider adding more variety or length."
    else:
        return "❌ Weak: " + " ".join(feedback) if feedback else "Very weak."


#======================Email Header Analyzer=============================

@app.route('/tools/EmailHeaderAnalyzer', methods=['GET', 'POST'])
def EmailHeaderAnalyzer():
    """Analyzes raw email headers."""
    result = None
    user_id = session.get('user_id')
    username = session.get('username', 'Guest')

    if request.method == 'POST':
        try:
            raw_headers = request.form.get('headers')
            if not raw_headers:
                result = "No headers provided."
                log_user_action(user_id, username, 'email_header_analysis_failed', 'No headers provided', request.remote_addr)
            else:
                # Parse the headers using email.parser
                msg = email.message_from_string(raw_headers, policy=policy.default)
                
                # Extract common header fields
                result = {
                    'From': msg.get('From', 'Not Found'),
                    'To': msg.get('To', 'Not Found'),
                    'Subject': msg.get('Subject', 'Not Found'),
                    'Date': msg.get('Date', 'Not Found'),
                    'Message-ID': msg.get('Message-ID', 'Not Found'),
                    'Received': msg.get_all('Received', ['Not Found']),
                    'Return-Path': msg.get('Return-Path', 'Not Found'),
                    'X-Originating-IP': msg.get('X-Originating-IP', 'Not Found'),
                    'Authentication-Results': msg.get('Authentication-Results', 'Not Found'),
                    'DKIM-Signature': msg.get('DKIM-Signature', 'Not Found'),
                    'Received-SPF': msg.get('Received-SPF', 'Not Found')
                }
                # Log success with some key details from the headers
                log_details = f"From: {result['From']}, Subject: {result['Subject']}"
                log_user_action(user_id, username, 'email_header_analysis_success', log_details, request.remote_addr)
        except Exception as e:
            result = f"Error parsing headers: {e}"
            log_user_action(user_id, username, 'email_header_analysis_error', f'Error parsing headers: {e}', request.remote_addr)

    return render_template('EmailHeaderAnalyzer.html', result=result)


# =================== Vulnerability Scanner (General) ===================

def check_http_headers(url):
    """Checks for common security HTTP headers."""
    headers_to_check = ['X-Content-Type-Options', 'X-Frame-Options', 'Content-Security-Policy', 'Strict-Transport-Security']
    try:
        res = requests.get(url, timeout=5) # Added timeout
        return {h: res.headers.get(h, 'Missing') for h in headers_to_check}
    except requests.exceptions.RequestException: # Catch all request errors (connection, timeout, etc.)
        return {h: 'Error/Unavailable' for h in headers_to_check}

def check_robots(url):
    """Checks for the presence of robots.txt."""
    try:
        res = requests.get(urljoin(url, '/robots.txt'), timeout=5)
        return res.text if res.status_code == 200 else "robots.txt not found"
    except requests.exceptions.RequestException:
        return "Error fetching robots.txt"

def detect_forms_xss(url):
    """Detects forms and inputs, indicating potential XSS vectors."""
    try:
        res = requests.get(url, timeout=5)
        forms = re.findall(r'<form.*?</form>', res.text, re.DOTALL)
        inputs = re.findall(r'<input.*?>', res.text)
        return len(forms), len(inputs)
    except requests.exceptions.RequestException:
        return 0, 0

def test_sqli(url):
    """Performs basic SQL Injection tests."""
    payloads = ["'", "' OR '1'='1", "'--", "'; DROP TABLE users; --"]
    for payload in payloads:
        try:
            res = requests.get(f"{url}?id={payload}", timeout=5)
            # Look for common SQL error messages
            if any(keyword in res.text.lower() for keyword in ["sql", "syntax", "mysql", "error", "warning"]):
                return True
        except requests.exceptions.RequestException:
            continue
    return False

def test_open_redirect(url):
    """Tests for open redirect vulnerability."""
    try:
        # Use a non-existent domain to avoid actual redirects to potentially malicious sites
        res = requests.get(url + "?redirect=http://example.com/redirect_test", allow_redirects=False, timeout=5)
        # Check if the Location header points to the controlled external domain
        return "example.com/redirect_test" in res.headers.get('Location', '')
    except requests.exceptions.RequestException:
        return False

def detect_tech(url):
    """Attempts to detect server technology from HTTP headers."""
    try:
        res = requests.get(url, timeout=5)
        server = res.headers.get('Server', 'Unknown')
        powered_by = res.headers.get('X-Powered-By', 'Unknown')
        # Add more specific checks if needed
        if 'flask' in res.text.lower() or 'werkzeug' in server.lower():
            server = 'Flask/Werkzeug' # More specific if detected
        return server, powered_by
    except requests.exceptions.RequestException:
        return "Unknown", "Unknown"

@app.route('/scanner', methods=['GET', 'POST'])
def scanner():
    """Handles general web vulnerability scanning requests."""
    results = {}
    user_id = session.get('user_id')
    username = session.get('username', 'Guest')

    if request.method == 'POST':
        target = request.form['target'].strip()
        # Ensure URL has a scheme, default to http if none
        if not target.startswith("http://") and not target.startswith("https://"):
            target = "http://" + target
        
        # Log the scan attempt
        log_user_action(user_id, username, 'vulnerability_scan_attempt', f'Target: {target}', request.remote_addr)

        try:
            parsed = urlparse(target)
            if not parsed.hostname: # Check if hostname exists after parsing
                raise ValueError("Invalid URL: Missing hostname")
            ip = socket.gethostbyname(parsed.hostname) # Resolve IP for logging/info
        except (socket.gaierror, ValueError) as e:
            flash(f"Invalid target URL or hostname: {e}", "danger")
            log_user_action(user_id, username, 'vulnerability_scan_failed', f'Invalid target: {target} ({e})', request.remote_addr)
            return render_template('scanner.html', results=results)

        scan_details_log = [] # To store details for the log entry
        
        # Perform selected scans
        if 'tech_detect' in request.form:
            tech_results = detect_tech(target)
            results['Tech Stack'] = tech_results
            scan_details_log.append(f"Tech: {tech_results[0]}/{tech_results[1]}")
        if 'header_check' in request.form:
            header_results = check_http_headers(target)
            results['Security Headers'] = header_results
            scan_details_log.append(f"Headers: {', '.join(k for k, v in header_results.items() if v == 'Missing')}")
        if 'robots_check' in request.form:
            robots_res = check_robots(target)
            results['robots.txt'] = robots_res
            scan_details_log.append("Robots.txt checked")
        if 'xss_check' in request.form:
            forms, inputs = detect_forms_xss(target)
            results['Forms Detected'] = (forms, inputs)
            scan_details_log.append(f"XSS: Forms({forms}), Inputs({inputs})")
        if 'sqli_check' in request.form:
            sqli_vulnerable = test_sqli(target)
            results['SQL Injection Vulnerable'] = sqli_vulnerable
            scan_details_log.append(f"SQLi: {'Vulnerable' if sqli_vulnerable else 'Not Vulnerable'}")
        if 'redirect_check' in request.form:
            open_redirect = test_open_redirect(target)
            results['Open Redirect'] = open_redirect
            scan_details_log.append(f"Redirect: {'Vulnerable' if open_redirect else 'Not Vulnerable'}")
        
        # Log successful scan with details
        log_user_action(user_id, username, 'vulnerability_scan_success', f'Target: {target}, Scans: {"; ".join(scan_details_log)}', request.remote_addr)

    return render_template('scanner.html', results=results)

# =================== Admin Logs View ===================
@app.route('/admin/logs')
@admin_required # Only admins can view these logs
def admin_logs():
    """Displays user activity logs for administrators."""
    conn = get_db_connection()
    logs = []
    if conn:
        try:
            cursor = conn.cursor(dictionary=True)
            # Retrieve last 200 logs for easier viewing, ordered by most recent
            cursor.execute("SELECT * FROM user_logs ORDER BY timestamp DESC LIMIT 200")
            logs = cursor.fetchall()
        except mysql.connector.Error as err:
            flash(f"Error fetching logs: {err}", "danger")
            print(f"Error fetching logs: {err}")
        finally:
            conn.close()
    return render_template('admin_logs.html', logs=logs)

@app.route('/edit-profile', methods=['GET', 'POST'])
@login_required # Assuming you have Flask-Login's login_required decorator
def edit_profile():
    user_id = session.get('user_id')
    if not user_id:
        flash("You must be logged in to edit your profile.", "warning")
        return redirect(url_for('login'))

    user_data = get_user_data_from_db(user_id)
    if not user_data:
        flash("User data not found. Please log in again.", "danger")
        log_user_action(user_id, session.get('username', 'Unknown'), 'profile_edit_error', 'User data not found for edit profile', request.remote_addr)
        return redirect(url_for('profile')) 

    if request.method == 'POST':
        new_username = request.form['username']
        new_email = request.form['email']
        new_bio = request.form.get('bio', '') # Get bio, default to empty string if not provided

        conn = get_db_connection()
        if conn:
            try:
                cursor = conn.cursor()
                # Check for email and username uniqueness if they are changed
                if new_email != user_data['email']:
                    cursor.execute("SELECT id FROM users WHERE email = %s AND id != %s", (new_email, user_id))
                    if cursor.fetchone():
                        flash("This email is already taken. Please choose another.", "danger")
                        log_user_action(user_id, session.get('username'), 'profile_update_failed', f'Email {new_email} already taken', request.remote_addr)
                        # Re-fetch user_data to ensure latest state is passed if form is re-rendered
                        user_data = get_user_data_from_db(user_id)
                        return render_template('edit_profile.html', current_user=user_data)

                if new_username != user_data['username']:
                    cursor.execute("SELECT id FROM users WHERE username = %s AND id != %s", (new_username, user_id))
                    if cursor.fetchone():
                        flash("This username is already taken. Please choose another.", "danger")
                        log_user_action(user_id, session.get('username'), 'profile_update_failed', f'Username {new_username} already taken', request.remote_addr)
                        # Re-fetch user_data to ensure latest state is passed if form is re-rendered
                        user_data = get_user_data_from_db(user_id)
                        return render_template('edit_profile.html', current_user=user_data)

                query = "UPDATE users SET username = %s, email = %s, bio = %s WHERE id = %s"
                cursor.execute(query, (new_username, new_email, new_bio, user_id))
                conn.commit()

                # Update session data immediately after successful DB update
                session['username'] = new_username
                session['email'] = new_email
                # No direct session update for 'bio' needed unless you explicitly use it from session elsewhere

                flash("Profile updated successfully!", "success")
                log_user_action(user_id, session.get('username'), 'profile_updated', f'Updated profile for user ID: {user_id}', request.remote_addr)
                return redirect(url_for('profile')) # Redirect to profile to see changes
            except mysql.connector.Error as err:
                flash(f"Error updating profile: {err}", "danger")
                print(f"Error updating profile: {err}")
                log_user_action(user_id, session.get('username'), 'profile_update_error', f'Database error updating profile for user ID {user_id}: {err}', request.remote_addr)
            finally:
                if conn:
                    conn.close()

    # For GET requests, or if POST failed due to an unexpected database error
    # user_data is already fetched at the beginning of the function
    return render_template('edit_profile.html', current_user=user_data)


@app.route('/security-settings')
@login_required # Or @admin_required if only admins can access full security settings
def security_settings():
    """Displays security settings for the user."""
    # You might fetch user-specific security settings here (e.g., 2FA status)
    return render_template('security_settings.html')




if __name__ == '__main__':
    # It's good practice to ensure the API key is set before running in production
    if not os.getenv('VT_API_KEY') or os.getenv('VT_API_KEY') == 'YOUR_VIRUSTOTAL_API_KEY_HERE':
        print("WARNING: VT_API_KEY environment variable is not set or is default. Malware scanning features may not work.")
        print("Please add VT_API_KEY='YOUR_ACTUAL_VIRUSTOTAL_API_KEY' to your .env file.")
    
    app.run(debug=True)