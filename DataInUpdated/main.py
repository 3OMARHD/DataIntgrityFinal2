from flask import Flask, render_template, redirect, url_for, request, flash, session, make_response, send_file, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask import current_app
from datetime import datetime, timedelta
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
import os
import secrets
import pyotp
import qrcode
import io
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from Crypto.Cipher import AES
from sqlalchemy.dialects.mysql import BLOB
from Crypto.PublicKey import RSA
import hmac
import logging
from sqlalchemy import or_, func, extract, inspect
from sqlalchemy.orm import joinedload
import csv
from io import StringIO
from collections import defaultdict
import requests
import re
import hashlib

# Setup logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', secrets.token_hex(32))
app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql+pymysql://{os.getenv('MYSQL_USER')}:{os.getenv('MYSQL_PASSWORD')}@{os.getenv('MYSQL_HOST', 'localhost')}/{os.getenv('MYSQL_DB')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'pdf', 'docx', 'txt'}
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# GitHub OAuth credentials
GITHUB_CLIENT_ID = os.getenv('GITHUB_CLIENT_ID')
GITHUB_CLIENT_SECRET = os.getenv('GITHUB_CLIENT_SECRET')

#HMAC key
hmac_key_b64 = os.getenv('HMAC_SECRET_KEY_BASE64')
app.config['HMAC_SECRET_KEY'] = base64.b64decode(hmac_key_b64)

# Set Egypt's timezone
from pytz import timezone
LOCAL_TIMEZONE = timezone('Africa/Cairo')

def local_now():
    return datetime.now(LOCAL_TIMEZONE)

# --- Database Models ---
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(50), nullable=False)
    message = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    ip_address = db.Column(db.String(100))
    timestamp = db.Column(db.DateTime, default=local_now)
    is_read = db.Column(db.Boolean, default=False)
    user = db.relationship('User', backref='notifications')

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150))
    auth_method = db.Column(db.String(20))
    github_id = db.Column(db.String(200))
    two_factor_secret = db.Column(db.String(100))
    is_2fa_enabled = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=local_now)
    is_admin_upload_account = db.Column(db.Boolean, default=False)

class LoginLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=True)
    email = db.Column(db.String(150))
    username = db.Column(db.String(50))
    role = db.Column(db.Enum('user', 'admin'))
    status = db.Column(db.String(20))
    ip_address = db.Column(db.String(100)) 
    country = db.Column(db.String(100), nullable=True)
    timestamp = db.Column(db.DateTime, default=local_now)
    session_duration = db.Column(db.Integer, nullable=True)
   

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    file_hash = db.Column(db.String(64), nullable=False)
    encrypted_data = db.Column(db.LargeBinary)
    file_size = db.Column(db.Integer, nullable=False)
    encryption_status = db.Column(db.String(20), default='Encrypted')
    aes_key = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=local_now)
    user = db.relationship('User', backref='documents')
    hmac = db.Column(db.String(64), nullable=False)
    is_signed = db.Column(db.Boolean, default=False)
    signature = db.Column(db.LargeBinary, nullable=True)
    signer_type = db.Column(db.String(10))  # "user" or "admin"


class DocumentActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey('document.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(50), nullable=False)
    ip_address = db.Column(db.String(100))
    timestamp = db.Column(db.DateTime, default=local_now)
    user = db.relationship('User', backref='activities')
    document = db.relationship('Document', backref='activities')

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)


class AdminActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('admin.id'), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(100))
    timestamp = db.Column(db.DateTime, default=local_now)
    admin = db.relationship('Admin', backref='admin_activities')

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    role_name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(255))

class UserRole(db.Model):
    id = db.Column(db.Integer, primary_key=True)
   ## user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)
    user = db.relationship('User', backref='user_roles')
    role = db.relationship('Role', backref='user_roles')

class UserKey(db.Model):
    __tablename__ = 'user_keys'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    public_key = db.Column(db.Text, nullable=False)

    user = db.relationship('User', backref=db.backref('user_key', uselist=False))

# Example SQLAlchemy model for AdminKey

class AdminKey(db.Model):
    __tablename__ = 'admin_keys'
    admin_id = db.Column(db.Integer, db.ForeignKey('admin.id'), primary_key=True)
    public_key = db.Column(db.Text, nullable=False)


# --- Database Initialization ---
with app.app_context():
    db.create_all()
    if not Role.query.first():
        default_roles = [
            Role(role_name='Admin', description='Full system access'),
            Role(role_name='User', description='Standard user access')
        ]
        db.session.bulk_save_objects(default_roles)
        db.session.commit()

# --- Middleware ---
@app.before_request
def prevent_back_navigation():
    protected_routes = ['home', 'upload_document', 'documents_list', 'download_document', 'profile', 'two_factor_setup', 'two_factor_verify']
    if request.endpoint in protected_routes and 'user_id' not in session:
        response = make_response(redirect(url_for('login')))
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '-1'
        return response

# --- Helper Functions ---
def save_login_log (user_id=None, admin_id=None, email=None, status=None, username=None, role=None):
    try:
        ip_address = request.remote_addr
        country = get_ip_location(ip_address)
        if admin_id:
            role = 'admin'
        elif user_id:
            role = 'user'
        else:
            role = role or 'unknown'
        new_log = LoginLog(
            user_id=user_id,
            email=email,
            username=username,
            role=role,
            status=status,
            ip_address=ip_address,
            country=country
        )
        db.session.add(new_log)
        db.session.commit()
        if status == 'Failed':
            recent_fails = LoginLog.query.filter_by(ip_address=ip_address, status='Failed').filter(LoginLog.timestamp >= local_now() - timedelta(minutes=10)).count()
            if recent_fails >= 3:
                notification = Notification(type='Failed Login', message=f'Multiple failed login attempts from IP {ip_address} (Country: {country})', ip_address=ip_address)
                db.session.add(notification)
                db.session.commit()
        return new_log.id
    except Exception as e:
        logging.error(f"Error in save_login_log: {str(e)}")
        db.session.rollback()
        return None

def log_document_activity(document_id, user_id, action):
    try:
        ip_address = request.remote_addr
        new_activity = DocumentActivity(document_id=document_id, user_id=user_id, action=action, ip_address=ip_address)
        db.session.add(new_activity)
        db.session.commit()
    except Exception as e:
        logging.error(f"Error in log_document_activity: {str(e)}")
        db.session.rollback()

def log_admin_activity(admin_id, action):
    try:
        ip_address = request.remote_addr
        new_activity = AdminActivity(admin_id=admin_id, action=action, ip_address=ip_address)
        db.session.add(new_activity)
        db.session.commit()
    except Exception as e:
        logging.error(f"Error in log_admin_activity: {str(e)}")
        db.session.rollback()

def valid_password(password):
    return (len(password) >= 8 and
            re.search(r'[A-Z]', password) and
            re.search(r'[a-z]', password) and
            re.search(r'[0-9]', password) and
            re.search(r'[\W_]', password))

def get_ip_location(ip_address):
    try:
        response = requests.get(f'http://ip-api.com/json/{ip_address}', timeout=5)
        response.raise_for_status()
        data = response.json()
        return data.get('country', 'Unknown')
    except Exception as e:
        logging.error(f"Error in get_ip_location: {str(e)}")
        return 'Unknown'

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


def generate_rsa_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return public_key, private_key
def generate_signature(data, private_key_path):
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )

    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature




# --- Routes ---
@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    username = user.username if user else "User"
    response = make_response(render_template('home.html', username=username))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']

        if not username or not email or not password:
            flash('All fields are required!', 'danger')
            return redirect(url_for('register'))

        if not valid_password(password):
            flash('Password must be at least 8 characters, with uppercase, lowercase, number, and special character!', 'danger')
            return redirect(url_for('register'))

        try:
            existing_user = User.query.filter((User.email == email) | (User.username == username)).first()
            if existing_user:
                flash('Email or Username already exists!', 'danger')
                return redirect(url_for('register'))

            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = User(username=username, email=email, password=hashed_password, auth_method='manual')
            db.session.add(new_user)
            db.session.commit()

            # Assign Role
            user_role = UserRole(user_id=new_user.id, role_id=Role.query.filter_by(role_name='User').first().id)
            db.session.add(user_role)
            db.session.commit()

            # --- Generate RSA key pair ---
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            public_key = private_key.public_key()

            # Serialize private key to PEM (unencrypted, for now)
            private_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )

            # Serialize public key to PEM (text)
            public_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            # Store private key in 'keys/' folder
            key_dir = os.path.join(os.path.dirname(__file__), 'keys')
            os.makedirs(key_dir, exist_ok=True)
            private_key_path = os.path.join(key_dir, f"{username}_private.pem")
            with open(private_key_path, 'wb') as f:
                f.write(private_bytes)

            # Save public key in database
            user_key = UserKey(user_id=new_user.id, public_key=public_bytes.decode('utf-8'))
            db.session.add(user_key)
            db.session.commit()

            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))

        except Exception as e:
            logging.error(f"Error in register: {str(e)}")
            db.session.rollback()
            flash(f'Error: {str(e)}', 'danger')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip()
        password = request.form['password']
        remember = request.form.get('remember') == 'on'

        if not email or not password:
            save_login_log(email=email, status='Failed')
            flash('Email and password are required!', 'danger')
            return redirect(url_for('login'))

        user = User.query.filter_by(email=email).first()
        admin = Admin.query.filter_by(username=email).first()
        if user:
            if user.auth_method == 'github':
                flash('This account uses GitHub login. Please use GitHub to log in.', 'danger')
                return redirect(url_for('login'))
            if bcrypt.check_password_hash(user.password, password):
                session['user_id'] = user.id
                session['role'] = 'user'

                session['pending_2fa'] = True
                if remember:
                    session.permanent = True
                    admin_id = admin.id if admin else None
                log_id = save_login_log(user_id=user.id, email=email, status='Success')
                session['login_log_id'] = log_id
                if user.is_2fa_enabled:
                    return redirect(url_for('two_factor_verify'))
                else:
                    return redirect(url_for('two_factor_setup'))
            else:
                save_login_log(email=email, status='Failed')
                flash('Invalid password!', 'danger')
        else:
            save_login_log(email=email, status='Failed')
            flash('Email not found!', 'danger')
    return render_template('login.html')

@app.route('/login/google')
def google_login():
    google_client_id = os.getenv('GOOGLE_CLIENT_ID')
    redirect_uri = os.getenv('GOOGLE_REDIRECT_URI')
    scope = "https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile openid"

    return redirect(
        f"https://accounts.google.com/o/oauth2/v2/auth"
        f"?response_type=code"
        f"&client_id={google_client_id}"
        f"&redirect_uri={redirect_uri}"
        f"&scope={scope}"
        f"&access_type=offline"
        f"&prompt=consent"
    )

@app.route('/callback/google')
def google_callback():
    try:
        code = request.args.get("code")
        if not code:
            flash("Authorization failed.", "danger")
            return redirect(url_for("login"))

        token_url = "https://oauth2.googleapis.com/token"
        token_data = {
            "code": code,
            "client_id": os.getenv("GOOGLE_CLIENT_ID"),
            "client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
            "redirect_uri": os.getenv("GOOGLE_REDIRECT_URI"),
            "grant_type": "authorization_code",
        }

        token_response = requests.post(token_url, data=token_data)
        token_json = token_response.json()
        access_token = token_json.get("access_token")

        user_info = requests.get(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers={"Authorization": f"Bearer {access_token}"}
        ).json()

        email = user_info.get("email")
        username = user_info.get("name")
        google_id = user_info.get("id")

        if not email or not google_id:
            flash("Failed to retrieve user info from Google.", "danger")
            return redirect(url_for("login"))

        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(username=username, email=email, auth_method='google')
            db.session.add(user)
            db.session.commit()
            user_role = UserRole(user_id=user.id, role_id=Role.query.filter_by(role_name='User').first().id)
            db.session.add(user_role)
            db.session.commit()

        session['user_id'] = user.id
        session['pending_2fa'] = True
        log_id = save_login_log(user_id=user.id, email=email, status='Success')
        session['login_log_id'] = log_id
        if user.is_2fa_enabled:
            return redirect(url_for('two_factor_verify'))
        else:
            return redirect(url_for('two_factor_setup'))

    except Exception as e:
        logging.error(f"Error during Google login: {e}")
        flash("Google login failed. Please try again.", "danger")
        return redirect(url_for("login"))

@app.route('/login/github', methods=['GET'])
def github_login():
    redirect_uri = "https://yourdomain.com/callback/github"
    return redirect(f"https://github.com/login/oauth/authorize?client_id={GITHUB_CLIENT_ID}&scope=user:email&redirect_uri={redirect_uri}")

@app.route('/callback/github')
def github_callback():
    code = request.args.get('code')
    if not code:
        flash('Authorization code not found. Please try again.', 'danger')
        return redirect(url_for('login'))

    try:
        access_token_response = requests.post(
            'https://github.com/login/oauth/access_token',
            headers={'Accept': 'application/json'},
            data={
                'client_id': GITHUB_CLIENT_ID,
                'client_secret': GITHUB_CLIENT_SECRET,
                'code': code
            }
        )
        if access_token_response.status_code != 200:
            flash('Failed to retrieve access token from GitHub.', 'danger')
            return redirect(url_for('login'))

        access_token_data = access_token_response.json()
        access_token = access_token_data.get('access_token')

        if not access_token:
            error_message = access_token_data.get('error', 'Unknown error')
            flash(f'Failed to obtain access token: {error_message}', 'danger')
            return redirect(url_for('login'))

        user_info_response = requests.get(
            'https://api.github.com/user',
            headers={'Authorization': f'token {access_token}'}
        )
        if user_info_response.status_code != 200:
            flash('Failed to retrieve user information from GitHub.', 'danger')
            return redirect(url_for('login'))

        github_info = user_info_response.json()
        if 'id' not in github_info:
            error_message = github_info.get('message', 'Unknown error')
            flash(f'Failed to retrieve GitHub user ID: {error_message}', 'danger')
            return redirect(url_for('login'))

        github_id = str(github_info['id'])
        username = github_info.get('login')
        if not username:
            flash('Failed to retrieve GitHub username.', 'danger')
            return redirect(url_for('login'))

        email_response = requests.get(
            'https://api.github.com/user/emails',
            headers={'Authorization': f'token {access_token}'}
        )
        if email_response.status_code != 200:
            flash('Failed to retrieve email from GitHub.', 'danger')
            return redirect(url_for('login'))

        email_data = email_response.json()
        email = None
        for email_entry in email_data:
            if email_entry.get('primary') and email_entry.get('verified'):
                email = email_entry.get('email')
                break

        if not email:
            flash('No verified email found in your GitHub account. Please add a verified email to your GitHub profile.', 'danger')
            return redirect(url_for('login'))

        user = User.query.filter_by(github_id=github_id).first()
        if not user:
            user = User(username=username, email=email, github_id=github_id, auth_method='github')
            db.session.add(user)
            db.session.commit()
            user_role = UserRole(user_id=user.id, role_id=Role.query.filter_by(role_name='User').first().id)
            db.session.add(user_role)
            db.session.commit()

        session['user_id'] = user.id
        session['pending_2fa'] = True
        log_id = save_login_log(user_id=user.id, email=email, status='Success')
        session['login_log_id'] = log_id
        if user.is_2fa_enabled:
            return redirect(url_for('two_factor_verify'))
        else:
            return redirect(url_for('two_factor_setup'))
    except Exception as e:
        save_login_log(email=email, status='Failed')
        logging.error(f"Error in GitHub callback: {str(e)}")
        flash('An error occurred during GitHub login. Please try again.', 'danger')
        return redirect(url_for('login'))

@app.route('/logout', methods=['GET'])
def logout():
    log_id = session.get('login_log_id')
    if log_id:
        log_entry = LoginLog.query.get(log_id)
        if log_entry and log_entry.status == 'Success':
            naive_timestamp = log_entry.timestamp
            aware_timestamp = LOCAL_TIMEZONE.localize(naive_timestamp)
            duration = (local_now() - aware_timestamp).total_seconds()
            log_entry.session_duration = int(duration)
            db.session.commit()
    
    session.clear()
    response = make_response(render_template('logout.html'))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    flash('Logged out successfully!', 'success')
    return response

@app.route('/2fa/setup', methods=['GET', 'POST'])
def two_factor_setup():
    if 'user_id' not in session:
        flash('Please log in first!', 'danger')
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        token = request.form.get('token')
        if not user.two_factor_secret:
            flash('2FA setup not initiated properly!', 'danger')
            return redirect(url_for('two_factor_setup'))
        
        if pyotp.TOTP(user.two_factor_secret).verify(token):
            user.is_2fa_enabled = True
            session.pop('pending_2fa', None)
            db.session.commit()
            flash('2FA setup successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid 2FA code!', 'danger')
    
    if not user.two_factor_secret:
        user.two_factor_secret = pyotp.random_base32()
        db.session.commit()
    
    totp_uri = pyotp.TOTP(user.two_factor_secret).provisioning_uri(
        name=user.email, issuer_name="SecureDocs"
    )
    qr = qrcode.make(totp_uri)
    buffered = io.BytesIO()
    qr.save(buffered, format="PNG")
    qr_code = base64.b64encode(buffered.getvalue()).decode('utf-8')
    
    return render_template('2fa_setup.html', qr_code=qr_code)

@app.route('/2fa/verify', methods=['GET', 'POST'])
def two_factor_verify():
    if 'user_id' not in session or not session.get('pending_2fa'):
        flash('Please log in first!', 'danger')
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        token = request.form.get('token')
        if pyotp.TOTP(user.two_factor_secret).verify(token):
            session.pop('pending_2fa', None)
            flash('2FA verification successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid 2FA code!', 'danger')
    
    return render_template('2fa_verify.html')

@app.route('/upload', methods=['GET', 'POST'])
def upload_document():
    if 'user_id' not in session:
        flash('Please log in to upload documents!', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        if 'file' not in request.files or request.files['file'].filename == '':
            flash('No file selected!', 'danger')
            return redirect(url_for('upload_document'))

        file = request.files['file']
        if not allowed_file(file.filename):
            flash('Invalid file type! Only PDF, DOCX, and TXT are allowed.', 'danger')
            return redirect(url_for('upload_document'))

        try:
            file_content = file.read()
            file_size = len(file_content)
            file_hash = hashlib.sha256(file_content).hexdigest()

            # Check for duplicate file by hash for this user
            existing_doc = Document.query.filter_by(user_id=session['user_id'], file_hash=file_hash).first()
            if existing_doc:
                flash('You have already uploaded this file.', 'warning')
                return redirect(url_for('upload_document'))

            # AES-256 encryption with EAX mode (nonce+tag)
            aes_key = secrets.token_bytes(32)
            cipher = AES.new(aes_key, AES.MODE_EAX)
            ciphertext, tag = cipher.encrypt_and_digest(file_content)
            encrypted_data = cipher.nonce + tag + ciphertext
            encoded_key = base64.b64encode(aes_key).decode('utf-8')

            # HMAC for integrity using app secret key
            hmac_key = current_app.config['HMAC_SECRET_KEY']
            hmac_value = hmac.new(hmac_key, encrypted_data, hashlib.sha256).hexdigest()

            is_signed = 'sign_document' in request.form
            signature = None
            signer_type = None

            if is_signed:
                try:
                    # Get current user's username to locate their private key
                    user = User.query.get(session['user_id'])
                    private_key_path = os.path.join(os.path.dirname(__file__), 'keys', f"{user.username}_private.pem")

                    # Sign the original (unmodified) file content
                    signature = generate_signature(file_content, private_key_path)
                    signer_type = 'user'
                except Exception as sign_error:
                    logging.error(f"Signing failed: {sign_error}")
                    flash("Document uploaded but signature failed.", "warning")
                    is_signed = False

            new_document = Document(
                user_id=session['user_id'],
                filename=secure_filename(file.filename),
                file_hash=file_hash,
                encrypted_data=encrypted_data,
                file_size=file_size,
                encryption_status='Encrypted',
                aes_key=encoded_key,
                hmac=hmac_value,
                is_signed=is_signed,
                signature=signature,
                signer_type=signer_type
            )
            db.session.add(new_document)
            db.session.commit()

            log_document_activity(new_document.id, session['user_id'], 'Uploaded')
            flash('Document uploaded and encrypted successfully!', 'success')
            return redirect(url_for('upload_document'))

        except Exception as e:
            logging.error(f"Error in upload_document: {e}")
            flash('An error occurred while uploading the document. Please try again.', 'danger')
            return redirect(url_for('upload_document'))

    return render_template('upload.html')




@app.route('/documents', methods=['GET'])
def documents_list():
    if 'user_id' not in session:
        flash('Please log in to view your documents!', 'danger')
        return redirect(url_for('login'))
    
    try:
        user_id = session['user_id']
        search_query = request.args.get('search', '').strip()
        
        query = Document.query.filter_by(user_id=user_id)
        if search_query:
            query = query.filter(Document.filename.ilike(f'%{search_query}%'))
        
        documents = query.order_by(Document.created_at.desc()).all()
        total_documents = len(documents)
        
        last_activity = DocumentActivity.query.filter_by(user_id=user_id).order_by(DocumentActivity.timestamp.desc()).first()
        
        return render_template('documents.html', 
                             documents=documents, 
                             total_documents=total_documents,
                             last_activity=last_activity,
                             search_query=search_query)
    except Exception as e:
        logging.error(f"Error in documents_list: {str(e)}")
        flash('An error occurred while retrieving documents. Please try again.', 'danger')
        return redirect(url_for('home'))

@app.route('/download/<int:document_id>', methods=['GET'])
def download_document(document_id):
    if 'user_id' not in session:
        flash('Please log in to download documents!', 'danger')
        return redirect(url_for('login'))

    try:
        document = Document.query.get_or_404(document_id)
        if document.user_id != session['user_id']:
            flash('You do not have permission to download this document!', 'danger')
            return redirect(url_for('documents_list'))

        # Decode AES key from base64
        aes_key = base64.b64decode(document.aes_key)

        # Extract nonce, tag, ciphertext from encrypted_data
        encrypted_data = document.encrypted_data
        nonce = encrypted_data[:16]
        tag = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]

        hmac_key = current_app.config['HMAC_SECRET_KEY']
        calculated_hmac = hmac.new(hmac_key, document.encrypted_data, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(calculated_hmac, document.hmac):
            flash('Document integrity check failed! The file may be tampered with.', 'danger')
            return redirect(url_for('documents_list'))

        # Decrypt file
        cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)

        # Log download activity
        log_document_activity(document.id, session['user_id'], 'Downloaded')

        # Prepare file for download
        file_buffer = io.BytesIO(decrypted_data)
        mimetype = {
            'pdf': 'application/pdf',
            'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'txt': 'text/plain'
        }.get(document.filename.rsplit('.', 1)[1].lower(), 'application/octet-stream')

        return send_file(
            file_buffer,
            as_attachment=True,
            download_name=document.filename,
            mimetype=mimetype
        )

    except Exception as e:
        logging.error(f"Error in download_document: {str(e)}")
        flash('An error occurred while downloading the document. Please try again.', 'danger')
        return redirect(url_for('documents_list'))
    
    
@app.route('/document/edit/<int:doc_id>', methods=['GET', 'POST'])
def edit_document(doc_id):
    if 'user_id' not in session:
        flash('Please log in first!', 'danger')
        return redirect(url_for('login'))
    
    doc = Document.query.get_or_404(doc_id)
    
    # Make sure the document belongs to the logged-in user
    if doc.user_id != session['user_id']:
        abort(403)  # Forbidden
    
    if request.method == 'POST':
        new_name = request.form['filename'].strip()
        if new_name:
            doc.filename = secure_filename(new_name)
            db.session.commit()
            flash('Filename updated.', 'success')
            # Optionally log user activity here
        return redirect(url_for('documents_list'))
    
    return render_template('edit_document.html', doc=doc)

@app.route('/document/delete/<int:doc_id>', methods=['POST'])
def delete_document(doc_id):
    if 'user_id' not in session:
        flash('Please log in first!', 'danger')
        return redirect(url_for('login'))

    doc = Document.query.get_or_404(doc_id)
    
    # Check ownership
    if doc.user_id != session['user_id']:
        abort(403)
    
    try:
        DocumentActivity.query.filter_by(document_id=doc.id).delete()
        db.session.delete(doc)
        db.session.commit()
        flash('Document deleted successfully.', 'success')
        # Optionally log user activity here
    except Exception as e:
        logging.error(f"Error deleting document: {str(e)}")
        db.session.rollback()
        flash('An error occurred while deleting the document.', 'danger')
    
    return redirect(url_for('documents_list'))

    

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        admin = Admin.query.filter_by(username=username).first()
        if admin and check_password_hash(admin.password_hash, password):
            # Check if admin already has a key pair
            admin_key = AdminKey.query.filter_by(admin_id=admin.id).first()
            if not admin_key:
                # Generate key pair
                private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                public_key = private_key.public_key()

                private_bytes = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                public_bytes = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )

                # Save private key in 'keys/' folder
                key_dir = os.path.join(os.path.dirname(__file__), 'keys')
                os.makedirs(key_dir, exist_ok=True)
                private_key_path = os.path.join(key_dir, f"{username}_private.pem")
                with open(private_key_path, 'wb') as f:
                    f.write(private_bytes)

                # Save public key in admin_keys table
                new_admin_key = AdminKey(admin_id=admin.id, public_key=public_bytes.decode('utf-8'))
                db.session.add(new_admin_key)
                db.session.commit()

            # Set session and continue login
            session['admin_id'] = admin.id
            session['user_id'] = admin.id
            session['role'] = 'admin'

            log_id = save_login_log(admin_id=admin.id, email=username, status='Success')
            session['admin_login_log_id'] = log_id
            log_admin_activity(admin.id, 'Logged in')
            flash('Welcome, Admin!', 'success')
            return redirect(url_for('admin_home'))
        else:
            save_login_log(email=username, status='Failed')
            flash('Invalid admin credentials!', 'danger')
            return redirect(url_for('admin_login'))

    return render_template('admin_login.html')

@app.route('/admin/logout')
def logout_admin():
    admin_id = session.get('admin_id')
    log_id = session.get('admin_login_log_id')
    if log_id:
        log_entry = LoginLog.query.get(log_id)
        if log_entry and log_entry.status == 'Success':
            naive_timestamp = log_entry.timestamp
            aware_timestamp = LOCAL_TIMEZONE.localize(naive_timestamp)
            duration = (local_now() - aware_timestamp).total_seconds()
            log_entry.session_duration = int(duration)
            db.session.commit()
    
    if admin_id:
        log_admin_activity(admin_id, 'Logged out')
    session.pop('admin_id', None)
    session.pop('admin_login_log_id', None)
    flash('Logged out successfully!', 'success')
    return redirect(url_for('admin_login'))

@app.route('/admin/home')
def admin_home():
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))
    
    try:
        total_users = User.query.count()
        total_documents = Document.query.count()
        recent_activities = DocumentActivity.query.order_by(DocumentActivity.timestamp.desc()).limit(5).all()
        return render_template('admin_home.html', 
                             total_users=total_users,
                             total_documents=total_documents,
                             recent_activities=recent_activities)
    except Exception as e:
        logging.error(f"Error in admin_home: {str(e)}")
        flash('An error occurred while loading the admin dashboard.', 'danger')
        return redirect(url_for('admin_login'))

@app.route('/admin/users')
def admin_users():
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))
    
    try:
        active_filter = request.args.get('active', '')
        query = User.query.options(joinedload(User.user_roles).joinedload(UserRole.role))
        
        if active_filter == '24h':
            active_user_ids = db.session.query(LoginLog.user_id).filter(
                LoginLog.status == 'Success',
                LoginLog.timestamp >= local_now() - timedelta(hours=24)
            ).distinct().subquery()
            query = query.filter(User.id.in_(active_user_ids))
        
        users = query.all()
        return render_template('admin_users.html', users=users, active_filter=active_filter)
    except Exception as e:
        logging.error(f"Error in admin_users: {str(e)}")
        flash('An error occurred while loading users.', 'danger')
        return redirect(url_for('admin_home'))

@app.route('/admin/user/delete/<int:user_id>', methods=['POST'])
def admin_delete_user(user_id):
    if 'admin_id' not in session:
        abort(403)

    try:
        user = User.query.get_or_404(user_id)

        if user.is_admin_upload_account:
            flash("You can't delete the AdminUploader account.", 'danger')
            return redirect(url_for('admin_users'))

        user_documents = Document.query.filter_by(user_id=user.id).all()
        for doc in user_documents:
            DocumentActivity.query.filter_by(document_id=doc.id).delete()
        Document.query.filter_by(user_id=user.id).delete()
        LoginLog.query.filter_by(user_id=user.id).delete()
        UserRole.query.filter_by(user_id=user.id).delete()
        db.session.delete(user)
        db.session.commit()

        log_admin_activity(session['admin_id'], f'Deleted user {user_id}')
        flash('User and all related data have been deleted.', 'success')
    except Exception as e:
        logging.error(f"Error in admin_delete_user: {str(e)}")
        db.session.rollback()
        flash('An error occurred while deleting the user.', 'danger')
    return redirect(url_for('admin_users'))

@app.route('/admin/documents')
def admin_documents():
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))
    try:
        documents = Document.query.options(joinedload(Document.user)).all()
        return render_template('admin_documents.html', documents=documents)
    except Exception as e:
        logging.error(f"Error in admin_documents: {str(e)}")
        flash('An error occurred while loading documents.', 'danger')
        return redirect(url_for('admin_home'))

@app.route('/admin/document/delete/<int:doc_id>', methods=['POST'])
def admin_delete_document(doc_id):
    if 'admin_id' not in session:
        abort(403)
    try:
        doc = Document.query.get_or_404(doc_id)
        DocumentActivity.query.filter_by(document_id=doc.id).delete()
        db.session.delete(doc)
        db.session.commit()
        log_admin_activity(session['admin_id'], f'Deleted document {doc_id}')
        flash('Document deleted successfully.', 'success')
    except Exception as e:
        logging.error(f"Error in admin_delete_document: {str(e)}")
        db.session.rollback()
        flash('An error occurred while deleting the document.', 'danger')
    return redirect(url_for('admin_documents'))

@app.route('/admin/document/download/<int:document_id>', methods=['GET'])
def admin_download_document(document_id):
    if 'admin_id' not in session:
        flash('Admin access required!', 'danger')
        return redirect(url_for('admin_login'))

    try:
        document = Document.query.get_or_404(document_id)

        aes_key = base64.b64decode(document.aes_key)
        encrypted_data = document.encrypted_data

        nonce = encrypted_data[:16]
        tag = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]

        hmac_key = current_app.config['HMAC_SECRET_KEY']
        calculated_hmac = hmac.new(hmac_key, document.encrypted_data, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(calculated_hmac, document.hmac):
            flash('Document integrity check failed! The file may be tampered with.', 'danger')
            return redirect(url_for('documents_list'))
        
        cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)

        mimetype = {
            'pdf': 'application/pdf',
            'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'txt': 'text/plain'
        }.get(document.filename.rsplit('.', 1)[-1].lower(), 'application/octet-stream')

        log_admin_activity(session['admin_id'], f'Downloaded document {document_id}')
        return send_file(
            io.BytesIO(decrypted_data),
            as_attachment=True,
            download_name=document.filename,
            mimetype=mimetype
        )

    except Exception as e:
        logging.error(f"Admin download error: {str(e)}")
        flash('An error occurred while downloading the file.', 'danger')
        return redirect(url_for('admin_documents'))

@app.route('/admin/upload', methods=['GET', 'POST'])
def admin_upload():
    if 'admin_id' not in session:
        flash('Admin access required!', 'danger')
        return redirect(url_for('admin_login'))

    if request.method == 'POST':
        if 'file' not in request.files or request.files['file'].filename == '':
            flash('No file selected!', 'danger')
            return redirect(url_for('admin_upload'))

        file = request.files['file']
        if not allowed_file(file.filename):
            flash('Invalid file type! Only PDF, DOCX, and TXT are allowed.', 'danger')
            return redirect(url_for('admin_upload'))

        try:
            file_content = file.read()
            file_size = len(file_content)
            file_hash = hashlib.sha256(file_content).hexdigest()

            # Avoid duplicate uploads by hash (system-wide)
            if Document.query.filter_by(file_hash=file_hash).first():
                flash('File already uploaded!', 'danger')
                return redirect(url_for('admin_upload'))

            # AES-256 encryption with EAX mode
            aes_key = secrets.token_bytes(32)
            cipher = AES.new(aes_key, AES.MODE_EAX)
            ciphertext, tag = cipher.encrypt_and_digest(file_content)
            encrypted_data = cipher.nonce + tag + ciphertext
            encoded_key = base64.b64encode(aes_key).decode('utf-8')

            hmac_key = current_app.config['HMAC_SECRET_KEY']
            hmac_value = hmac.new(hmac_key, encrypted_data, hashlib.sha256).hexdigest()

            # --- Load admin private key (example path) ---
            key_dir = os.path.join(os.path.dirname(__file__), 'keys')
            admin_private_key_path = os.path.join(key_dir, "admin_private.pem")
            with open(admin_private_key_path, "rb") as key_file:
                admin_private_key = load_pem_private_key(key_file.read(), password=None)

            # --- Sign the encrypted data ---
            signature = admin_private_key.sign(
    file_content,  # ← original content, not encrypted_data
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
            signature_b64 = base64.b64encode(signature).decode('utf-8')

            # Find or create special admin uploader user
            admin_user = User.query.filter_by(is_admin_upload_account=True).first()
            if not admin_user:
                admin_user = User(
                    username='AdminUploader',
                    email='adminuploader@example.com',
                    is_admin_upload_account=True,
                    auth_method='system',
                    # Consider setting password or disabling login for this account
                )
                db.session.add(admin_user)
                db.session.commit()

            new_document = Document(
                user_id=admin_user.id,
                filename=secure_filename(file.filename),
                file_hash=file_hash,
                encrypted_data=encrypted_data,
                file_size=file_size,
                encryption_status='Encrypted',
                aes_key=encoded_key,
                hmac=hmac_value,
                is_signed=True,
                signer_type='admin',
                signature=signature
            )
            db.session.add(new_document)
            db.session.commit()

            log_document_activity(new_document.id, admin_user.id, 'Uploaded by Admin')
            log_admin_activity(session['admin_id'], f'Uploaded document {new_document.id}')

            flash('Document uploaded, AES-encrypted, and signed successfully!', 'success')
            return redirect(url_for('admin_upload'))

        except Exception as e:
            logging.error(f"Admin upload error: {e}")
            db.session.rollback()
            flash('An error occurred while uploading the document.', 'danger')
            return redirect(url_for('admin_upload'))

    return render_template('admin_upload.html')


@app.route('/admin/document/edit/<int:doc_id>', methods=['GET', 'POST'])
def admin_edit_document(doc_id):
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))

    doc = Document.query.get_or_404(doc_id)

    if request.method == 'POST':
        new_name = request.form['filename'].strip()
        if new_name:
            doc.filename = secure_filename(new_name)
            db.session.commit()
            log_admin_activity(session['admin_id'], f'Edited document {doc_id} filename')
            flash('Filename updated.', 'success')
        return redirect(url_for('admin_documents'))

    return render_template('admin_edit_document.html', doc=doc)

@app.route('/admin/document/view/<int:doc_id>', methods=['GET'])
def admin_view_document(doc_id):
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))

    doc = Document.query.get_or_404(doc_id)

    try:
        aes_key = base64.b64decode(doc.aes_key)
        encrypted_data = doc.encrypted_data

        # HMAC verification
        hmac_key = current_app.config['HMAC_SECRET_KEY']
        calculated_hmac = hmac.new(hmac_key, encrypted_data, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(calculated_hmac, doc.hmac):
            flash('Document integrity check failed! It may be tampered with.', 'danger')
            return render_template('admin_view_document.html', doc=doc, file_content='[HMAC verification failed]')

        # Continue decryption
        nonce = encrypted_data[:16]
        tag = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]

        cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        file_content = plaintext.decode('utf-8', errors='ignore')

        log_admin_activity(session['admin_id'], f'Viewed document {doc_id}')

    except Exception as e:
        logging.error(f"Error in admin_view_document: {str(e)}")
        flash('Failed to decrypt or decode file.', 'danger')
        file_content = '[Cannot decode encrypted file]'

    return render_template('admin_view_document.html', doc=doc, file_content=file_content)


@app.route('/admin/user/add', methods=['GET', 'POST'])
def admin_add_user():
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))

    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']

        if not all([username, email, password]):
            flash('All fields are required.', 'danger')
            return redirect(url_for('admin_add_user'))

        if not valid_password(password):
            flash('Password must be at least 8 characters, with uppercase, lowercase, number, and special character!', 'danger')
            return redirect(url_for('admin_add_user'))

        try:
            existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
            if existing_user:
                flash('Username or email already exists!', 'danger')
                return redirect(url_for('admin_add_user'))

            hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
            user = User(username=username, email=email, password=hashed_pw, created_at=local_now(), auth_method='manual')
            db.session.add(user)
            db.session.commit()
            
            user_role = UserRole(user_id=user.id, role_id=Role.query.filter_by(role_name='User').first().id)
            db.session.add(user_role)
            db.session.commit()
            
            log_admin_activity(session['admin_id'], f'Added user {user.id}')
            flash('User added successfully.', 'success')
            return redirect(url_for('admin_users'))
        except Exception as e:
            logging.error(f"Admin add user error: {str(e)}")
            db.session.rollback()
            flash('An error occurred while adding the user.', 'danger')
            return redirect(url_for('admin_add_user'))

    return render_template('admin_add_user.html')

@app.route('/admin/user/edit/<int:user_id>', methods=['GET', 'POST'])
def admin_edit_user(user_id):
    if 'admin_id' not in session:
        flash('Admin access required!', 'danger')
        return redirect(url_for('admin_login'))

    user = User.query.get_or_404(user_id)

    if user.is_admin_upload_account:
        flash("Cannot edit the AdminUploader account!", 'danger')
        return redirect(url_for('admin_users'))

    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form.get('password')

        if not username or not email:
            flash('Username and email are required!', 'danger')
            return redirect(url_for('admin_edit_user', user_id=user_id))

        existing_user = User.query.filter(
            ((User.username == username) | (User.email == email)) & (User.id != user.id)
        ).first()
        if existing_user:
            flash('Username or email already exists!', 'danger')
            return redirect(url_for('admin_edit_user', user_id=user_id))

        user.username = username
        user.email = email
        if password and valid_password(password):
            user.password = bcrypt.generate_password_hash(password).decode('utf-8')
        elif password:
            flash('Password does not meet requirements!', 'danger')
            return redirect(url_for('admin_edit_user', user_id=user_id))

        try:
            db.session.commit()
            log_admin_activity(session['admin_id'], f'Updated user {user_id}')
            flash(f"User {user.username} updated successfully!", 'success')
        except Exception as e:
            logging.error(f"Error updating user: {str(e)}")
            db.session.rollback()
            flash('An error occurred while updating the user.', 'danger')

        return redirect(url_for('admin_users'))

    return render_template('admin_edit_user.html', user=user)

@app.route('/admin/roles', methods=['GET', 'POST'])
def admin_roles():
    if 'admin_id' not in session:
        flash('Admin access required!', 'danger')
        return redirect(url_for('admin_login'))
    
    if request.method == 'POST':
        role_name = request.form['role_name'].strip()
        description = request.form['description'].strip()
        
        if not role_name:
            flash('Role name is required!', 'danger')
            return redirect(url_for('admin_roles'))
        
        existing_role = Role.query.filter_by(role_name=role_name).first()
        if existing_role:
            flash('Role already exists!', 'danger')
            return redirect(url_for('admin_roles'))
        
        new_role = Role(role_name=role_name, description=description)
        db.session.add(new_role)
        db.session.commit()
        log_admin_activity(session['admin_id'], f'Added role {role_name}')
        flash('Role added successfully!', 'success')
        return redirect(url_for('admin_roles'))
    
    roles = Role.query.all()
    return render_template('admin_roles.html', roles=roles)

@app.route('/admin/user/assign_role/<int:user_id>', methods=['GET', 'POST'])
def admin_assign_role(user_id):
    if 'admin_id' not in session:
        flash('Admin access required!', 'danger')
        return redirect(url_for('admin_login'))
    
    user = User.query.get_or_404(user_id)
    if user.is_admin_upload_account:
        flash("Cannot modify roles for AdminUploader account!", 'danger')
        return redirect(url_for('admin_users'))
    
    if request.method == 'POST':
        role_id = request.form['role_id']
        role = Role.query.get_or_404(role_id)
        
        UserRole.query.filter_by(user_id=user_id).delete()
        
        new_user_role = UserRole(user_id=user_id, role_id=role_id)
        db.session.add(new_user_role)
        db.session.commit()
        log_admin_activity(session['admin_id'], f'Assigned role {role.role_name} to user {user_id}')
        flash(f"Role {role.role_name} assigned to {user.username}!", 'success')
        return redirect(url_for('admin_users'))
    
    roles = Role.query.all()
    current_roles = [ur.role_id for ur in UserRole.query.filter_by(user_id=user_id).all()]
    return render_template('admin_assign_role.html', user=user, roles=roles, current_roles=current_roles)

@app.route('/admin/user/activity/<int:user_id>')
def user_activity(user_id):
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))
    
    try:
        user = User.query.get_or_404(user_id)
        login_logs = LoginLog.query.filter_by(user_id=user_id).order_by(LoginLog.timestamp.desc()).all()
        documents = Document.query.filter_by(user_id=user_id).order_by(Document.created_at.desc()).all()
        document_activities = DocumentActivity.query.filter_by(user_id=user_id).order_by(DocumentActivity.timestamp.desc()).all()
        user_roles = UserRole.query.filter_by(user_id=user_id).all()
        role_names = [Role.query.get(user_role.role_id).role_name for user_role in user_roles]
        
        return render_template('user_activity.html', 
                             user=user, 
                             login_logs=login_logs, 
                             documents=documents, 
                             document_activities=document_activities,
                             role_names=role_names)
    except Exception as e:
        logging.error(f"Error in user_activity: {str(e)}")
        flash('An error occurred while loading user activity.', 'danger')
        return redirect(url_for('admin_users'))

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        flash('Please log in to view your profile!', 'danger')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form.get('password')

        if not username or not email:
            flash('Username and email are required!', 'danger')
            return redirect(url_for('profile'))

        existing_user = User.query.filter(
            ((User.username == username) | (User.email == email)) & (User.id != user.id)
        ).first()
        if existing_user:
            flash('Username or email already exists!', 'danger')
            return redirect(url_for('profile'))

        user.username = username
        user.email = email
        if password and valid_password(password):
            user.password = bcrypt.generate_password_hash(password).decode('utf-8')
        elif password:
            flash('Password does not meet requirements!', 'danger')
            return redirect(url_for('profile'))

        try:
            db.session.commit()
            flash('Profile updated successfully!', 'success')
        except Exception as e:
            logging.error(f"Error updating profile: {str(e)}")
            db.session.rollback()
            flash('An error occurred while updating your profile.', 'danger')

        return redirect(url_for('profile'))

    return render_template('profile.html', user=user)

@app.route('/admin/logs', methods=['GET'])
def admin_logs():
    if 'admin_id' not in session:
        flash('Admin access required!', 'danger')
        return redirect(url_for('admin_login'))

    # Check if required tables exist to prevent database errors
    try:
        inspector = db.inspect(db.engine)
        required_tables = ['login_log', 'document_activity', 'admin_activity', 'user', 'admin', 'document']
        missing_tables = [table for table in required_tables if table not in inspector.get_table_names()]
        if missing_tables:
            flash(f"Missing tables: {missing_tables}. Please initialize the database.", 'danger')
            return redirect(url_for('admin_home'))
    except Exception as e:
        logging.error(f"Error checking tables: {str(e)}")
        flash('Database error. Please check logs.', 'danger')
        return redirect(url_for('admin_home'))

    # Set default values for stats and charts to prevent errors if queries fail
    total_users = total_documents = failed_logins_today = active_users = 0
    chart_data = {'labels': ['No Users'], 'data': [0]}
    file_types_data = {'labels': ['PDF', 'DOCX', 'TXT'], 'data': [0, 0, 0]}
    last_7_days = [(local_now().date() - timedelta(days=x)).strftime('%Y-%m-%d') for x in range(6, -1, -1)]
    login_attempts_data = {'labels': last_7_days, 'data': [0] * 7}
    activity_types_data = {'labels': ['No Activity'], 'data': [0]}
    login_logs = activity_logs = admin_activities = []
    login_logs_paginated = activity_logs_paginated = admin_activities_paginated = None

    # Statistics (Total users, documents, failed logins, active users)
    try:
        total_users = User.query.count()
        logging.debug(f"Total users: {total_users}")
        total_documents = Document.query.count()
        logging.debug(f"Total documents: {total_documents}")

        failed_logins_today = LoginLog.query.filter(
            LoginLog.status == 'Failed',
            func.date(LoginLog.timestamp) == local_now().date()
        ).count()
        logging.debug(f"Failed logins today: {failed_logins_today}")

        active_users = db.session.query(func.count(func.distinct(LoginLog.user_id))).filter(
            LoginLog.status == 'Success',
            LoginLog.timestamp >= local_now() - timedelta(hours=24)
        ).scalar() or 0
        logging.debug(f"Active users (last 24h): {active_users}")
    except Exception as e:
        logging.error(f"Error in stats: {str(e)}")

    # Documents per User Chart
    try:
        document_counts = db.session.query(
            User.username,
            func.count(Document.id)
        ).outerjoin(Document, User.id == Document.user_id)\
         .group_by(User.id, User.username).all()
        chart_data = {
            'labels': [username for username, _ in document_counts] or ['No Users'],
            'data': [count for _, count in document_counts] or [0]
        }
        logging.debug(f"Documents per user chart data: {chart_data}")
    except Exception as e:
        logging.error(f"Error in documents chart: {str(e)}")

    # File Types Distribution Chart
    try:
        file_types = db.session.query(
            func.substr(Document.filename, -4).label('extension'),
            func.count(Document.id).label('count')
        ).group_by(func.substr(Document.filename, -4)).all()
        file_types_data = {
            'labels': [ext.upper().lstrip('.') for ext, _ in file_types] or ['PDF', 'DOCX', 'TXT'],
            'data': [count for _, count in file_types] or [0, 0, 0]
        }
        logging.debug(f"File types chart data: {file_types_data}")
    except Exception as e:
        logging.error(f"Error in file types chart: {str(e)}")

    # Login Attempts Over Last 7 Days
    try:
        login_attempts = db.session.query(
            func.date(LoginLog.timestamp).label('login_date'),
            func.count(LoginLog.id).label('count')
        ).filter(
            LoginLog.timestamp >= local_now() - timedelta(days=7)
        ).group_by(func.date(LoginLog.timestamp))\
         .order_by(func.date(LoginLog.timestamp)).all()
        attempts_dict = {str(date): count for date, count in login_attempts}
        login_attempts_data = {
            'labels': last_7_days,
            'data': [attempts_dict.get(day, 0) for day in last_7_days]
        }
        logging.debug(f"Login attempts chart data: {login_attempts_data}")
    except Exception as e:
        logging.error(f"Error in login attempts chart: {str(e)}")

    # Activity Types Distribution Chart
    try:
        activity_types = db.session.query(
            DocumentActivity.action,
            func.count(DocumentActivity.id).label('count')
        ).group_by(DocumentActivity.action).all()
        activity_types_data = {
            'labels': [action for action, _ in activity_types] or ['No Activity'],
            'data': [count for _, count in activity_types] or [0]
        }
        logging.debug(f"Activity types chart data: {activity_types_data}")
    except Exception as e:
        logging.error(f"Error in activity types chart: {str(e)}")

    # Get filter parameters
    activity_type = request.args.get('activity_type', '').strip()
    search_query = request.args.get('search', '').strip()
    date_from = request.args.get('date_from', (local_now().date() - timedelta(days=7)).strftime('%Y-%m-%d')).strip()
    date_to = request.args.get('date_to', local_now().date().strftime('%Y-%m-%d')).strip()
    page = int(request.args.get('page', 1))
    per_page = 10

    # Login Logs
    try:
        login_logs_query = db.session.query(
            LoginLog,
            User.username.label('user_username'),
            User.id.label('user_id'),
        ).outerjoin(User, LoginLog.user_id == User.id)\
         

        if search_query:
            login_logs_query = login_logs_query.filter(
                or_(
                    LoginLog.email.ilike(f'%{search_query}%'),
                    User.username.ilike(f'%{search_query}%'),
                )
            )
        if date_from:
            login_logs_query = login_logs_query.filter(LoginLog.timestamp >= datetime.strptime(date_from, '%Y-%m-%d'))
        if date_to:
            login_logs_query = login_logs_query.filter(LoginLog.timestamp <= datetime.strptime(date_to + ' 23:59:59', '%Y-%m-%d %H:%M:%S'))

        login_logs_paginated = login_logs_query.order_by(LoginLog.timestamp.desc()).paginate(page=page, per_page=per_page, error_out=False)
        login_logs = login_logs_paginated.items if login_logs_paginated else []
        logging.debug(f"Login logs query returned {len(login_logs)} items")
        for log in login_logs:
            logging.debug(f"Login log entry: {log}")
    except Exception as e:
        logging.error(f"Error in login logs: {str(e)}")
        login_logs = []
        login_logs_paginated = None

    # Document Activity Logs
    try:
        activity_logs_query = db.session.query(
            DocumentActivity,
            User.username.label('username'),
            User.id.label('user_id'),
            Document.filename.label('filename'),
            Document.is_signed.label('is_signed')
        ).outerjoin(User, DocumentActivity.user_id == User.id)\
         .outerjoin(Document, DocumentActivity.document_id == Document.id)

        if search_query:
            activity_logs_query = activity_logs_query.filter(
                or_(
                    User.username.ilike(f'%{search_query}%'),
                    DocumentActivity.action.ilike(f'%{search_query}%'),
                    Document.filename.ilike(f'%{search_query}%')
                )
            )
        if activity_type:
            activity_logs_query = activity_logs_query.filter(DocumentActivity.action == activity_type)
        if date_from:
            activity_logs_query = activity_logs_query.filter(DocumentActivity.timestamp >= datetime.strptime(date_from, '%Y-%m-%d'))
        if date_to:
            activity_logs_query = activity_logs_query.filter(DocumentActivity.timestamp <= datetime.strptime(date_to + ' 23:59:59', '%Y-%m-%d %H:%M:%S'))

        activity_logs_paginated = activity_logs_query.order_by(DocumentActivity.timestamp.desc()).paginate(page=page, per_page=per_page, error_out=False)
        activity_logs = activity_logs_paginated.items if activity_logs_paginated else []
        logging.debug(f"Activity logs query returned {len(activity_logs)} items")
        for log in activity_logs:
            logging.debug(f"Activity log entry: {log}")
    except Exception as e:
        logging.error(f"Error in activity logs: {str(e)}")
        activity_logs = []

    # Admin Activity Logs
    try:
        admin_activities_query = db.session.query(
            AdminActivity,
            Admin.username
        ).outerjoin(Admin, AdminActivity.admin_id == Admin.id)

        if search_query:
            admin_activities_query = admin_activities_query.filter(
                or_(
                    Admin.username.ilike(f'%{search_query}%'),
                    AdminActivity.action.ilike(f'%{search_query}%')
                )
            )
        if date_from:
            admin_activities_query = admin_activities_query.filter(AdminActivity.timestamp >= datetime.strptime(date_from, '%Y-%m-%d'))
        if date_to:
            admin_activities_query = admin_activities_query.filter(AdminActivity.timestamp <= datetime.strptime(date_to + ' 23:59:59', '%Y-%m-%d %H:%M:%S'))

        admin_activities_paginated = admin_activities_query.order_by(AdminActivity.timestamp.desc()).paginate(page=page, per_page=per_page, error_out=False)
        admin_activities = admin_activities_paginated.items if admin_activities_paginated else []
        logging.debug(f"Admin activities query returned {len(admin_activities)} items")
        for log in admin_activities:
            logging.debug(f"Admin activity log entry: {log}")
    except Exception as e:
        logging.error(f"Error in admin activities: {str(e)}")
        admin_activities = []

    return render_template('admin_logs.html', 
                         total_users=total_users,
                         total_documents=total_documents,
                         failed_logins_today=failed_logins_today,
                         active_users=active_users,
                         chart_data=chart_data,
                         file_types_data=file_types_data,
                         login_attempts_data=login_attempts_data,
                         activity_types_data=activity_types_data,
                         login_logs=login_logs, 
                         login_logs_paginated=login_logs_paginated,
                         activity_logs=activity_logs, 
                         activity_logs_paginated=activity_logs_paginated,
                         admin_activities=admin_activities,
                         admin_activities_paginated=admin_activities_paginated,
                         search_query=search_query,
                         activity_type=activity_type,
                         date_from=date_from,
                         date_to=date_to,
                         page=page)

@app.route('/admin/notifications', methods=['GET'])
def admin_notifications():
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))

    try:
        time_threshold = local_now() - timedelta(hours=24)
        
        failed_logins = LoginLog.query.filter(
            LoginLog.status == 'Failed',
            LoginLog.timestamp >= time_threshold
        ).order_by(LoginLog.timestamp.desc()).all()

        critical_actions = AdminActivity.query.filter(
            AdminActivity.action.ilike('%deleted%'),
            AdminActivity.timestamp >= time_threshold
        ).join(Admin, AdminActivity.admin_id == Admin.id)\
         .order_by(AdminActivity.timestamp.desc()).all()

        suspicious_logins = db.session.query(LoginLog)\
            .filter(LoginLog.user_id != None, LoginLog.status == 'Success', LoginLog.timestamp >= time_threshold)\
            .group_by(LoginLog.user_id, LoginLog.country)\
            .having(func.count(func.distinct(LoginLog.country)) > 1).all()
        
        for log in suspicious_logins:
            existing_notification = Notification.query.filter_by(
                type='Suspicious Login',
                user_id=log.user_id,
                ip_address=log.ip_address
            ).first()
            if not existing_notification:
                notification = Notification(
                    type='Suspicious Login',
                    message=f'User {log.user_id} logged in from multiple countries: {log.country}',
                    user_id=log.user_id,
                    ip_address=log.ip_address,
                    timestamp=local_now()
                )
                db.session.add(notification)
        db.session.commit()

        notifications = Notification.query.order_by(Notification.timestamp.desc()).all()

        return render_template('admin_notifications.html',
                             failed_logins=failed_logins,
                             critical_actions=critical_actions,
                             notifications=notifications)
    except Exception as e:
        logging.error(f"Error in admin_notifications: {str(e)}")
        flash('An error occurred while loading notifications.', 'danger')
        return redirect(url_for('admin_home'))

@app.route('/admin/notifications/mark_read/<int:notification_id>', methods=['POST'])
def mark_notification_read(notification_id):
    if 'admin_id' not in session:
        flash('Admin access required!', 'danger')
        return redirect(url_for('admin_login'))

    try:
        notification = Notification.query.get_or_404(notification_id)
        notification.is_read = True
        db.session.commit()
        log_admin_activity(session['admin_id'], f'Marked notification {notification_id} as read')
        flash('Notification marked as read.', 'success')
    except Exception as e:
        logging.error(f"Error in mark_notification_read: {str(e)}")
        db.session.rollback()
        flash('An error occurred while marking notification.', 'danger')
    return redirect(url_for('admin_notifications'))

@app.route('/admin/logs/export/<log_type>', methods=['GET'])
def export_logs(log_type):
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))
    
    try:
        output = StringIO()
        writer = csv.writer(output)
        
        if log_type == 'login':
            writer.writerow(['ID', 'User', 'Admin', 'Email', 'Status', 'IP Address', 'Country', 'Timestamp', 'Duration'])
            logs = db.session.query(
                LoginLog,
                User.username.label('user_username'),
                Admin.username.label('admin_username')
            ).outerjoin(User, LoginLog.user_id == User.id)\
             .outerjoin(Admin, LoginLog.admin_id == Admin.id).all()
            for log, user_name, admin_name in logs:
                duration = f"{log.session_duration // 60}m {log.session_duration % 60}s" if log.session_duration else 'N/A'
                writer.writerow([log.id, user_name or '', admin_name or '', log.email, log.status, log.ip_address, log.country or 'Unknown', log.timestamp, duration])
        
        elif log_type == 'user_activity':
            writer.writerow(['ID', 'Username', 'Document ID', 'Action', 'IP Address', 'Timestamp'])
            logs = db.session.query(
                DocumentActivity,
                User.username
            ).join(User, DocumentActivity.user_id == User.id).all()
            for activity, username in logs:
                writer.writerow([activity.id, username, activity.document_id, activity.action, activity.ip_address, activity.timestamp])
        
        elif log_type == 'admin_activity':
            writer.writerow(['ID', 'Admin Username', 'Action', 'IP Address', 'Timestamp'])
            logs = db.session.query(
                AdminActivity,
                Admin.username
            ).join(Admin, AdminActivity.admin_id == Admin.id).all()
            for activity, username in logs:
                writer.writerow([activity.id, username, activity.action, activity.ip_address, activity.timestamp])
        
        else:
            flash('Invalid log type!', 'danger')
            return redirect(url_for('admin_logs'))
        
        output.seek(0)
        log_admin_activity(session['admin_id'], f'Exported {log_type} logs as CSV')
        return send_file(
            io.BytesIO(output.getvalue().encode('utf-8')),
            as_attachment=True,
            download_name=f"{log_type}_logs_{local_now().strftime('%Y%m%d_%H%M%S')}.csv",
            mimetype='text/csv'
        )
    except Exception as e:
        logging.error(f"Error in export_logs: {str(e)}")
        flash('An error occurred while exporting logs.', 'danger')
        return redirect(url_for('admin_logs'))

# Error Handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    logging.error(f"Internal server error: {str(error)}")
    return render_template('500.html'), 500

if __name__ == '__main__':
    import ssl
    if not os.path.exists('cert.pem') or not os.path.exists('key.pem'):
        logging.error("SSL certificates (cert.pem, key.pem) not found. Please generate them.")
        raise FileNotFoundError("SSL certificates (cert.pem, key.pem) not found.")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('cert.pem', 'key.pem')
    app.run(debug=True, port=4000, ssl_context=context)