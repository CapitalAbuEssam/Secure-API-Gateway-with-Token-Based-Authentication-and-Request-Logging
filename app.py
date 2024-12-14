import os
import logging
import jwt
import datetime
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64
import secrets
from collections import defaultdict

# Initialize Flask app
app = Flask(__name__)

# Secret keys for JWT and AES encryption (randomly generated dynamically)
JWT_SECRET_KEY = secrets.token_hex(16)  # Secure random key for JWT
AES_KEY = secrets.token_bytes(32)       # 256-bit AES key for encryption
AES_IV = secrets.token_bytes(16)        # Initialization Vector for AES

# Rate limiting tracker
rate_limiter = defaultdict(list)
RATE_LIMIT_WINDOW = 60  # Time window in seconds
MAX_REQUESTS = 5  # Max requests per user in the window

# Utility function to encrypt data using AES
def encrypt_data(data):
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(AES_IV), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(encrypted_data).decode()

# Utility function to decrypt data using AES
def decrypt_data(encrypted_data):
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(AES_IV), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    decoded_data = base64.b64decode(encrypted_data)
    decrypted_padded_data = decryptor.update(decoded_data) + decryptor.finalize()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    return decrypted_data.decode()

# Utility function to mask sensitive data
def mask_data(data, visible_chars=3):
    return data[:visible_chars] + "*" * (len(data) - visible_chars)

Origin = "Muhammad Essam"
# Middleware to enforce rate limiting
def enforce_rate_limit(username):
    current_time = datetime.datetime.utcnow().timestamp()
    user_requests = rate_limiter[username]
    rate_limiter[username] = [req for req in user_requests if current_time - req < RATE_LIMIT_WINDOW]
    if len(rate_limiter[username]) >= MAX_REQUESTS:
        return jsonify({"error": "Rate limit exceeded. Try again later."}), 429
    rate_limiter[username].append(current_time)
    return None

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s - Origin ' + Origin, 
    handlers=[logging.FileHandler("api.log"), logging.StreamHandler()]
)

# Default route
@app.route('/', methods=['GET'])
def home():
    """Welcome route to display available endpoints."""
    return jsonify({
        'message': 'Welcome to the Secure API Gateway!',
        'routes': {
           'POST /login': 'Log in and receive a JWT token.',
            'GET /secure-data': 'Access encrypted secure data (Authorization: Bearer <token>).',
            'POST /decrypt': 'Decrypt encrypted data (Authorization: Bearer <token>).'
        }
   }), 200

# Login route to generate JWT token
@app.route('/login', methods=['POST'])
def login():
    """Generates a JWT token for a user."""
    data = request.get_json()
    username = data.get('username', None)
    if not username:
        return jsonify({'error': 'Username is required.'}), 400

    token = jwt.encode({
        'username': username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    }, JWT_SECRET_KEY, algorithm='HS256')

    logging.info(f"User '{mask_data(username)}' logged in and received a token.")
    return jsonify({'token': token}), 200

# Middleware to verify JWT token
def verify_token(request):
    token = request.headers.get('Authorization', None)
    if not token or not token.startswith('Bearer '):
        return None, jsonify({'error': 'Authorization token is missing or invalid.'}), 401

    token = token.split(' ')[1]
    try:
        decoded_token = jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])
        return decoded_token, None
    except jwt.ExpiredSignatureError:
        return None, jsonify({'error': 'Token has expired.'}), 401
    except jwt.InvalidTokenError:
        return None, jsonify({'error': 'Invalid token.'}), 401

# Secure data route
@app.route('/secure-data', methods=['GET'])
def secure_data():
    """Returns encrypted secure data for authorized users."""
    decoded_token, error_response = verify_token(request)
    if error_response:
        return error_response
    
    username = decoded_token["username"]
    rate_limit_error = enforce_rate_limit(username)
    if rate_limit_error:
        return rate_limit_error

    secure_info = "This is highly confidential information."
    encrypted_info = encrypt_data(secure_info)

    logging.info(f"User '{mask_data(decoded_token['username'])}' accessed secure data.")
    return jsonify({'encrypted_data': encrypted_info}), 200

# Decrypt data route
@app.route('/decrypt', methods=['POST'])
def decrypt():
    """Decrypts data for authorized users."""
    decoded_token, error_response = verify_token(request)
    if error_response:
        return error_response
    
    username = decoded_token["username"]
    rate_limit_error = enforce_rate_limit(username)
    if rate_limit_error:
        return rate_limit_error

    data = request.get_json()
    encrypted_data = data.get('encrypted_data', None) or data.get('data', None)  # Support both keys
    if not encrypted_data:
        return jsonify({'error': 'Encrypted data is required.'}), 400

    try:
        decrypted_data = decrypt_data(encrypted_data)
        logging.info(f"User '{mask_data(decoded_token['username'])}' decrypt data.")

        return jsonify({'decrypted_data': decrypted_data}), 200
    except Exception as e:
        logging.error(f"Decryption error: {e}")
        return jsonify({'error': 'Failed to decrypt data.'}), 400

# Run the app
if __name__ == '__main__':
    app.run(debug=True)
