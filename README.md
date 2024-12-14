# Secure API Gateway

This project implements a **secure API gateway** using Flask. It includes robust features such as JWT authentication, AES encryption, rate limiting, and temporary data sharing. Below is an in-depth explanation of the functionality, structure, and usage of this application.

---

## Features
1. **JWT Authentication**:
   - Users log in with their username to receive a secure JWT token for authentication.
   - The token is valid for 30 minutes.
2. **AES Encryption**:
   - Confidential data is encrypted and decrypted using AES (Advanced Encryption Standard) with a 256-bit key.
3. **Rate Limiting**:
   - Users are limited to 5 requests per minute to prevent abuse.
4. **Temporary Links**:
   - Secure, time-limited links allow users to share encrypted data temporarily.
5. **Logging**:
   - All significant actions are logged for debugging and monitoring purposes.

---

## File Structure

```
project/
|-- app.py           # Main application file
|-- api.log          # Logs all requests and actions (created dynamically)
```

---

## How It Works

### 1. **JWT Authentication**
- **Route**: `/login`
- **Method**: POST
- **Description**:
  - Users send a `username` to this route.
  - A JWT token is generated, signed with a secret key, and sent back.
- **Token Example**:
  ```json
  {
      "token": "<JWT_TOKEN>"
  }
  ```
- **Security**:
  - The token expires in 30 minutes to reduce vulnerability.

---

### 2. **AES Encryption & Decryption**
#### **Encrypt Data**
- The app uses a randomly generated 256-bit AES key and a 128-bit initialization vector (IV).
- Data is padded with PKCS7 to match AES block size requirements.
- Encrypted data is Base64-encoded to make it JSON-compatible.

#### **Decrypt Data**
- The app reverses the encryption process by:
  1. Decoding Base64 data.
  2. Decrypting using AES and the same key and IV.
  3. Removing padding.

---

### 3. **Rate Limiting**
- Each user is allowed a maximum of **5 requests per minute**.
- Requests exceeding this limit return a `429 Too Many Requests` response.

---

### 4. **Temporary Links**
#### **Create Temporary Link**
- **Route**: `/create-temp-link`
- **Method**: POST
- **Description**:
  - Users provide data to encrypt.
  - The app creates a unique link with a 10-minute expiration time.
- **Response Example**:
  ```json
  {
      "temporary_link": "http://localhost:5000/access-temp-link/<LINK_ID>",
      "expires_at": "<TIMESTAMP>"
  }
  ```

#### **Access Temporary Link**
- **Route**: `/access-temp-link/<link_id>`
- **Method**: GET
- **Description**:
  - Decrypts and retrieves data from the link if it has not expired.
  - Expired links are cleaned up automatically.

---

### 5. **Logging**
- All actions (logins, access attempts, errors) are logged in `api.log` for monitoring.
- Logs include timestamps, severity levels, and masked usernames.

---

## Available Endpoints

| Endpoint                  | Method | Description                                                |
|---------------------------|--------|------------------------------------------------------------|
| `/`                       | GET    | Welcome message and available routes.                     |
| `/login`                  | POST   | User login to receive JWT token.                          |
| `/secure-data`            | GET    | Access encrypted secure data (requires JWT token).        |
| `/decrypt`                | POST   | Decrypt data (requires JWT token).                        |
| `/create-temp-link`       | POST   | Generate a temporary sharing link for encrypted data.     |
| `/access-temp-link/<id>`  | GET    | Access data from a temporary link (if not expired).       |

---

## Setup & Run

### Prerequisites
- Python 3.9+
- Install required packages:
  ```bash
  pip install flask pyjwt cryptography
  ```

### Run the Application
- Start the Flask server:
  ```bash
  python app.py
  ```
- Access the API at `http://localhost:5000`.

---

## Detailed Code Explanation

### **Key Components**
#### **1. Flask App Initialization**
- The Flask app is initialized with `Flask(__name__)`.
- Secret keys for JWT and AES are dynamically generated using `secrets`.

#### **2. Authentication Middleware**
- The `verify_token` function validates JWT tokens in incoming requests.
- Tokens are expected in the `Authorization` header as `Bearer <token>`.

#### **3. Encryption/Decryption Utilities**
- Encryption and decryption functions handle AES-based security with:
  - CBC (Cipher Block Chaining) mode.
  - PKCS7 padding for block size alignment.
  - Base64 encoding for JSON serialization.

#### **4. Rate Limiting Middleware**
- The `enforce_rate_limit` function tracks request timestamps per user using a `defaultdict`.

#### **5. Temporary Links**
- Shared links are stored in a `shared_links` dictionary.
- Each link has an expiration time (10 minutes).

---

## Example Usage

### 1. **Log In**
Request:
```bash
curl -X POST http://localhost:5000/login -H "Content-Type: application/json" -d '{"username": "test_user"}'
```
Response:
```json
{
    "token": "<JWT_TOKEN>"
}
```

### 2. **Access Secure Data**
Request:
```bash
curl -X GET http://localhost:5000/secure-data -H "Authorization: Bearer <JWT_TOKEN>"
```
Response:
```json
{
    "encrypted_data": "<BASE64_ENCRYPTED_INFO>"
}
```

### 3. **Decrypt Data**
Request:
```bash
curl -X POST http://localhost:5000/decrypt -H "Authorization: Bearer <JWT_TOKEN>" -H "Content-Type: application/json" -d '{"data": "<BASE64_ENCRYPTED_INFO>"}'
```
Response:
```json
{
    "decrypted_data": "This is highly confidential information."
}
```

### 4. **Create Temporary Link**
Request:
```bash
curl -X POST http://localhost:5000/create-temp-link -H "Authorization: Bearer <JWT_TOKEN>" -H "Content-Type: application/json" -d '{"data": "Sensitive Information"}'
```
Response:
```json
{
    "temporary_link": "http://localhost:5000/access-temp-link/<LINK_ID>",
    "expires_at": "<TIMESTAMP>"
}
```

---

## Security Measures
1. **Dynamic Keys**:
   - AES keys and IVs are dynamically generated at runtime to ensure unpredictability.
2. **JWT Expiration**:
   - Tokens expire after 30 minutes to mitigate unauthorized access risks.
3. **Rate Limiting**:
   - Prevents abuse by enforcing limits on API usage.
4. **Masked Logging**:
   - Usernames are partially masked in logs to protect sensitive information.

---

## License
This project is open-source and available under the MIT License.

---

Happy Coding! 🎉
