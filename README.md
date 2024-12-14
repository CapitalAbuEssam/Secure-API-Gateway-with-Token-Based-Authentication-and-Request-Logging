# Secure Flask API

This project implements a secure API using Flask, incorporating advanced security features such as JSON Web Tokens (JWT), AES encryption, rate limiting, and robust logging.

---

## **Features**

1. **JWT Authentication**: Users are authenticated with JSON Web Tokens for secure and stateless session management.
2. **AES Encryption**: Sensitive data is encrypted and transmitted securely using AES (Advanced Encryption Standard).
3. **Rate Limiting**: Prevents abuse by limiting the number of requests a user can make within a specified time window.
4. **Detailed Logging**: Logs all events with timestamps and masked sensitive data for security and debugging.

---

## **Endpoints**

### **1. `/` (GET)**
Returns a welcome message with a list of available API endpoints.

### **2. `/login` (POST)**
Generates a JWT token for the user.

- **Input**: JSON payload with the username:
  ```json
  {
    "username": "your_username"
  }
  ```

- **Output**: JWT token:
  ```json
  {
    "token": "<your_jwt_token>"
  }
  ```

### **3. `/secure-data` (GET)**
Returns encrypted confidential data for authenticated users.

- **Input**: Include the JWT token in the Authorization header:
  ```
  Authorization: Bearer <your_jwt_token>
  ```

- **Output**: Encrypted data:
  ```json
  {
    "encrypted_data": "<base64_encoded_encrypted_data>"
  }
  ```

### **4. `/decrypt` (POST)**
Decrypts the data provided by the user.

- **Input**: JSON payload with encrypted data and Authorization header:
  ```json
  {
    "encrypted_data": "<base64_encoded_encrypted_data>"
  }
  ```

- **Output**: Original decrypted data:
  ```json
  {
    "decrypted_data": "<original_data>"
  }
  ```

---

## **Core Functionalities**

### **1. JWT Authentication**
- **Why**: Secure, stateless user authentication.
- **How It Works**:
  - Generates a token for the user with an expiration time.
  - Validates the token on each request.

### **2. AES Encryption**
- **Why**: Secure data transmission.
- **How It Works**:
  - Encrypts data using AES with a key and IV.
  - Encodes encrypted data in Base64 for safe transmission.

### **3. Rate Limiting**
- **Why**: Prevent abuse by restricting requests.
- **How It Works**:
  - Tracks each user’s request timestamps.
  - Allows a maximum of 5 requests in a 60-second window.

### **4. Logging**
- **Why**: Monitor activity and debug issues.
- **How It Works**:
  - Logs every request with a timestamp and origin.
  - Masks sensitive data in logs to ensure security.

---

## **Configuration**

### **Environment Variables**
- `JWT_SECRET_KEY`: Secret key for signing JWT tokens.
- `AES_KEY`: Secure random key for AES encryption.
- `AES_IV`: Initialization vector for AES encryption.
- `RATE_LIMIT_WINDOW`: Time window for rate limiting (in seconds).
- `MAX_REQUESTS`: Maximum requests allowed in the rate limit window.

---

## **Code Structure**

### **Global Configurations**
- **`JWT_SECRET_KEY`**: Used to sign and verify JWT tokens.
- **`AES_KEY` & `AES_IV`**: Used for encrypting and decrypting data.
- **`rate_limiter`**: Tracks user requests to enforce rate limits.

### **Functions**

#### **`encrypt_data(data)`**
- Encrypts input data using AES encryption.
- Pads data to match the AES block size (128 bits).
- Encodes encrypted data in Base64.

#### **`decrypt_data(encrypted_data)`**
- Decrypts Base64-encoded AES-encrypted data.
- Removes padding to return the original data.

#### **`mask_data(data, visible_chars=3)`**
- Masks sensitive data in logs.
- Example: `"my_password"` becomes `"my_********"`.

#### **`enforce_rate_limit(username)`**
- Tracks user request timestamps and enforces limits.
- Blocks requests exceeding `MAX_REQUESTS` in `RATE_LIMIT_WINDOW` seconds.

#### **`verify_token(request)`**
- Validates the JWT token in the request header.
- Verifies expiration and token authenticity.

---

## **Setup and Running the Application**

### **Requirements**
- Python 3.7+
- Flask
- Cryptography
- PyJWT

### **Installation**
1. Clone the repository.
2. Install dependencies:
   ```bash
   pip install flask cryptography pyjwt
   ```
3. Run the application:
   ```bash
   python app.py
   ```

### **Accessing the API**
- API runs on `http://127.0.0.1:5000/` by default.

---

## **Examples**

### **1. Login and Get Token**
Request:
```bash
curl -X POST http://127.0.0.1:5000/login -H "Content-Type: application/json" -d '{"username": "test_user"}'
```
Response:
```json
{
  "token": "<jwt_token>"
}
```

### **2. Get Secure Data**
Request:
```bash
curl -X GET http://127.0.0.1:5000/secure-data -H "Authorization: Bearer <jwt_token>"
```
Response:
```json
{
  "encrypted_data": "<base64_encoded_encrypted_data>"
}
```

### **3. Decrypt Data**
Request:
```bash
curl -X POST http://127.0.0.1:5000/decrypt -H "Authorization: Bearer <jwt_token>" -H "Content-Type: application/json" -d '{"encrypted_data": "<base64_encoded_encrypted_data>"}'
```
Response:
```json
{
  "decrypted_data": "<original_data>"
}
```

---

## **License**
This project is licensed under the MIT License. Feel free to use and modify it as needed.
