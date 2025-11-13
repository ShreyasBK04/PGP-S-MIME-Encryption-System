

# 🔐 PGP/S-MIME Hybrid Encryption System

A browser-based hybrid encryption tool built using **React.js**, **JavaScript**, and the **Web Crypto API**.
This system implements real AES-256 and RSA-2048 encryption similar to PGP/S/MIME.

---

## 🚀 Features

### 🔑 **Key Generation**

* Generates an RSA-2048 key pair (Public + Private)
* Keys exported in Base64 (SPKI & PKCS8 formats)
* Secure random number generation using `crypto.getRandomValues()`

### 🔒 **Encryption (Hybrid Model)**

Uses a two-layer hybrid encryption approach:

1. **AES-256-GCM** – Encrypts the plaintext message
2. **RSA-2048 (OAEP)** – Encrypts the AES session key
3. Bundles everything as a JSON package:

   ```json
   {
     "encryptedSessionKey": "...",
     "encryptedMessage": "...",
     "iv": "..."
   }
   ```

### 🔓 **Decryption**

* Decrypts AES session key using RSA private key
* Uses AES-GCM to decrypt the actual message
* Displays original plaintext

### 🧩 **UI Features**

* Clean, modern UI built with **Tailwind CSS**
* Tabs for Key Generation, Encryption, and Decryption
* Copy-to-Clipboard buttons
* Status messages for success/error feedback

---

## 🛠️ Tech Stack

| Technology                        | Purpose                                        |
| --------------------------------- | ---------------------------------------------- |
| **React.js**                      | Frontend UI and application logic              |
| **JavaScript (ES6+)**             | Core encryption logic                          |
| **Web Crypto API (SubtleCrypto)** | AES/RSA key generation, encryption, decryption |
| **Tailwind CSS**                  | Styling and layout                             |
| **Lucide React Icons**            | UI icons                                       |

---

## 📦 How It Works — Architecture

### 🔐 **1. Key Generation**

```js
crypto.subtle.generateKey({
  name: "RSA-OAEP",
  modulusLength: 2048,
  publicExponent: new Uint8Array([1, 0, 1]),
  hash: "SHA-256",
})
```

### 🔒 **2. Encryption Process**

* Generate AES-256 session key
* Encrypt message using AES-GCM
* Encrypt session key using RSA-OAEP
* Convert everything to Base64
* Prepare encrypted package

### 🔓 **3. Decryption Process**

* Import private key
* Decrypt AES session key
* Decrypt actual message
* Display plaintext

---

## 🧪 Testing Instructions

1. Go to **Key Generation** tab → Generate RSA Key Pair
2. Copy the **public key**
3. Go to **Encrypt** tab → Enter message → Paste public key → Encrypt
4. Copy the encrypted package
5. Go to **Decrypt** tab → Paste package + private key → Decrypt
6. View original message

---

## 📂 Folder Structure (Important Files)

```
/src
│── components/
│── App.js
│── PGPEncryptionSystem.jsx   ← main component
│── index.js
│── styles.css
```

---

## 🔧 Requirements

* Node.js & npm
* React environment

Install dependencies:

```bash
npm install
```

Start development server:

```bash
npm run dev
```

Build for production:

```bash
npm run build
```



