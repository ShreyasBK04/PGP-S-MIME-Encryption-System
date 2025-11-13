import React, { useState } from 'react';
import { Lock, Unlock, Key, Mail, AlertCircle, CheckCircle, Copy } from 'lucide-react';

const PGPEncryptionSystem = () => {
  const [activeTab, setActiveTab] = useState('encrypt');
  const [message, setMessage] = useState('');
  const [encryptedPackage, setEncryptedPackage] = useState('');
  const [decryptedMessage, setDecryptedMessage] = useState('');
  const [recipientPublicKey, setRecipientPublicKey] = useState('');
  const [recipientPrivateKey, setRecipientPrivateKey] = useState('');
  const [status, setStatus] = useState('');
  const [generatedKeys, setGeneratedKeys] = useState(null);

  // Convert string to ArrayBuffer
  const str2ab = (str) => {
    const buf = new ArrayBuffer(str.length);
    const bufView = new Uint8Array(buf);
    for (let i = 0; i < str.length; i++) {
      bufView[i] = str.charCodeAt(i);
    }
    return buf;
  };

  // Convert ArrayBuffer to string
  const ab2str = (buf) => {
    return String.fromCharCode.apply(null, new Uint8Array(buf));
  };

  // Convert ArrayBuffer to base64
  const ab2base64 = (buffer) => {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  };

  // Convert base64 to ArrayBuffer
  const base642ab = (base64) => {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  };

  // Generate RSA key pair
  const generateKeyPair = async () => {
    try {
      const keyPair = await window.crypto.subtle.generateKey(
        {
          name: 'RSA-OAEP',
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: 'SHA-256',
        },
        true,
        ['encrypt', 'decrypt']
      );

      const publicKey = await window.crypto.subtle.exportKey('spki', keyPair.publicKey);
      const privateKey = await window.crypto.subtle.exportKey('pkcs8', keyPair.privateKey);

      const publicKeyBase64 = ab2base64(publicKey);
      const privateKeyBase64 = ab2base64(privateKey);

      setGeneratedKeys({
        public: publicKeyBase64,
        private: privateKeyBase64
      });

      setStatus('Key pair generated successfully!');
    } catch (error) {
      setStatus('Error generating keys: ' + error.message);
    }
  };

  // Encrypt message
  const encryptMessage = async () => {
    try {
      if (!message || !recipientPublicKey) {
        setStatus('Please enter a message and recipient public key');
        return;
      }

      // 1. Generate random symmetric session key (AES-256)
      const sessionKey = await window.crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
      );

      // 2. Encrypt the message with the session key
      const iv = window.crypto.getRandomValues(new Uint8Array(12));
      const encodedMessage = new TextEncoder().encode(message);
      
      const encryptedMessage = await window.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv },
        sessionKey,
        encodedMessage
      );

      // 3. Export session key to raw format
      const rawSessionKey = await window.crypto.subtle.exportKey('raw', sessionKey);

      // 4. Import recipient's public key
      const publicKeyBuffer = base642ab(recipientPublicKey);
      const publicKey = await window.crypto.subtle.importKey(
        'spki',
        publicKeyBuffer,
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        false,
        ['encrypt']
      );

      // 5. Encrypt the session key with recipient's public key
      const encryptedSessionKey = await window.crypto.subtle.encrypt(
        { name: 'RSA-OAEP' },
        publicKey,
        rawSessionKey
      );

      // 6. Bundle everything together
      const bundle = {
        encryptedSessionKey: ab2base64(encryptedSessionKey),
        encryptedMessage: ab2base64(encryptedMessage),
        iv: ab2base64(iv)
      };

      const bundleStr = JSON.stringify(bundle, null, 2);
      setEncryptedPackage(bundleStr);
      setStatus('Message encrypted successfully!');
    } catch (error) {
      setStatus('Encryption error: ' + error.message);
    }
  };

  // Decrypt message
  const decryptMessage = async () => {
    try {
      if (!encryptedPackage || !recipientPrivateKey) {
        setStatus('Please enter encrypted package and private key');
        return;
      }

      // Parse the bundle
      const bundle = JSON.parse(encryptedPackage);

      // 1. Import recipient's private key
      const privateKeyBuffer = base642ab(recipientPrivateKey);
      const privateKey = await window.crypto.subtle.importKey(
        'pkcs8',
        privateKeyBuffer,
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        false,
        ['decrypt']
      );

      // 2. Decrypt the session key with private key
      const encryptedSessionKeyBuffer = base642ab(bundle.encryptedSessionKey);
      const sessionKeyBuffer = await window.crypto.subtle.decrypt(
        { name: 'RSA-OAEP' },
        privateKey,
        encryptedSessionKeyBuffer
      );

      // 3. Import the decrypted session key
      const sessionKey = await window.crypto.subtle.importKey(
        'raw',
        sessionKeyBuffer,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
      );

      // 4. Decrypt the message with the session key
      const iv = base642ab(bundle.iv);
      const encryptedMessageBuffer = base642ab(bundle.encryptedMessage);
      
      const decryptedBuffer = await window.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: new Uint8Array(iv) },
        sessionKey,
        encryptedMessageBuffer
      );

      // 5. Convert decrypted message to string
      const decryptedText = new TextDecoder().decode(decryptedBuffer);
      setDecryptedMessage(decryptedText);
      setStatus('Message decrypted successfully!');
    } catch (error) {
      setStatus('Decryption error: ' + error.message);
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    setStatus('Copied to clipboard!');
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 p-6">
      <div className="max-w-6xl mx-auto">
        <div className="bg-white rounded-lg shadow-xl p-8 mb-6">
          <div className="flex items-center gap-3 mb-6">
            <Lock className="w-8 h-8 text-indigo-600" />
            <h1 className="text-3xl font-bold text-gray-800">PGP/S/MIME Encryption System</h1>
          </div>
          
    
          
          {/* Problem Statement Dropdown */}
          <details className="mb-6 bg-purple-50 rounded-lg border border-purple-200">
            <summary className="cursor-pointer p-4 font-semibold text-purple-900 hover:bg-purple-100 rounded-lg transition-colors">
              📋 Problem Statement / Question
            </summary>
            <div className="p-4 pt-2 text-gray-700 space-y-3">
              <h3 className="font-bold text-lg text-purple-900">PGP/S/MIME Message Encryption</h3>
              <p className="font-medium">Create a program that encrypts a message for a recipient. It should:</p>
              <ol className="list-decimal ml-6 space-y-2">
                <li>Generate a random symmetric session key</li>
                <li>Encrypt the message with the session key</li>
                <li>Encrypt the session key with the recipient's public key</li>
                <li>Bundle the encrypted session key and encrypted message together</li>
              </ol>
              <p className="font-medium mt-4">Also, write the corresponding program for decryption:</p>
              <p className="ml-6">The recipient uses their private key to decrypt the session key and then uses the session key to decrypt the main message.</p>
            </div>
          </details>
          
          <p className="text-gray-600 mb-6">
            This implements hybrid encryption: messages are encrypted with a random AES-256 session key, 
            and the session key is encrypted with the recipient's RSA public key.
          </p>

          {/* Status Message */}
          {status && (
            <div className={`flex items-center gap-2 p-4 rounded-lg mb-6 ${
              status.includes('Error') || status.includes('error') 
                ? 'bg-red-50 text-red-700' 
                : 'bg-green-50 text-green-700'
            }`}>
              {status.includes('Error') || status.includes('error') 
                ? <AlertCircle className="w-5 h-5" />
                : <CheckCircle className="w-5 h-5" />
              }
              <span>{status}</span>
            </div>
          )}

          {/* Tab Navigation */}
          <div className="flex gap-2 mb-6 border-b">
            <button
              onClick={() => setActiveTab('keygen')}
              className={`px-6 py-3 font-medium transition-colors ${
                activeTab === 'keygen'
                  ? 'text-indigo-600 border-b-2 border-indigo-600'
                  : 'text-gray-500 hover:text-gray-700'
              }`}
            >
              <div className="flex items-center gap-2">
                <Key className="w-4 h-4" />
                Key Generation
              </div>
            </button>
            <button
              onClick={() => setActiveTab('encrypt')}
              className={`px-6 py-3 font-medium transition-colors ${
                activeTab === 'encrypt'
                  ? 'text-indigo-600 border-b-2 border-indigo-600'
                  : 'text-gray-500 hover:text-gray-700'
              }`}
            >
              <div className="flex items-center gap-2">
                <Lock className="w-4 h-4" />
                Encrypt
              </div>
            </button>
            <button
              onClick={() => setActiveTab('decrypt')}
              className={`px-6 py-3 font-medium transition-colors ${
                activeTab === 'decrypt'
                  ? 'text-indigo-600 border-b-2 border-indigo-600'
                  : 'text-gray-500 hover:text-gray-700'
              }`}
            >
              <div className="flex items-center gap-2">
                <Unlock className="w-4 h-4" />
                Decrypt
              </div>
            </button>
          </div>

          {/* Key Generation Tab */}
          {activeTab === 'keygen' && (
            <div className="space-y-6">
              <div className="bg-blue-50 p-4 rounded-lg">
                <p className="text-sm text-blue-800">
                  Generate a new RSA-2048 key pair for testing. The public key is used for encryption, 
                  and the private key is used for decryption.
                </p>
              </div>

              <button
                onClick={generateKeyPair}
                className="w-full bg-indigo-600 text-white py-3 rounded-lg hover:bg-indigo-700 transition-colors font-medium"
              >
                Generate New Key Pair
              </button>

              {generatedKeys && (
                <div className="space-y-4">
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <label className="block text-sm font-medium text-gray-700">Public Key</label>
                      <button
                        onClick={() => copyToClipboard(generatedKeys.public)}
                        className="text-sm text-indigo-600 hover:text-indigo-700 flex items-center gap-1"
                      >
                        <Copy className="w-4 h-4" />
                        Copy
                      </button>
                    </div>
                    <textarea
                      value={generatedKeys.public}
                      readOnly
                      className="w-full h-32 p-3 border rounded-lg font-mono text-xs bg-gray-50"
                    />
                  </div>

                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <label className="block text-sm font-medium text-gray-700">Private Key (Keep Secret!)</label>
                      <button
                        onClick={() => copyToClipboard(generatedKeys.private)}
                        className="text-sm text-indigo-600 hover:text-indigo-700 flex items-center gap-1"
                      >
                        <Copy className="w-4 h-4" />
                        Copy
                      </button>
                    </div>
                    <textarea
                      value={generatedKeys.private}
                      readOnly
                      className="w-full h-32 p-3 border rounded-lg font-mono text-xs bg-red-50"
                    />
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Encryption Tab */}
          {activeTab === 'encrypt' && (
            <div className="space-y-6">
              <div className="bg-green-50 p-4 rounded-lg">
                <p className="text-sm text-green-800 mb-2">
                  <strong>Encryption Process:</strong>
                </p>
                <ol className="text-sm text-green-700 space-y-1 ml-4 list-decimal">
                  <li>Generate a random AES-256 session key</li>
                  <li>Encrypt the message with the session key</li>
                  <li>Encrypt the session key with recipient's public key</li>
                  <li>Bundle encrypted session key and message together</li>
                </ol>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Message to Encrypt
                </label>
                <textarea
                  value={message}
                  onChange={(e) => setMessage(e.target.value)}
                  placeholder="Enter your secret message here..."
                  className="w-full h-32 p-3 border rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Recipient's Public Key
                </label>
                <textarea
                  value={recipientPublicKey}
                  onChange={(e) => setRecipientPublicKey(e.target.value)}
                  placeholder="Paste the recipient's public key here..."
                  className="w-full h-32 p-3 border rounded-lg font-mono text-xs focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                />
              </div>

              <button
                onClick={encryptMessage}
                className="w-full bg-green-600 text-white py-3 rounded-lg hover:bg-green-700 transition-colors font-medium flex items-center justify-center gap-2"
              >
                <Lock className="w-5 h-5" />
                Encrypt Message
              </button>

              {encryptedPackage && (
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <label className="block text-sm font-medium text-gray-700">
                      Encrypted Package (Send this to recipient)
                    </label>
                    <button
                      onClick={() => copyToClipboard(encryptedPackage)}
                      className="text-sm text-indigo-600 hover:text-indigo-700 flex items-center gap-1"
                    >
                      <Copy className="w-4 h-4" />
                      Copy
                    </button>
                  </div>
                  <textarea
                    value={encryptedPackage}
                    readOnly
                    className="w-full h-48 p-3 border rounded-lg font-mono text-xs bg-gray-50"
                  />
                </div>
              )}
            </div>
          )}

          {/* Decryption Tab */}
          {activeTab === 'decrypt' && (
            <div className="space-y-6">
              <div className="bg-purple-50 p-4 rounded-lg">
                <p className="text-sm text-purple-800 mb-2">
                  <strong>Decryption Process:</strong>
                </p>
                <ol className="text-sm text-purple-700 space-y-1 ml-4 list-decimal">
                  <li>Use private key to decrypt the session key</li>
                  <li>Use the session key to decrypt the message</li>
                  <li>Display the original plaintext message</li>
                </ol>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Encrypted Package
                </label>
                <textarea
                  value={encryptedPackage}
                  onChange={(e) => setEncryptedPackage(e.target.value)}
                  placeholder="Paste the encrypted package here..."
                  className="w-full h-48 p-3 border rounded-lg font-mono text-xs focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Your Private Key
                </label>
                <textarea
                  value={recipientPrivateKey}
                  onChange={(e) => setRecipientPrivateKey(e.target.value)}
                  placeholder="Paste your private key here..."
                  className="w-full h-32 p-3 border rounded-lg font-mono text-xs focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                />
              </div>

              <button
                onClick={decryptMessage}
                className="w-full bg-purple-600 text-white py-3 rounded-lg hover:bg-purple-700 transition-colors font-medium flex items-center justify-center gap-2"
              >
                <Unlock className="w-5 h-5" />
                Decrypt Message
              </button>

              {decryptedMessage && (
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Decrypted Message
                  </label>
                  <div className="w-full p-4 border-2 border-green-500 rounded-lg bg-green-50">
                    <p className="text-gray-800 whitespace-pre-wrap">{decryptedMessage}</p>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Info Section */}
        <div className="bg-white rounded-lg shadow-xl p-6">
          <h2 className="text-xl font-bold text-gray-800 mb-4">How It Works</h2>
          <div className="space-y-4 text-sm text-gray-600">
            <div>
              <h3 className="font-semibold text-gray-800 mb-2">Hybrid Encryption:</h3>
              <p>
                This system combines asymmetric (RSA) and symmetric (AES) encryption. The message is encrypted with a fast 
                symmetric key, and that key is encrypted with the recipient's public key. This provides both security and efficiency.
              </p>
            </div>
            <div>
              <h3 className="font-semibold text-gray-800 mb-2">Security Features:</h3>
              <ul className="list-disc ml-5 space-y-1">
                <li>RSA-2048 asymmetric encryption for key exchange</li>
                <li>AES-256-GCM symmetric encryption for message content</li>
                <li>Random session keys for each message</li>
                <li>Initialization vectors (IV) for AES security</li>
              </ul>
            </div>
            <div>
              <h3 className="font-semibold text-gray-800 mb-2">Testing Instructions:</h3>
              <ol className="list-decimal ml-5 space-y-1">
                <li>Generate a key pair in the "Key Generation" tab</li>
                <li>Copy the public key to the "Encrypt" tab</li>
                <li>Enter a message and encrypt it</li>
                <li>Copy the encrypted package to the "Decrypt" tab</li>
                <li>Use the private key to decrypt and see your original message</li>
              </ol>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default PGPEncryptionSystem;