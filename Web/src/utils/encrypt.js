// src/utils/encryption.js
import JSEncrypt from 'jsencrypt';

// Load public key (you could put this in various places depending on your setup)

// Alternatively, fetch it from a file
async function loadPublicKey() {
  try {
    const response = await fetch('/keys/public.pem'); // Adjust path as needed
    return await response.text();
  } catch (error) {
    console.error('Error loading public key:', error);
    throw error;
  }
}

export async function encodeString(content) {
  const encryptor = new JSEncrypt();
  
  // Use static key or fetch dynamically
  encryptor.setPublicKey(publicKey); // Using static key
  // OR: encryptor.setPublicKey(await loadPublicKey()); // Dynamic loading
  
  return encryptor.encrypt(content); // Returns base64 encoded string
}

export async function encodeToken(mobile, password) {
  const data = {
    mobile,
    password
  };
  
  return await encodeString(JSON.stringify(data));
}