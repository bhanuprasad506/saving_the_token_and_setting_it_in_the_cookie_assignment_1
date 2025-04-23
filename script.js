const jwt = require('jsonwebtoken');
const crypto = require('crypto');
require('dotenv').config();

const secret = process.env.JWT_SECRET;
const encryptionKey = Buffer.from(process.env.ENCRYPTION_KEY); // Must be 32 bytes

// Function to encrypt JWT
function createEncryptedToken(payload) {
  const token = jwt.sign(payload, secret, { expiresIn: '1h' });
  const iv = crypto.randomBytes(16); // 16 bytes

  const cipher = crypto.createCipheriv('aes-256-cbc', encryptionKey, iv);
  let encrypted = cipher.update(token, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  return {
    iv: iv.toString('hex'),
    encryptedData: encrypted
  };
}

// Function to decrypt JWT
function decryptToken(encryptedData, ivHex) {
  const iv = Buffer.from(ivHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', encryptionKey, iv);

  let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  try {
    const decoded = jwt.verify(decrypted, secret);
    console.log('✅ Success:', decoded);
    return decoded;
  } catch (err) {
    console.error('❌ JWT Verification Failed:', err.message);
    return null;
  }
}

// Test it out
const result = createEncryptedToken({ username: 'kalvian', role: 'student' });
console.log('\n🔐 Encrypted:', result);

console.log('\n🔓 Decrypted:');
decryptToken(result.encryptedData, result.iv);
