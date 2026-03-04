const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

class SecureTokenStorage {
  constructor(encryptionKey, filePath = './tokens.encrypted.json') {
    this.filePath = filePath;
    const salt = 'fixed_salt'; // 키 파생을 위한 고정값

    // AES-256을 위해 키를 항상 32바이트(256비트) Buffer로 변환
    this.key = crypto.scryptSync(encryptionKey || 'default_secret', salt, 32);
  }

  // 암호화 (수정됨)
  encrypt(data) {
    const iv = crypto.randomBytes(16); // 16바이트 랜덤 IV 생성
    const cipher = crypto.createCipheriv('aes-256-cbc', this.key, iv); // iv 전달 필수
    
    let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    return {
      iv: iv.toString('hex'),
      encrypted: encrypted
    };
  }

  // 복호화 (수정됨)
  decrypt(encryptedData) {
    try {
      if (!encryptedData.iv || !encryptedData.encrypted) return null;

      const iv = Buffer.from(encryptedData.iv, 'hex');
      const decipher = crypto.createDecipheriv('aes-256-cbc', this.key, iv); // iv 사용
      
      let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      
      return JSON.parse(decrypted);
    } catch (error) {
      console.error('Decryption failed:', error.message);
      return null;
    }
  }

  // 이하 saveTokens, loadTokens 등의 로직은 동일하지만 내부에서 수정된 encrypt/decrypt를 호출함
  saveTokens(tokens) {
    try {
      const encrypted = this.encrypt(tokens);
      fs.writeFileSync(this.filePath, JSON.stringify(encrypted));
      console.log('Tokens saved securely');
      return true;
    } catch (error) {
      console.error('Failed to save tokens:', error.message);
      return false;
    }
  }

  loadTokens() {
    try {
      if (!fs.existsSync(this.filePath)) {
        console.log('No existing tokens found');
        return null;
      }
      const encryptedData = JSON.parse(fs.readFileSync(this.filePath, 'utf8'));
      const tokens = this.decrypt(encryptedData);
      if (tokens) {
        console.log('Tokens loaded successfully');
        return tokens;
      }
      return null;
    } catch (error) {
      console.error('Failed to load tokens:', error.message);
      return null;
    }
  }

  clearTokens() {
    try {
      if (fs.existsSync(this.filePath)) {
        fs.unlinkSync(this.filePath);
        console.log('Tokens cleared');
      }
      return true;
    } catch (error) {
      console.error('Failed to clear tokens:', error.message);
      return false;
    }
  }

  hasValidTokens() {
    const tokens = this.loadTokens();
    if (!tokens || !tokens.access_token) return false;
    const bufferTime = 5 * 60 * 1000;
    return Date.now() < (tokens.expires_at - bufferTime);
  }
}

module.exports = SecureTokenStorage;
