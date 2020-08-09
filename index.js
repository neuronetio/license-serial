const NodeRSA = require('node-rsa');
const CryptoJS = require('crypto-js');
const fs = require('fs');

class LicenseSerial {
  constructor(cert = null) {
    if (cert == null) {
      this.rsa = new NodeRSA();
      this.rsa.generateKeyPair();
    } else {
      this.rsa = new NodeRSA(cert);
    }
  }

  generateLicense(licenseKeyData) {
    if (!this.rsa.isPrivate()) {
      throw 'Cannot generate license key. Key provided is not private.';
    }

    if (licenseKeyData == null) {
      throw 'No license key data provided.';
    }

    const randomSymmetricKey = CryptoJS.lib.WordArray.random(128 / 8).toString(
      CryptoJS.enc.Base64
    );
    const encryptedData = CryptoJS.AES.encrypt(
      JSON.stringify(licenseKeyData),
      randomSymmetricKey
    ).toString();

    //encrypt the symmetric key.
    const encryptedSymmetricKey = this.rsa.encryptPrivate(
      randomSymmetricKey,
      'base64'
    );

    //combine the encrypted symmetric key with the encrypted data
    const encrypted = encryptedSymmetricKey + '||' + encryptedData;

    // build the signature for the license key data
    const signature = this.rsa.sign(JSON.stringify(licenseKeyData), 'base64');

    let licenseKey = '====BEGIN LICENSE KEY====\n';
    licenseKey += encrypted + '\n';
    licenseKey += signature;
    licenseKey += '\n====END LICENSE KEY====';

    return licenseKey;
  }

  validateLicense(licenseKey) {
    //parse the license key
    licenseKey = licenseKey.trim();
    //parse the license key
    const lines = licenseKey.split('\n');
    const keyMsg = lines[1].split('||');
    const signature = lines[2];

    let randomSymmetricKey = '',
      decryptedData = '';

    //decrypt the random symmetric key
    try {
      randomSymmetricKey = this.rsa.decryptPublic(keyMsg[0], 'utf8');
    } catch (e) {
      throw 'Invalid data: Could not extract symmetric key.';
    }

    //decrypt the payload
    try {
      decryptedData = CryptoJS.AES.decrypt(
        keyMsg[1],
        randomSymmetricKey
      ).toString(CryptoJS.enc.Utf8);
    } catch (e) {
      throw 'Invalid Data: Could not decrypt data with key found.';
    }

    //verify the signature.
    // @ts-ignore
    if (this.rsa.verify(decryptedData, signature, 'utf8', 'base64')) {
      //return the decrypted data.
      return JSON.parse(decryptedData);
    } else {
      throw 'License Key signature invalid. This license key may have been tampered with';
    }
  }

  /**
   * Exports the private key in PEM format
   */
  exportPrivateKey(filePath) {
    if (!this.rsa.isPrivate()) {
      throw 'The key is not a private key. Cannot export private key from public key.';
    }
    if (filePath == null) {
      return this.rsa.exportKey();
    } else {
      try {
        fs.writeFileSync(filePath, this.rsa.exportKey());
      } catch (e) {
        throw e; //error writing the private key out to disk.
      }
    }
  }

  /**
   * Exports the public key
   */
  exportPublicKey(filePath) {
    if (filePath == null) {
      return this.rsa.exportKey('public');
    } else {
      try {
        fs.writeFileSync(filePath, this.rsa.exportKey('public'));
      } catch (e) {
        throw e; //error writing the private key out to disk.
      }
    }
  }
}

module.exports = LicenseSerial;
