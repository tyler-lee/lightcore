/**
 * (c) by Huorong Li (leehuorong@gmail.com). All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS-IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

var AES = require('./aes');
var JSEncrypt = require('./JSEncrypt');
var HmacSHA256 = require('./hmac-sha256');

//generate new key pair: set default_key_size as parameter
var generateKeyPair = function(default_key_size) {
	var keyObj = {};

	if(default_key_size == undefined || default_key_size < 2048) {
		default_key_size = 2048;
	}

	var rsa = new JSEncrypt();
	rsa.default_key_size = default_key_size;
	keyObj.publicKey = rsa.getPublicKey();
	keyObj.privateKey = rsa.getPrivateKey();

	return keyObj;
}

//encrypt with public key
var encryptWithPublicKey = function(publicKey, message) {
	var encrypt = new JSEncrypt();
	encrypt.setPublicKey(publicKey);
	var encrypted = encrypt.encrypt(JSON.stringify(message));

	return encrypted;
}

//decrypt with private key
var decryptWithPrivateKey = function(privateKey, encryptedMessage) {
	var decrypt = new JSEncrypt();
	decrypt.setPrivateKey(privateKey);
	var decrypted = decrypt.decrypt(encryptedMessage);

	return JSON.parse(decrypted);
}

var computeHmac = function(message, passcode) {
	return HmacSHA256.HmacSHA256(message, passcode);
}

var isValidHmac = function(message, passcode, hmac) {
	if (typeof passcode !== 'string') {
		passcode = AES.random(0).concat(passcode);
	}
	var tempHmac = computeHmac(message, passcode);

	if (hmac.sigBytes != tempHmac.sigBytes) {
		return false;
	}
	for (var index in hmac.words) {
		if (tempHmac.words[index] != hmac.words[index]) {
			return false;
		}
	}

	return true;
}

/**
Input:
	encPassword: 		strings
	plainPadPassword:	strings or WordArray object

Output:
	cipherPadPassword:	{cipher: CipherParams object strings, mac: {nonce: WordArray object, hmac: WordArray object}}

Note: mac is used to verify whether the plainPadPassword is correct. hmac is done upon the nonce with plainPadPassword.
**/
var encryptPadPassword = function(encPassword, plainPadPassword) {
	//encrypt
	var cipher = AES.encrypt(plainPadPassword, encPassword);

	//do hmac
	var mac = {};
	mac.nonce = AES.random(32);
	mac.hmac = computeHmac(mac.nonce, plainPadPassword);

	//generate result
	var cipherPadPassword = {};
	cipherPadPassword.cipher = cipher.toString();
	cipherPadPassword.mac = mac;

	return cipherPadPassword;
}

/**
Input:
	encPassword: 		strings
	cipherPadPassword:	{cipher: CipherParams object strings, mac: {nonce: WordArray object, hmac: WordArray object}}

Output:
	plainPadPassword:	WordArray object or null
Note: mac is used to verify whether the plainPadPassword is correct. hmac is done upon the nonce with plainPadPassword.
**/
var decryptPadPassword = function(encPassword, cipherPadPassword) {
	//decrypt
	var plainPadPassword = AES.decrypt(cipherPadPassword.cipher, encPassword);

	//check hmac
	var mac = cipherPadPassword.mac;
	if (!isValidHmac(mac.nonce, plainPadPassword, mac.hmac)) {
		return null;
	}

	return plainPadPassword;
}

exports.encryptPadPassword = encryptPadPassword;
exports.decryptPadPassword = decryptPadPassword;

exports.computeHmac = computeHmac;
exports.isValidHmac = isValidHmac;

exports.generateKeyPair = generateKeyPair;
exports.encryptWithPublicKey = encryptWithPublicKey;
exports.decryptWithPrivateKey = decryptWithPrivateKey;

/*
var encPassword = 'encPassword';
var plain = 'strPlain';
console.log(plain);
var cipher = encryptPadPassword(encPassword, plain);
//console.log(cipher);
var decrypted = decryptPadPassword(encPassword, cipher);
console.log(decrypted, '\n');

plain = AES.random(8);
console.log(plain);
cipher = encryptPadPassword(encPassword, plain);
decrypted = decryptPadPassword(encPassword, cipher);
console.log(decrypted);
// */

