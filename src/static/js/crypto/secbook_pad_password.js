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
var HmacSHA256 = require('./hmac-sha256');


var computeHmac = function(message, passcode) {
	return HmacSHA256.HmacSHA256(message, passcode);
}

var isValidHmac = function(message, passcode, hmac) {
	var tempHmac = computeHmac(message, passcode);

	if(hmac.sigBytes != tempHmac.sigBytes) {
		return false;
	}
	for(var index in hmac.words) {
		if(tempHmac.words[index] != hmac.words[index]) {
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
	if(!isValidHmac(mac.nonce, plainPadPassword, mac.hmac)) {
		return null;
	}

	return plainPadPassword;
}

exports.encryptPadPassword = encryptPadPassword;
exports.decryptPadPassword = decryptPadPassword;
exports.computeHmac = computeHmac;
exports.isValidHmac = isValidHmac;

//*
var encPassword = 'encPassword';
//var plain = 'strPlain';
var plain = AES.random(8);
console.log(plain);
var cipher = encryptPadPassword(encPassword, plain);
console.log(cipher);

var decrypted = decryptPadPassword(encPassword, cipher);
console.log(decrypted);
// */
