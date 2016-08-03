/**
 * (c) by Huorong Li. All rights reserved.
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

/**
Input:
	encPassword: 		strings
	plainPadPassword:	strings or WordArray object

Output:
	cipherPadPassword:	{cipher: CipherParams object strings, valid: {nonce: WordArray object, hmac: WordArray object}}
	
Note: valid is used to verify whether the plainPadPassword is correct. hmac is done upon the nonce with plainPadPassword.
**/
var encryptPadPassword = function(encPassword, plainPadPassword) {
	//encrypt
	var cipher = AES.encrypt(plainPadPassword, encPassword);
	
	//do hmac
	var mac = {};
	mac.nonce = AES.random(32);
	/* var hmac = HmacSHA256.HmacSHA256Create(encPassword);
	hmac.update(mac.nonce);
	hmac.update(plainPadPassword);
	mac.hmac = hmac.finalize(); */
	mac.hmac = HmacSHA256.HmacSHA256(mac.nonce, plainPadPassword);
	
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
Note: valid is used to verify whether the plainPadPassword is correct. hmac is done upon the nonce with plainPadPassword.
**/
var decryptPadPassword = function(encPassword, cipherPadPassword) {
	//decrypt
	var plainPadPassword = AES.decrypt(cipherPadPassword.cipher, encPassword);
	
	//check hmac
	var mac = cipherPadPassword.mac;
	/* var hmac = HmacSHA256.HmacSHA256Create(encPassword);
	hmac.update(mac.nonce);
	hmac.update(plainPadPassword);
	hmac = hmac.finalize(); */
	var hmac = HmacSHA256.HmacSHA256(mac.nonce, plainPadPassword);
		
	if(hmac.sigBytes != mac.hmac.sigBytes) {
		return null;
	}
	for(var index in hmac.words) {
		if(mac.hmac.words[index] != hmac.words[index]) {
			return null;
		}
	}
	
	return plainPadPassword;
}

exports.encryptPadPassword = encryptPadPassword;
exports.decryptPadPassword = decryptPadPassword;

/* 
var encPassword = 'encPassword';
//var plain = 'strPlain';
var plain = AES.random(8);
console.log(plain);
var cipher = encryptPadPassword(encPassword, plain);
console.log(cipher);

var decrypted = decryptPadPassword(encPassword, cipher);
console.log(decrypted);
 */