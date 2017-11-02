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

var Changeset = require('../Changeset');
var AttributePool = require('../AttributePool');
var HmacSHA256 = require('./hmac-sha256').HmacSHA256;
var Crypto = require('./StreamCrypto');
var putCipherInfoAttribs = require('./CipherInfoAttributeManager').putCipherInfoAttribs;
var getCipherInfoAttribs = require('./CipherInfoAttributeManager').getCipherInfoAttribs;

var DocsCrypto = function(userId, password) {
	this.password = password;

	this.encryptor = new Crypto(userId + password);
	this.decryptorList = {};
}

//TODO：udpate StreamCrypto module, removing isResetIV feature
DocsCrypto.prototype.encryptCharBank = function(charBank, isResetIV) {
	return this.encryptor.encrypt(charBank, isResetIV);
}

DocsCrypto.prototype.decryptCharBank = function(userId, charBank, nonce, offset) {
	if (! (userId in this.decryptorList)) {
		this.decryptorList[userId] = new Crypto(userId + this.password);
	}

	return this.decryptorList[userId].decrypt(charBank, nonce, offset);
};

DocsCrypto.prototype.encryptCS = function(unEncryptedChangeset, apool) {
	var newCS = unEncryptedChangeset;
	var cs = Changeset.unpack(newCS);

	//if changeset's charBank is not NULL nor '\n', then we do encrypt and update key info attribute.
	if (cs.charBank.length > 0 && cs.charBank != '' && cs.charBank != '\n') {
		var cipherObj = this.encryptCharBank(cs.charBank, false);
		cs.charBank = cipherObj.ciphertext;

		newCS = Changeset.pack(cs.oldLen, cs.newLen, cs.ops, cs.charBank);
		Changeset.checkRep(newCS);

		//update changeset with key info attribute
		var cipherInfo = {};
		cipherInfo.nonce = cipherObj.nonce;
		cipherInfo.offset = cipherObj.offset;
		newCS = putCipherInfoAttribs(newCS, apool, cipherInfo);
	}

	return newCS;
}

DocsCrypto.prototype.decryptCS = function(encryptedChangeset, apool) {
	var newCS = encryptedChangeset;
	var cs = Changeset.unpack(newCS);

	//if changeset's charBank is not NULL nor '\n', then we do encrypt and update key info attribute.
	if (cs.charBank.length > 0 && cs.charBank != '' && cs.charBank != '\n') {
		var iterator = Changeset.opIterator(cs.ops),
		op;
		var plaintext = '';
		var count = 0;

		while (iterator.hasNext()) {
			op = iterator.next();

			//only inserted chars will appear in charBank
			if (op.opcode == '+') {
				//process the given char from charBank
				var ch = cs.charBank.substring(count, count + op.chars);
				//note that, each insert operation only process one char
				if (ch != '\n') {
					var cipherInfo = getCipherInfoAttribs(apool, op.attribs);
					var plainObj = this.decryptCharBank(cipherInfo.authorId, ch, cipherInfo.nonce, cipherInfo.offset);
					ch = plainObj.plaintext;
				}

				plaintext += ch;
				count += op.chars;
			}
		}
		cs.charBank = plaintext;
		newCS = Changeset.pack(cs.oldLen, cs.newLen, cs.ops, cs.charBank);
		Changeset.checkRep(newCS);
	}

	return newCS;
}

DocsCrypto.prototype.decryptAtext = function(atext, apool) {
	var iterator = Changeset.opIterator(atext.attribs),
	text = atext.text,
	op;

	//make sure apool is an instance of AttributePool.
	if (! (apool instanceof AttributePool)) {
		var tempApool = new AttributePool();
		tempApool.fromJsonable(apool);
		apool = tempApool;
	}

	var plaintext = '';
	var count = 0;

	while (iterator.hasNext()) {
		op = iterator.next();

		//only inserted chars will appear in charBank
		if (op.opcode == '+') {
			//process the given char from charBank
			var ch = text.substring(count, count + op.chars);
			//note that, each insert operation only process one char
			if (ch != '\n') {
				var cipherInfo = getCipherInfoAttribs(apool, op.attribs);
				var plainObj = this.decryptCharBank(cipherInfo.authorId, ch, cipherInfo.nonce, cipherInfo.offset);
				ch = plainObj.plaintext;
			}

			plaintext += ch;
			count += op.chars;
		}
	}
	atext.text = plaintext;
}

module.exports = DocsCrypto;

/*
//test part
function randomString(length)
{
	var chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	var randomString = '';
	for (var i = 0; i < length; i++)
	{
		var index = Math.floor(Math.random() * chars.length);
		randomString += chars.substring(index, index + 1);
	}
	return randomString;
}

var masterKey="hello123kitty";
var userId = 'tyler lee';
var changesetCrypto=new DocsCrypto(userId, masterKey);

var changeset = 'Z:z>b|2=m=b*0|1+b$123\n4567890';
var apool = new AttributePool();
apool.putAttrib(['author', userId]);
apool.putAttrib(['bold', 'true']);

////test encrypt and decrypt changeset
//var changeset = 'Z:u>a|a=t*0|3+7*0+3$\nasd\nf\nasd';
//var apool = new AttributePool();
//apool.numToAttrib = { '0': [ 'author', userId ] };
//apool.nextNum = 1;

var encryptedChangeset=changesetCrypto.encryptCS(changeset, apool);
var decryptedChangeset=changesetCrypto.decryptCS(encryptedChangeset, apool);
if((decryptedChangeset.split('$'))[1] === (changeset.split('$'))[1]) {
	console.log("Encrypt and decrypt changeset success\n")
}
else {
	console.log("Encrypt and decrypt changeset fail\n")
	console.log(changeset);
	console.log(decryptedChangeset);
}
//console.log('\n',apool.getAttrib(2))

//test decryptAtext
var text = 'Z:0>b*0|1+b$123\n4567890';
var encryptedText=changesetCrypto.encryptCS(text, apool);
var atext = {};
atext.attribs = encryptedText.substring(encryptedText.indexOf('*'), encryptedText.lastIndexOf('$'));
atext.text = (encryptedText.split('$'))[1];
changesetCrypto.decryptAtext(atext, apool);
if(atext.text === (text.split('$'))[1]) {
	console.log("Decrypt atext success\n")
}
else {
	console.log("Decrypt atext fail\n")
	console.log(text);
	console.log(atext.text);
}
//*/

