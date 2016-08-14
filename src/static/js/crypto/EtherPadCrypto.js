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
var AttributePool=require('../AttributePool');
var Crypto=require('./StreamCrypto');
var putCipherInfoAttribs = require('./CipherInfoAttributeManager').putCipherInfoAttribs;
var getCipherInfoAttribs = require('./CipherInfoAttributeManager').getCipherInfoAttribs;


var DocsCrypto=function(uid,masterkey,keyLen,streamMaxLength,ivStr){
	this.encryptor=new Crypto(uid,masterkey,keyLen,streamMaxLength,ivStr);
	this.decryptList={};
	this.masterkey=masterkey;
	this.keyLen=keyLen;
	this.userId=uid;
	this.streamMaxLength = streamMaxLength;
	this.ivStr=ivStr.substring(0,64);
}

//TODO：udpate StreamCrypto module, removing isResetIV feature
DocsCrypto.prototype.encryptCharBank=function(charBank, isResetIV)
{
	return this.encryptor.encrypt(charBank, isResetIV);
}

DocsCrypto.prototype.AddDecryptor=function(uid,masterkey,keyLen,streamMaxLength,ivStr){
	var newCrypto=new Crypto(uid,masterkey,keyLen,streamMaxLength,ivStr);
	this.decryptList[uid]=newCrypto;
	return newCrypto;
};

DocsCrypto.prototype.decryptCharBank=function(uid,charBank,ivStr,offset){
	if(uid in this.decryptList){
		return this.decryptList[uid].decrypt(charBank,ivStr,offset);
	}
	else{
		var newCrypto=this.AddDecryptor(uid,this.masterkey,this.keyLen,this.streamMaxLength,ivStr);
		return newCrypto.decrypt(charBank,ivStr,offset);
	}
};

DocsCrypto.prototype.getTotalKeystreamSize=function(){
	var rt=0;
	var ri=0;
	var re;
	for( var dcrypto in this.decryptList){
		re=this.decryptList[dcrypto].getTotalSize();
		rt+=re.totalKeySize;
		ri+=re.initialTimes;
	}
	return ri+"times ---"+rt/1024;
}

DocsCrypto.prototype.encryptCS=function(unEncryptedChangeset,apool){
	var newCS = unEncryptedChangeset;
	var cs = Changeset.unpack(newCS);

	//if changeset's charBank is not NULL nor '\n', then we do encrypt and update key info attribute.
	if(cs.charBank.length > 0 && cs.charBank != '' && cs.charBank != '\n')
	{
		var cipherObj = this.encryptCharBank(cs.charBank, false);
		cs.charBank=cipherObj.ciphertext;

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

DocsCrypto.prototype.decryptCS=function(encryptedChangeset,apool){
	var newCS=encryptedChangeset;
	var cs = Changeset.unpack(newCS);

	//console.log(apool, encryptedChangeset)
	//if changeset's charBank is not NULL nor '\n', then we do encrypt and update key info attribute.
	if(cs.charBank.length > 0 && cs.charBank != '' && cs.charBank != '\n') {
		var iterator = Changeset.opIterator(cs.ops)
			,op;
		var plaintext = '';
		var count = 0;

		while(iterator.hasNext()) {
			op = iterator.next();

			//only inserted chars will appear in charBank
			if(op.opcode == '+') {
				//process the given char from charBank
				var ch = cs.charBank.substring(count, count + op.chars);
				//note that, each insert operation only process one char
				if(ch != '\n') {
					var cipherInfo = getCipherInfoAttribs(apool, op.attribs);
					//console.log(ch, count, cipherInfo.authorId, cipherInfo.nonce, cipherInfo.offset);
					var plainObj = this.decryptCharBank(cipherInfo.authorId, ch, this.ivStr + cipherInfo.nonce, cipherInfo.offset);
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
	var iterator = Changeset.opIterator(atext.attribs)
	, text = atext.text
	, op;

	//make sure apool is an instance of AttributePool.
	if(!(apool instanceof AttributePool)) {
		var tempApool = new AttributePool();
		tempApool.fromJsonable(apool);
		apool = tempApool;
	}

	var plaintext = '';
	var count = 0;

	while(iterator.hasNext()) {
		op = iterator.next();

		//only inserted chars will appear in charBank
		if(op.opcode == '+') {
			//process the given char from charBank
			var ch = text.substring(count, count + op.chars);
			//note that, each insert operation only process one char
			if(ch != '\n') {
				var cipherInfo = getCipherInfoAttribs(apool, op.attribs);
				var plainObj = this.decryptCharBank(cipherInfo.authorId, ch, this.ivStr + cipherInfo.nonce, cipherInfo.offset);
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
var ivStr=randomString(68);
var keyLength=128;
var streamMaxLen = 256;
var tempMax = "4";
streamMaxLen = streamMaxLen * parseInt(tempMax);
var changesetCrypto=new DocsCrypto(userId, masterKey, keyLength, streamMaxLen, ivStr);

var changeset = 'Z:z>b|2=m=b*0|1+b$123\n4567890';
var apool = new AttributePool();
apool.numToAttrib = { '0': [ 'author', userId ], '1': [ 'bold', 'true' ] };
apool.nextNum = 2;

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

