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

var streamCryptoJS=require('./rabbit');
//var streamCryptoJS = require('./rc4');
var sha256JS = require('./hmac-sha256');

/*
 * 生成指定长度的随机字符串
 */
function generateRandomString(length) {
	var chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	var randomString = '';
	for (var i = 0; i < length; i++) {
		var index = Math.floor(Math.random() * chars.length);
		randomString += chars.substring(index, index + 1);
	}
	return randomString;
}

//support general key length.
//This function shuffle addInfo using password to derive keyBitLength crypto info
var deriveCrypto = function(password, addInfo, keyBitLength) {
	var crypto = sha256JS.random(0);
	var deriveInfo = addInfo + keyBitLength;

	//sha256 will generate 256 bit output.
	var temp = sha256JS.HmacSHA256(deriveInfo, password);

	if (keyBitLength == 64) {
		var mid = temp.words.length / 4;
		for (var i = 0; i < mid; i++) {
			crypto.words[i] = temp.words[i] ^ temp.words[mid + i] ^ temp.words[2 * mid + i] ^ temp.words[3 * mid + i];
		}
		crypto.sigBytes = keyBitLength >> 3;
	}
	else if (keyBitLength == 128) {
		var mid = temp.words.length / 2;
		for (var i = 0; i < mid; i++) {
			crypto.words[i] = temp.words[i] ^ temp.words[mid + i];
		}
		crypto.sigBytes = keyBitLength >> 3;
	}
	else if (keyBitLength == 256) {
		crypto = temp;
	}
	else {
		console.log('The required crypto length is not supported.');
	}

	return crypto;
}

/*
 * Init:
 * key is derived from password.
 * nonce is generated randomly.
 * IV is generated using nonce: IV = hmac(nonce, password).
 *
 * Reset:
 * key and mapArray will never change, but nonce and IV will be reset.
 *
 */

StreamCrypto = function(password) {
	this.password = password;

	this.keyBitLength = 128;
	this.key = deriveCrypto(this.password, 'key', this.keyBitLength);

	this.ivBitLength = 64;

	//the max key stream length: key stream length exceed this will lead to reset
	this.streamMaxLength = (4 << 10);

	this.nonce = null;
	/*
	 * cryptoStore = {
	 *  nonce1: {
	 *   cryptor: xx,	//The cryptor of the key stream if key stream has not exceeded the max stream length.
	 *   stream: [],	//The key stream having been generated.
	 *   cursor: xx		//The current cursor of the key stream.
	 *  }
	 *  nonce2: {
	 *  }
	 * }
	 *
	 * storeCapacity = xx;	//The capacity of the cryptoStore.
	 * storeLoopup = [nonce1, nonce2, ...];	//nonce list used to loopup by index.
	 * storeNextIndex = xx;	//The next index of the nonce in storeLoopup that will be replaced.
	 */
	this.cryptoStore = {};
	this.storeCapacity = 5;
	this.storeLoopup = [];
	this.storeNextIndex = -1;

	this.selectCryptor(generateRandomString(4));
};

StreamCrypto.prototype.selectCryptor = function(nonce) {
	if (! (nonce in this.cryptoStore)) {
		//nonce does not exist, so we need to create cryptor identified by the nonce.
		this.storeNextIndex = (this.storeNextIndex + 1) % this.storeCapacity;
		var iv = deriveCrypto(this.key, nonce, this.ivBitLength);
		var cryptor = streamCryptoJS.createEncryptor(this.key, {
			iv: iv
		});

		//update cryptoStore related info
		var deletedNonce = this.storeLoopup[this.storeNextIndex];
		this.storeLoopup[this.storeNextIndex] = nonce;
		delete this.cryptoStore[deletedNonce];
		this.cryptoStore[nonce] = {
			cryptor: cryptor,
			stream: [],
			cursor: 0
		};
	}

	this.nonce = nonce;
	return this.cryptoStore[nonce];
}

/*
 * 这个函数生成密钥流，使其长度达到length，因为当前每次生成16bytes，因此这里的达到指的是达到包含length位置在内的最小密钥流长度，它是16的整数倍
 */
var generateStreamUpToLength = function(cryptorObj, upToLength) {
	//当前已经生成的密钥流长度
	var index = cryptorObj.stream.length;
	//根据当前已经生成密钥流的长度来判断需要再生成多少才满足需求
	var requiredStreamSize = upToLength - index;

	if (requiredStreamSize > 0) {
		//每次调用KeyStream产生的密钥流长度
		requiredStreamSize = ((requiredStreamSize >> 4) + 1) << 4;
		var stream = streamCryptoJS.generateKeyStream(cryptorObj.cryptor, requiredStreamSize);
		var textword = stream.words;
		var word = 0;
		for (var i = 0; i < textword.length; i++) {
			word = textword[i];
			//更新密钥流，由于一个word包涵4个字节，而密钥流stream是以字节为单位存储的，因此一个word需要4个stream位置来存储
			cryptorObj.stream[index] = (word >> 24) & 0xff;
			cryptorObj.stream[index + 1] = (word >> 16) & 0xff;
			cryptorObj.stream[index + 2] = (word >> 8) & 0xff;
			cryptorObj.stream[index + 3] = word & 0xff;

			index += 4;
		}
	}
	else {
		//小于等于0说明当前已经生成的密钥流长度足够，不需要生成新的密钥流
		return;
	}
};

/*
 * 加密给定明文，如果isResetIV为true则先更新IV后用新的IV密钥流进行加密，否则用当前密钥流加密，并且如果本次加密结束后，当前IV密钥流超过设定值则更新IV
 * plaintext	待加密的明文
 * isResetIV	加密前是否先更新IV：true更新，false继续使用当前IV
 */
StreamCrypto.prototype.encrypt = function(plaintext, isResetIV) {
	var cryptorObj = this.selectCryptor(this.nonce);
	if (isResetIV) {
		this.nonce = generateRandomString(4);
		cryptorObj = this.selectCryptor(this.nonce);
		//一次生成并缓存所有this.streamMaxLength密钥流
		generateStreamUpToLength(cryptorObj, this.streamMaxLength);
	}

	//加密完当前明文后密钥流将达到的长度：明文长度为plaintext<<1，当前已经使用到的位置为this.cursor
	var needToGenerateStreamSize = (plaintext.length << 1) + (cryptorObj.cursor);
	//计算本次明文加密需要多少密钥流，一次性生成足够密钥流
	generateStreamUpToLength(cryptorObj, needToGenerateStreamSize);

	//组织密文结构
	/*
	cipherObj = {
		ciphertext: 'xxx',
		nonce: 'xxxx',
		offset: [a, b, c, ...]
	}
	*/
	var returnObj = {ciphertext: '', nonce: this.nonce, offset:[]};

	var plain = 0;
	var cipher = 0;
	var highByte = 0;
	var lowByte = 0;
	var finisedCount = 0;
	while (finisedCount < plaintext.length) {
		//经过事先生成足够的密钥流，可以保证整个加密过程中密钥流足够使用，因此加密过程中不需要再去判断是否需要生成更多的密钥流
		plain = plaintext.charCodeAt(finisedCount);
		cipher = plain;

		if (plain != 10) { //10是回车符
			//0xDF80到0xDFFF是非法区
			do
			{
				highByte = (plain >> 8) ^ cryptorObj.stream[cryptorObj.cursor];
				lowByte = ((plain & 0xFF) ^ cryptorObj.stream[cryptorObj.cursor + 1]);
				cipher = (highByte << 8) | lowByte;

				if (cipher >= 0xDF80 && cipher <= 0xDFFF) {
					cryptorObj.cursor += 1;
					needToGenerateStreamSize += 1;

					if (needToGenerateStreamSize >= this.streamMaxLength) {
						generateStreamUpToLength(cryptorObj, needToGenerateStreamSize);
					}
				}
				else {
					returnObj.offset[finisedCount] = cryptorObj.cursor;
					break;
				}
			} while (true);

			if (cipher == 10) {
				cipher = 0;
			}
			cryptorObj.cursor += 2;
		}
		returnObj.ciphertext += String.fromCharCode(cipher);
		//处理完一个字符
		finisedCount++;
	}

	//本次加密结束后，判断是否需要更换IV，这部分语句必须要放在生成nonce之后，否则存储的就是更新后的IV信息了，这样必然会导致解密错误
	if (cryptorObj.cursor >= this.streamMaxLength) {
		//已经达到或超过最大加密长度，立即更新IV
		this.nonce = generateRandomString(4);
	}

	return returnObj;
};

/*
 * 解密给定密文，提供的信息有加密该密文的IV以及该IV下的密钥流使用起始偏移值
 * ciphertext	待解密的密文
 * nonce		解密密文所使用的nonce值
 * offset		密文所使用对应IV密钥流的偏移量
 *
 * 事实上，解密时是单个字符解密，因为每个字符就是一个CS
 */
StreamCrypto.prototype.decrypt = function(ciphertext, nonce, offset) {
	var cryptorObj = this.selectCryptor(nonce);

	//计算本次密文解密需要多少密钥流，一次性生成足够密钥流
	//解密时计算需要生成到的密钥流位置，即在offset基础上延伸ciphertext*2长度
	var needToGenerateStreamSize = (offset + (ciphertext.length << 1));
	generateStreamUpToLength(cryptorObj, needToGenerateStreamSize);

	var cipher = 0;
	var plain = 0;
	var plaintext = '';
	var highByte = 0;
	var lowByte = 0;
	var finisedCount = 0;
	while (finisedCount < ciphertext.length) {
		//经过事先生成足够的密钥流，可以保证整个解密过程中密钥流足够使用，因此解密过程中不需要再去判断是否需要生成更多的密钥流
		cipher = ciphertext.charCodeAt(finisedCount);
		plain = cipher;
		cryptorObj.cursor = offset[finisedCount];

		if (cipher != 10) {
			//一个字有两个字节，而密钥流是以字节8bit为单位进行处理的，因此需要分开取出处理
			if (cipher == 0x0000) {
				cipher = 0x000A;
			}

			highByte = (cipher >> 8) ^ cryptorObj.stream[cryptorObj.cursor];
			lowByte = (cipher & 0xFF) ^ cryptorObj.stream[cryptorObj.cursor + 1];

			plain = (highByte << 8) | lowByte;
		}
		plaintext += String.fromCharCode(plain);
		finisedCount++;
	}

	return {
		'plaintext': plaintext
	};
};

//导出该封装后的密码模块
module.exports = StreamCrypto;

/*
//test part
var masterkey = "hello123kitty";
var keyBitLength = 128;

var streamCryptoTest = new StreamCrypto("tylerlee");

var length = 513; //TODO: set plaintext length
//var length=(512<<10);	//TODO: set plaintext length
var text = generateRandomString(length);

var cipher1 = streamCryptoTest.encrypt(text, false);
var cipher2 = streamCryptoTest.encrypt(text, false);
var plain1 = streamCryptoTest.decrypt(cipher1.ciphertext, cipher1.nonce, cipher1.offset);
var plain2 = streamCryptoTest.decrypt(cipher2.ciphertext, cipher2.nonce, cipher2.offset);

if (text === plain1.plaintext && text == plain2.plaintext) {
	console.log("Encrypt and decrypt success\n")
}
else {
	console.log("Encrypt and decrypt fail\n")
}

//*/

