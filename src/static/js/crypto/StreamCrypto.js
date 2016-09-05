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
	this.streamMaxLength = 1024;

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
	this.storeNextIndex = - 1;

	//生成高8bits映射数组
	this.mapArray = [];
	this.initMappingArray();

	this.nonce = null;
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

StreamCrypto.prototype.initMappingArray = function() {
	//0xD800~0xDFFF是非法区域
	//可以被映射的合法字符区域，使用Streamkey的性质对这个区域的数字进行重新排列
	//然后将中文可能出现的字符区间映射到这些字符区域，这也是相当于加密
	var legalAera = [0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0];
	var shuffleHash = parseInt(sha256JS.HmacSHA256('shuffle', this.key).toString().substring(0, 5), 16);

	//初始化长度为16的数组，用于存储映射后的值
	//必须显示初始化js数组，真是好麻烦
	for (var a = 0; a < 16; a++)
	this.mapArray.push( - 1);

	//实际加密前最高4比特可能的数值，往右移动成为检索下标
	var legalIndex = [0x00, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0F];

	var legalAeraLen = legalAera.length;
	//将this.mapArray中对应着legalIndex的位置的数值根据Hmac值进行映射
	//完成下标和值之间的11对应关系
	for (var i in legalIndex) {
		var randPos = shuffleHash % legalAeraLen;
		this.mapArray[legalIndex[i]] = legalAera[randPos];

		//删除已经使用的合法区域，并且减少长度
		legalAera.splice(randPos, 1);
		legalAeraLen = legalAeraLen - 1;
	}
}

//top8bits as 0xa0..
StreamCrypto.prototype.undoMaps = function(top8bits) {
	//这里我们需要从mapA中得到对应的下标，然后左移4bits返回
	//如果找不到，那就发生错误
	for (var i in this.mapArray) {
		if (this.mapArray[i] == top8bits) return (i << 4);
	}

	console.log("Fatal err in StreamCrypto.prototype.undoMaps. top8bits is " + top8bits);
	return top8bits;
}

StreamCrypto.prototype.doMaps = function(top8bits) {
	var a = top8bits >> 4;
	if (this.mapArray[a] == - 1) {
		console.log("doMaps-top8bits>>4 = " + a);
		return top8bits;
	}

	return this.mapArray[a];
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
	if (isResetIV) {
		this.nonce = generateRandomString(4);
	}

	var cryptorObj = this.selectCryptor(this.nonce);
	//加密完当前明文后密钥流将达到的长度：明文长度为plaintext<<1，当前已经使用到的位置为this.cursor
	var needToGenerateStreamSize = (plaintext.length << 1) + (cryptorObj.cursor);
	//计算本次明文加密需要多少密钥流，一次性生成足够密钥流
	generateStreamUpToLength(cryptorObj, needToGenerateStreamSize);

	//记录此次加密所使用密钥流的起始位置
	var baseoffset = cryptorObj.cursor;
	var nonce = this.nonce;

	var plain = 0;
	var cipher = 0;
	var ciphertext = '';
	var highByte = 0;
	var lowByte = 0;
	var finisedCount = 0;
	while (finisedCount < plaintext.length) {
		//经过事先生成足够的密钥流，可以保证整个加密过程中密钥流足够使用，因此加密过程中不需要再去判断是否需要生成更多的密钥流
		plain = plaintext.charCodeAt(finisedCount);
		cipher = plain;

		if (plain != 10) { //10是回车符
			//加密
			highByte = (plain >> 8);
			lowByte = (plain & 0x00FF);

			var top8bits = highByte & 0xf0;
			highByte = (highByte ^ cryptorObj.stream[cryptorObj.cursor]) & 0x0f;

			top8bits = this.doMaps(top8bits);
			highByte = highByte | top8bits;

			lowByte = ((plain & 0x00FF) ^ cryptorObj.stream[cryptorObj.cursor + 1]);
			cipher = (highByte << 8) | lowByte;

			if (cipher == 10) {
				cipher = 0;
			}
			cryptorObj.cursor += 2;
		}
		ciphertext += String.fromCharCode(cipher);
		//处理完一个字符
		finisedCount++;
	}

	//本次加密结束后，判断是否需要更换IV，这部分语句必须要放在生成nonce之后，否则存储的就是更新后的IV信息了，这样必然会导致解密错误
	if (cryptorObj.cursor >= this.streamMaxLength) {
		//已经达到或超过最大加密长度，立即更新IV
		this.nonce = generateRandomString(4);
	}

	//加密返回结果包括密文以及加密所使用密钥流的位置相关信息
	return {
		'ciphertext': ciphertext,
		'nonce': nonce,
		'offset': baseoffset
	};
};

/*
 * 解密给定密文，提供的信息有加密该密文的IV以及该IV下的密钥流使用起始偏移值
 * ciphertext	待解密的密文
 * nonce		解密密文所使用的nonce值
 * offset		密文所使用对应IV密钥流的偏移量
 */
StreamCrypto.prototype.decrypt = function(ciphertext, nonce, offset) {
	var cryptorObj = this.selectCryptor(nonce);

	//计算本次密文解密需要多少密钥流，一次性生成足够密钥流
	//解密时计算需要生成到的密钥流位置，即在offset基础上延伸ciphertext*2长度
	var needToGenerateStreamSize = (offset + (ciphertext.length << 1));
	generateStreamUpToLength(cryptorObj, needToGenerateStreamSize);

	//移动cursor到给定offset处
	cryptorObj.cursor = offset;

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

		if (cipher != 10) {
			//一个字有两个字节，而密钥流是以字节8bit为单位进行处理的，因此需要分开取出处理
			if (cipher == 0x0000) {
				cipher = 0x000A;
			}

			highByte = (cipher >> 8);
			lowByte = (cipher & 0x00FF);

			var top8bits = highByte & 0xf0;
			top8bits = this.undoMaps(top8bits);

			highByte = (highByte ^ cryptorObj.stream[cryptorObj.cursor]) & 0x0f;
			highByte = highByte | top8bits;
			lowByte = lowByte ^ cryptorObj.stream[cryptorObj.cursor + 1];

			plain = (highByte << 8) | lowByte;
			cryptorObj.cursor += 2;

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

//test part
/*
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

