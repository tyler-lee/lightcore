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

//var streamCryptoJS=require('./rabbit');
var streamCryptoJS=require('./rc4');
var sha256JS=require('./hmac-sha256');
var sha512JS=require('./hmac-sha512');

var md5Js = require('./md5');

generateKey=function(uid,masterKey,keyLength){
	if(keyLength==512){
		var keyBuff=sha512JS.CreatSHA512Hmac(uid,masterKey);
		return keyBuff;
	}
	else if(keyLength==256){
		var keyBuff=sha256JS.CreatSHA256Hmac(uid,masterKey);
		return keyBuff;
	}
	else{// default 128bit 4=128/32
		var keyBuff=sha256JS.CreatSHA256Hmac(uid,masterKey);
		var hexstr=sha512JS.toHex(keyBuff);
		var key=streamCryptoJS.toHex(hexstr.substring(0,32));
		return key;
	}
}

StreamCrypto=function(uid,masterkey,keyLength,streamMaxLength,ivStr){
	this.userId=uid;
	this.masterkey=masterkey;
	this.key=generateKey(uid+ivStr,masterkey,keyLength);
	this.keyLength=keyLength/8;

	//当前密钥流使用到的位置
	this.cursor=0;

	//TODO:改变密钥缓存长度
	this.streamMaxLength=streamMaxLength;

	this.streamCryptor=streamCryptoJS.Init(this.key);
	//缓存前一个streamCryptor，因为当从当前状态切换到前一个IV时，可能还需要前一个streamCryptor去生成剩下的密钥流
	this.streamCryptorBackup = streamMaxLength;

	//定义一个变量用于储存密钥流
	this.stream=[];
	//缓存前一个IV产生的密钥流
	this.streamBackup=[];

	this.ivStr=ivStr;
	//缓存前一个IV
	this.ivStrBackup;
    this.totalkeystreamsize=0;
	this.ivResetTimes=1;

    //生成高8bits映射数组
    this.initMappingArray(masterkey);
    //console.log(this.mapArray);
};


StreamCrypto.prototype.initMappingArray = function(masterkey) {
	//可以被映射的合法字符区域，使用Streamkey的性质对这个区域的数字进行重新排列
	//然后将中文可能出现的字符区间映射到这些字符区域，这也是相当于加密
	var legalAera = new Array(0x00,0x10,0x20,0x30,0x40,0x50,0x60,0x70,0x80,0x90,0xa0,0xb0,0xc0);
	var masterkeyhash = parseInt(md5Js.CreatMD5(masterkey).toString().substring(0,5),16);

	//初始化长度为16的数组，用于存储映射后的值
	//初始化其中的值全为零
	this.mapArray = new Array();
	//必须显示初始化js数组，真是好麻烦
	for(var a =0;a<16;a++)
		this.mapArray.push(-1);


	//实际加密前最高8比特可能的数值，往右移动成为检索下标
	var indexA = new Array(0x00,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0F);

	var  legalAeraLen = legalAera.length;
	//将this.mapArray中对应着indexA的位置的数值根据MD5值进行映射
	//完成下标和值之间的11对应关系
	for( x in indexA) {
		var At_legalAera = masterkeyhash % legalAeraLen;
		this.mapArray[ indexA[x] ] = legalAera[At_legalAera];

		//console.log("this.mapArray[" + indexA[x] +"] = legalAera[" + At_legalAera + "] = " + legalAera[At_legalAera]);
		//删除已经使用的合法区域，并且减少长度
		legalAera.splice(At_legalAera,1);
		legalAeraLen = legalAeraLen - 1;
	}
}


//top8bits as 0xa0..
StreamCrypto.prototype.undoMaps = function(top8bits) {
	//这里我们需要从mapA中得到对应的下标，然后左移4bits返回
	//如果找不到，那就发生错误
	for(x in this.mapArray) {
		if(this.mapArray[x] == top8bits)
			return (x<<4) ;
	}
	console.log("Fatal err in StreamCrypto.prototype.undoMaps. top8bits is " + top8bits);
	console.log( this.mapArray);
	return top8bits;
}

StreamCrypto.prototype.doMaps = function(top8bits) {
	var a = top8bits>>4;
	if(this.mapArray[a] == -1){
		console.log("doMaps-top8bits>>4 = " + a );
		console.log(this.mapArray);
		return top8bits;
	}

	return this.mapArray[a];
}

/*
 * 这个函数生成密钥流，使其长度达到length，因为当前每次生成16bytes，因此这里的达到指的是达到包含length位置在内的最小密钥流长度，它是16的整数倍
 */
StreamCrypto.prototype.generateStreamUpToLength=function(upToLength){
	//当前已经生成的密钥流长度
	var index=this.stream.length;
	//根据当前已经生成密钥流的长度来判断需要再生成多少才满足需求
	var needToGenerateStreamSize=upToLength-index;

	if(needToGenerateStreamSize>0) {
		//TODO: 每次调用KeyStream产生的密钥流长度
		//当前streamCryptoJS.KeyStream每次调用吐出的字节数，可以在rc4.js文件中修改该函数，当前为16字节
		var oneKeyStreamOutputLength=16;
		//确实需要生成新的密钥流，且长度给定
		var round1 = Math.ceil(needToGenerateStreamSize/oneKeyStreamOutputLength);
		//在当前已经生成的密钥流基础上再生成给定轮数的（1轮16bytes）密钥流
		var word=0;
		var stream;
		var textword;
		var length;
		for(var t=0; t<round1; t++) {
			stream=streamCryptoJS.KeyStream(this.streamCryptor);

			textword=stream.words;
			length=textword.length;
			//更新密钥流，由于一个word包涵4个字节，而密钥流stream是以字节为单位存储的，因此一个word需要4个stream位置来存储
			for(var i=0;i<length;i++){
				word=textword[i];
				this.stream[index]=(word>>24)&0xff;
				this.stream[index+1]=(word>>16)&0xff;
				this.stream[index+2]=(word>>8)&0xff;
				this.stream[index+3]=word&0xff;

				index+=4;
			}
		}
               this.totalkeystreamsize += round1*oneKeyStreamOutputLength;
	}
	else {
		//小于等于0说明当前已经生成的密钥流长度足够，不需要生成新的密钥流
		return;
	}
};
StreamCrypto.prototype.getTotalSize=function(){
   return {totalKeySize:this.totalkeystreamsize,initialTimes:this.ivResetTimes};
}
/*
 * 生成指定长度的随机字符串
 */
function generateRandomString(length)
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

/*
 * 生成一个IV
 */
StreamCrypto.prototype.generateIV = function () {
	var ivStr = this.ivStr.substring(0, 64) + generateRandomString(4);
	return ivStr;
}

/*
 * 用给定IV重新初始化一个密码子
 */
StreamCrypto.prototype.reset=function(ivStr){
	//结束旧的rabbit
	streamCryptoJS.Finalize(this.streamCryptor);
	//以下三条语句存在顺序问题，不可以颠倒
	//更新IV

	this.ivStr=ivStr;
	//生成与新IV相关的新密钥
	this.key=generateKey(this.userId+this.ivStr,this.masterkey,this.keyLength*8);
	//生成与新IV及新密钥相关的新的rabbit
	this.streamCryptor=streamCryptoJS.Init(this.key);

	//清空当前this.stream中的密钥流
	this.stream=[];
	//重置后应该要重置新IV密钥流所使用的位置
	this.cursor=0;
	this.ivResetTimes +=1;
};

/*
 * 用给定IV重置加密子
 */
StreamCrypto.prototype.resetEncryptor=function() {
       var newIV=this.generateIV();
       this.reset(newIV);
}

/*
 * 用给定IV重置解密子
 */
StreamCrypto.prototype.resetDecryptor=function(ivStr) {
	this.backupDecryptor();
	this.reset(ivStr);
}

/*
 * 备份解密子
 */
StreamCrypto.prototype.backupDecryptor=function() {
	//保存即将被弃用的IV
	this.ivStrBackup=this.ivStr;
	//保存即将被弃用的IV密钥流
	this.streamBackup=this.stream;
	//保存即将被弃用的rabbit
	this.streamCryptorBackup=this.streamCryptor;
}

/*
 * 恢复解密子
 */
StreamCrypto.prototype.restoreDecryptor=function() {
	//将当前这次的rabbit换成前一次的rabbit，并保存当前的rabbit
	var tempStreamCryptor=this.streamCryptor;
	this.streamCryptor=this.streamCryptorBackup;
	this.streamCryptorBackup=tempStreamCryptor;

	//将当前这次的IV换成前一次的IV，并保存当前的IV
	var tempIV=this.ivStr;
	this.ivStr=this.ivStrBackup;
	this.ivStrBackup=tempIV;

	//将当前这次的IV的密钥流换成前一次IV的密钥流，并保存当前IV的密钥流
	var tempStream=this.stream;
	this.stream=this.streamBackup;
	this.streamBackup=tempStream;
}

/*
 * 加密给定明文，如果isResetIV为true则先更新IV后用新的IV密钥流进行加密，否则用当前密钥流加密，并且如果本次加密结束后，当前IV密钥流超过设定值则更新IV
 * plaintext	待加密的明文
 * isResetIV	加密前是否先更新IV：true更新，false继续使用当前IV
 */
StreamCrypto.prototype.encrypt=function(plaintext, isResetIV){
	//根据传入明文的大小，一次性先将需要的密钥流生成出来
	if(isResetIV) {
		if(this.cursor>0) {
			//当前IV已经使用过了，尽管没有使用达到最大长度，也更新
			this.resetEncryptor();
		}
		else {
			//<=0说明当前这个密钥流是刚重新初始化过，不需要再次初始化。
		}
	}

	//加密完当前明文后密钥流将达到的长度：明文长度为plaintext<<1，当前已经使用到的位置为this.cursor
	var needToGenerateStreamSize=(plaintext.length<<1)+(this.cursor);
	//计算本次明文加密需要多少密钥流，一次性生成足够密钥流
	this.generateStreamUpToLength(needToGenerateStreamSize);

	//记录此次加密所使用密钥流的起始位置
	var baseoffset=this.cursor;

	var plain=0;
	var cipher=0;
	var ciphertext="";
	var highByte=0;
	var lowByte=0;
	var finisedCount=0;
	while(finisedCount<plaintext.length){
		//经过事先生成足够的密钥流，可以保证整个加密过程中密钥流足够使用，因此加密过程中不需要再去判断是否需要生成更多的密钥流
		plain=plaintext.charCodeAt(finisedCount);
		cipher=plain;

		if(plain!=10){//10是回车符
			//加密
			highByte = (plain >> 8);
			lowByte = (plain & 0x00FF);

			var top8bits = highByte & 0xf0;
			highByte = (highByte ^ this.stream[this.cursor]) & 0x0f;

			top8bits = this.doMaps(top8bits);
			highByte = highByte | top8bits;

			lowByte=((plain&0x00FF)^this.stream[this.cursor+1]);
			cipher = (highByte << 8) | lowByte;

			if(cipher==10) {
				cipher=0;
			}
			this.cursor+=2;
		}
		ciphertext+=String.fromCharCode(cipher);
		//处理完一个字符
		finisedCount++;

	}
	//存储本次加密明文所用的相关信息, 这里存储的是密钥流的绝对起始位置
	//nonce有4个字节, ivStr头64个字符是Hmac值，最后4个字符作为IV的标识
	var nonce=this.ivStr.substring(64);

	//本次加密结束后，判断是否需要更换IV，这部分语句必须要放在生成nonce之后，否则存储的就是更新后的IV信息了，这样必然会导致解密错误
	if(this.cursor>=this.streamMaxLength) {
		//已经达到或超过最大加密长度，立即更新IV
               this.resetEncryptor();
	}

	//加密返回结果包括密文以及加密所使用密钥流的位置相关信息
	return {'ciphertext': ciphertext, 'nonce': nonce, 'offset': baseoffset};
};


/*
 * 解密给定密文，提供的信息有加密该密文的IV以及该IV下的密钥流使用起始偏移值
 * ciphertext	待解密的密文
 * ivStr		解密密文所使用的IV值
 * offset		密文所使用对应IV密钥流的偏移量
 */
StreamCrypto.prototype.decrypt=function(ciphertext,ivStr,offset){
	if(this.ivStr!=ivStr) {
		//如果IV与当前正在使用的IV不匹配
		if(this.ivStrBackup==ivStr) {
			//如果IV与最近一次使用的IV匹配，则直接取出上一次使用IV的密钥流，接着使用
			this.restoreDecryptor();
		}
		else {
			//如果IV值不匹配，则更新IV值
			this.resetDecryptor(ivStr);
		}
	}

	//计算本次密文解密需要多少密钥流，一次性生成足够密钥流
	//解密时计算需要生成到的密钥流位置，即在offset基础上延伸ciphertext*2长度
	var needToGenerateStreamSize=(offset+(ciphertext.length<<1));
	this.generateStreamUpToLength(needToGenerateStreamSize);

	//移动cursor到给定offset处
	this.cursor=offset;

	var cipher=0;
	var plain=0;
	var plaintext="";
	var highByte=0;
	var lowByte=0;
	var finisedCount=0;
	while(finisedCount<ciphertext.length){
		//经过事先生成足够的密钥流，可以保证整个解密过程中密钥流足够使用，因此解密过程中不需要再去判断是否需要生成更多的密钥流
		cipher=ciphertext.charCodeAt(finisedCount);
		plain=cipher;

		if(cipher!=10){
			//一个字有两个字节，而密钥流是以字节8bit为单位进行处理的，因此需要分开取出处理
			if(cipher == 0x0000) {
				cipher = 0x000A;
			}

			highByte=(cipher>>8);
			lowByte=(cipher&0x00FF);

			var top8bits = highByte & 0xf0;
			top8bits = this.undoMaps(top8bits);

			highByte = (highByte ^ this.stream[this.cursor]) & 0x0f;
			highByte = highByte | top8bits;
			lowByte = lowByte^this.stream[this.cursor+1];


			plain = (highByte << 8) | lowByte;
			this.cursor+=2;

		}
		plaintext+=String.fromCharCode(plain);
		finisedCount++;
	}

	return {'plaintext': plaintext};
};

//导出该封装后的密码模块
module.exports = StreamCrypto;


//test part
/*
var masterKey="hello123kitty";
var ivStr=generateRandomString(68);
var keyLength=128;

var streamCryptoTest=new StreamCrypto("tylerlee",masterKey, keyLength, 1024, ivStr);

var length=1023;	//TODO: set plaintext length
//var length=(512<<10);	//TODO: set plaintext length
var text=generateRandomString(length);

var cipher1=streamCryptoTest.encrypt(text,false);
var cipher2=streamCryptoTest.encrypt(text,false);
var plain1=streamCryptoTest.decrypt(cipher1.ciphertext, ivStr.substring(0, 64) + cipher1.nonce, cipher1.offset);
var plain2=streamCryptoTest.decrypt(cipher2.ciphertext, ivStr.substring(0, 64) + cipher2.nonce, cipher2.offset);

if(text === plain1.plaintext && text == plain2.plaintext) {
	console.log("Encrypt and decrypt success\n")
}
else {
	console.log("Encrypt and decrypt fail\n")
}

//*/

