var sha256JS=require('./hmac-sha256');
var sha512JS=require('./hmac-sha512');
var rc4=require('./rabbit.js');
var aes=require('./aes.js');

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
		//TODO: is there any difference between the following two?
		//var key=aes.toHex(hexstr.substring(0,32));
		var key=rc4.toHex(hexstr.substring(0,32));
		return key;
	}
}

var uid='tylerlee'
var masterKey="hello123kitty";
var keyLength=128;

var key=generateKey(uid, masterKey, keyLength);

var timeStart;
var initTimes=10000;			//initiate times, then get the average time
var streamLength=10*(1<<10<<10);	//output stream length
var baseLength=1<<4;	//128 bits(16 bytes) per round
var rounds=Math.ceil(streamLength/baseLength);
var stream;
///////////////////////////////////////////////////
//test aes time
//initiate time
timeStart=process.hrtime();
var myaes;
for(var i=0; i<initTimes; i++) {
	myaes= aes.Init(key);
}
var aesInitTime=process.hrtime(timeStart);

//output rate
//aes: KeyStream=function(myaes,iv,Counter){
var iv="pG5CM4FxDagm8peJrtZ41234";
timeStart=process.hrtime();
for(var i=0; i<rounds; i++) {
	//TODO: whether Counter will influence the outcome
	stream=aes.KeyStream(myaes, iv, i);
}
var aesOutputTime=process.hrtime(timeStart);


///////////////////////////////////////////////////
//test rc4 time
//initiate time
timeStart=process.hrtime();
var myrc4;
for(var i=0; i<initTimes; i++) {
	myrc4= rc4.Init(key);
}
var rc4InitTime=process.hrtime(timeStart);

//output rate
//rc4: KeyStream=function(rc4){
timeStart=process.hrtime();
for(var i=0; i<rounds; i++) {
	stream=rc4.KeyStream(myrc4);
}
var rc4OutputTime=process.hrtime(timeStart);


//////////////////////////////////////////////////
//output infomation
var time;
var outputRate;

//initiate rate
console.log("\n\nInitiate Time Test\n--------------------------------------------------------");
console.log("Initiate Times: " + initTimes +" times");

time=aesInitTime[0]+aesInitTime[1]*(1e-9);
outputRate=initTimes/time;
console.log("AES Initiate Time: "+ time + " seconds");
console.log("AES Initiate Rate: "+ outputRate + " times/s");

console.log();

time=rc4InitTime[0]+rc4InitTime[1]*(1e-9);
outputRate=initTimes/time;
console.log("RC4 Initiate Time: "+ time + " seconds");
console.log("RC4 Initiate Rate: "+ outputRate + " times/s");

//output rate
console.log("\n\nOutput Rate Test\n--------------------------------------------------------");
console.log("Generate Stream Length: " + (streamLength>>10) +" KB");

time=aesOutputTime[0]+aesOutputTime[1]*(1e-9);
outputRate=(streamLength>>20)/time;
console.log("AES Output Time: "+ time + " seconds");
console.log("AES Output Rate: "+ outputRate + " KB/s");

console.log();

time=rc4OutputTime[0]+rc4OutputTime[1]*(1e-9);
outputRate=(streamLength>>20)/time;
console.log("RC4 Output Time: "+ time + " seconds");
console.log("RC4 Output Rate: "+ outputRate + " KB/s");
