var CryptoJS = require('crypto-js');

exports.Init=function(key){
var rc4=CryptoJS.algo.RC4.createEncryptor(key);
return rc4;
}
exports.KeyEmpty=function(rc4,round1){
var pHex={words:[0,0,0,0],sigBytes:16};
 for(var j=0;j<round1;j++)
   rc4.process(pHex);
}
exports.KeyStream=function(rc4){
var pHex={words:[0,0,0,0],sigBytes:16};
var pc=rc4.process(pHex);
return pc;
}
exports.Finalize=function(rc4){
return rc4.finalize();
}
exports.toHex=function(str){
var strHex=CryptoJS.enc.Hex.parse(str);
return strHex;
}

