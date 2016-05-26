var CryptoJS = require('crypto-js');

exports.CreatSHA256Hmac=function(msg,cryptokey,format){
var hash=CryptoJS.HmacSHA256(msg,cryptokey);
return hash;
}
exports.toHex=function(hash){
return hash.toString(CryptoJS.enc.Hex);
}
