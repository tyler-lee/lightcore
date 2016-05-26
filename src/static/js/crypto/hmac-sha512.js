var CryptoJS = require('crypto-js');

exports.CreatSHA512Hmac=function(msg,cryptokey,format){
var hash=CryptoJS.HmacSHA512(msg,cryptokey);
return hash;
}
exports.toHex=function(hash){
return hash.toString(CryptoJS.enc.Hex);
}
