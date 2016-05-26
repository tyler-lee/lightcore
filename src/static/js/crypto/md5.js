var CryptoJS = require('crypto-js');

exports.CreatMD5 = function(str){
  var md5Value = CryptoJS.MD5(str);
  return md5Value;
}
