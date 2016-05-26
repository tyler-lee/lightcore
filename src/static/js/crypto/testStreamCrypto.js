var StreamCrypto=require('./StreamCrypto');
var fs=require('fs');

function generateRandomString(length) {
    var sample="abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    var randomString="";
	var index=0;
    for (var i = 0; i < length; i++)
    {
		index=Math.floor(Math.random() * sample.length);
		randomString+=""+sample.substring(index, index + 1);
    }

    return randomString;
}


var masterKey="hello123kitty";
var ivStr="pG5CM4FxDagm8peJrtZ41234";
var keyLength=128;

var streamCryptoTest=new StreamCrypto("tylerlee",masterKey, keyLength, ivStr);

var length=(512<<10);	//TODO: set plaintext length
var text=generateRandomString(length);
//var text="uFeFzplTydcsjQHCUF3iavh00TMkp";
//var text="YwIGOeUzsGwNqe2bqk7g0wFbxi5umksEhFPO8POu2pVhKWZac7eIOpHWvT1Diz4qbpnXlqlwww0mmQIaZVXSlhFvk1c2Qs3JnT97xUYeFsCM6CI5P89Odfxai9qVEQZ9Agblz7chtcAGx2vPBrwlpLfv1mkq7Uth9WbhC1nMh6cKYzjsYgK6cGV7g9Hu6ZtzoOBhaBJIwDOh4C3EsfosePIZCUORp9czuHqdDjEP2c4O0UluCr48uLGWbY9lNhcEU3BkkTF1zORZQK69PN9V6y9QSozbKXiExZpAkotBF9rK2EEFLYmnxjvFMdAoSJq8qXAXVRjm4THTKAUGeGkJxC1ghUzTOVggMtnJk2WwmZo7mUqNx6BlRmjpLfAKiGUTXIh9KW2ohzvAJAOFj4By4eOHOLl52zojYDoNXhTxRE3g2CQY7Bl9LeWwi16wheapqQhYa9nSUFPVWeLyjU5T5ndDSdHo1WKDD5mtbz2iIPrCPjlNYhOsU7lm0jel2Z2bKuVDFuzdqih8VdwC7kjuFeFzplTydcsjQHCUF3iavh00TMkpn0imGCux4cEGw1rTwLdSMNxXGGAeneqbmAqMJKOfRYsqtkQK7b7J5DBLQ6IpqVtgUo040zHt1QfbaOeJ9cAosvB1kC3xFPZ7VpV1AW9k4WMpllpQ7tEFmrbWkvySn5b6yMO8S6hw2vvK0NIMqRSZN4Um0PPs9YD6EsVtbtTH9rkwu3IBfaIJz0vW9gPMHcvGtGk6mfI67vVLcSULDjHDob5XDbwY03mVCdD56k8wffeyUim47tNsXObOoFUuvrd9dQqQFbDcwIxCzc6iln5ZVqBfnQGpdZZxwDd4R7tWRUVCvu4WuFzQu1Tm28qCiRp2IqpPAhex7h2MaUtQF73rAUM6fRpwD2qTUssqEvKrhgsSi2GyHF7ENppDd0vOF8ScWAKBnuEgqiqdOKqdMrlaKkAD6PlGlYU1Vz7LwxKeigQvY5iOIgiP7PUTDgx74knWYE57dh2F05l7ViF1"

//RabbitCrypto.prototype.encrypt=function(plainText, isResetIV){
	//return {ciphertext:str,keyinfo:keyInfo};
var cipher=streamCryptoTest.encrypt(text,false);
var encryptStream=streamCryptoTest.stream;

//RabbitCrypto.prototype.decrypt=function(cipherText,ivStr,offset){
	//return {plaintext:str, nextpos:nextPos};
var plain=streamCryptoTest.decrypt(cipher.ciphertext, ivStr, 0);
var decryptStream=streamCryptoTest.stream;

//console.log("text is: \n"+ text.toString(16));
//console.log("ciphertext is: \n"+ cipher.ciphertext);
console.log("plaintext is: \n"+ plain.plaintext.toString());
console.log("\n");
//write to file
//fs.writeFile('textBeforeEncrypt.txt', toHexString(text), function(err) {
//	if(err) throw err;
//	console.log("write textBeforeEncrypt.txt success");
//});
//fs.writeFile('textAfterDecrypt.txt', toHexString(plain.plaintext), function(err) {
//	if(err) throw err;
//	console.log("write textAfterDecrypt.txt success");
//});

//console.log("encryptStream is:\n"+encryptStream);
//console.log("decryptStream is:\n"+decryptStream);
//write to file
//fs.writeFile('encryptStream.txt', encryptStream, function(err) {
//	if(err) throw err;
//	console.log("write encryptStream.txt success");
//});
//fs.writeFile('decryptStream.txt', decryptStream, function(err) {
//	if(err) throw err;
//	console.log("write decryptStream.txt success");
//});

console.log("text length is "+ text.length*2 + " byte");
console.log("ciphertext length is "+ cipher.ciphertext.length*2 + " byte");
console.log("plaintext length is "+ plain.plaintext.length*2 + " byte");
console.log("\n");

//*/
//convert given string to Hex string
function toHexString(string) {
	var hexString='';
	var charStr=0;
	for(var i=0; i<string.length; i++){
		charStr=string.charCodeAt(i);

		//10个字一行
		if(i%10==0) {
			hexString+="\n";
		}
		hexString+=charStr.toString(16);
	}

	return hexString;
}

