var Changeset = require('../Changeset');
var AttributePool=require('../AttributePool');
var Crypto=require('./StreamCrypto');


function randomString(len)
  {
    var chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    var randomstring = '';
    for (var i = 0; i < len; i++)
    {
      var rnum = Math.floor(Math.random() * chars.length);
      randomstring += chars.substring(rnum, rnum + 1);
    }
    return randomstring;
  }
var DocsCrypto=function(uid,masterkey,keyLen,streamMaxLength,ivStr){
this.encryptor=new Crypto(uid,masterkey,keyLen,streamMaxLength,ivStr);
this.decryptList={};
this.masterkey=masterkey;
this.keyLen=keyLen;
this.userId=uid;
this.streamMaxLength = streamMaxLength;
this.ivStr=ivStr.substring(0,20);
//增加一个全局的指示当前位置信息的变量
this.currentLine=0;
}

//TODO：增加一个重置标识，指明是否进行了跳转需要重置IV重新初始化
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
	var newCS=unEncryptedChangeset;
	var cs = Changeset.unpack(newCS);
	if(cs.charBank.length>0 && cs.charBank != '\n' && cs.charBank != '')
	{
		var iterator = Changeset.opIterator(cs.ops)
		,op
		,assem = Changeset.smartOpAssembler();
		//alert(newCS);
		if(apool.nextNum<0)apool.nextNum=0;

		//记录操作的起始位置
		var startLine=-1;
		//标志是否已经取得行信息
		var lineInfoGetted=false;
		//标志是否需要使用新的IV：如果当前行与操作行不一致，则true，否则false
		var isResetIV=false;
		while(iterator.hasNext()) {
			op = iterator.next();

			//获取changeset中的行信息
			if(!lineInfoGetted) {
				if(op.lines>=0) {
					startLine=op.lines;
					lineInfoGetted=true;
				}
				else {
					startLine=0;
				}
			}

			if(op.opcode == '+') {
				op.attribs=op.attribs+'*'+apool.nextNum.toString();
				flag=true;
			}
			assem.append(op)
		}
		//	 */
		assem.endDocument();
		if(flag){//encrypt the charBank
			//TODO: isResetIV标识是否需要进行IV重置，true则重置，false则继续使用当前IV
			//根据startLine和currentLine的位置关系确定isResetIV，如果二者相等，则继续使用当前IV，否则重置IV
			if(startLine>=this.currentLine) {
				isResetIV=false;
			}
			else {
				isResetIV=true;
				//维护this.currentLine信息
				this.currentLine=startLine;
			}
			var encryptedResult=this.encryptCharBank(cs.charBank, isResetIV);
			var keyInfoName='Key';
			var keyinforvalue=encryptedResult.keyinfo;
			var attrib=[keyInfoName||'',keyinforvalue||''];
			apool.numToAttrib[apool.nextNum]=attrib;
			apool.nextNum=apool.nextNum+1;
			cs.charBank=encryptedResult.ciphertext;

			newCS = Changeset.pack(cs.oldLen, cs.newLen, assem.toString(),cs.charBank);
			Changeset.checkRep(newCS);
       }
   }
   return newCS;
}

DocsCrypto.prototype.decryptCS=function(encryptedChangeset,apool){
	var newCS=encryptedChangeset;
	var cs = Changeset.unpack(newCS);
	if(cs.charBank.length>0 && cs.charBank != '\n' && cs.charBank != ''){
		var iterator = Changeset.opIterator(cs.ops)
			,op
			, assem = Changeset.smartOpAssembler();
		var iv="";
		var flag=false;
		var keyNum=-1;
		var authorId="";

		var offset=0;
		//var counter=0;
		var sentry="";

		//get keyinformation
		if(apool.numToAttrib){
			for (var attr in apool.numToAttrib){
				if(apool.numToAttrib[attr][0]=='author')authorId=apool.numToAttrib[attr][1];
				// get the keyInfo which includes cryptoKey position and iv
				if (apool.numToAttrib[attr][0] == 'Key')
				{
					var keyInfo=apool.numToAttrib[attr][1];
					var nonce=keyInfo.substring(0,4);
					iv = this.ivStr+nonce;
					offset=parseInt(keyInfo.substring(4),16);
					//counter= Math.floor(startPos / (this.keyLen/8));
					//offset=startPos % (this.keyLen/8);
					flag=true;
					keyNum=attr;
					break;
				}
			}
		}
		if(flag){
			var lineInfoGetted=false;
			while(iterator.hasNext()) {//update the op, remove the crypto attribute
				op = iterator.next();

				//获取changeset中的行信息
				if(!lineInfoGetted) {
					if(op.lines>=0) {
						//更新当前行信息
						this.currentLine=op.lines;
					}
				}

				if(op.opcode == '+') { //a
					var attriblist= op.attribs.split('*');
					if(attriblist){//b
						for(var att in attriblist){//c
							var attribNum=attriblist[att];
							if(attribNum==keyNum){//d
								var re='*'+keyNum.toString();
								op.attribs=op.attribs.replace(re,'');
							} //d
						}//c
					}//b
				} //a
				assem.append(op)
			}//endwhile
			assem.endDocument();
			//cs.charBank=Base64.decode(cs.charBank);
			var ss = this.decryptCharBank(authorId,cs.charBank,iv,offset);
			cs.charBank=ss.plaintext;
			newCS = Changeset.pack(cs.oldLen, cs.newLen, assem.toString(), cs.charBank);
		}//endif flag
	}
	return newCS;
}

DocsCrypto.prototype.decryptAtext = function(atext, apool) {
	// intentionally skips last newline char of atext
	var iter = Changeset.opIterator(atext.attribs);
	var plainText="";
	var startPos=0;
	var op = Changeset.newOp();
	//var assem = Changeset.smartOpAssembler();
	var newpool=new AttributePool();
	newpool.fromJsonable(apool);
	// var newtext=Base64.decode(atext.text);
	var lineInfoGetted=false;
	while (iter.hasNext()) {
		iter.next(op);
		var opvalue=1;
		if(op.opcode=='-')
			opvalue=-1;

		//获取changeset中的行信息
		if(!lineInfoGetted) {
			if(op.lines>=0) {
				//更新当前行信息
				this.currentLine=op.lines;
			}
		}

		var dectext=atext.text.substring(startPos,startPos + (op.chars*opvalue));
		startPos += op.chars*opvalue;
		if(dectext!='\n'){
			if(op.opcode=='+'){//opcode
				var KeyInfo='';
				var sentry='';
				var attriblist= op.attribs.split('*');
				var flag=-1;
				var keyNum=-1;
				var authorId="";
				if(attriblist){ //attriblist
					for(var att in attriblist){//for
						var attribNum=attriblist[att];
						if(attribNum!=''){//attribNum
							var attr = newpool.getAttrib(parseInt(attribNum, 36));
							if(!attr){
								console.log("bad attributNum of %d,cannot find it in apool",parseInt(attribNum, 36));
								continue;
							}
							else if('Key' == attr[0]){
                                                                KeyInfo=attr[1];//get crypto key Infomation
                                                                keyNum=attribNum;
                                                                flag++;
                                                        }
                                                        else if('author'==attr[0]){
                                                                authorId=attr[1];
                                                                flag ++;
                                                        }
                                                        if(KeyInfo !='' && authorId != "")
                                                                        break;

						}//end attribNum
					}//endfor
				}//end attriblistAes
				if(flag==1)
				{
					var nonce=KeyInfo.substring(0,4);
					var iv=this.ivStr+nonce;
					//var startKeyPos=parseInt(KeyInfo.substring(4),16);
					//var counter= Math.floor(startKeyPos / (this.keyLen/8));
					//var offset = startKeyPos % (this.keyLen/8);
					var offset=parseInt(KeyInfo.substring(4),16);
					var ss=this.decryptCharBank(authorId,dectext,iv,offset);
					dectext=ss.plaintext;
					nextPos=ss.nextpos;
					newpool.numToAttrib[parseInt(keyNum, 36)][1]=nonce+nextPos;
				}
			}//end opcode
		}//end dectext
		plainText+=dectext;
		//   assem.append(op);
	}//end while
	atext.text=plainText;
}
module.exports = DocsCrypto;



