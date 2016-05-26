var Changeset = require('../Changeset');
var AttributePool=require('../AttributePool');
var Crypto=require('./AesCrypto');


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
var DocsCrypto=function(uid,masterkey,keyLen, streamMaxLength, ivStr){
this.encryptor=new Crypto(uid,masterkey,keyLen,ivStr);
this.decryptList={};
this.masterkey=masterkey;
this.keyLen=keyLen;
this.userId=uid;
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
 var newCrypto=new Crypto(uid,masterkey,keyLen,ivStr);
 this.decryptList[uid]=newCrypto;
 return newCrypto;
};
DocsCrypto.prototype.decryptCharBank=function(uid,charBank,ivStr,counter,offset){
  if(uid in this.decryptList){
      return this.decryptList[uid].decrypt(charBank,ivStr,counter,offset);
      }else{
    var newCrypto=this.AddDecryptor(uid,this.masterkey,this.keyLen,ivStr);
    return newCrypto.decrypt(charBank,ivStr,counter,offset);
    }
};
DocsCrypto.prototype.getEncryptTimes=function(){
   var total=0;
   for( uid in this.decryptList){
        total += this.decryptList[uid].getTimes();
    }
   return total;
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
   //update the inserted op
   /*
   var startLine=-1;
   if(iterator.hasNext()) {
	   op=iterator.next();
	   startLine=op.lines;
	   //alert(startLine);
   }
   do {
	   if(op.opcode == '+') {
                     op.attribs=op.attribs+'*'+apool.nextNum.toString();
                     flag=true;
                   }
         assem.append(op);
          op = iterator.next();

   }while(iterator.hasNext());
   //*/
   var startLine=-1;
   var lineInfoGetted=false;
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
	   var isResetIV=false;
	   //根据startLine和currentLine的位置关系确定isResetIV，如果二者相等，则继续使用当前IV，否则重置IV
	    if(startLine==this.currentLine) {
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
DocsCrypto.prototype.decryptTest=function(charBank){
 var newCrypto=this.AddDecryptor('jwytesting',this.masterkey,this.keyLen,this.ivStr);
 var len1=this.ivStr.length;
 var ivStr=this.ivStr;
 if(len1<24)ivStr=ivStr+randomString(24-len1);
 var counter=0;
 var offset=0;
 newCrypto.decrypt(charBank,ivStr,counter,offset);
 return newCrypto.getTimes();
}
DocsCrypto.prototype.decryptCS=function(encryptedChangeset,apool){
var newCS=encryptedChangeset;
var cs = Changeset.unpack(newCS);
if(cs.charBank.length>0 && cs.charBank != '\n' && cs.charBank != '')
 {
   var iterator = Changeset.opIterator(cs.ops)
       ,op
      , assem = Changeset.smartOpAssembler();
   var iv="";
   var flag=false;
   var keyNum=-1;
   var authorId="";
   var offset=0;
   var counter=0;
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
                      iv=this.ivStr+nonce;
                  var startPos=parseInt(keyInfo.substring(4),16);
                      counter= Math.floor(startPos / (this.keyLen/8));
                      offset=startPos % (this.keyLen/8);
                      flag=true;
                      keyNum=attr;
                      break;
              }
          }
       }
  if(flag){
		var startLine=-1;
		var lineInfoGetted=false;
        while(iterator.hasNext()) {//update the op, remove the crypto attribute
          op = iterator.next();
          //获取changeset中的行信息
		  if(!lineInfoGetted) {
			  if(op.lines>=0) {
				  startLine=op.lines;
				  lineInfoGetted=true;
				  this.currentLine=startLine;
			  }
			  else {
				  startLine=0;
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
      var ss = this.decryptCharBank(authorId,cs.charBank,iv,counter,offset);
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
  while (iter.hasNext()) {
         iter.next(op);
         var opvalue=1;
         if(op.opcode=='-')opvalue=-1;

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
                                      }else if('Key' == attr[0]){
                                           KeyInfo=attr[1];//get crypto key Infomation
                                           keyNum=attribNum;
                                         if(flag==0){flag=1;break;}
                                      }else if('author'==attr[0]){
                                           authorId=attr[1];
                                           flag=0;
                                     }
                             }//end attribNum
                  }//endfor
                }//end attriblistAes
                if(flag==1)
                 {
                      var nonce=KeyInfo.substring(0,4);
                      var iv=this.ivStr+nonce;
                      var startKeyPos=parseInt(KeyInfo.substring(4),16);
                      var counter= Math.floor(startKeyPos / (this.keyLen/8));
                      var offset = startKeyPos % (this.keyLen/8);
                      var ss=this.decryptCharBank(authorId,dectext,iv,counter,offset);
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



