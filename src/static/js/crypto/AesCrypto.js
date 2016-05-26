var aesJS=require('./aes');
var sha256JS=require('./hmac-sha256');
var sha512JS=require('./hmac-sha512');

keyGen=function(uid,masterKey,keyLen){
if(keyLen==512){
  var keyBuff=sha512JS.CreatSHA512Hmac(uid,masterKey);
  return keyBuff;
}
else if(keyLen==256){
  var keyBuff=sha256JS.CreatSHA256Hmac(uid,masterKey);
  return keyBuff;
   }
else{// default 128bit 4=128/32
    var keyBuff=sha256JS.CreatSHA256Hmac(uid,masterKey);
    var hexstr=sha512JS.toHex(keyBuff);
    var key=aesJS.toHex(hexstr.substring(0,32));
    return key;
   }
}

function correctValueBefore(c,beforeorafter){
  var t1=Math.abs(c-beforeorafter);
  var changed=(c^0x0800);
  var t2=Math.abs(changed-beforeorafter);
  if(t1>t2)return changed;
  else return c;
}
/*initialize the stream buffer
param key is the key of crypto algorithm
param keyLen, is the bit length of the key
param ivCounter is the ivStr+counter to be encrypted
*/
function initStream(myaes,ivStr,streamLen){
var stream=new Array(streamLen);
var encrypted=aesJS.KeyStream(myaes,ivStr,0);
var textword=encrypted.words;
var len=textword.length;
var i=0;
var j=0;
var w=0;
 for(;i<len;i++,j+=4){
       w=textword[i];
       stream[j]=(w>>24)&0xff;
       stream[j+1]=(w>>16)&0xff;
       stream[j+2]=(w>>8)&0xff;
       stream[j+3]=w&0xff;
       }
return stream;
}
//structure of crypto
var AesCrypto=function(uid,masterkey,keyLen,iv){
this.key=keyGen(uid,masterkey,keyLen);
this.keyLength=keyLen/8;
this.ivStr=iv;
this.myAes=aesJS.Init(this.key);
this.startCounter=0;
this.streamLen=this.keyLength;
this.stream=initStream(this.myAes,this.ivStr,this.streamLen);
this.encrypttimes=1;
this.cursor=0;
};
AesCrypto.prototype.getTimes=function(){
return this.encrypttimes;
};
AesCrypto.prototype.setStream=function(){
var encrypted=aesJS.KeyStream(this.myAes,this.ivStr,this.startCounter);
var textword=encrypted.words;
var len=textword.length;
var i=0;
var j=0;
var w=0;
 for(;i<len;i++,j+=4){
       w=textword[i];
       this.stream[j]=(w>>24)&0xff;
       this.stream[j+1]=(w>>16)&0xff;
       this.stream[j+2]=(w>>8)&0xff;
       this.stream[j+3]=w&0xff;
       }
this.myAes.finalize();
};
AesCrypto.prototype.ivReset=function(ivStr){
   this.ivStr=ivStr;
   this.startCounter=0;
   this.setStream();
   this.cursor=0;
   this.encrypttimes++;
}
AesCrypto.prototype.updateStream=function(){//start must be the mutiple of 16bytes,counterBytes also must be zhengshubei of 16
      this.startCounter++;
      this.setStream();
      this.cursor=0;
      this.encrypttimes++;
};


AesCrypto.prototype.encrypt=function(plainText){
    if(this.cursor>=this.keyLength)this.updateStream();
   var basecounter=this.startCounter;
   var baseoffset=this.cursor;

   var str="";
   var dataLen=plainText.length;
   var num=0;
   var i=0;
   var c=0;
   var newc=0;
   var first=0;
   var second=0;
   while(num<dataLen){
         i=this.cursor;
         //alert(this.stream);
         for(;i<this.keyLength && num<dataLen;num++){
             c=plainText.charCodeAt(num);
             newc=c;
             if(c!=10){
             first=(c>>8)^this.stream[i];
             second=(c&0xff)^this.stream[i+1];
             if(first>=0xD8&&first<=0xDF)first=first^0x08;
             newc=(first<<8)+second;
             i=i+2;
             }
             str+=String.fromCharCode(newc);
           }
        this.cursor=i;
        if(this.cursor>=this.keyLength){this.updateStream();}
      }
   var startPos=(basecounter*this.keyLength+baseoffset).toString(16);
   var nonce=this.ivStr.substring(20);
   var keyInfo=nonce+startPos;
  return {ciphertext:str,keyinfo:keyInfo};
};
AesCrypto.prototype.decrypt=function(cipherText,ivStr,counter,offset){

    if(this.ivStr!=ivStr) this.ivReset(ivStr);
    if(counter != this.startCounter){
         this.startCounter = counter-1;
         this.updateStream();
         }
    this.cursor=offset;

   var dataLen=cipherText.length;
   var num=0;
   var str="";
   var i=0;
   var c=0;
   var newp=0;
   var first=0;
   var second=0;
   var temp=0;
  // alert("this iv "+this.ivStr+" this counter"+this.startCounter);
    while(num<dataLen){
         i=this.cursor;
         //alert(this.stream);
         for(;i<this.keyLength && num<dataLen;num++){
             c=cipherText.charCodeAt(num);
             newp=c;
             if(c!=10){
             first=c>>8;
             second=c&0xff;
                 newp=((first^this.stream[i])<<8)+(second^this.stream[i+1]);
             if((first>>4)==0x0D){
                 temp=newp ^ 0x0800;
                 if(Math.abs(temp-128)<Math.abs(newp-128))newp=temp;
               }//end
             i=i+2;
             }//end c!=10
             str=str+String.fromCharCode(newp);
           }//end for
        this.cursor=i;
        if(this.cursor>=this.keyLength){
          this.updateStream();
          }
      }
  var nextPos=((this.startCounter)*this.keyLength+this.cursor).toString(16);
  return {plaintext:str, nextpos:nextPos};
};
/*
AesCrypto.prototype.encryptEachLine=function(plainText){
   var str="";
   var dataLen=plainText.length;
   var num=0;
   if(this.cursor==this.keyLength)this.updateStream();
   while(num<dataLen){
         var i=this.cursor;
         for(;i<this.keyLength && num<dataLen;i+=2,num++){
             var c=plainText.charCodeAt(num);
             var first=(c>>8)^this.stream[i];
             var second=(c%256)^this.stream[i+1];
             if(first>=0xD8&&first<=0xDF)first=first^0x08;
             var newc=first*256+second;
             str+=String.fromCharCode(newc);
           }
        this.cursor=i;
        if(this.cursor>=this.keyLength){this.updateStream();}
      }
  return str;
};
AesCrypto.prototype.decryptEachLine=function(cipherText){
   var dataLen=cipherText.length;
   var num=0;
   var str="";
   if(this.cursor==this.keyLength){
   this.updateStream();
   }
   while(num<dataLen){
         var i=this.cursor;
         for(;i<this.keyLength && num<dataLen;i+=2,num++){
              var c=cipherText.charCodeAt(num);
              var newp=(c%256)^this.stream[i+1];
              str=str+String.fromCharCode(newp);
           }
        this.cursor=i;
        if(this.cursor>=this.keyLength){
          this.updateStream();
        }
     }
  return str;
};
AesCrypto.prototype.encrypt=function(plainText){

   if(this.cursor==this.keyLength)this.updateStream();
   var basecounter=this.startCounter;
   var baseoffset=this.cursor;

   var pstr=plainText;
   var cipherstr="";
   var sentry="";
   var index=pstr.indexOf('\n');
   if(-1==index){
    var ss=this.encryptEachLine(pstr);
    cipherstr += ss;
   }else{
    while(-1 != (index=pstr.indexOf('\n'))){
     var temp=pstr.substring(0,index);
     var ss=this.encryptEachLine(temp);
     cipherstr += ss+'\n';
     pstr=pstr.substring(index+1);
    }
    if(pstr.length>0){
     var ss=this.encryptEachLine(pstr);
     cipherstr += ss;
    }
  }
   var startPos=(basecounter*this.keyLength+baseoffset).toString(16);
   var nonce=this.ivStr.substring(20);
   var keyInfo=nonce+startPos;
   return {ciphertext:cipherstr,keyinfo:keyInfo};
}

AesCrypto.prototype.decrypt=function(data,ivStr,counter,offset){// decrypt with posStr, or encrypt without posStr

    if(this.ivStr!=ivStr) this.ivReset(ivStr);
    if(counter != this.startCounter){
         this.startCounter = counter-1;
         this.updateStream();
         }
    this.cursor=offset;

   var cstr=data;
   var pstr="";
   if(-1==cstr.indexOf('\n')){
      var clen=cstr.length;
      var ss=this.decryptEachLine(cstr);
      pstr += ss;
   }else{
    var index=-1;
    while(-1!=(index=cstr.indexOf('\n'))){
     var temp=cstr.substring(0,index);
     var ss=this.decryptEachLine(temp);
     pstr += ss+'\n';
     cstr=cstr.substring(index+1);
     }
    if(cstr.length>0){
     pstr += this.decryptEachLine(cstr);
     }
  }
    var nextPos=((this.startCounter)*this.keyLength+this.cursor).toString(16);
    return {plaintext:pstr, nextpos:nextPos};
}
*/
module.exports = AesCrypto;

