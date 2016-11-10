/*
* Author: Tyler Lee
* Email: leehuorong@gmail.com
*
* All rights reserved.
*/

/*
# Changeset Library

```
"Z:z>1|2=m=b*0|1+1$\n"
```

This is a Changeset. Its just a string and its very difficult to read in this form. But the Changeset Library gives us some tools to read it.

A changeset describes the diff between two revisions of the document. The Browser sends changesets to the server and the server sends them to the clients to update them. This Changesets gets also saved into the history of a pad. Which allows us to go back to every revision from the past.

## Changeset.unpack(changeset)

 * `changeset` {String}

This functions returns an object representaion of the changeset, similar to this:

```
{ oldLen: 35, newLen: 36, ops: '|2=m=b*0|1+1', charBank: '\n' }
```

 * `oldLen` {Number} the original length of the document.
 * `newLen` {Number} the length of the document after the changeset is applied.
 * `ops` {String} the actual changes, introduced by this changeset.
 * `charBank` {String} All characters that are added by this changeset.

## Changeset.opIterator(ops)

 * `ops` {String} The operators, returned by `Changeset.unpack()`

Returns an operator iterator. This iterator allows us to iterate over all operators that are in the changeset.

You can iterate with an opIterator using its `next()` and `hasNext()` methods. Next returns the `next()` operator object and `hasNext()` indicates, whether there are any operators left.

## The Operator object
There are 3 types of operators: `+`,`-` and `=`. These operators describe different changes to the document, beginning with the first character of the document. A `=` operator doesn't change the text, but it may add or remove text attributes. A `-` operator removes text. And a `+` Operator adds text and optionally adds some attributes to it.

 * `opcode` {String} the operator type
 * `chars` {Number} the length of the text changed by this operator.
 * `lines` {Number} the number of lines changed by this operator.
 * `attribs` {attribs} attributes set on this text.

### Example
```
{ opcode: '+',
  chars: 1,
  lines: 1,
  attribs: '*0' }
```
*/

var Changeset = require('../Changeset');
var AttributePool = require('../AttributePool');

/*
 * This function unpack userChangeset and add key info to each char in the charBank,
 * and during this process, some new attrib will be create for each char, so this info
 * will be updated to apool for the userChangeset.
 *
 * cipherInfo is in following format:
 *		{'authorId': 'xxx', 'nonce': 'xxxx', 'offset': [a, b, ...]}
 * offset is number.
 * some of the field may be missing.
 * TODO: Currently, authorId is no used.
 *
 * return: new userChangeset
 */
var putCipherInfoAttribs = function (userChangeset, apool, cipherInfo) {
	//make sure apool is an instance of AttributePool.
	if(!(apool instanceof AttributePool)) {
		var tempApool = new AttributePool();
		tempApool.fromJsonable(apool);
		apool = tempApool;
	}

	//get authorId, nonce and offset
	var nonce = cipherInfo.nonce || '';
	var offset = cipherInfo.offset;
	//put nonce attribute into apool
	var nonceAttribNum = apool.putAttrib(['nonce', nonce]);
	//var nonceAttribNum = putAttribToApool(apool, ['nonce', nonce]);

	var cs = Changeset.unpack(userChangeset)
	, iterator = Changeset.opIterator(cs.ops)
	, op
	, assem = Changeset.mergingOpAssembler();

	//console.log(userChangeset, cs.ops);
	var charCount = 0;
	while(iterator.hasNext()) {
		op = iterator.next()
		if(op.opcode == '+') {
			//only inserted chars will appear in charBank
			for(var count = 0; count < op.chars; count++) {
				//copy op
				var newOp = Changeset.newOp();
				newOp.opcode = op.opcode;
				newOp.chars = 1;
				newOp.lines = 0;
				newOp.attribs = op.attribs;

				//we ignore newLine charactor
				//console.log('charCount: ' + charCount.toString());
				if(cs.charBank[charCount] != '\n') {
					//append nonce attrib info
					newOp.attribs += '*' + Number(nonceAttribNum).toString(36);
					//put offset[count] attribute into apool
					var offsetAttribNum = apool.putAttrib(['offset', Number(offset[count]).toString(36)]);
					newOp.attribs += '*' + Number(offsetAttribNum).toString(36);
				}
				else {
					newOp.lines = 1;
				}
				assem.append(newOp);
				//console.log(newOp.attribs, charCount, cs.charBank[charCount]);
				charCount++;
			}
		}
		else {
			assem.append(op)
		}
	}
	assem.endDocument();
	userChangeset = Changeset.pack(cs.oldLen, cs.newLen, assem.toString(), cs.charBank)
	Changeset.checkRep(userChangeset)

	return userChangeset;
}
exports.putCipherInfoAttribs = putCipherInfoAttribs;

/*
 * Function: get crypto info from apool according to the each operation's attribs.
 * Note: only one char is processed at a time, so there is only one offset attribute.
 *
 * Return:
 *		{'authorId': 'xxx', 'nonce': 'xxxx', 'offset': [a, b, ...]}
 * offset is number.
 */
var getCipherInfoAttribs = function(apool, attribs) {
	var result = {offset:[]};

	var opAttribs= attribs.split('*');
	for(var index in opAttribs) {
		if(opAttribs[index] == '') continue;
		var attNum = parseInt(String(opAttribs[index]), 36);
		//check whether the attribute is in apool
		if(! (attNum in apool.numToAttrib)) {
			console.log('Cannot find attribute %d in apool', attNum);
		}

		//make sure apool is an instance of AttributePool.
		if(!(apool instanceof AttributePool)) {
			var newApool=new AttributePool();
			newApool.fromJsonable(apool);
			apool = newApool;
		}
		var attrib = apool.getAttrib(attNum);
		if(attrib[0] == 'author') {
			result.authorId = attrib[1];
		}
		else if(attrib[0] == 'nonce') {
			result.nonce = attrib[1];
		}
		else if(attrib[0] == 'offset') {
			result.offset[0] = parseInt(String(attrib[1]), 36);
		}
	}

	//TODO: we should check whether all the needed cipher info is get.

	return result;
}
exports.getCipherInfoAttribs= getCipherInfoAttribs;

/*
//test part
var apool = new AttributePool();
apool.putAttrib(['author', 'tyler']);
apool.putAttrib(['bold', 'true']);
var userChangeset = 'Z:z>b|2=m=b*0|1+b$123\n4567890'
var cipherInfo = {'nonce': 'ivst', 'offset': 234};

//test putCipherInfoAttribs
//console.log('before expand:')
//console.log(userChangeset, apool);
userChangeset = putCipherInfoAttribs(userChangeset, apool, cipherInfo);
//console.log('after expand:')
console.log(userChangeset, apool);	//Z:z>b|2=m=b*0*2*3+1*0*2*4+1*0*2*5+1*0|1+1*0*2*6+1*0*2*7+1*0*2*8+1*0*2*9+1*0*2*a+1*0*2*b+1*0*2*c+1$123\n4567890

//test getCipherInfoAttribs
var attribs = '';
var cipherInfo = {};
attribs = '*0*2*3';
cipherInfo = getCipherInfoAttribs(apool, attribs);
console.log(cipherInfo);
attribs = '*0*2*9';
cipherInfo = getCipherInfoAttribs(apool, attribs);
console.log(cipherInfo);
attribs = '*0*2*b';
cipherInfo = getCipherInfoAttribs(apool, attribs);
console.log(cipherInfo);

//*/

