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
* put attrib to apool and update apool info
* Note:
*	attrib should be in the following format: ['attribKey', 'attribValue']
*/
var putAttribToApool = function (apool, attrib) {
	var str = String(attrib);
	//if (str in apool.attribToNum) {
	//	return apool.attribToNum[str];
	//}
	for(var index in apool.numToAttrib) {
		if(str == apool.numToAttrib[index]) {
			console.log('attribute %s is already existing', str);
			return index;
		}
	}

	var num = apool.nextNum++;
	//apool.attribToNum[str] = num;
	apool.numToAttrib[num] = [String(attrib[0] || ''), String(attrib[1] || '')];
	return num;
};
exports.putAttribToApool = putAttribToApool;

/*
 * This function unpack userChangeset and add key info to each char in the charBank,
 * and during this process, some new attrib will be create for each char, so this info
 * will be updated to apool for the userChangeset.
 *
 * key info is made of nonce||offset, which the first 4 chars are nonce and the left is offset.
 * offset is encoded into hexidecimal.
 *
 * return: new userChangeset
 */
var addKeyInfoAttrib = function (userChangeset, apool, keyInfo) {
	var cs = Changeset.unpack(userChangeset)
	, iterator = Changeset.opIterator(cs.ops)
	, op
	, assem = Changeset.mergingOpAssembler();
	//get nonce and offset
	var nonce = keyInfo.substring(0, 4);
	var offset = parseInt(keyInfo.substring(4), 36);
	//put nonce attribute into apool
	var nonceAttribNum = putAttribToApool(apool, ['nonce', nonce]);


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
					//put offset attribute into apool
					var offsetAttribNum = putAttribToApool(apool, ['offset', Number(offset).toString(36)]);
					//each char occupies two bytes
					offset += 2;
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
exports.addKeyInfoAttrib = addKeyInfoAttrib;

/*
 * Function: get crypto info from apool according to the each operation's attribs.
 *
 * Return: {'authorId': xxx, 'nonce': xx, 'offset': xx}
 */
var getCipherInfoAttribsFromApool = function(apool, attribs) {
	var result = {};

	var opAttribs= attribs.split('*');
	for(var index in opAttribs) {
		if(opAttribs[index] == '') continue;
		var attNum = parseInt(String(opAttribs[index]), 36);
		//check whether the attribute is in apool
		if(! (attNum in apool.numToAttrib)) {
			console.log('Cannot find attribute %d in apool', attNum);
		}

		var attrib = apool.getAttrib(attNum);
		if(attrib[0] == 'author') {
			result.authorId = attrib[1];
		}
		else if(attrib[0] == 'nonce') {
			result.nonce = attrib[1];
		}
		else if(attrib[0] == 'offset') {
			result.offset = parseInt(String(attrib[1]), 36);
		}
	}

	//TODO: we should check whether all the needed key info is get.

	return result;
}
exports.getCipherInfoAttribsFromApool = getCipherInfoAttribsFromApool;

/*
//test part
var apool = new AttributePool();

//test putAttribToApool
putAttribToApool(apool, ['author', 'tyler']);
putAttribToApool(apool, ['bold', 'true']);
var userChangeset = 'Z:z>b|2=m=b*0|1+b$123\n4567890'
var keyInfo = 'ivstae';	//nonce: asdf		offset: 0

//test addKeyInfoAttrib
//console.log('before expand:')
//console.log(userChangeset, apool);
userChangeset = addKeyInfoAttrib(userChangeset, apool, keyInfo);
//console.log('after expand:')
console.log(userChangeset, apool);	//Z:z>b|2=m=b*0*2*3+1*0*2*4+1*0*2*5+1*0|1+1*0*2*6+1*0*2*7+1*0*2*8+1*0*2*9+1*0*2*a+1*0*2*b+1*0*2*c+1$123\n4567890

//test getCipherInfoAttribsFromApool
var attribs = '';
var cipherInfo = {};
attribs = '*0*2*3';
cipherInfo = getCipherInfoAttribsFromApool(apool, attribs);
console.log(cipherInfo);
attribs = '*0*2*9';
cipherInfo = getCipherInfoAttribsFromApool(apool, attribs);
console.log(cipherInfo);
attribs = '*0*2*b';
cipherInfo = getCipherInfoAttribsFromApool(apool, attribs);
console.log(cipherInfo);

//*/

