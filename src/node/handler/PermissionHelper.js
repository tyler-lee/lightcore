var mysql   = require('mysql');

var getUserPadPermission = function(userId, padId, callback) {
	//TODO: set configure according to db info
	var configure = {
		host: 'localhost',
		//port: 3306,
		user: 'root',
		password: 'secbook',
		database: 'rti'
	};

	var connection = mysql.createConnection(configure);
	connection.connect();

	//user_company中的codeid为发送到lightcore中的userId，workfile中的context是发送到lightcore中的padid
	var queryStr = 'select permission from user_workfiles left join user_company u on u_id=u.id left join workfiles w on w_id=w.id where u.codeid=' + connection.escape(userId) + ' and w.context=' + connection.escape(padId);
	 
	//这个的查询结果就为权限permission , 其中0位只读，1位可写，2位创建者。查询的结果为空，说明该用户没有那个文档；查询结果不为空且结果只有一个，说明用户有该文档；查询结果有多个，说明表结构错误（不会发生）；
	connection.query(queryStr, function(err, rows, fields) {
		var value;
		if (!err && undefined !== rows[0]) {
			//The result is:  [ { permission: 2 } ]
			value = rows[0].permission;
		}

		callback(err,value);
	});

	connection.end();
}
 
exports.getUserPadPermission = getUserPadPermission;

/*
var userId='lee';
var padId = 'fYUqM0SOaqwBkgJtreDkiYbrB79eN7xBRhAtfLhB';
getUserPadPermission(userId, padId, function(err, permission){
	if(!err) console.log(permission);
});

padId = 'fYUqM0SOaqwBkgJtreDkiYbrB79eN7xBRhAerror';
getUserPadPermission(userId, padId, function(err, permission){
	if(!err) console.log(permission);
})
//*/
