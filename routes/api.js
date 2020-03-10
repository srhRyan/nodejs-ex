var express = require('express');
var router = express.Router();
var jwt = require("jsonwebtoken");
const uuidv4 = require('uuid/v4');

// database
var Pool = require("ibm_db").Pool;
var ibmdb = new Pool();

var cn = process.env.DB;

var enrollAvaiableBegin = 1553472000000; // 2019-03-25 08:00:00
var enrollAvaiableEnd = 1553677200000; // 2019-03-27 17:00:00
var adminList = ['027267858', 'AVNBTG858', 'ZZ02FV672'];

var currentTs = function() {
	// generate timestamp
	var now = new Date;
	var utc_timestamp = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(),
		now.getUTCHours(), now.getUTCMinutes(), now.getUTCSeconds(), now.getUTCMilliseconds()) + 8 * 60 * 60 * 1000;
	var twTimestamp = new Date(utc_timestamp).toJSON().replace(/T/i, ' ').replace(/Z/i, '');
	return twTimestamp;
};

var customlogger = {
	info: function(sessionId, sessionSn, loginfo) {
		var finalPrintContent = '';
		for (var i = 0; i < loginfo.length; i++) {
			var printInfo = loginfo[i];
			if (typeof loginfo[i] === 'object') {
				printInfo = JSON.stringify(loginfo[i]);
			}
			finalPrintContent += printInfo;
			finalPrintContent += " ";
		}
		var now = currentTs();
		console.log('[' + now + '|' + sessionId + '|' + sessionSn + '] ' + finalPrintContent);
	}
};

function camelize(str) {
	var rtl = "";
	var arr = str.split("_");
	for (var i = 0; i < arr.length; i++) {
		rtl += arr[i].replace(/(?:^\w|[A-Z]|\b\w|\s+)/g, function(match, index) {
			if (+match === 0) return ""; // or if (/\s+/.test(match)) for white spaces
			return index == 0 ? match.toUpperCase() : match.toLowerCase();
		});
	}
	rtl = rtl.charAt(0).toLowerCase() + rtl.slice(1);
	return rtl;
}

function convertKeysToCamelize(obj) {

	// array
	if (Array.isArray(obj)) {
		for (var i = 0; i < obj.length; i++) {
			for (var propertyName in obj[i]) {
				var old_key = propertyName;
				var new_key = camelize(old_key);
				if (old_key !== new_key) {
					Object.defineProperty(obj[i], new_key,
						Object.getOwnPropertyDescriptor(obj[i], old_key));
					delete obj[i][old_key];
				}
			}
		}
		return obj;
	}

	return obj;

}

var securityValid = function(inputString) {
	var lt = /</g,
		gt = />/g,
		ap = /'/g,
		ic = /"/g;
	lq = /{/g;
	rq = /}/g;
	inputString = inputString.toString().replace(lt, "&lt;").replace(gt, "&gt;").replace(ap, "&#39;").replace(ic, "&#34;").replace(lq, "").replace(rq, "");
	return inputString;
};

function securityValidObject(obj) {
	if (obj) {
		for (var propertyName in obj) {
			if (typeof obj[propertyName] === 'string') {
				obj[propertyName] = securityValid(obj[propertyName]);
			}
		}
	}
}

module.exports = function(app, config, passport) {

	/////////////////////////////////////////////////////////////////////////////
	// Core - authenticate
	/////////////////////////////////////////////////////////////////////////////

	// validate JWT on all API calls
	router.use("/", function(req, res, next) {

		// issue a request id
		req.rid = uuidv4();

		// clean request
		securityValidObject(req.body);
		securityValidObject(req.query);

		var sessionId = req.sessionID || req.rid;
		// pring request
		customlogger.info(sessionId, "", ["L001", "request URL:", req.url]);
		customlogger.info(sessionId, "", ["L002", "request JSON:", JSON.stringify(req.body)]);
		customlogger.info(sessionId, "", ["L003", "request QueryString:", JSON.stringify(req.query)]);

		// check header or url parameters or post parameters for token
		var token = req.headers['authorization'] || req.body.token || req.query.token || "";
		jwt.verify(token, config.passport.sessionSecret, function(err, decoded) {
			if (err) {
				var responseJSON = {
					code: "9001",
					success: false,
					message: 'Failed to authenticate token.'
				};
				customlogger.info(req.rid, "", ["L009", "response JSON:", JSON.stringify(responseJSON)]);
				return res.status(403).send(responseJSON);
			} else {
				if (decoded && decoded.uid) {
					// Set user UID in the request
					req.user = {
						uid: decoded.uid,
						displayName: decoded.displayName,
						empNum: decoded.empNum
					};
					// In a real application the user profile should be retrieved from the persistent storage here
					customlogger.info(req.rid, req.user.uid, ["L004", "pass token verify"]);
					customlogger.info(req.rid, req.user.uid, ["request User:", JSON.stringify(req.user)]);
					next();
				} else {
					// return an error
					var responseJSON = {
						code: "9002",
						success: false,
						message: 'Invalid ID in token'
					};
					customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
					return res.status(403).send(responseJSON);
				}
			}
		});
	});

	/////////////////////////////////////////////////////////////////////////////
	// Core - Profile APIs
	/////////////////////////////////////////////////////////////////////////////

	// Example of an API call  
	// router.get("/example",
	// 	function(req, res) {
	// 		ibmdb.open(cn, function(err, conn) {
	// 			if (err) {
	// 				console.log("error=", JSON.stringify(err));
	// 				conn.closeSync();
	// 				res.status(400).json({
	// 					code: "9900",
	// 					message: "system error"
	// 				});
	// 				return;
	// 			}
	// 			// business logic begin
	// 			try {
	// 				// end of business
	// 				conn.closeSync();

	// 				// response
	// 				res.json({

	// 				});
	// 			} catch (err) {
	// 				console.log("error=", JSON.stringify(err));
	// 				conn.closeSync();
	// 				res.status(400).json({
	// 					code: "9900",
	// 					message: "system error"
	// 				});
	// 				return;
	// 			}
	// 		});
	// 	}
	// );

	// router.get("/exampleTx",
	// 	function(req, res) {
	// 		ibmdb.open(cn, function(err, conn) {
	// 			if (err) {
	// 				console.log("error=", JSON.stringify(err));
	// 				conn.closeSync();
	// 				res.status(400).json({
	// 					code: "9900",
	// 					message: "system error"
	// 				});
	// 				return;
	//             }
	//             conn.beginTransaction(function(err2) {
	// 				if (err2) {
	// 					//could not begin a transaction for some reason.
	// 					console.log("error=", JSON.stringify(err2));
	// 					conn.endTransactionSync(true);
	// 					conn.closeSync();
	// 					var responseJSON = {
	// 						code: "9900",
	// 						message: "system error",
	// 						newEnrolledCourse: null
	// 					};
	// 					console.log("response JSON:", JSON.stringify(responseJSON));
	// 					res.status(400).json(responseJSON);
	// 					return;
	//                 }
	//                 // end transaction
	//                 var isRollback = false;
	// 				conn.endTransactionSync(false);
	// 				//Close the connection
	// 				conn.closeSync();
	// 				var responseJSON = {
	// 					code: "0001",
	// 					message: "already enrolled.",
	// 					newEnrolledCourse: rows
	// 				};
	// 				console.log("response JSON:", JSON.stringify(responseJSON));
	// 				res.json(responseJSON);
	// 				return;
	//             });

	// 			try {
	//                 // business logic begin
	// 				// end of business
	// 				conn.closeSync();
	// 				// response
	// 				res.json({

	//                 });
	// 			} catch (err) {
	// 				console.log("error=", JSON.stringify(err));
	// 				conn.closeSync();
	// 				res.status(400).json({
	// 					code: "9900",
	// 					message: "system error"
	// 				});
	// 				return;
	// 			}
	// 		});
	// 	}
	// );


	router.get("/profile",
		function(req, res) {
			try {
				ibmdb.open(cn, function(err, conn) {
					if (err) {
						customlogger.info(req.rid, req.user.uid, ["error=", JSON.stringify(err)]);
						conn.closeSync();
						var responseJSON = {
							code: "9900",
							message: "system error"
						};
						customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
						res.status(400).json(responseJSON);
						return;
					}
					// business logic begin
					try {
						var userProfile = conn.querySync("select * from user where emp_num=?", [req.user.empNum]);
						if (userProfile.error) {
                            console.log(userProfile);
							throw "SQL Error";
						}
						convertKeysToCamelize(userProfile);
						var empGroup = 0;
						var empTeam = '';
						var whiteList = null;
						var profileUser = false;
						if (userProfile && userProfile.length > 0) {
							empGroup = userProfile[0].empGroup;
							empTeam = userProfile[0].team;
							whiteList = userProfile[0].whiteList;
							profileUser = true;
						}
						customlogger.info(req.rid, req.user.uid, ["userProfile=", JSON.stringify(userProfile)]);
						// end of business
						conn.closeSync();
						// response
						var responseJSON = {
							code: "0000",
							message: "success",
							result: req.user,
							empGroup: empGroup,
							empTeam: empTeam,
							whiteList: whiteList,
							profileUser: profileUser
						};
						customlogger.info(req.rid, req.user.uid, ["response JSON=", JSON.stringify(responseJSON)]);
						res.json(responseJSON);
					} catch (err) {
						customlogger.info(req.rid, req.user.uid, ["error=", JSON.stringify(err)]);
						conn.closeSync();
						var responseJSON = {
							code: "9900",
							message: "system error"
						};
						customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
						res.status(400).json(responseJSON);
						return;
					}
				});
			} catch (mainException) {
				customlogger.info(req.rid, req.user.uid, ["error=", JSON.stringify(mainException)]);
				var responseJSON = {
					code: "9900",
					message: "system error"
				};
				customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
				res.status(400).json(responseJSON);
				return;
			}
		}
	);

	/////////////////////////////////////////////////////////////////////////////
	// Core - Inquiry APIs
	/////////////////////////////////////////////////////////////////////////////

	router.get("/courseList",
		function(req, res) {
			try {
				ibmdb.open(cn, function(err, conn) {
					if (err) {
						customlogger.info(req.rid, req.user.uid, ["error=", JSON.stringify(err)]);
						conn.closeSync();
						var responseJSON = {
							code: "9900",
							message: "system error"
						};
						customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
						res.status(400).json(responseJSON);
						return;
					}
					// business logic begin
					try {

						var rows = conn.querySync("select * from course order by course_begin, course_id asc");
						if (rows.error) {
							throw "SQL Error";
						}
						convertKeysToCamelize(rows);

						var courseList = getCourseList(rows);

						conn.closeSync();
						var responseJSON = {
							code: "0000",
							message: "success",
							courses: courseList
						};
						customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
						res.json(responseJSON);

					} catch (err) {
						customlogger.info(req.rid, req.user.uid, ["error=", JSON.stringify(err)]);
						conn.closeSync();
						var responseJSON = {
							code: "9900",
							message: "system error",
							courses: null
						};
						customlogger.info(req.rid, req.user.uid, ["responseJSON=", JSON.stringify(responseJSON)]);
						res.status(400).json(responseJSON);
						return;
					}
				});
			} catch (mainException) {
				customlogger.info(req.rid, req.user.uid, ["error=", JSON.stringify(mainException)]);
				var responseJSON = {
					code: "9900",
					message: "system error"
				};
				customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
				res.status(400).json(responseJSON);
				return;
			}
		}
	);

	router.get("/courseInfo",
		function(req, res) {
			// paramater check
			if (!req.query.courseId) {
				var responseJSON = {
					code: "9901",
					message: "input paramater error",
					courses: null
				};
				customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
				res.status(400).json(responseJSON);
				return;
			}
			try {
				ibmdb.open(cn, function(err, conn) {
					if (err) {
						customlogger.info(req.rid, req.user.uid, ["error=", JSON.stringify(err)]);
						conn.closeSync();
						var responseJSON = {
							code: "9900",
							message: "system error",
							course: null
						};
						customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
						res.status(400).json(responseJSON);
						return;
					}
					// business logic begin
					try {
						//blocks until the query is completed and all data has been acquired
						var rows = conn.querySync("select * from course where course_id=? order by course_begin, course_id asc", [req.query.courseId]);
						if (rows.error) {
							throw "SQL Error";
						}
						convertKeysToCamelize(rows);
						var courseList = getCourseList(rows);
						conn.closeSync();
						var responseJSON = {
							code: "0000",
							message: "success",
							course: courseList
						};
						customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
						res.json(responseJSON);
					} catch (err) {
						customlogger.info(req.rid, req.user.uid, ["error=", JSON.stringify(err)]);
						conn.closeSync();
						var responseJSON = {
							code: "9900",
							message: "system error",
							course: null
						};
						customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
						res.status(400).json(responseJSON);
						return;
					}
				});
			} catch (mainException) {
				customlogger.info(req.rid, req.user.uid, ["error=", JSON.stringify(mainException)]);
				var responseJSON = {
					code: "9900",
					message: "system error",
					course: null
				};
				customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
				res.status(400).json(responseJSON);
				return;
			}
		}
	);

	// static, business logic method
	function getCourseList(rows) {

		var resultCourseMap = {};

		// merge result into map
		for (var i = 0; i < rows.length; i++) {
			// fetch from db
			var currentRow = rows[i];
			var courseId = currentRow.courseId;
			// fetch from map
			var resultCourse = resultCourseMap[courseId];

			if (resultCourseMap[courseId]) {
				// already exist
			} else {
				resultCourseMap[courseId] = currentRow;
				resultCourseMap[courseId].sessions = [];
				resultCourse = resultCourseMap[courseId];
			}

			resultCourse.sessions.push({
				"courseBegin": currentRow.courseBegin,
				"courseEnd": currentRow.courseEnd
			});

			if (resultCourse.courseBegin) {
				delete resultCourse.courseBegin;
			}

			if (resultCourse.courseEnd) {
				delete resultCourse.courseEnd;
			}

		}

		const idList = Object.keys(resultCourseMap);

		var courseList = [];
		for (var i = 0; i < idList.length; i++) {
			courseList.push(resultCourseMap[idList[i]]);
		}

		return courseList;
	}

	router.get("/enrollList",
		function(req, res) {
			try {
				ibmdb.open(cn, function(err, conn) {
					if (err) {
						customlogger.info(req.rid, req.user.uid, ["error=", JSON.stringify(err)]);
						conn.closeSync();
						var responseJSON = {
							code: "9900",
							message: "system error",
							enrollList: null
						};
						customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
						res.status(400).json(responseJSON);
						return;
					}
					// business logic begin
					try {
						//blocks until the query is completed and all data has been acquired
						var rows = conn.querySync("select e.enroll_id, e.emp_num, c.* from enroll e, course c where e.course_id = c.course_id and e.emp_num=? order by course_begin asc", [req.user.empNum]);
						if (rows.error) {
							throw "SQL Error";
						}
						convertKeysToCamelize(rows);
						var totalCredit = conn.querySync("select sum(course_credit) as credit from (select distinct c.course_id, c.course_credit from enroll e, course c where e.course_id = c.course_id and e.emp_num=?)", [req.user.empNum]);
						if (totalCredit.error) {
							throw "SQL Error";
						}
						convertKeysToCamelize(totalCredit);
						var creditPoints = 0;
						if (totalCredit && totalCredit.length > 0) {
							creditPoints = Number.parseInt(totalCredit[0].credit);
						}
						conn.closeSync();
						var responseJSON = {
							code: "0000",
							message: "success",
							enrollList: rows,
							credits: creditPoints
						};
						customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
						res.json(responseJSON);
						return;
					} catch (err) {
						customlogger.info(req.rid, req.user.uid, ["error=", JSON.stringify(err)]);
						conn.closeSync();
						var responseJSON = {
							code: "9900",
							message: "system error",
							enrollList: null
						};
						customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
						res.status(400).json(responseJSON);
						return;
					}
				});
			} catch (mainException) {
				customlogger.info(req.rid, req.user.uid, ["error=", JSON.stringify(mainException)]);
				var responseJSON = {
					code: "9900",
					message: "system error",
					enrollList: null
				};
				customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
				res.status(400).json(responseJSON);
				return;
			}
		}
	);

	////////////////////////////////////////////////////////
	// Core Enroll, Unenroll
	////////////////////////////////////////////////////////

	router.post("/enroll",
		function(req, res) {
			// paramater check
			if (!req.body.courseId) {
				var responseJSON = {
					code: "9901",
					message: "input paramater error",
					newEnrolledCourse: null
				};
				customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
				res.status(400).json(responseJSON);
				return;
			}
			// time window check
			var nowTimeStamp = Date.now();
			if (nowTimeStamp < enrollAvaiableBegin || nowTimeStamp > enrollAvaiableEnd) {
				console.log(nowTimeStamp);
				var responseJSON = {
					code: "1006",
					message: "enroll/unenroll time window is closed.",
					newEnrolledCourse: null
				};
				customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
				res.json(responseJSON);
				return;
			}
			try {
				ibmdb.open(cn, function(err, conn) {
					if (err) {
						customlogger.info(req.rid, req.user.uid, ["error=", JSON.stringify(err)]);
						conn.closeSync();
						var responseJSON = {
							code: "9900",
							message: "system error",
							newEnrolledCourse: null
						};
						customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
						res.status(400).json(responseJSON);
						return;
					}
					conn.beginTransaction(function(err2) {
						if (err2) {
							//could not begin a transaction for some reason.
							customlogger.info(req.rid, req.user.uid, ["error=", JSON.stringify(err2)]);
							conn.endTransactionSync(true);
							conn.closeSync();
							var responseJSON = {
								code: "9900",
								message: "system error",
								newEnrolledCourse: null
							};
							customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
							res.status(400).json(responseJSON);
							return;
						}
						try {
							// 搜尋課程資料
							customlogger.info(req.rid, req.user.uid, ["checking enrolled course info"]);
							var rows = conn.querySync("select c.*, e.* from (select * from course where course_id=?) c left join (select * from enroll where emp_num=?) e on e.course_id = c.course_id", [req.body.courseId, req.user.empNum]);
							if (rows.error) {
								throw "SQL Error";
							}
							customlogger.info(req.rid, req.user.uid, [JSON.stringify(rows)]);
							convertKeysToCamelize(rows);
							if (rows && rows.length > 0) {

								var courseInfo = rows[0];
								// 1. 沒有選過同一門課
								// != null 代表已經選過課程
								customlogger.info(req.rid, req.user.uid, ["check duplicate"]);
								if (courseInfo.enrollId != null) {
									// end transaction
									conn.endTransactionSync(false);
									//Close the connection
									conn.closeSync();
									var responseJSON = {
										code: "0001",
										message: "already enrolled.",
										newEnrolledCourse: rows
									};
									customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
									res.json(responseJSON);
									return;
								}

								// 2. 這門課要有空位
								// 如果 max >= enrolled num，代表已經額滿
								customlogger.info(req.rid, req.user.uid, ["check open seats"]);
								customlogger.info(req.rid, req.user.uid, ["courseInfo=", JSON.stringify(courseInfo)]);
								customlogger.info(req.rid, req.user.uid, ["courseInfo.courseEnrolledNum=", courseInfo.courseEnrolledNum]);
								customlogger.info(req.rid, req.user.uid, ["courseInfo.courseMaxSeat=", courseInfo.courseMaxSeat]);
								if (Number.parseInt(courseInfo.courseEnrolledNum) >= Number.parseInt(courseInfo.courseMaxSeat)) {
									// end transaction
									conn.endTransactionSync(false);
									//Close the connection
									conn.closeSync();
									var responseJSON = {
										code: "1001",
										message: "course not allow to enroll, no open seats",
										newEnrolledCourse: null
									};
                                    customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
                                    // 改為 status(200) 相容前端頁面
									res.json(responseJSON);
									return;
								}

								// 3. 學員資格符合
								// 如果 empGroup < 課程限制，則資格不符
								customlogger.info(req.rid, req.user.uid, ["check group"]);
								var userProfile = conn.querySync("select * from user where emp_num=?", [req.user.empNum]);
								if (userProfile.error) {
									throw "SQL Error";
								}
								convertKeysToCamelize(userProfile);
								var empGroup = -1; // default band-6
								if (userProfile && userProfile.length > 0) {
									empGroup = Number.parseInt(userProfile[0].empGroup);
								}
								customlogger.info(req.rid, req.user.uid, ["empGroup=", empGroup]);
								customlogger.info(req.rid, req.user.uid, ["courseInfo.courseAllowGroup=", courseInfo.courseAllowGroup]);
								if (empGroup < courseInfo.courseAllowGroup) {
									// end transaction
									conn.endTransactionSync(false);
									//Close the connection
									conn.closeSync();
									var responseJSON = {
										code: "1002",
										message: "user not allow to enroll",
										newEnrolledCourse: null
									};
                                    customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
                                    // 改為 status(200) 相容前端頁面
									res.json(responseJSON);
									return;
								}

								// 4. 這門課跟已經選的課不能衝堂
								customlogger.info(req.rid, req.user.uid, ["check conflict"]);
								customlogger.info(req.rid, req.user.uid, ["req.user.empNum=|" + req.user.empNum + "|"]);
								customlogger.info(req.rid, req.user.uid, ["req.body.courseId=|" + req.body.courseId + "|"]);
								var conflictCourses = conn.querySync("select * from (select * from (select cc.course_id, cc.course_name, cc.course_begin, cc.course_end from enroll ee, course cc where ee.course_id = cc.course_id and ee.emp_num = ?) a, (select dd.course_begin as new_course_begin, dd.course_end as new_course_end from course dd where course_id=?) b ) where (max(new_course_begin, course_begin) < min(new_course_end, course_end))", [req.user.empNum, req.body.courseId]);
								if (conflictCourses.error) {
									throw "SQL Error";
								}
								customlogger.info(req.rid, req.user.uid, [JSON.stringify(conflictCourses)]);

								if (conflictCourses && conflictCourses.length > 0) {
									// end transaction
									conn.endTransactionSync(false);
									//Close the connection
									conn.closeSync();
									var responseJSON = {
										code: "1003",
										message: "user enrolled course time conflict",
										newEnrolledCourse: null
									};
                                    customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
                                    // 改為 status(200) 相容前端頁面
									res.json(responseJSON);
									return;

								} else {

									// 正常加選
									// 沒有選同一門課，嘗試加選
									customlogger.info(req.rid, req.user.uid, ["L201 pass validation, try to enroll course: courseID, empNum", req.body.courseId, req.user.empNum]);

									var result1 = conn.querySync("insert into enroll (course_id, emp_num, last_mod_user, last_mod_ts) values (?, ?, ?, ?)", [req.body.courseId, req.user.empNum, req.user.empNum, currentTs()]);
									if (result1.error) {
										customlogger.info(req.rid, req.user.uid, ["insert into enroll (course_id, emp_num, last_mod_user, last_mod_ts) values (?, ?, ?, ?)", req.body.courseId, req.user.empNum, req.user.empNum, currentTs()]);
										customlogger.info(req.rid, req.user.uid, ["SQL Error", result1]);
										throw "SQL Error";
									}
									customlogger.info(req.rid, req.user.uid, ["result1=", result1]);
									var result2 = conn.querySync("insert into enroll_hist (enroll_id , course_id , emp_num , last_mod_ts , last_mod_user , enroll_action) values (null, ?, ?, ?, ?, ?)", [req.body.courseId, req.user.empNum, currentTs(), req.user.empNum, "enroll"]);
									if (result2.error) {
										customlogger.info(req.rid, req.user.uid, ["insert into enroll_hist (enroll_id , course_id , emp_num , last_mod_ts , last_mod_user , enroll_action) values (null, ?, ?, ?, ?, ?)", req.body.courseId, req.user.empNum, currentTs(), req.user.empNum, "enroll"]);
										customlogger.info(req.rid, req.user.uid, ["SQL Error", result2]);
										throw "SQL Error";
									}
									var result3 = conn.querySync("update course set course_enrolled_num = course_enrolled_num+1 where course_id=?", [req.body.courseId]);
									if (result3.error) {
										customlogger.info(req.rid, req.user.uid, ["update course set course_enrolled_num = course_enrolled_num+1 where course_id=?", req.body.courseId]);
										customlogger.info(req.rid, req.user.uid, ["SQL Error", result3]);
										throw "SQL Error";
									}

									conn.commitTransaction(function(err4) {
										if (err4) {
											//could not begin a transaction for some reason.
											customlogger.info(req.rid, req.user.uid, [err4]);
											var isRollback = true;
											conn.endTransactionSync(isRollback);
											conn.closeSync();
											var responseJSON = {
												code: "9900",
												message: "system error",
												newEnrolledCourse: null
											};
											customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
											res.status(400).json(responseJSON);
											return;
										}
										//blocks until the query is completed and all data has been acquired
										rows = conn.querySync("select e.enroll_id, e.emp_num, c.* from enroll e, course c where e.course_id = c.course_id and e.emp_num=? and c.course_id=?", [req.user.empNum, req.body.courseId]);
										if (rows.error) {
											throw "SQL Error";
										}
										convertKeysToCamelize(rows);

										// customlogger.info(req.rid, req.user.uid, [rows);
										// end transaction
										var isRollback = false;
										conn.endTransactionSync(isRollback);
										//Close the connection
										conn.closeSync();
										var responseJSON = {
											code: "0000",
											message: "success",
											newEnrolledCourse: rows
										};
										customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
										res.json(responseJSON);
										return;

									});

								}

							} else {
								// 查無此課程
								// end transaction
								var isRollback = true;
								conn.endTransactionSync(isRollback);
								//Close the connection
								conn.closeSync();
								var responseJSON = {
									code: "1005",
									message: "no course found",
									newEnrolledCourse: null
								};
								customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
								res.status(400).json(responseJSON);
								return;
							}

						} catch (err) {
							customlogger.info(req.rid, req.user.uid, ["error=", JSON.stringify(err)]);
							var isRollback = true;
							conn.endTransactionSync(isRollback);
							//Close the connection
							conn.closeSync();
							var responseJSON = {
								code: "9900",
								message: "system error",
								newEnrolledCourse: null
							};
							customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
							res.status(400).json(responseJSON);
							return;
						}
					});
				});
			} catch (mainException) {
				customlogger.info(req.rid, req.user.uid, ["error=", JSON.stringify(mainException)]);
				var responseJSON = {
					code: "9900",
					message: "system error",
					newEnrolledCourse: null
				};
				customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
				res.status(400).json(responseJSON);
				return;
			}
		}
	);

	router.delete("/unenroll",
		function(req, res) {
			// paramater check
			if (!req.body.courseId) {
				var responseJSON = {
					code: "9901",
					message: "input paramater error",
					unEnrolledCourse: null
				};
				customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
				res.status(400).json(responseJSON);
				return;
			}
			// time window check
			var nowTimeStamp = Date.now();
			if (nowTimeStamp < enrollAvaiableBegin || nowTimeStamp > enrollAvaiableEnd) {
				var responseJSON = {
					code: "1106",
					message: "enroll/unenroll time window is closed.",
					unEnrolledCourse: null
				};
				customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
				res.json(responseJSON);
				return;
			}
			try {
				ibmdb.open(cn, function(err, conn) {
					if (err) {
						customlogger.info(req.rid, req.user.uid, ["error=", JSON.stringify(err)]);
						conn.closeSync();
						var responseJSON = {
							code: "9900",
							message: "system error",
							unEnrolledCourse: null
						};
						customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
						res.status(400).json(responseJSON);
						return;
					}
					conn.beginTransaction(function(err2) {
						if (err2) {
							//could not begin a transaction for some reason.
							customlogger.info(req.rid, req.user.uid, ["error=", JSON.stringify(err2)]);
							var isRollback = true;
							conn.endTransactionSync(true);
							conn.closeSync();
							var responseJSON = {
								code: "9900",
								message: "system error",
								unEnrolledCourse: null
							};
							customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
							res.status(400).json(responseJSON);
							return;
						}
						try {
							var rows = conn.querySync("select e.enroll_id, e.emp_num, c.* from enroll e, course c where e.course_id = c.course_id and e.emp_num=? and c.course_id=?", [req.user.empNum, req.body.courseId]);
							if (rows.error) {
								customlogger.info(req.rid, req.user.uid, [rows.error]);
								throw "SQL Error";
							}
							convertKeysToCamelize(rows);
							if (rows && rows.length == 0) {
								var isRollback = true;
								conn.endTransactionSync(isRollback);
								conn.closeSync();
								var responseJSON = {
									code: "0001",
									message: "already unenrolled.",
									unEnrolledCourse: rows
								};
								customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
								res.json(responseJSON);
								return;
							} else {

                                customlogger.info(req.rid, req.user.uid, ["L301 try to unenroll a user"]);

								var result1 = conn.querySync("delete from enroll where course_id=? and emp_num=?", [req.body.courseId, req.user.empNum]);
								if (result1.error) {
									customlogger.info(req.rid, req.user.uid, ["delete from enroll where course_id=? and emp_num=?", req.body.courseId, req.user.empNum]);
									customlogger.info(req.rid, req.user.uid, ["SQL Error", result1]);
									throw "SQL Error";
								}
								var result2 = conn.querySync("insert into enroll_hist (enroll_id , course_id , emp_num , last_mod_ts , last_mod_user , enroll_action) values (null, ?, ?, ?, ?, ?)", [req.body.courseId, req.user.empNum, currentTs(), req.user.empNum, "unenroll"]);
								if (result2.error) {
									customlogger.info(req.rid, req.user.uid, ["insert into enroll_hist (enroll_id , course_id , emp_num , last_mod_ts , last_mod_user , enroll_action) values (null, ?, ?, ?, ?, ?)", req.body.courseId, req.user.empNum, currentTs(), req.user.empNum, "unenroll"]);
									customlogger.info(req.rid, req.user.uid, ["SQL Error", result2]);
									throw "SQL Error";
								}
								var result3 = conn.querySync("update course set course_enrolled_num = course_enrolled_num-1 where course_id=?", [req.body.courseId]);
								if (result3.error) {
									customlogger.info(req.rid, req.user.uid, ["update course set course_enrolled_num = course_enrolled_num-1 where course_id=?", req.body.courseId]);
									customlogger.info(req.rid, req.user.uid, ["SQL Error", result3]);
									throw "SQL Error";
								}
								// if no error occur
								var isRollback = false;
								conn.commitTransactionSync();
								conn.endTransactionSync(isRollback);
								conn.closeSync();
								var responseJSON = {
									code: "0000",
									message: "success",
									unEnrolledCourse: rows
								};
								customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
								res.json(responseJSON);
								return;
							}
						} catch (err) {
							customlogger.info(req.rid, req.user.uid, ["error=", JSON.stringify(err)]);
							var isRollback = true;
							conn.endTransactionSync(isRollback);
							conn.closeSync();
							var responseJSON = {
								code: "9900",
								message: "system error",
								unEnrolledCourse: null
							};
							customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
							res.status(400).json(responseJSON);
							return;
						}
					});
				});
			} catch (mainException) {
				customlogger.info(req.rid, req.user.uid, ["error=", JSON.stringify(mainException)]);
				var responseJSON = {
					code: "9900",
					message: "system error",
					unEnrolledCourse: null
				};
				customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
				res.status(400).json(responseJSON);
				return;
			}
		}
	);

	////////////////////////////////////////////////////////
	// question feature
	////////////////////////////////////////////////////////

	router.get("/getQuestion",
		function(req, res) {
			// paramater check
			if (!req.query.questionId) {
				var responseJSON = {
					code: "9901",
					message: "input paramater error"
				};
				customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
				res.status(400).json(responseJSON);
				return;
			}
			try {
				ibmdb.open(cn, function(err, conn) {
					if (err) {
						customlogger.info(req.rid, req.user.uid, ["error=", JSON.stringify(err)]);
						conn.closeSync();
						var responseJSON = {
							code: "9900",
							message: "system error"
						};
						customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
						res.status(400).json(responseJSON);
						return;
					}
					// business logic begin
					try {
						var rows = conn.querySync("select * from question where emp_num=? and question_id=?", [req.user.empNum, req.query.questionId]);
						if (rows.error) {
							throw "SQL Error";
						}
						convertKeysToCamelize(rows);
						customlogger.info(req.rid, req.user.uid, [rows]);
						var answer = null;
						if (rows && rows.length > 0) {
							answer = rows[0].answer;
						}
						conn.closeSync();
						var responseJSON = {
							code: "0000",
							message: "success",
							questionId: req.query.questionId,
							answer: answer
						};
						customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
						res.json(responseJSON);
					} catch (err) {
						customlogger.info(req.rid, req.user.uid, ["error=", JSON.stringify(err)]);
						conn.closeSync();
						var responseJSON = {
							code: "9900",
							message: "system error"
						};
						customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
						res.status(400).json(responseJSON);
						return;
					}
				});
			} catch (mainException) {
				customlogger.info(req.rid, req.user.uid, ["error=", JSON.stringify(mainException)]);
				var responseJSON = {
					code: "9900",
					message: "system error"
				};
				customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
				res.status(400).json(responseJSON);
				return;
			}
		}
	);

	router.post("/updateQuestion",
		function(req, res) {
			// paramater check
			if (!req.body.questionId || !req.body.answer) {
				var responseJSON = {
					code: "9901",
					message: "input paramater error"
				};
				customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
				res.status(400).json(responseJSON);
				return;
			}
			try {
				ibmdb.open(cn, function(err, conn) {
					if (err) {
						customlogger.info(req.rid, req.user.uid, ["error=", JSON.stringify(err)]);
						conn.closeSync();
						var responseJSON = {
							code: "9900",
							message: "system error"
						};
						customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
						res.status(400).json(responseJSON);
						return;
					}
					conn.beginTransaction(function(err2) {
						if (err2) {
							//could not begin a transaction for some reason.
							customlogger.info(req.rid, req.user.uid, ["error=", JSON.stringify(err2)]);
							var isRollback = true;
							conn.endTransactionSync(true);
							conn.closeSync();
							var responseJSON = {
								code: "9900",
								message: "system error"
							};
							customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
							res.status(400).json(responseJSON);
							return;
						}
						// business logic begin
						try {

							//blocks until the query is completed and all data has been acquired
							var rows = conn.querySync("select * from question where emp_num=? and question_id=?", [req.user.empNum, req.body.questionId]);
							if (rows.error) {
								throw "SQL Error";
							}
							convertKeysToCamelize(rows);

							if (rows && rows.length == 0) {
                                // insert
                                customlogger.info(req.rid, req.user.uid, ["L401 try to add a choice"]);
								var result1 = conn.querySync("INSERT INTO QUESTION (EMP_NUM, QUESTION_ID, ANSWER) VALUES (?, ?, ?)", [req.user.empNum, req.body.questionId, req.body.answer]);
								if (result1.error) {
									throw "SQL Error";
								}
							} else {
                                customlogger.info(req.rid, req.user.uid, ["L402 try to change a choice"]);
								var result2 = conn.querySync("update QUESTION set ANSWER=? where emp_num=? and question_id=?", [req.body.answer, req.user.empNum, req.body.questionId]);
								if (result2.error) {
									throw "SQL Error";
								}
							}
							conn.commitTransaction(function(err4) {
								if (err4) {
									//could not begin a transaction for some reason.
									customlogger.info(req.rid, req.user.uid, [err4]);
									var isRollback = true;
									conn.endTransactionSync(isRollback);
									conn.closeSync();
									var responseJSON = {
										code: "9900",
										message: "system error"
									};
									customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
									res.status(400).json(responseJSON);
									return;
								}
								var isRollback = false;
								conn.endTransactionSync(isRollback);
								conn.closeSync();
								var responseJSON = {
									code: "0000",
									message: "success"
								};
								customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
								res.json(responseJSON);
								return;
							});
						} catch (exception) {
							//could not begin a transaction for some reason.
							customlogger.info(req.rid, req.user.uid, ["error=", JSON.stringify(exception)]);
							var isRollback = true;
							conn.endTransactionSync(isRollback);
							conn.closeSync();
							var responseJSON = {
								code: "9900",
								message: "system error"
							};
							customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
							res.status(400).json(responseJSON);
							return;
						}
					});
				});
			} catch (mainException) {
				customlogger.info(req.rid, req.user.uid, ["error=", JSON.stringify(mainException)]);
				var responseJSON = {
					code: "9900",
					message: "system error"
				};
				customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
				res.status(400).json(responseJSON);
				return;
			}
		}
	);

	////////////////////////////////////////////////////////
	// admin feature
	////////////////////////////////////////////////////////

	router.get("/univadmin/enrollList",
		function(req, res) {

			var isPrivilege = false;

			for(var i=0; i<adminList.length; i++) {
				var currentUser = req.user.empNum;
				if(adminList[i] == currentUser) {
					isPrivilege = true;
					break;
				}
			}

			if(!isPrivilege) {
				var responseJSON = {
					code: "9902",
					message: "cannot auth you",
					enrollList: null
				};
				customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
				res.status(400).json(responseJSON);
				return;
			}

			// req.user should be set from the token validation
			ibmdb.open(cn, function(err, conn) {
				if (err) {
					customlogger.info(req.rid, req.user.uid, ["error=", JSON.stringify(err)]);
					conn.closeSync();
					var responseJSON = {
						code: "9900",
						message: "system error",
						enrollList: null
					};
					customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
					res.status(400).json(responseJSON);
					return;
				}
				//blocks until the query is completed and all data has been acquired
				var rows = conn.querySync("select e.enroll_id, e.emp_num, e.last_mod_ts, c.* from enroll e, course c where e.course_id = c.course_id and e.emp_num=?", [req.query.queryEmpNum]);
				convertKeysToCamelize(rows);

				var histRows = conn.querySync("select e.*, c.course_name from enroll_hist e, course c where e.course_id = c.course_id and e.emp_num=? order by last_mod_ts asc", [req.query.queryEmpNum]);
				convertKeysToCamelize(histRows);

				//blocks until the query is completed and all data has been acquired
				var backupRows = conn.querySync("select emp_num, backup_course, backup_num from user where emp_num=?", [req.query.queryEmpNum]);
				convertKeysToCamelize(backupRows);

				var backupCourseId = null;
				var backupNum = 0;
				if (backupRows && backupRows.length > 0) {
					backupCourseId = backupRows[0].backupCourse;
					backupNum = backupRows[0].backupNum;
				}

				conn.closeSync();
				var responseJSON = {
					code: "0000",
					message: "success",
					enrollList: rows,
					hist: histRows,
					backupCourseId: backupCourseId,
					backupNum: backupNum
				};
				customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
				res.json(responseJSON);
			});
		}
	);

	router.get("/univadmin/course/enrollList",
		function(req, res) {

			var isPrivilege = false;

			for(var i=0; i<adminList.length; i++) {
				var currentUser = req.user.empNum;
				if(adminList[i] == currentUser) {
					isPrivilege = true;
					break;
				}
			}

			if(!isPrivilege) {
				var responseJSON = {
					code: "9902",
					message: "cannot auth you",
					enrollList: null
				};
				customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
				res.status(400).json(responseJSON);
				return;
			}

			// req.user should be set from the token validation
			ibmdb.open(cn, function(err, conn) {
				if (err) {
					customlogger.info(req.rid, req.user.uid, ["error=", JSON.stringify(err)]);
					conn.closeSync();
					var responseJSON = {
						code: "9900",
						message: "system error",
						enrollList: null
					};
					customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
					res.status(400).json(responseJSON);
					return;
				}
				//blocks until the query is completed and all data has been acquired
				var rows = conn.querySync("select e.enroll_id, e.emp_num, e.last_mod_ts, c.* from enroll e, course c where e.course_id = c.course_id and e.course_id=?", [req.query.queryCourseId]);
				convertKeysToCamelize(rows);

				var backUsers = conn.querySync("select * from user where backup_course=? order by backup_ts asc", [req.body.courseId]);
				convertKeysToCamelize(backUsers);

				conn.closeSync();
				var responseJSON = {
					code: "0000",
					message: "success",
					enrollList: rows,
					backupList: backUsers
				};
				customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
				res.json(responseJSON);
			});
		}
	);


	router.post("/univadmin/enroll",
		function(req, res) {

			var isPrivilege = false;

			for (var i = 0; i < adminList.length; i++) {
				var currentUser = req.user.empNum;
				if (adminList[i] == currentUser) {
					isPrivilege = true;
					break;
				}
			}

			if (!isPrivilege) {
				var responseJSON = {
					code: "9902",
					message: "cannot auth you",
					enrollList: null
				};
				customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
				res.status(400).json(responseJSON);
				return;
			}

			if (!req.body.courseId) {
				var responseJSON = {
					code: "9901",
					message: "input paramater error",
					newEnrolledCourse: null
				};
				customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
				res.status(400).json(responseJSON);
				return;
			}

			try {
				ibmdb.open(cn, function(err, conn) {
					if (err) {
						customlogger.info(req.rid, req.user.uid, ["error=", JSON.stringify(err)]);
						conn.closeSync();
						var responseJSON = {
							code: "9900",
							message: "system error",
							newEnrolledCourse: null
						};
						customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
						res.status(400).json(responseJSON);
						return;
					}
					conn.beginTransaction(function(err2) {
						if (err2) {
							//could not begin a transaction for some reason.
							customlogger.info(req.rid, req.user.uid, ["error=", JSON.stringify(err2)]);
							conn.endTransactionSync(true);
							conn.closeSync();
							var responseJSON = {
								code: "9900",
								message: "system error",
								newEnrolledCourse: null
							};
							customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
							res.status(400).json(responseJSON);
							return;
						}
						try {
							// 搜尋課程資料
							customlogger.info(req.rid, req.user.uid, ["checking enrolled course info"]);
							var rows = conn.querySync("select c.*, e.* from (select * from course where course_id=?) c left join (select * from enroll where emp_num=?) e on e.course_id = c.course_id", [req.body.courseId, req.body.queryEmpNum]);
							if (rows.error) {
								throw "SQL Error";
							}
							customlogger.info(req.rid, req.user.uid, [JSON.stringify(rows)]);
							convertKeysToCamelize(rows);
							if (rows && rows.length > 0) {

								var courseInfo = rows[0];
								// 1. 沒有選過同一門課
								// != null 代表已經選過課程
								customlogger.info(req.rid, req.user.uid, ["check duplicate"]);
								if (courseInfo.enrollId != null) {
									// end transaction
									conn.endTransactionSync(false);
									//Close the connection
									conn.closeSync();
									var responseJSON = {
										code: "0001",
										message: "already enrolled.",
										newEnrolledCourse: rows
									};
									customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
									res.json(responseJSON);
									return;
								}

								// 2. 這門課要有空位
								// 如果 max >= enrolled num，代表已經額滿
								customlogger.info(req.rid, req.user.uid, ["check open seats"]);
								customlogger.info(req.rid, req.user.uid, ["courseInfo=", JSON.stringify(courseInfo)]);
								customlogger.info(req.rid, req.user.uid, ["courseInfo.courseEnrolledNum=", courseInfo.courseEnrolledNum]);
								customlogger.info(req.rid, req.user.uid, ["courseInfo.courseMaxSeat=", courseInfo.courseMaxSeat]);
								if (Number.parseInt(courseInfo.courseEnrolledNum) >= Number.parseInt(courseInfo.courseMaxSeat)) {
									// end transaction
									conn.endTransactionSync(false);
									//Close the connection
									conn.closeSync();
									var responseJSON = {
										code: "1001",
										message: "course not allow to enroll, no open seats",
										newEnrolledCourse: null
									};
									customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
									// 改為 status(200) 相容前端頁面
									res.json(responseJSON);
									return;
								}

								// 3. 學員資格符合
								// 如果 empGroup < 課程限制，則資格不符
								customlogger.info(req.rid, req.user.uid, ["check group"]);
								var userProfile = conn.querySync("select * from user where emp_num=?", [req.body.queryEmpNum]);
								if (userProfile.error) {
									throw "SQL Error";
								}
								convertKeysToCamelize(userProfile);
								var empGroup = -1; // default band-6
								if (userProfile && userProfile.length > 0) {
									empGroup = Number.parseInt(userProfile[0].empGroup);
								}
								customlogger.info(req.rid, req.user.uid, ["empGroup=", empGroup]);
								customlogger.info(req.rid, req.user.uid, ["courseInfo.courseAllowGroup=", courseInfo.courseAllowGroup]);
								if (empGroup < courseInfo.courseAllowGroup) {
									// end transaction
									conn.endTransactionSync(false);
									//Close the connection
									conn.closeSync();
									var responseJSON = {
										code: "1002",
										message: "user not allow to enroll",
										newEnrolledCourse: null
									};
									customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
									// 改為 status(200) 相容前端頁面
									res.json(responseJSON);
									return;
								}

								// 4. 這門課跟已經選的課不能衝堂
								customlogger.info(req.rid, req.user.uid, ["check conflict"]);
								customlogger.info(req.rid, req.user.uid, ["req.body.queryEmpNum=|" + req.body.queryEmpNum + "|"]);
								customlogger.info(req.rid, req.user.uid, ["req.body.courseId=|" + req.body.courseId + "|"]);
								var conflictCourses = conn.querySync("select * from (select * from (select cc.course_id, cc.course_name, cc.course_begin, cc.course_end from enroll ee, course cc where ee.course_id = cc.course_id and ee.emp_num = ?) a, (select dd.course_begin as new_course_begin, dd.course_end as new_course_end from course dd where course_id=?) b ) where (max(new_course_begin, course_begin) < min(new_course_end, course_end))", [req.body.queryEmpNum, req.body.courseId]);
								if (conflictCourses.error) {
									throw "SQL Error";
								}
								customlogger.info(req.rid, req.user.uid, [JSON.stringify(conflictCourses)]);

								if (conflictCourses && conflictCourses.length > 0) {
									// end transaction
									conn.endTransactionSync(false);
									//Close the connection
									conn.closeSync();
									var responseJSON = {
										code: "1003",
										message: "user enrolled course time conflict",
										newEnrolledCourse: null
									};
									customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
									// 改為 status(200) 相容前端頁面
									res.json(responseJSON);
									return;

								} else {

									// 正常加選
									// 沒有選同一門課，嘗試加選
									customlogger.info(req.rid, req.user.uid, ["L201 pass validation, try to enroll course: courseID, empNum", req.body.courseId, req.body.queryEmpNum]);

									var result1 = conn.querySync("insert into enroll (course_id, emp_num, last_mod_user, last_mod_ts) values (?, ?, ?, ?)", [req.body.courseId, req.body.queryEmpNum, req.user.empNum, currentTs()]);
									if (result1.error) {
										customlogger.info(req.rid, req.user.uid, ["insert into enroll (course_id, emp_num, last_mod_user, last_mod_ts) values (?, ?, ?, ?)", req.body.courseId, req.body.queryEmpNum, req.user.empNum, currentTs()]);
										customlogger.info(req.rid, req.user.uid, ["SQL Error", result1]);
										throw "SQL Error";
									}
									customlogger.info(req.rid, req.user.uid, ["result1=", result1]);
									var result2 = conn.querySync("insert into enroll_hist (enroll_id , course_id , emp_num , last_mod_ts , last_mod_user , enroll_action) values (null, ?, ?, ?, ?, ?)", [req.body.courseId, req.body.queryEmpNum, currentTs(), req.user.empNum, "enroll"]);
									if (result2.error) {
										customlogger.info(req.rid, req.user.uid, ["insert into enroll_hist (enroll_id , course_id , emp_num , last_mod_ts , last_mod_user , enroll_action) values (null, ?, ?, ?, ?, ?)", req.body.courseId, req.body.queryEmpNum, currentTs(), req.user.empNum, "enroll"]);
										customlogger.info(req.rid, req.user.uid, ["SQL Error", result2]);
										throw "SQL Error";
									}
									var result3 = conn.querySync("update course set course_enrolled_num = course_enrolled_num+1 where course_id=?", [req.body.courseId]);
									if (result3.error) {
										customlogger.info(req.rid, req.user.uid, ["update course set course_enrolled_num = course_enrolled_num+1 where course_id=?", req.body.courseId]);
										customlogger.info(req.rid, req.user.uid, ["SQL Error", result3]);
										throw "SQL Error";
									}

									conn.commitTransaction(function(err4) {
										if (err4) {
											//could not begin a transaction for some reason.
											customlogger.info(req.rid, req.user.uid, [err4]);
											var isRollback = true;
											conn.endTransactionSync(isRollback);
											conn.closeSync();
											var responseJSON = {
												code: "9900",
												message: "system error",
												newEnrolledCourse: null
											};
											customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
											res.status(400).json(responseJSON);
											return;
										}
										//blocks until the query is completed and all data has been acquired
										rows = conn.querySync("select e.enroll_id, e.emp_num, c.* from enroll e, course c where e.course_id = c.course_id and e.emp_num=? and c.course_id=?", [req.body.queryEmpNum, req.body.courseId]);
										if (rows.error) {
											throw "SQL Error";
										}
										convertKeysToCamelize(rows);

										// customlogger.info(req.rid, req.user.uid, [rows);
										// end transaction
										var isRollback = false;
										conn.endTransactionSync(isRollback);
										//Close the connection
										conn.closeSync();
										var responseJSON = {
											code: "0000",
											message: "success",
											newEnrolledCourse: rows
										};
										customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
										res.json(responseJSON);
										return;

									});

								}

							} else {
								// 查無此課程
								// end transaction
								var isRollback = true;
								conn.endTransactionSync(isRollback);
								//Close the connection
								conn.closeSync();
								var responseJSON = {
									code: "1005",
									message: "no course found",
									newEnrolledCourse: null
								};
								customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
								res.status(400).json(responseJSON);
								return;
							}

						} catch (err) {
							customlogger.info(req.rid, req.user.uid, ["error=", JSON.stringify(err)]);
							var isRollback = true;
							conn.endTransactionSync(isRollback);
							//Close the connection
							conn.closeSync();
							var responseJSON = {
								code: "9900",
								message: "system error",
								newEnrolledCourse: null
							};
							customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
							res.status(400).json(responseJSON);
							return;
						}
					});
				});
			} catch (mainException) {
				customlogger.info(req.rid, req.user.uid, ["error=", JSON.stringify(mainException)]);
				var responseJSON = {
					code: "9900",
					message: "system error",
					newEnrolledCourse: null
				};
				customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
				res.status(400).json(responseJSON);
				return;
			}

		}
	);

	router.delete("/univadmin/unenroll",
		function(req, res) {

			var isPrivilege = false;

			for (var i = 0; i < adminList.length; i++) {
				var currentUser = req.user.empNum;
				if (adminList[i] == currentUser) {
					isPrivilege = true;
					break;
				}
			}

			if (!isPrivilege) {
				var responseJSON = {
					code: "9902",
					message: "cannot auth you",
					enrollList: null
				};
				customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
				res.status(400).json(responseJSON);
				return;
			}

			// paramater check
			if (!req.body.courseId) {
				var responseJSON = {
					code: "9901",
					message: "input paramater error",
					unEnrolledCourse: null
				};
				customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
				res.status(400).json(responseJSON);
				return;
			}

			try {
				ibmdb.open(cn, function(err, conn) {
					if (err) {
						customlogger.info(req.rid, req.user.uid, ["error=", JSON.stringify(err)]);
						conn.closeSync();
						var responseJSON = {
							code: "9900",
							message: "system error",
							unEnrolledCourse: null
						};
						customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
						res.status(400).json(responseJSON);
						return;
					}
					conn.beginTransaction(function(err2) {
						if (err2) {
							//could not begin a transaction for some reason.
							customlogger.info(req.rid, req.user.uid, ["error=", JSON.stringify(err2)]);
							var isRollback = true;
							conn.endTransactionSync(true);
							conn.closeSync();
							var responseJSON = {
								code: "9900",
								message: "system error",
								unEnrolledCourse: null
							};
							customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
							res.status(400).json(responseJSON);
							return;
						}
						try {
							var rows = conn.querySync("select e.enroll_id, e.emp_num, c.* from enroll e, course c where e.course_id = c.course_id and e.emp_num=? and c.course_id=?", [req.body.queryEmpNum, req.body.courseId]);
							if (rows.error) {
								customlogger.info(req.rid, req.user.uid, [rows.error]);
								throw "SQL Error";
							}
							convertKeysToCamelize(rows);
							if (rows && rows.length == 0) {
								var isRollback = true;
								conn.endTransactionSync(isRollback);
								conn.closeSync();
								var responseJSON = {
									code: "0001",
									message: "already unenrolled.",
									unEnrolledCourse: rows
								};
								customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
								res.json(responseJSON);
								return;
							} else {

								customlogger.info(req.rid, req.user.uid, ["L301 try to unenroll a user"]);

								var result1 = conn.querySync("delete from enroll where course_id=? and emp_num=?", [req.body.courseId, req.body.queryEmpNum]);
								if (result1.error) {
									customlogger.info(req.rid, req.user.uid, ["delete from enroll where course_id=? and emp_num=?", req.body.courseId, req.body.queryEmpNum]);
									customlogger.info(req.rid, req.user.uid, ["SQL Error", result1]);
									throw "SQL Error";
								}
								var result2 = conn.querySync("insert into enroll_hist (enroll_id , course_id , emp_num , last_mod_ts , last_mod_user , enroll_action) values (null, ?, ?, ?, ?, ?)", [req.body.courseId, req.body.queryEmpNum, currentTs(), req.user.empNum, "unenroll"]);
								if (result2.error) {
									customlogger.info(req.rid, req.user.uid, ["insert into enroll_hist (enroll_id , course_id , emp_num , last_mod_ts , last_mod_user , enroll_action) values (null, ?, ?, ?, ?, ?)", req.body.courseId, req.body.queryEmpNum, currentTs(), req.user.empNum, "unenroll"]);
									customlogger.info(req.rid, req.user.uid, ["SQL Error", result2]);
									throw "SQL Error";
								}
								var result3 = conn.querySync("update course set course_enrolled_num = course_enrolled_num-1 where course_id=?", [req.body.courseId]);
								if (result3.error) {
									customlogger.info(req.rid, req.user.uid, ["update course set course_enrolled_num = course_enrolled_num-1 where course_id=?", req.body.courseId]);
									customlogger.info(req.rid, req.user.uid, ["SQL Error", result3]);
									throw "SQL Error";
								}
								// if no error occur
								var isRollback = false;
								conn.commitTransactionSync();
								conn.endTransactionSync(isRollback);
								conn.closeSync();
								var responseJSON = {
									code: "0000",
									message: "success",
									unEnrolledCourse: rows
								};
								customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
								res.json(responseJSON);
								return;
							}
						} catch (err) {
							customlogger.info(req.rid, req.user.uid, ["error=", JSON.stringify(err)]);
							var isRollback = true;
							conn.endTransactionSync(isRollback);
							conn.closeSync();
							var responseJSON = {
								code: "9900",
								message: "system error",
								unEnrolledCourse: null
							};
							customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
							res.status(400).json(responseJSON);
							return;
						}
					});
				});
			} catch (mainException) {
				customlogger.info(req.rid, req.user.uid, ["error=", JSON.stringify(mainException)]);
				var responseJSON = {
					code: "9900",
					message: "system error",
					unEnrolledCourse: null
				};
				customlogger.info(req.rid, req.user.uid, ["response JSON:", JSON.stringify(responseJSON)]);
				res.status(400).json(responseJSON);
				return;
			}

		}
	);

	return router;
};

function enrollSingleCourse(empNum, modifier, courseIdToEnroll, conn) {

	console.log("entry enrollSingleCourse");

	var currentTimestamp = currentTs();

	// add enroll record
	var result1 = conn.querySync("insert into enroll (course_id, emp_num, last_mod_user, last_mod_ts) values (?, ?, ?, ?)", [courseIdToEnroll, empNum, modifier, currentTimestamp]);

	// add history record
	insertEnrollHistByEnroll(courseIdToEnroll, empNum, modifier, "enroll", conn);

	// update course open seats
	var result2 = conn.querySync("update course set course_enrolled_num = course_enrolled_num+1 where course_id=?", [courseIdToEnroll]);

}

function unEnrollSingleCourse(empNum, modifier, courseIdToUnenroll, conn) {

	console.log("entry unEnrollSingleCourse");

	// unenroll course
	var result1 = conn.querySync("delete from enroll where course_id=? and emp_num=?", [courseIdToUnenroll, empNum]);

	// add to history
	insertEnrollHistByEnroll(courseIdToUnenroll, empNum, modifier, "unenroll", conn);

	// update course open seats
	var result2 = conn.querySync("update course set course_enrolled_num = course_enrolled_num-1 where course_id=?", [courseIdToUnenroll]);

	// check unenroll course has user in waiting list
	// auto enroll first user
	var waitingList = conn.querySync("select emp_num, backup_course from user where backup_course=? order by backup_num asc", [courseIdToUnenroll]);

	console.log("waitingList=", waitingList);
	convertKeysToCamelize(waitingList);

	if (waitingList && waitingList.length > 0) {
		var firstWaiting = waitingList[0];
		autoEnroll(firstWaiting.empNum, courseIdToUnenroll, conn);
	}

}

function autoUnEnrollConflictedCourse(empNum, courseIdToCheckConflict, conn) {

	// un-enroll specific user's course which conflict with specific course's time
	// steps:
	// 1. check conflict courses
	// 2. unenroll all conflicted courses
	// 3. check each unenroll course has waiting users
	// 4. auto enroll

	console.log("entry autoUnEnrollConflictedCourse");

	// check conflict courses
	var conflictCourses = conn.querySync("select distinct course_id from (select * from (select cc.course_id, cc.course_name, cc.course_begin, cc.course_end from enroll ee, course cc where ee.course_id = cc.course_id and ee.emp_num = ?) a, (select dd.course_begin as new_course_begin, dd.course_end as new_course_end from course dd where course_id=?) b ) where ((new_course_begin >= course_begin and new_course_begin<=course_end) or (new_course_end >= course_begin and new_course_end<=course_end))", [empNum, courseIdToCheckConflict]);
	convertKeysToCamelize(conflictCourses);
	// unenroll all conflicted courses
	// may 1 or more course, mutiple duration
	if (conflictCourses && conflictCourses.length > 0) {
		console.log("user " + empNum + " has conflict courses");
		for (var i = 0; i < conflictCourses.length; i++) {
			var conflictedCourseId = conflictCourses[i].courseId;
			unEnrollSingleCourse(empNum, "system", conflictedCourseId, conn);
		}
	} else {
		console.log("user " + empNum + " has no conflict courses");
	}

}

function autoEnroll(empNum, courseIdToEnroll, conn) {

	// steps:
	// 1. auto unenroll conflict courses
	// 2. enroll course
	// 3. add to history
	// 4. clean backup
	// 5. update all backup number

	console.log("entry autoEnroll");

	var modifier = "system";

	// auto unenroll conflict courses
	autoUnEnrollConflictedCourse(empNum, courseIdToEnroll, conn);

	// enroll course
	enrollSingleCourse(empNum, modifier, courseIdToEnroll, conn);

	// clean backup
	var result2 = conn.querySync("update user set backup_num=null, backup_course=null, backup_ts=null where backup_course=? and emp_num=?", [courseIdToEnroll, empNum]);
	insertEnrollHistByBackup(courseIdToEnroll, empNum, modifier, "un-waiting", conn);

	// update all backup number
	updatebackupNum(courseIdToEnroll, conn);

}


function updateBackupCourse() {
	return "update user set backup_num=null, backup_course=null, backup_ts=null where backup_course=? and emp_num=?";
}

function updatebackupNum(courseId, conn) {
	console.log("=======cal new backup========");
	var backupNum = conn.querySync("select * from user where backup_course=? order by backup_ts asc", [courseId]);
	//convertKeysToCamelize(backupNum);
	console.log(courseId);
	// for(var i=0; i<backupNum.length; i++) {
	//     var arr = Object.keys(backup_Num[i]);
	//     for(var j=0; j<arr.length; j++) {
	//         if(backupNum[i][arr[j]]) {
	//             backupNum[i][arr[j]] = eval('"' + backupNum[i][arr[j]] + '"');
	//         }
	//     }
	// }
	if (backupNum.length != 0) {
		for (var i = 0; i < backupNum.length; i++) {
			var courseInfo = backupNum[i];
			// var number = parseInt(courseInfo.BACKUP_NUM)-1;
			var number = (i + 1);
			courseInfo.BACKUP_NUM = number;
			var updatebackupNum = conn.querySync("update user set backup_num=? where backup_course=? and emp_num=?", [courseInfo.BACKUP_NUM, courseInfo.BACKUP_COURSE, courseInfo.EMP_NUM]);
			insertEnrollHistByBackup(courseInfo.BACKUP_COURSE, courseInfo.EMP_NUM, 'system', "change-number", conn);
		}

	}
}

function insertHis(enrollId, courseId, empNum, lastUser, action, conn) {
	var updateHis = conn.querySync("insert into enroll_hist (enroll_id , course_id , emp_num , last_mod_ts , last_mod_user , enroll_action) values (?,?,?,current_timestamp,?,?)", [enrollId, courseId, empNum, lastUser, action]);
	console.log("insertHis result:", updateHis);
}

function insertEnrollHistByBackup(courseId, empNum, lastUser, action, conn) {
	var updateHis = conn.querySync("insert into enroll_hist (enroll_id , course_id , emp_num , last_mod_ts , last_mod_user , enroll_action) values (null, ?, ?, ?, ?, ?)", [courseId, empNum, currentTs(), lastUser, action]);
	console.log("insertHis result:", updateHis);
}

function insertEnrollHistByEnroll(courseId, empNum, lastUser, action, conn) {
	// leave enroll id as null, threat 2 enroll as 1 record
	console.log("enroll_id , course_id , emp_num , last_mod_ts , last_mod_user , enroll_action", courseId, empNum, currentTs(), lastUser, action);
	var updateHis = conn.querySync("insert into enroll_hist (enroll_id , course_id , emp_num , last_mod_ts , last_mod_user , enroll_action) values (null, ?, ?, ?, ?, ?)", [courseId, empNum, currentTs(), lastUser, action]);
	console.log("insertHis result:", updateHis);
}