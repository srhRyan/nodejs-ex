var express = require('express');
var router = express.Router();
var jwt = require("jsonwebtoken");

var relayHandler = function relayHandler(req, res) {
    var relayState = req.query && req.query.RelayState || req.body && req.body.RelayState; 
    var hashQuery = relayState && relayState.match(/^\#/) && ("/app"+relayState) || relayState  || "/"; 
    res.redirect(hashQuery);
};

module.exports = function(app, config, passport) {

    var currentTs = function() {
        // generate timestamp
        var now = new Date;
        var utc_timestamp = Date.UTC(now.getUTCFullYear(),now.getUTCMonth(), now.getUTCDate() , 
            now.getUTCHours(), now.getUTCMinutes(), now.getUTCSeconds(), now.getUTCMilliseconds()) + 8*60*60*1000;
        var twTimestamp = new Date(utc_timestamp).toJSON().replace(/T/i, ' ').replace(/Z/i, '');
        return twTimestamp;
    };

    var customlogger = {
        info : function(sessionId, sessionSn, loginfo) {
            var finalPrintContent = '';
            for(var i=0; i<loginfo.length; i++) {
                var printInfo = loginfo[i];
                if(typeof loginfo[i] === 'object') {
                    printInfo = JSON.stringify(loginfo[i]);
                }
                finalPrintContent += printInfo;
            }
            var now = currentTs();
            console.log('[' + now + '|' + sessionId + '|' + sessionSn + '] ' + finalPrintContent);
        }
    };

    router.get("/accessDenied",   function(req, res) { res.render("error", {message: "Access denied", error: {}}); }   );
    
 // Main page requires an authenticated user    
    router.get("/", 
            function(req, res) {
                if (req.user) {

                    if(req.sessionID && req.user.uid) {
                        customlogger.info(req.sessionID, req.user.uid, ["L000 ","redirect to index success"]);
                        customlogger.info(req.sessionID, req.user.uid, [JSON.stringify(req.user)]);
                    } else {
                        customlogger.info("nosession", "noid", ["L000 ","redirect to index success with warning"]);
                    }

                    res.render("index", {title: 'SSO Demo', user : req.user});
                } else {
                    res.redirect('/login');
                }
            }
    );

    router.get("/s/c", 
            function(req, res) {
                res.render("qr_course_list", {user : req.query.u});
            }
    );

    router.get("/univ_admin", 
            function(req, res) {
                if (req.user) {
                    if(req.user.id == '027267858' || req.user.id == 'AVNBTG858' || req.user.id == 'ZZ02FV672') {
                        res.render("univ_admin", {title: 'SSO Demo', user : req.user});
                    } else {
                        res.redirect('/');
                    }
                } else {
                    res.redirect('/login');
                }
            }
    );

    router.get("/univ_admin_course", 
            function(req, res) {
                if (req.user) {
                    if(req.user.id == '027267858' || req.user.id == 'AVNBTG858' || req.user.id == 'ZZ02FV672') {
                        res.render("univ_admin_course", {title: 'SSO Demo', user : req.user});
                    } else {
                        res.redirect('/');
                    }
                } else {
                    res.redirect('/login');
                }
            }
    );

 // JWT example - issue token    
    router.get("/getToken", 
            function(req, res) {
                if (req.user) {
                    // Generate JWT - set expire to 3 minutes to test token expiration 
                    // display name is encoded into the token as an example, real application usually should not need it here
                    // console.log("req.user");
                    // console.log(req.user);
                    // res.setHeader("Access-Control-Allow-Origin",'*');
                    res.json({success: true,
                              token: jwt.sign({uid:req.user.uid, displayName: req.user.displayName, empNum: req.user.id}, config.passport.sessionSecret, {expiresIn: 2*3600 })  
                        });
                } else {
                    res.json({token: null});
                }
            }
    );    
// // Example of a resource not requiring authentication
//     router.get("/open", 
//             function(req, res) {
//               res.render("index", {title: 'SSO Demo', user : req.user || {displayName: "Anonymous" , blueGroups: [] } });
//             }
//     );
    
 // Start SAML login process
    router.get("/login",
       passport.authenticate(config.passport.strategy, {/*successRedirect : "/", */failureRedirect : "/accessDenied"}),
       relayHandler);

 // Process callback from IDP for login
 router.post('/login/callback/postResponse',
 // !!! Important !!! Response XML structure needs to be tweaked to pass signature validation
       passport.patchResponse(),
       passport.authenticate(config.passport.strategy, {/*successRedirect : "/", */failureRedirect : "/accessDenied"}),
       relayHandler);    

    return router;
};
