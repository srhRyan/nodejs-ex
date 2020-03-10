var SamlStrategy = require('passport-saml').Strategy;
var samlSignature = require('./samlSignature');


module.exports = function (passport, config) {
    passport.serializeUser(function(user, done) {
        done(null, JSON.stringify(user));
    });

    passport.deserializeUser(function(user, done) {
        done(null, JSON.parse(user));
    });

    var verifySaml = function(profile, done) {
        var blueGroups = config.passport.saml.attributesAsJson && config.passport.saml.attributesAsJson.blueGroups && 
                            profile.blueGroups && JSON.parse(profile.blueGroups) || 
                        profile.blueGroups || []; 
        var user = {
                id : profile.uid,              // Serial + country code
                uid: profile.emailaddress + "/" +profile.uid, // intranet e-mail + serial # is unique and human readable 
                nameID: profile.nameID,
                nameIDFormat: profile.nameIDFormat,
                sessionIndex: profile.sessionIndex, 
                email : profile.emailaddress,
                displayName : profile.cn,
                firstName : profile.firstName,
                lastName : profile.lastName,
                blueGroups: (blueGroups.map?blueGroups.map(function(item){return item.split(/.*cn=|,/)[1];}):
                                    [blueGroups.split(/.*cn=|,/)[1]]) // like ['cn=w3id-saml-adopters-techcontacts,ou=memberlist,ou=ibmgroups,o=ibm.com']
            };
        var blueGroupCheck = (typeof config.passport.saml.blueGroupCheck === "undefined") || 
            config.passport.saml.blueGroupCheck && config.passport.saml.blueGroupCheck.some &&
                    config.passport.saml.blueGroupCheck.some(function(item){
                        return user.blueGroups.indexOf(item)>=0;}) ||
                    user.blueGroups.indexOf(config.passport.saml.blueGroupCheck)>=0;
        if (blueGroupCheck) {
            return done(null,user);
        } else {
            return done(null, false, { message : "User is not a memeber of a required group" });
        }
        
    };
    
    var strategies = {
        saml:  {passportStrategy: SamlStrategy, config: config.passport.saml, verify: verifySaml}
    };
    if (strategies[config.passport.strategy] ) {
        var strategyConf = strategies[config.passport.strategy];
        var strategy = new strategyConf.passportStrategy(strategyConf.config, strategyConf.verify);
        passport.use(strategy);
    }   
    
    // Add handler for patching the signed IDP response
    passport.patchResponse = samlSignature.patchResponse;
    
};