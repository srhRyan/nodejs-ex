var xml2js    = require('xml2js'),
    SignedXml = require('xml-crypto').SignedXml,
    zlib      = require('zlib');

module.exports = {
  patchResponse:  function patchResponse(){ 
      return function(req, res, next) {
        if (req.body.SAMLResponse || req.query.SAMLResponse) {
            var bufferIn = new Buffer(req.body.SAMLResponse || req.query.SAMLResponse, 'base64');
              zlib.inflateRaw(bufferIn, function(err, buffer){
                if (err) {
                    // May be the request was not deflated
                    buffer = bufferIn;
                }
                xml2js.parseString(bufferIn.toString('utf8'), function(err, samlMessage){
                    if (err || !samlMessage || !samlMessage["samlp:Response"]) {
                        return next(new Error('Invalid SAML Response format!'));
                    }
                    
                    if (samlMessage["samlp:Response"]["ds:Signature"])  samlMessage["samlp:Response"]["ds:Signature"][0]["$"]["xmlns:ds"] = "http://www.w3.org/2000/09/xmldsig#";
                    if (samlMessage["samlp:Response"]["saml:Assertion"]) {
                      samlMessage["samlp:Response"]["saml:Assertion"][0]["$"]["xmlns:xsi"] = "http://www.w3.org/2001/XMLSchema-instance";
                      samlMessage["samlp:Response"]["saml:Assertion"][0]["$"]["xmlns:xs"] = "http://www.w3.org/2001/XMLSchema";
                      if (samlMessage["samlp:Response"]["saml:Assertion"][0]["ds:Signature"]) {
                          samlMessage["samlp:Response"]["saml:Assertion"][0]["ds:Signature"][0]["$"]["xmlns:ds"] = "http://www.w3.org/2000/09/xmldsig#";
                      }
                    }
                    
                    var builder = new xml2js.Builder({renderOpts:{ 'pretty': false}});
                    var samlMessageOut = builder.buildObject(samlMessage);
                    if (req.body.SAMLResponse) {
                        req.body.SAMLResponse = (new Buffer(samlMessageOut, 'utf8')).toString('base64');
                    } else {
                        req.query.SAMLResponse = (new Buffer(samlMessageOut, 'utf8')).toString('base64');
                    }
                    return next();
                });
              });
        } else {
            return next(new Error('Invalid SAML Response!'));
        }
      };
  }
};