// var appHost = process.env.APP_HOST || process.env.VCAP_APPLICATION && JSON.parse(process.env.VCAP_APPLICATION).application_uris[0] || "localhost";
// var xmlCert = process.env.XML_CERT; // || "MxDDAKBgNVBAoTA2libTEMMAoGA1UECx"; 

var appHost = process.env.APP_HOST;
var xmlCert = process.env.XML_CERT;
var w3Cert = process.env.W3CERT;

module.exports = {
    "dev" : {
        passport: {
            strategy : 'saml',
            saml : {
                issuer:                 "https://" + appHost + "/",  //  "https://your-app.w3ibm.mybluemix.net/"
                callbackUrl:            "https://" + appHost + "/login/callback/postResponse",

                // Your SAML private signing key. Mellon script generates PKCS#8 key, make sure your key's header matches the ----BEGIN * PRIVATE KEY----- header here
                privateCert:            xmlCert ? "-----BEGIN PRIVATE KEY-----\n" + 
                                        xmlCert.match(/.{1,64}/g).join('\n') + 
                                        "\n-----END PRIVATE KEY-----\n" : undefined,
                signatureAlgorithm:     'sha256',
                
                // List groups that permit access to the application. Comment out to allow all authenticated users
                // blueGroupCheck:         ["w3id-saml-adopters-techcontacts", "w3legacy-saml-adopters-techcontacts"],
                // Some SSO templates return blueGroups attribute as JSON
                // attributesAsJson:       {"blueGroups": true},

                passive:                        false,
                identifierFormat:               "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
                skipRequestCompression:         false,
                disableRequestedAuthnContext:   true,

                // Update IDP attributes according to the service used
                entryPoint:     "https://w3id.alpha.sso.ibm.com/auth/sps/samlidp2/saml20/login", 
                logoutUrl:      "https://w3id.alpha.sso.ibm.com/auth/sps/samlidp2/saml20/slo",
                // w3id certificate
                cert: w3Cert
            },
            sessionSecret: xmlCert
        }
    }
};