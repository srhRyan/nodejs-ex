

# Sso-W3Id-Saml-Demo

Demo of Node.js Express application using IBM w3id SAML SSO service.

- Generate SP metadata and private / public key pair ([a script](https://github.com/UNINETT/mod_auth_mellon/blob/master/mellon_create_metadata.sh) from Mellon project can help).  
Suggested mellon_create_metadata.sh usage (modify the URLs according to your application, **make sure** to use Entity ID and callback URLs as shown, except for the YourAppDomain):  
`$ mellon_create_metadata.sh https://YourAppDomain.w3ibm.mybluemix.net/ https://YourAppDomain.w3ibm.mybluemix.net/login/callback`
- Register your application through [SSO Self-Boarding](https://w3.innovate.ibm.com/tools/sso/home.html). Use w3id SAML service. Make sure to use "Upload a Service Provider Metadata File" option and upload the generated SP metadata file
- Update [config/saml.js](config/saml.js) with the IDP endpoint and certificate from the IDP metadata
  `entryPoint`
  `logoutUrl`
  `cert`  

  

# Usage

In [config/saml.js](config/saml.js) the *blueGroupCheck* property lists all bluegroups allowing access to the application. If undefined, all authenticated users are allowed.

- Depending on your OpenSSH build you may need to correct the private key header in [config/saml.js](config/saml.js) (privateCert property). Mellon script may generates PKCS#8 or PKCS#1 key, make sure your key's header matches the BEGIN PRIVATE KEY header. If you are getting `ASN1_CHECK_TLEN` error, change the header/footer to BEGIN __RSA__ PRIVATE KEY / END __RSA__ PRIVATE KEY. When adding your private key content to the application or env variable make sure that there are no extra headers, line breaks, or spaces in the key string. 
Some text editors may break the long lines and add extra characters to the literal. 
- Depending on the application profile you used when registering your w3id profile, the bluegroup attributes may or may not be passed JSON-encoded. If you are getting Unexpected token error after authentication, change attributesAsJson property to [config/saml.js](config/saml.js) - it lists attributes that should be treated as JSON.


### Running locally: 
You can register the application with real host name in w3id and still run/test locally by pointing that name to localhost in your hosts file.
Also, you will have to run the node application on HTTPS port 443 which may require administrator privileges. 
You will need to set the host name (matching the SSO registration), private key, and the HTTPS port. The first two can be set in [config/saml.js](config/saml.js), the HTTPS port is set through env var `LOCAL_HTTPS_PORT`   

* Edit your hosts file (/etc/hosts or c:\windows\system32\drivers\etc\hosts) and point the host name registered in w3id to 127.0.0.1
* Set the *appHost* in [config/saml.js](config/saml.js) to the host name registered for SSO or set APP_HOST env variable
* Set *xmlCert* to Base64 encoded value of your private key (.key file content without header/footer or line breaks) in [config/saml.js](config/saml.js) or set env variable XML_CERT
* Set env variable `LOCAL_HTTPS_PORT` to 443
* Start the application 

`npm install`       
`export LOCAL_HTTPS_PORT=443`  
`npm start`    


### Deployed to BlueMix:
Set XML_CERT environment variable with Base64 encoded value of your private key (.key file content without header/footer or line breaks / spaces)
For real applications it's recommended to set APP_HOST env variable if you plan to deploy the application without assigning routes (e.g. blue/green deployment)

------
## Developing

The application defines several routes in [routes/secure.js](routes/secure.js) and [routes/api.js](routes/api.js). 
The API routes are using JSON web tokens to show an example of a more realisting web application with REST services protected by JWT.

A few URLs that you can try with the demo application (also available at [https://w3id-saml-demo.w3ibm.mybluemix.net/](https://w3id-saml-demo.w3ibm.mybluemix.net/) ):

* [/open](https://w3id-saml-demo.w3ibm.mybluemix.net/open) - does not require authentication
* [/app](https://w3id-saml-demo.w3ibm.mybluemix.net/app)  - forces the user to log in and shows user's bluegroups. You can also get an API token on that page and run an API call.    
Click Get Token button, then click Call API to see the results. Tokens are set to expire in 3 minutes to observe the effect of their expiration.
* [/getToken](https://w3id-saml-demo.w3ibm.mybluemix.net/getToken) - JSON service to get a signed token if you have a valid session
* [/api/profile?token=$yourValidToken](https://w3id-saml-demo.w3ibm.mybluemix.net/api/profile?token=$yourValidToken) - REST service protected by JWT returning your name and UID.
  


### Tools

Created with [Nodeclipse](https://github.com/Nodeclipse/nodeclipse-1)
 ([Eclipse Marketplace](http://marketplace.eclipse.org/content/nodeclipse), [site](http://www.nodeclipse.org))   

Nodeclipse is free open-source project that grows with your contributions.
