var express = require('express');
var path = require('path');
var favicon = require('serve-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');

var routes = require('./routes/index');
var users = require('./routes/users');

var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');

// uncomment after placing your favicon in /public
//app.use(favicon(__dirname + '/public/favicon.ico'));
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Set up session framework
var redisIP = process.env.REDIS_IP;
var redisPort = process.env.REDIS_PORT;
var redisPassword = process.env.REDIS_PASS;
var passport = require("passport"),
    redis = require('redis'),
    session = require("express-session"),
    RedisStore = require('connect-redis')(session),
    samlConfig = require('./config/saml')["dev"]; // Select configuration based on profile
    var redisClient = redis.createClient(redisPort, redisIP, {auth_pass: redisPassword});
    // var MemoryStore = require('session-memory-store')(session);

/*
 * =====================================================================
 *  Mount API handlers before session to improve performance
 */
app.use('/api', require('./routes/api')(app, samlConfig, passport));
app.use('/s/api', require('./routes/s')(app));

/*
 * =====================================================================
 *  Setup session support
 */
app.use(session({secret: samlConfig.passport.sessionSecret || 'SAML support for BlueMix',
    cookie: { path: '/', httpOnly: true, secure: !!samlConfig.passport.saml,  maxAge: null }, 
    resave: true,
    proxy: true,
    saveUninitialized: true,
    store: new RedisStore({client: redisClient})}));
    // store: new MemoryStore()}));
/*
 * =====================================================================
 *  Passport framework setup
 */
app.use(passport.initialize());
app.use(passport.session());

// Configure passport SAML strategy parameters
require('./lib/passport')(passport, samlConfig);

/*
 * =====================================================================
 *  Configure secure routes
 */

app.use('/', require('./routes/secure')(app, samlConfig, passport));
/*
 * =====================================================================
 */

//app.use('/', routes);
//app.use('/users', users);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  var err = new Error('Not Found');
  err.status = 404;
  next(err);
});

// error handlers

// development error handler
// will print stacktrace
if (app.get('env') === 'development') {
  app.use(function(err, req, res, next) {
    res.status(err.status || 500);
    res.render('error', {
      message: err.message,
      error: err
    });
  });
}

// production error handler
// no stacktraces leaked to user
app.use(function(err, req, res, next) {
  res.status(err.status || 500);
  res.render('error', {
    message: err.message,
    error: {}
  });
});


module.exports = app;
