// Config
var cfg = require('./modules/config/config');

// Web - Session
var express = require('express');
var session = require('express-session');
var MongoStore = require('connect-mongo')(session);
var bodyParser = require('body-parser');

// Authentication Strategy
var passport = require('passport');
var BasicStrategy = require('passport-http').BasicStrategy;

// Mongoose
var mongoose = require('mongoose');

// Custom modules
var auth = require('./modules/handlers/auth.js');
var utility = require('workwoo-utils').utility;
var log = require('workwoo-utils').logger;
var widget = 'workwoo-auth';
log.registerWidget(widget);

/*
* This function initializes the express app along with mongoose and passport.
* We do not start the app until we've successfully setup mongoDB w/ mongoose.
*/
(function startup() {
	try {
		log.info('| ################## Auth Startup ################## |', widget);

		// 1. Initialize mongoose
		initializeMongoose();

		// 2. Initialize express
		var app = initializeAuth();

		// 3. Start app
		app.listen(process.env.PORT || cfg.port);

	} catch (error) {
		log.error('| ################## Auth Startup Error ################## | -> ' + error, widget);
	}
})();

function initializeMongoose() {
	try {
		log.info('|initializeMongoose|', widget);
		
		// TODO: Setup more options
		var options = {
			server: { poolSize: cfg.mongo.poolSize, socketOptions: cfg.mongo.keepAlive }
		}

		mongoose.connect(cfg.mongo.uri, options);

		var db = mongoose.connection;
		db.on('error', console.error.bind(console, 'connection error:'));
		db.once('open', function() {
		  log.info('|initializeMongoose| -> Successful connection made to mongoDB', widget);
		});

	} catch (e) {
		log.error('|initializeMongoose| Unknown -> ' + error, widget);
		process.exit(0);
	}
}

function initializeAuth() {
	try {
		log.info('|initializeAuth|', widget);
		var app = express();
		app.use(bodyParser.urlencoded({ extended: false }));
		app.use(bodyParser.json());

		// Session setup
		app.use(session({
			name: cfg.session.name,
			secret: cfg.session.secret,
			cookie: cfg.session.cookie,
			resave: false,
			saveUninitialized: false,
			store: new MongoStore({ 
				mongooseConnection: mongoose.connection, /* Reuse our mongoose connection pool */
				ttl: cfg.session.store.ttl,
				autoRemove: cfg.session.store.autoRemove,
				touchAfter: cfg.session.store.touchAfter
			})
		}));

		// Passport setup
		app.use(passport.initialize());
		app.use(passport.session());

		passport.use(new BasicStrategy(auth.verifyCredentials));

		passport.serializeUser(function(user, done) {
			done(null, user.id);
		});

		passport.deserializeUser(function(id, done) {
			done(null, user.id);
		});

		/* 
		* These headers are for allowing Cross-Origin Resource Sharing (CORS).
		* This enables the angular front-end, which resides in the QuikPaper 
		* Platform app, to make requests to the QuikPaper Auth app.
		*/
		app.use(function (req, res, next) {
			res.set({
				'Access-Control-Allow-Headers': 'Content-Type, Authorization',
				'Access-Control-Allow-Methods': 'POST',
				'Access-Control-Allow-Origin' : req.headers.origin,
				'Access-Control-Allow-Credentials': true
			});
			next();
		});

		// Express routes
		app.route('/login').get(function(req, res) {
			log.info('|login| Incorrect GET instead of POST', widget);
			req.logout();
			res.sendStatus(401);
		}).post(function(req, res, next) {
			log.info('|login|', widget);
			passport.authenticate('basic', function(error, user, info) {
				if (error) { return next(error); }
				if (!user) { return res.sendStatus(401); }

		    	req.logIn(user, function(error) {
		    		if (error) { return next(error); }
		    		req.session.userprofile = user;
		    		return res.send(JSON.stringify(user));
				});
			})(req, res, next);
		});

		app.route('/signup').get(function(req, res) {
			log.info('|signup| Incorrect GET instead of POST', widget);
			req.logout();
			res.sendStatus(401);
		}).post(auth.signupRequest);

		app.route('/forgotPwd').get(function(req, res) {
			log.info('|forgotPwd| Incorrect GET instead of POST', widget);
			req.logout();
			res.sendStatus(401);
		}).post(auth.forgotPasswordRequest);

		app.route('/resetPwd').get(function(req, res) {
			log.info('|resetPwd| Incorrect GET instead of POST', widget);
			req.logout();
			res.sendStatus(401);
		}).post(auth.resetPasswordRequest);

		return app;
	} catch (e) {
		log.error('|initializeAuth| Unknown -> ' + error, widget);
		process.exit(0);
	}
}


