var config = module.exports = {};

config.env = 'development';
config.hostname = 'app.workwoo.com';
config.port = 1338;

//mongo database
config.mongo = {};
config.mongo.uri = process.env.MONGO_URI || 'mongodb://heroku_r235lts9:nthn5e0gqvdl37qajcq2b0gif9@ds037244.mongolab.com:37244/heroku_r235lts9';
config.mongo.poolSize = 10;
config.mongo.keepAlive = 120; //milliseconds

//Mongoose
config.mongoose = {};
config.mongoose.options = { versionKey: '_version', timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } };

//mailer
config.mailer = {};
config.mailer.user = 'quikpaper.mailer@gmail.com';
config.mailer.pass = 'w3c@n7b3s70pp3d1';
config.mailer.tokenPlaceholder = '|TOKEN|';
config.mailer.hostNamePlaceholder = '|HOSTNAME|';

config.mailer.forgotPasswordTemplate = 'Forgot Password';
config.mailer.resetPasswordTemplate = 'Reset Password';
config.mailer.signupTemplate = 'Signup';

//platform app
config.platform = {};
config.platform.url = 'http://app.workwoo.com/';

//session
config.session = {};
config.session.name = 'workwoo-session';
config.session.secret = 'supercat keiko';

config.session.cookie = {};
config.session.cookie.path = '/';
config.session.cookie.httpOnly = false;
config.session.cookie.secure = false;
config.session.cookie.maxAge = null;
config.session.cookie.domain = '.workwoo.com';


config.session.store = {};
config.session.store.url = process.env.MONGO_SESSION_URI || 'mongodb://heroku_r235lts9:nthn5e0gqvdl37qajcq2b0gif9@ds037244.mongolab.com:37244/heroku_r235lts9';
config.session.store.ttl = 30 * 60; // 30 minutes
config.session.store.touchAfter = 15 * 60; // 15 minutes
config.session.store.autoRemove = 'native';

// Cache
config.cache = {};
config.cache.checkPeriod = 300; // 5 Minutes
config.cache.longTTL = 7200; // 2 hours
config.cache.mediumTTL = 3600; // 1 hour
config.cache.shortTTL = 1800; // 30 Minutes

