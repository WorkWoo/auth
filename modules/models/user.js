var cfg = require('../config/config');
var mongoose = require('mongoose');
var bcrypt = require('bcrypt');
var crypto = require('crypto');
var Counter = require('../models/counter');
var log = require('workwoo-utils').logger;
var widget = 'user';
log.registerWidget(widget);

var Schema = mongoose.Schema;

var userSchema = new Schema({
	emailAddress: { type: String, required: true, unique: true },
	password: { type: String, required: true },
 	firstName: { type: String, required: true },
 	lastName: { type: String, required: true},
	_org: { type: Schema.Types.ObjectId, ref: 'Org' },
	phone: String,
	role: String,
	number: String,
	state: String,
	resetPwdToken: String,
    resetPwd: Boolean,
    resetPwdExpiration: Date,
    verified: Boolean,
    verifyToken: String,
    newUser: Boolean,
	_created_by: { type: Schema.Types.ObjectId, ref: 'User' },
    _updated_by: { type: Schema.Types.ObjectId, ref: 'User' }
}, cfg.mongoose.options);

userSchema.statics.authenticate = function(emailAddress, password, callback) {
	log.info('|User.authenticate|', widget);
	this.findOne({ 'emailAddress': emailAddress })
		.populate('_org')
		.exec(
		function (err, user) {
			if (err) { return callback(err); }
			
			if (!user) { 
				log.error('|User.authenticate| User not found -> ' + emailAddress, widget);
				return callback(null, false);
			}

			bcrypt.compare(password, user.password, function(err, isMatch) {
				if (err) {
					log.error(err, widget);
					return callback(err);
				}

				if (isMatch) {
					log.info('|User.authenticate| Credentials match for -> ' + emailAddress, widget);

					if (user.resetPwd == true) {
						return callback('User is in reset password mode');
					} else if (user.verified == false) {
						return callback('User is not verified');
					}

					return callback(null, user);
				} else {
					log.error('|User.authenticate| Credentials do not match for -> ' + emailAddress, widget);
					return callback(null, false);
				}
			});
		});
};

userSchema.statics.forgotPassword = function(emailAddress, callback) {
	log.info('|User.forgotPassword|', widget);
	this.findOne({emailAddress: emailAddress})
		.exec(
		function (err, user) {
			if (err) { return callback(err); }
			
			if (!user) { 
				log.error('|User.forgotPassword| User not found -> ' + emailAddress, widget);
				return callback(null, false);
			}

			var token = crypto.randomBytes(64).toString('hex');
			var now = new Date();
			now.setHours(now.getHours() + 1);

			user.resetPwdToken = token;
			user.resetPwd = true;
			user.resetPwdExpiration = now.toString();

			user.save(function (err) {
				if (err) { return callback(err); }
  				log.error('|User.forgotPassword| Request submitted successfully -> ' + emailAddress, widget);
  				return callback(null, user, token);
			});
		});
};


userSchema.statics.resetPassword = function(token, newPassword, callback) {
	log.info('|User.resetPassword|', widget);
	this.findOne({resetPwdToken: token})
		.exec(
		function (err, user) {
			if (err) { return callback(err); }
			
			if (!user) { 
				log.error('|User.resetPassword| Matching token not found -> ' + token, widget);
				return callback(null, false);
			}

			bcrypt.genSalt(10, function(err, salt) {
		    	bcrypt.hash(newPassword, salt, function(err, hash) {
		    		user.password = hash;
		    		user.resetPwdToken = '';
					user.resetPwd = false;
					user.resetPwdExpiration = '';
					user.save(function (err) {
					if (err) { return callback(err); }
		  				log.info('|User.resetPassword| Password reset successful', widget);
		  				return callback(null, user);
					});				
		    	});
			});
		});
};

userSchema.statics.verify = function(token, callback) {
	log.info('|User.verify|', widget);
	this.findOne({verifyToken: token})
		.exec(
		function (err, user) {
			if (err) { return callback(err); }
			
			if (!user) { 
				log.error('|User.verify| Matching token not found -> ' + token, widget);
				return callback(null, false);
			}
		    		
		    user.verified = true;
		    user.verifyToken = '';
		    		
			user.save(function (err) {
				if (err) { return callback(err); }
		  		log.info('|User.verify| Verify successful', widget);
		  		return callback(null, user);
			});						    
		});
};

// Encrypt password when creating a new user
userSchema.pre('save', function(next) {
	var user = this;
	if (this.isNew) {
    	bcrypt.genSalt(10, function(err, salt) {
	    	bcrypt.hash(user.password, salt, function(err, hash) {
	    		user.password = hash;
	    		user.resetPwdToken = '';
				user.resetPwd = false;
				user.resetPwdExpiration = '';
				next();		
	    	});
		});
	} else {
		next();	
	}

});	

// Set counter when creating a new user
userSchema.pre('save', function(next) {
	var user = this;
	if (this.isNew) {
		Counter.increment('users', this._org, function(error, autonumber) {
			user.number = autonumber;
			next();
		});
	} else {
		next();
	}
});	

// Remove user data not needed by app
userSchema.post('save', function(user, next) {
	user.password = '';
	user.resetPwdToken = '';
    next();
});

// Populate org reference
userSchema.post('save', function(user, next) {
	user.populate('_org', function(error, user) {
		if (error) { next(error); }
		next();
	});
});

var User = mongoose.model('User', userSchema);

module.exports = User;