// Config
var cfg = require('workwoo-utils').config;

var crypto = require('crypto');

// Mongoose
var User = require('workwoo-utils').user;
var Org = require('workwoo-utils').org;
var Counter = require('workwoo-utils').counter;
var NotificationTemplate = require('workwoo-utils').notificationTemplate;

// Custom modules
var mailer = require('workwoo-utils').mailer;
var utility = require('workwoo-utils').utility;
var validator = require('workwoo-utils').validator;
var log = require('workwoo-utils').logger;
var widget = 'auth';
log.registerWidget(widget);

exports.verifyCredentials = function(emailAddress, password, callback) {
	try {
		var error = null;
		if (validator.checkNull(emailAddress)) { error = 'Email Address is Null'; } 
		else if (!validator.checkEmail(emailAddress)) { error = 'Email Address is not valid: ' + emailAddress; } 
		else if (validator.checkNull(password)) { error = 'Password is Null'; }

		if (error) {
			log.error('|auth.verifyCredentials.authenticate| ' + error, widget);
			return callback(error);			
		}

		log.info('|auth.verifyCredentials| Email -> ' + emailAddress, widget);

		User.authenticate(emailAddress, password, function(error, user){
			if (error) {
				log.error('|auth.verifyCredentials.authenticate| Unknown -> ' + error, widget);
				return callback(error);
			}
			if (!user) {
				log.error('|auth.verifyCredentials.authenticate| User not found or password incorrect -> ' + emailAddress, widget);
				return callback(null, false);
			}

			log.info('|auth.verifyCredentials.authenticate| User credentials verified -> ' + emailAddress, widget);
			
			var userSession = {
				firstName: user.firstName,
				lastName: user.lastName,
				emailAddress: user.emailAddress,
				id: user.id,
				role: user.role,
				org: user._org,
				number: user.number,
				newUser: user.newUser,
				phone: user.phone
			};

			return callback(null, userSession);
		});

	} catch (error) {
		log.error('|auth.verifyCredentials| Unknown -> ' + error, widget);
		return callback(error);
	}
};

function createOrg(orgName, callback) {
	var newOrg = new Org();
	newOrg.name = orgName;
	newOrg.streetAddress = '';
	newOrg.city = '';
 	newOrg.state = '';
 	newOrg.country = '';
 	newOrg.zip = '';
 	newOrg.emailAddress = '';
 	newOrg.primaryCollection = null;
 	newOrg.accountType = '0';
	//newOrg._created_by = '56d67d7ee4b035e540be4bfd'; // System Account, move to config
    //newOrg._updated_by = '56d67d7ee4b035e540be4bfd';

	newOrg.save(function(error, org) {
		if (error) {
			callback(error);
		} else {
			createCounter(org._id, 'USR', 'users', function (error) {
				if (error) {
					callback(error);
				} else {
					callback(null, org._id);
				}
			});
		}
	});
};

function createCounter(orgId, prefix, col, callback) {
	var newCounter = new Counter();
	newCounter.col = col;
	newCounter.prefix = prefix;	
	newCounter._org = orgId;
	//newCounter._created_by = '56d67d7ee4b035e540be4bfd'; // System Account, move to config

	newCounter.save(function(error, counter) {
		if (error) {
			callback(error);
		} else {
			callback(null);
		}
	});
}

function createUser(req, orgId, callback) {
	var newUser = new User();
	newUser.firstName = req.body.firstName;
	newUser.lastName = req.body.lastName;
	newUser.emailAddress = req.body.newEmailAddress;
	newUser.role = 'Admin';
	newUser.state = 'active';
	newUser.password = req.body.newPassword;
	newUser._org = orgId;

	var token = crypto.randomBytes(64).toString('hex');
	newUser.verified = false;
	newUser.verifyToken = token;
	newUser.newUser = true;

	//newUser._created_by = '56d67d7ee4b035e540be4bfd'; // System Account, move to config
	//newUser._updated_by = '56d67d7ee4b035e540be4bfd';

	newUser.save(function(error, user) {
		if (error) {
			callback(error);
		} else {
			callback(null, user);
		}
	});
}

exports.signupRequest = function(req, res) {
	try {
		createOrg(req.body.orgName, function (error, orgId) {
			if (error) {
				log.error('|auth.createOrg| Unknown  -> ' + error, widget);
				return utility.errorResponseJSON(res, 'Error occurred creating org');
			} else {
				createUser(req, orgId, function (error, user) {
					if (error) {
						log.error('|auth.createUser| Unknown  -> ' + error, widget);
						return utility.errorResponseJSON(res, 'Error occurred creating user');
					} else {
						NotificationTemplate.findOne({name: cfg.mailer.signupTemplate}, function (error, notificationTemplate) {
							if (error) {
								log.error('|auth.signupRequest.NotificationTemplate| Unknown -> ' + error, widget);
								return utility.errorResponseJSON(res, 'Error while retrieving signup template');
							} else {
								notificationTemplate.html = notificationTemplate.html.replace(cfg.mailer.tokenPlaceholder, user.verifyToken);
								notificationTemplate.html = notificationTemplate.html.replace(cfg.mailer.hostNamePlaceholder, cfg.hostname);
								mailer.sendMail(notificationTemplate, {to: user.emailAddress}, user._id);								
								return res.send(JSON.stringify({result: true}));
							}
						});
					}
				});
			}
		});
	} catch (error) {
		log.error('|auth.signupRequest| Unknown -> ' + error, widget);
	    utility.errorResponseJSON(res, 'Error while processing signup request');
	}
};

exports.forgotPasswordRequest = function(req, res) {
	try {
		var emailAddress = req.body.emailAddress;

		var error = null;
		if (validator.checkNull(emailAddress)) { error = 'Email Address is Null'; } 
		else if (!validator.checkEmail(emailAddress)) { error = 'Email Address is not valid: ' + emailAddress; } 

		if (error) {
			log.error('|auth.forgotPasswordRequest| ' + error, widget);
			return utility.errorResponseJSON(res, error);
		}

		log.info('|auth.forgotPasswordRequest| Email -> ' + emailAddress, widget);
		
		User.forgotPassword(emailAddress, function (error, user, token){
			if (error) {
				log.error('|auth.forgotPasswordRequest.forgetPassword| Unknown -> ' + error, widget);
				return utility.errorResponseJSON(res, 'Error while processing forgot password request');
			}

			if (!user.emailAddress) { 
				log.error('|auth.forgotPasswordRequest.forgetPassword| User not found -> ' + emailAddress, widget);
				return res.send(JSON.stringify({result: false}));
			}

			NotificationTemplate.findOne({name: cfg.mailer.forgotPasswordTemplate}, function (error, notificationTemplate) {
				if (error) {
					log.error('|auth.forgotPasswordRequest.NotificationTemplate| Unknown -> ' + error, widget);
					return utility.errorResponseJSON(res, 'Error while processing forgot password request');
				} else {
					notificationTemplate.html = notificationTemplate.html.replace(cfg.mailer.tokenPlaceholder, token);
					notificationTemplate.html = notificationTemplate.html.replace(cfg.mailer.hostNamePlaceholder, cfg.hostname);	
					mailer.sendMail(notificationTemplate, {to: user.emailAddress}, user._id);
				}
			});

		    return res.send(JSON.stringify({result: true}));
		});
	} catch (error) {
		log.error('|auth.forgotPasswordRequest| Unknown -> ' + error, widget);
	    utility.errorResponseJSON(res, 'Error while processing forgot password request');
	}
};

exports.resetPasswordRequest = function(req, res) {
	try {
		var newPassword = req.body.newPassword;
		var token = req.body.token;

		var error = null;
		if (validator.checkNull(newPassword)) { error = 'New Password is Null'; } 
		else if (validator.checkNull(token)) { error = 'Reset Password Token is Null' } 

		if (error) {
			log.error('|auth.resetPasswordRequest| ' + error, widget);
			return utility.errorResponseJSON(res, error);
		}
		
		log.info('|auth.resetPasswordRequest| Token -> ' + token, widget);

		User.resetPassword(token, newPassword, function(error, user) {
			if (error) {
				log.error('|auth.resetPasswordRequest.resetPassword| Unknown -> ' + error, widget);
				return utility.errorResponseJSON(res, 'Error while resetting password');
			}

			if (!user.emailAddress) { 
				log.error('|auth.resetPasswordRequest.resetPassword| User not found for token -> ' + token, widget);
				return utility.errorResponseJSON(res, 'Error while resetting password');
			}

			NotificationTemplate.findOne({name: cfg.mailer.resetPasswordTemplate}, function (error, notificationTemplate) {
				if (error) {
					log.error('|auth.resetPasswordRequest.NotificationTemplate| Unknown -> ' + error, widget);
					return utility.errorResponseJSON(res, 'Error while resetting password');
				} else {
					mailer.sendMail(notificationTemplate, {to: user.emailAddress}, user._id);
				}
			});

		    return res.send(JSON.stringify({result: true}));
		});

	} catch (error) {
		log.error('|auth.resetPasswordRequest| Unknown -> ' + error, widget);
	    utility.errorResponseJSON(res, 'Error while resetting password');
	}
};

exports.verifyRequest = function(req, res) {
	try {
		var token = req.body.token;

		var error = null;
		if (validator.checkNull(token)) { error = 'Verify Token is Null'; } 

		if (error) {
			log.error('|auth.verifyRequest| ' + error, widget);
			return utility.errorResponseJSON(res, error);
		}
		
		log.info('|auth.verifyRequest| Token -> ' + token, widget);

		User.verify(token, function(error, user) {
			if (error) {
				log.error('|auth.verifyRequest.verify| Unknown -> ' + error, widget);
				return utility.errorResponseJSON(res, 'Error while verifying user');
			}

			if (!user.emailAddress) { 
				log.error('|auth.verifyRequest.verify| User not found for token -> ' + token, widget);
				return utility.errorResponseJSON(res, 'Error while verifying user');
			}

			// TO DO: Welcome email??
/*
			NotificationTemplate.findOne({name: cfg.mailer.resetPasswordTemplate}, function (error, notificationTemplate) {
				if (error) {
					log.error('|auth.resetPasswordRequest.NotificationTemplate| Unknown -> ' + error, widget);
					utility.errorResponseJSON(res, 'Error while resetting password');
				} else {
					mailer.sendMail(notificationTemplate, {to: user.emailAddress}, user._id);
				}
			});
*/
		    return res.send(JSON.stringify({result: true}));
		});

	} catch (error) {
		log.error('|auth.verifyRequest| Unknown -> ' + error, widget);
	    utility.errorResponseJSON(res, 'Error while verifying user');
	}
};


