// Config
var cfg = require('../config/config');

// Mongoose
var User = require('../models/user');
var Org = require('../models/org');
var Counter = require('../models/counter');
var NotificationTemplate = require('workwoo-utils').notificationTemplate;

// Custom modules
var mailer = require('workwoo-utils').mailer;
var utility = require('workwoo-utils').utility;
var log = require('workwoo-utils').logger;
var widget = 'auth';
log.registerWidget(widget);

exports.verifyCredentials = function(emailAddress, password, callback) {
	try {
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
				id: user.id,
				role: user.role,
				org: user._org,
				number: user.number
			};

			return callback(null, userSession);
		});

	} catch (error) {
		log.error('|auth.verifyCredentials| Unknown -> ' + error, widget);
		return callback(error);
	}
};

exports.signupRequest = function(req, res) {
	try {
		var newOrg = new Org();
		newOrg.name = req.body.orgName;
		newOrg.streetAddress = '';
 		newOrg.city = '';
	 	newOrg.state = '';
	 	newOrg.country = '';
	 	newOrg.zip = '';
	 	newOrg.emailAddress = '';
	 	newOrg.primaryWorkItem = 'orders';
		newOrg._created_by = '56d67d7ee4b035e540be4bfd'; // System Account, move to config
	    newOrg._updated_by = '56d67d7ee4b035e540be4bfd';

	    newOrg.save(function(error, org) {
	    	if (error) {
				log.error('|auth.signupRequest.newOrg.save| Unknown  -> ' + error, widget);
				utility.errorResponseJSON(res, 'Error occurred creating org');
			} else {
				var newCounter = new Counter();
				newCounter.col = 'users';
 				newCounter.prefix = 'USR';	
 				newCounter._org = org._id;
				newCounter._created_by = '56d67d7ee4b035e540be4bfd'; // System Account, move to config

				newCounter.save(function(error, counter) {
					if (error) {
						log.error('|auth.signupRequest.newCounter.save| Unknown  -> ' + error, widget);
						utility.errorResponseJSON(res, 'Error occurred creating counter');
					} else {
						var newUser = new User();

						newUser.firstName = req.body.firstName;
				 		newUser.lastName = req.body.lastName;
						newUser.emailAddress = req.body.newEmailAddress;
						newUser.role = 'Admin';
						newUser.state = 'active';

						newUser.password = req.body.newPassword;
						newUser._org = org._id;
						newUser._created_by = '56d67d7ee4b035e540be4bfd'; // System Account, move to config
				    	newUser._updated_by = '56d67d7ee4b035e540be4bfd';
										
				    	newUser.save(function(error, user) {
				    		if (error) {
								log.error('|auth.signupRequest.newUser.save| Unknown  -> ' + error, widget);
								utility.errorResponseJSON(res, 'Error occurred creating user');
							} else {
								NotificationTemplate.findOne({name: cfg.mailer.signupTemplate}, function (error, notificationTemplate) {
									if (error) {
										log.error('|auth.signupRequest.NotificationTemplate| Unknown -> ' + error, widget);
										utility.errorResponseJSON(res, 'Error while sending signup email');
									} else {
										//notificationTemplate.html = notificationTemplate.html.replace(cfg.mailer.tokenPlaceholder, token);
										//notificationTemplate.html = notificationTemplate.html.replace(cfg.mailer.hostNamePlaceholder, cfg.hostname);	
										mailer.sendMail(notificationTemplate, {to: user.emailAddress}, user._id);								
										return res.send(JSON.stringify({result: true}));
									}
								});
							}
				    	});
					}
				});
			}
	    });
	} catch (e) {
		log.error('|auth.signupRequest| Unknown -> ' + error, widget);
	    utility.errorResponseJSON(res, 'Error while processing signup request');
	}
};

exports.forgotPasswordRequest = function(req, res) {
	try {
		var emailAddress = req.body.emailAddress;
		log.info('|auth.forgotPasswordRequest| Email -> ' + emailAddress, widget);
		
		User.forgotPassword(emailAddress, function (error, user, token){
			if (error) {
				log.error('|auth.forgotPasswordRequest.forgetPassword| Unknown -> ' + error, widget);
				utility.errorResponseJSON(res, 'Error while processing forgot password request');
			}

			if (!user.emailAddress) { 
				log.error('|auth.forgotPasswordRequest.forgetPassword| User not found -> ' + emailAddress, widget);
				return res.send(JSON.stringify({result: false}));
			}

			NotificationTemplate.findOne({name: cfg.mailer.forgotPasswordTemplate}, function (error, notificationTemplate) {
				if (error) {
					log.error('|auth.forgotPasswordRequest.NotificationTemplate| Unknown -> ' + error, widget);
					utility.errorResponseJSON(res, 'Error while processing forgot password request');
				} else {
					notificationTemplate.html = notificationTemplate.html.replace(cfg.mailer.tokenPlaceholder, token);
					notificationTemplate.html = notificationTemplate.html.replace(cfg.mailer.hostNamePlaceholder, cfg.hostname);	
					mailer.sendMail(notificationTemplate, {to: user.emailAddress}, user._id);
				}
			});

		    return res.send(JSON.stringify({result: true}));
		});
	} catch (e) {
		log.error('|auth.forgotPasswordRequest| Unknown -> ' + error, widget);
	    utility.errorResponseJSON(res, 'Error while processing forgot password request');
	}
};

exports.resetPasswordRequest = function(req, res) {
	try {
		var newPassword = req.body.newPassword;
		var token = req.body.token;
		
		log.info('|auth.resetPasswordRequest| Token -> ' + token, widget);

		User.resetPassword(token, newPassword, function(error, user) {
			if (error) {
				log.error('|auth.resetPasswordRequest.resetPassword| Unknown -> ' + error, widget);
				utility.errorResponseJSON(res, 'Error while resetting password');
			}

			if (!user.emailAddress) { 
				log.error('|auth.resetPasswordRequest.resetPassword| User not found for token -> ' + token, widget);
				utility.errorResponseJSON(res, 'Error while resetting password');
			}

			NotificationTemplate.findOne({name: cfg.mailer.resetPasswordTemplate}, function (error, notificationTemplate) {
				if (error) {
					log.error('|auth.resetPasswordRequest.NotificationTemplate| Unknown -> ' + error, widget);
					utility.errorResponseJSON(res, 'Error while resetting password');
				} else {
					mailer.sendMail(notificationTemplate, {to: user.emailAddress}, user._id);
				}
			});

		    return res.send(JSON.stringify({result: true}));
		});

	} catch (e) {
		log.error('|auth.resetPasswordRequest| Unknown -> ' + error, widget);
	    utility.errorResponseJSON(res, 'Error while resetting password');
	}
};
