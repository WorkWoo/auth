var config = require('./config.global');

config.env = 'stage';
config.hostname = 'appstage.workwoo.com';

//platform app
config.platform = {};
config.platform.url = 'http://appstage.workwoo.com/';

module.exports = config;