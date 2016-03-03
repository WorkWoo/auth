var config = require('./config.global');

config.env = 'development';
config.hostname = 'localhost:1337';
config.port = 1338;

//platform app
config.platform = {};
config.platform.url = 'http://localhost:1337';

//session
config.session.cookie.domain = '';

module.exports = config;