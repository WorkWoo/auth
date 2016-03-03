var env = process.env.NODE_ENV || 'development';
var cfg = require('./config_files/config.' + env);
module.exports = cfg;