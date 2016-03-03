var cfg = require('../config/config');
var mongoose = require('mongoose');
var Schema = mongoose.Schema;

var orgSchema = new Schema({
	name: { type: String, required: true, unique: true },
	streetAddress: { type: String },
 	city: { type: String },
 	state: { type: String },
 	country: { type: String },
 	zip: { type: String },
 	emailAddress: { type: String },
 	primaryWorkItem: { type: String },
	_created_by: { type: Schema.Types.ObjectId, ref: 'User' },
    _updated_by: { type: Schema.Types.ObjectId, ref: 'User' }
}, cfg.mongoose.options);

var Org = mongoose.model('Org', orgSchema);

module.exports = Org;