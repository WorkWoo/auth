var cfg = require('../config/config');
var mongoose = require('mongoose');
var log = require('quikpaper-utils').qpLogger;
var widget = 'counter';
log.registerWidget(widget);

var Schema = mongoose.Schema;

var counterSchema = new Schema({
	col: { type: String, required: true},
	seq: { type: Number, default: 1000 },
 	prefix: { type: String, required: true },
	_org: { type: Schema.Types.ObjectId, ref: 'Org' },
	_created_by: { type: Schema.Types.ObjectId, ref: 'User' }
}, cfg.mongoose.options);

counterSchema.virtual('autonumber').get(function () {
	return this.prefix + this.seq;
});

counterSchema.statics.increment = function(collection, org, callback) {
	try {
		this.findOneAndUpdate({col: collection, _org: org}, {$inc: { seq: 1} }, {new: true}, function(error, counter)	{
        	if(error)
            	return callback(error);
        	callback(null, counter.autonumber);
    	});

	} catch (error) {
		log.error('|Counter.increment| Unknown -> ' + error, widget);
		return callback(error, false);
	}
};

var Counter = mongoose.model('Counter', counterSchema);

module.exports = Counter;