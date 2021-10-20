var mongoose = require('mongoose');
const Schema = mongoose.Schema;

const ArticleSchema = new Schema({
  title: String,
  content: [{ body: String }],
  date: { type: Date, default: Date.now },
  public: Boolean,
  Author: { type: Schema.Types.ObjectId, ref: 'User' },
});

module.exports = mongoose.model('Article', ArticleSchema);
