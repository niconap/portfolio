var mongoose = require('mongoose');
const Schema = mongoose.Schema;

const ArticleSchema = new Schema({
  title: String,
  content: String,
  date: { type: Date, default: Date.now },
  public: Boolean,
  user: {
    firstname: String,
    lastname: String,
    username: String,
    id: String,
  },
});

module.exports = mongoose.model('Article', ArticleSchema);
