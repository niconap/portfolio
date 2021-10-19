var mongoose = 'mongoose';
const { Schema } = mongoose;

const ArticleSchema = new Schema({
  title: String,
  content: [{ body: String }],
  date: { type: Date, default: Date.now },
  public: Boolean,
});

module.exports = mongoose.model('Article', ArticleSchema);
