var mongoose = require('mongoose');
const Schema = mongoose.Schema;

const UserSchema = new Schema({
  username: String,
  password: String,
  firstname: String,
  lastname: String,
});

module.exports = mongoose.model('User', UserSchema);
