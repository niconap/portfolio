const createError = require('http-errors');
const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const logger = require('morgan');
const dotenv = require('dotenv').config();
const passport = require('passport');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const passportJWT = require('passport-jwt');
const JWTStrategy = passportJWT.Strategy;
const ExtractJWT = passportJWT.ExtractJwt;
const LocalStrategy = require('passport-local').Strategy;
const User = require('./models/user');

passport.use(
  new LocalStrategy(
    { usernameField: 'username', passwordField: 'password' },
    function (username, password, done) {
      User.findOne({ username: username }, (err, user) => {
        if (err) return done(err);
        if (!user) return done(null, false, { message: 'Incorrect username' });
        bcrypt.compare(password, user.password, (err, res) => {
          if (res) return done(null, user);
          return done(null, false, { message: 'Incorrect password' });
        });
      });
    }
  )
);

passport.use(
  new JWTStrategy(
    {
      jwtFromRequest: ExtractJWT.fromAuthHeaderAsBearerToken(),
      secretOrKey: process.env.PASSPORT_SECRET,
    },
    function (jwtPayload, callback) {
      return user
        .findOneById(jwtPayload.id)
        .then((user) => {
          return callback(null, user);
        })
        .catch((err) => {
          return callback(err);
        });
    }
  )
);

var indexRouter = require('./routes/index');

var app = express();

var mongoose = require('mongoose');
const user = require('./models/user');
var mongoDB = process.env.MONGODB_URI;
mongoose.connect(mongoDB, { useNewUrlParser: true, useUnifiedTopology: true });
var db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error: '));

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({ secret: process.env.PASSPORT_SECRET }));
app.use(passport.initialize());
app.use(passport.session());

app.use('/', indexRouter);

// catch 404 and forward to error handler
app.use(function (req, res, next) {
  next(createError(404));
});

// error handler
app.use(function (err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};
  console.log(err);
  // render the error page
  res.status(err.status || 500);
  res.json({ message: 'An error occured' });
});

module.exports = app;
