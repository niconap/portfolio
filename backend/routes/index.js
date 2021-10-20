const express = require('express');
const router = express.Router();
const passport = require('passport');
const async = require('async');
const bcrypt = require('bcryptjs');
const { body, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const User = require('../models/user');

/* GET home page. */
router.get('/', function (req, res, next) {
  res.json({ message: 'Homepage' });
});

router.post('/auth/login', (req, res, next) => {
  passport.authenticate('local', { session: false }, (err, user, info) => {
    if (err || !user) {
      return res.status(400).json({
        message: 'Something went wrong',
        user,
        info,
      });
    }

    req.login(user, { session: false }, (err) => {
      if (err) res.json({ error: err });

      const token = jwt.sign(user.toJSON(), process.env.PASSPORT_SECRET);
      return res.json({ user, token });
    });
  })(req, res);
});

router.post('/auth/register', [
  (res, req, next) => {
    next();
  },

  body('firstname', 'First name must be longer than 3 characters.')
    .trim()
    .isLength({ min: 3 })
    .escape(),
  body('lastname', 'Last name must be longer than 3 characters.')
    .trim()
    .isLength({ min: 3 })
    .escape(),
  body('username', 'Username must be longer than 3 characters.')
    .trim()
    .isLength({ min: 3 })
    .escape(),
  body('username', 'Username is already in use.').custom((value, { req }) => {
    return new Promise((resolve, reject) => {
      User.findOne({ username: req.body.username }, function (err, user) {
        if (err) return next(err);
        if (user && user.username == value) {
          reject(new Error('Username is already in use.'));
        }
        resolve(true);
      });
    });
  }),
  body('password', 'Password must be longer than 3 characters.')
    .trim()
    .isLength({ min: 8 })
    .escape(),
  body('code', 'Code is incorrect.').trim().equals(process.env.CODE),

  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.json({ errors: errors.array() });
      return;
    }
    bcrypt.hash(req.body.password, 10, (err, hashedPassword) => {
      if (err) return next(err);
      var user = new User({
        firstname: req.body.firstname,
        lastname: req.body.lastname,
        username: req.body.username,
        password: hashedPassword,
      }).save((err, newUser) => {
        if (err) return next(err);
        res.json({
          message: 'Signup complete!',
          user: newUser.username,
        });
      });
    });
  },
]);

module.exports = router;
