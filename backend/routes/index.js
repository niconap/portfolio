const express = require('express');
const router = express.Router();
const passport = require('passport');
const async = require('async');
const bcrypt = require('bcryptjs');
const { body, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const User = require('../models/user');
const Article = require('../models/article');

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

router.get('/article/:id', function (req, res, next) {
  async.parallel(
    {
      article: function (callback) {
        Article.findById(req.params.id).populate('user').exec(callback);
      },
    },
    function (err, results) {
      if (err) return next(err);
      if (results.article == null) {
        res.json({
          error: 404,
          message: `Article with id ${req.params.id} not found`,
        });
        return;
      }
      res.json({
        article: results.article,
      });
    }
  );
});

router.post('/article', verifyToken, [
  (req, res, next) => {
    jwt.verify(req.token, process.env.PASSPORT_SECRET, (err, authData) => {
      if (err) {
        console.log(err);
        res.sendStatus(403);
      } else {
        req.authData = authData;
        next();
      }
    });
  },

  body(
    'title',
    'Title must be longer than 3 characters and shorter than 100 characters.'
  )
    .isLength({ min: 3, max: 100 })
    .trim()
    .escape(),
  body(
    'content',
    'Content must be longer than 10 characters and shorter than 300 characters.'
  )
    .trim()
    .escape(),
  body('public', 'Public must be a Boolean (true or false).')
    .trim()
    .isBoolean(),

  (req, res, next) => {
    const errors = validationResult(req);

    var article = new Article({
      title: req.body.title,
      content: req.body.content,
      user: {
        firstname: req.authData.firstname,
        lastname: req.authData.lastname,
        username: req.authData.username,
        id: req.authData._id,
      },
      date: new Date(),
      public: req.body.public,
    });

    if (!errors.isEmpty()) {
      res.json({
        errors: errors.array(),
      });
      return;
    } else {
      article.save(function (err) {
        if (err) return next(err);
        res.json({
          message: 'Article successfully added!',
          article,
        });
      });
    }
  },
]);

router.put('/article/:id', verifyToken, [
  (req, res, next) => {
    jwt.verify(req.token, process.env.PASSPORT_SECRET, (err, authData) => {
      if (err) {
        console.log(err);
        res.sendStatus(403);
      } else {
        req.authData = authData;
        next();
      }
    });
  },

  body(
    'title',
    'Title must be longer than 3 characters and shorter than 100 characters.'
  )
    .isLength({ min: 3, max: 100 })
    .trim()
    .escape(),
  body(
    'content',
    'Content must be longer than 10 characters and shorter than 300 characters.'
  )
    .trim()
    .escape(),
  body('public', 'Public must be a Boolean (true or false).')
    .trim()
    .isBoolean(),

  (req, res, next) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      res.json({
        errors: errors.array(),
      });
      return;
    } else {
      async.parallel(
        {
          article: function (callback) {
            Article.findById(req.params.id).populate('user').exec(callback);
          },
        },
        function (err, results) {
          if (err) return next(err);
          if (results.article == null) {
            res.json({
              error: 404,
              message: `Article with id ${req.params.id} not found.`,
            });
            return;
          }
          if (results.article.user.username !== req.authData.username) {
            res.sendStatus(403);
            return;
          }

          var article = new Article({
            title: req.body.title,
            content: req.body.content,
            user: {
              firstname: req.authData.firstname,
              lastname: req.authData.lastname,
              username: req.authData.username,
              id: req.authData._id,
            },
            date: new Date(),
            public: req.body.public,
            _id: results.article._id,
          });

          Article.findByIdAndUpdate(
            req.params.id,
            article,
            { new: true },
            function (err, newArticle) {
              if (err) return next(err);
              res.json({
                message: 'Article successfully updated!',
                article: newArticle,
              });
            }
          );
        }
      );
    }
  },
]);

router.delete('/article/:id', function(req, res, next) => {
  
})

router.get('/auth/session', verifyToken, function (req, res, next) {
  jwt.verify(req.token, 'secret', (err, authData) => {
    if (err) {
      res.json({
        error: 403,
        message:
          'You are not logged in or you do not have permission to access this information or route.',
      });
      return;
    }
    res.json({
      authData,
    });
  });
});

function verifyToken(req, res, next) {
  const bearer = req.headers['authorization'];
  if (typeof bearer !== 'undefined') {
    req.token = bearer;
    next();
  } else {
    res.sendStatus(403);
  }
}

module.exports = router;
