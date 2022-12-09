const router = require('express').Router()
const userController = require('../controllers/user')
const { body,param } = require('express-validator')
const validation = require('../handlers/validation')
const tokenHandler = require('../handlers/tokenHandler')
const User = require('../models/user')


router.post(
  '/signup',
  body('username').isLength({ min: 8 }).withMessage(
    'username must be at least 8 characters'
  ),
  body('email').isLength({ min: 8 }).withMessage(
    'email must be at least 8 characters'
  ),
  body('password').isLength({ min: 8 }).withMessage(
    'password must be at least 8 characters'
  ),
  body('confirmPassword').isLength({ min: 8 }).withMessage(
    'confirmPassword must be at least 8 characters'
  ),
  body('username').custom(value => {
    return User.findOne({ username: value }).then(user => {
      if (user) {
        return Promise.reject('username already used')
      }
    })
  }),
  body('email').custom(value => {
    return User.findOne({ email: value }).then(email => {
      if (email) {
        return Promise.reject('email already used')
      }
    })
  }),
  validation.validate,
  userController.register
)

router.post(
  '/forgetPassword',
  body('username').isLength({ min: 8 }).withMessage(
    'username must be at least 8 characters'
  ),
  validation.validate,
  userController.forgetPassword
)

router.post(
  '/login',
  body('username').isLength({ min: 8 }).withMessage(
    'username must be at least 8 characters'
  ),
  body('password').isLength({ min: 8 }).withMessage(
    'password must be at least 8 characters'
  ),
  validation.validate,
  userController.login
)

router.post(
  '/verify-token',
  tokenHandler.verifyToken,
  (req, res) => {
    res.status(200).json({ user: req.user })
  }
)

router.post(
  '/google-api',
   userController.GoogleApi
)

router.get(
  '/:userId',
  param('userId').custom(value => {
    if (!validation.isObjectId(value)) {
      return Promise.reject('invalid id')
    } else return Promise.resolve()
  }),
  validation.validate,
  tokenHandler.verifyToken,
  userController.getOne
)

router.post(
  '/updatePassword',
  validation.validate,
  tokenHandler.verifyToken,
  userController.updatePassword
)

module.exports = router