const User = require('../models/user')
const CryptoJS = require('crypto-js')
const jsonwebtoken = require('jsonwebtoken')
const nodemailer = require('nodemailer');
const {OAuth2Client,} = require('google-auth-library')
const {generateFromEmail} = require('unique-username-generator')

exports.register = async (req, res) => {
  const { password } = req.body
  try {
    req.body.password = CryptoJS.AES.encrypt(
      password,
      process.env.PASSWORD_SECRET_KEY
    )

    const user = await User.create(req.body)
    const token = jsonwebtoken.sign(
      { id: user._id },
      process.env.TOKEN_SECRET_KEY,
      { expiresIn: '24h' }
    )
    res.status(201).json({ user, token })
  } catch (err) {
    res.status(500).json(err)
  }
}

exports.forgetPassword = async (req, res) => {
  const { username } = req.body
  const password = Math.random().toString(36).slice(-8)
  const transport = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASSWORD
    }
  });
  try {
    const PasswordHash = CryptoJS.AES.encrypt(
      password,
      process.env.PASSWORD_SECRET_KEY
    )
    console.log(PasswordHash.toString()) 
    const user = await User.findOneAndUpdate({$or:[ {username},{email: username}] },{password:PasswordHash.toString()}).select('email')
    //send email reset
    console.log(user)
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: user.email,
      subject: 'Password reset',
      html: `Your new password is <b>${password}</b>. You can use this password to log in to your account.`
    };
    transport.sendMail(mailOptions, (err, info) => {
      if (err) {
        console.error(err);
      } else {
        console.log(`Email sent: ${info.response}`);
        console.log(password)
      }
    });
    res.status(200).json('Unathorized')
  } catch (err) {
    res.status(500).json(err)
    console.log(err)
  }
}

exports.login = async (req, res) => {
  const { username, password } = req.body
  try {
    const user = await User.findOne({$or:[ {username},{email: username}] }).select('password username')
    if (!user) {
      return res.status(401).json({
        errors: [
          {
            param: 'username',
            msg: 'Invalid username or password'
          }
        ]
      })
    }

    const decryptedPass = CryptoJS.AES.decrypt(
      user.password,
      process.env.PASSWORD_SECRET_KEY
    ).toString(CryptoJS.enc.Utf8)

    if (decryptedPass !== password) {
      return res.status(401).json({
        errors: [
          {
            param: 'username',
            msg: 'Invalid username or password'
          }
        ]
      })
    }

    user.password = undefined

    const token = jsonwebtoken.sign(
      { id: user._id },
      process.env.TOKEN_SECRET_KEY,
      { expiresIn: '24h' }
    )

    res.status(200).json({ user, token })

  } catch (err) {
    res.status(500).json(err)
  }
}

exports.GoogleApi = async (req, res) => {
  try {
    const { credential, clientId } = req.body
    const oAuth2Client = new OAuth2Client(
      process.env.CLIENT_ID_G,
      process.env.CLIENT_SECRET_G,
      'postmessage',

    );

    const ticket = await oAuth2Client.verifyIdToken({
      idToken: credential,
      audience: clientId,
    })
    console.log(ticket);
    const payload = ticket.getPayload()
    const exp = parseInt(payload['exp'], 10)

    let user = await User.findOne({ email:payload.email })
    if(!user){
      const username = generateFromEmail(payload.email,3)
      console.log(username)
      const password = Math.random().toString(36).slice(-8)
      const PasswordHash = CryptoJS.AES.encrypt(
        password,
        process.env.PASSWORD_SECRET_KEY
      )
      user = await User.create({email:payload.email,username:username,password:PasswordHash.toString()})
    }
    const token = jsonwebtoken.sign(
      { id: user._id },
      process.env.TOKEN_SECRET_KEY,
      { expiresIn: '24h' }
    )
    res.status(200).json({ user, token })
  } catch (error) {
    throw error
  }
}

exports.getOne = async (req, res) => {
  const { userId } = req.params
  try {
    const user = await User.findById(userId).select('email password username')
    const decryptedPass = CryptoJS.AES.decrypt(
      user.password,
      process.env.PASSWORD_SECRET_KEY
    ).toString(CryptoJS.enc.Utf8)
    user.password = decryptedPass;
    if (!user) return res.status(404).json('User not found')
    res.status(200).json(user)

  } catch (err) {
    res.status(500).json(err)
  }
}

exports.updatePassword = async (req, res) => {
  const { username1,password1 } = req.body
  console.log(password1) 
  try {
    const PasswordHash = CryptoJS.AES.encrypt(
      password1,
      process.env.PASSWORD_SECRET_KEY
    )
    console.log(PasswordHash.toString()) 
    const user = await User.findOneAndUpdate({username:username1},{password:PasswordHash.toString()}).select('email')
    //send email reset
    res.status(200).json(user)
  } catch (err) {
    res.status(500).json(err)
    console.log(err)
  }
}
