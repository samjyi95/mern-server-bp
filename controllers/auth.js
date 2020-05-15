require('dotenv').config()
let db = require('../models')
let router = require('express').Router()
let jwt = require('jsonwebtoken')

// POST /auth/login (find and validate user; send token)
router.post('/login', (req, res) => {
  console.log(req.body)

  db.User.findOne({ email: req.body.email})
  .then(user => {
    //check whether the user exists
    if (!user) {
      return res.status(404).send({ message: 'User was not found '})
    }

    //They exist - but make sure they have the correct passwor
    if (!user.validPasswords(req.body.password)) {
      //incorrect pasword, send error 
      return res.status(401).send({ message: 'invalid credentials '})
    }

    //We have a good user - make them a token 
    let token = jwt.sign(user.toJSON(), process.env.JWT_SECRET, {
      expiresIn: 60*60*8 //8hours in secs
    }) 
    res.send({ token })
  })
  .catch(err => {
    console.log('Error in POST auth/login', err)
    res.status(503).send({ message: 'Server-side or DB error'})
  })
})

// POST to /auth/signup (create user; generate token)
router.post('/signup', (req, res) => {
  console.log(req.body)
  //look up the user by email to make sure they're new 
  db.User.findOne({email: req.body.email })
  .then(user => {
    //if the user exists already, do not let them create another account 
    if (user) {
      //NO no1 sign up instead
      return res.status(416).send({ message: 'Email already in use' })
    }

    //we know the user is legitamely a new user: Create them!!
      db.User.create(req.body)
      .then(newUser => {
        //Yay1 things worked and the user exists! Now Create a new token for the new user
        let token = jwt.sign(newUser.toJSON(), process.env.JWT_SECRET, {
          expiresIn: 120//60 * 60 * 8 // 8 hours in seconds
        }) 

        res.send({ token })
      })
      .catch(innerErr => {
        console.log('Error creating user', innerErr)
        if (innerErr.name === 'ValidationError') {
          res.status(412).send({message: `Validation Error! ${innerErr.message}.` })
        }
        else {
          res.status(500).send({ message: 'Error creating user'})
        }
      })
  })
  .catch(err => {
    console.log('ERROR IN POST /auth/signup', err)
    res.status(503).send({ message: 'Database or server error' })
  })
})


module.exports = router
