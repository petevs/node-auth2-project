const { JWT_SECRET } = require("../secrets"); // use this secret!
const jwt = require('jsonwebtoken')
const { find } = require('../users/users-model')


const restricted = async (req, res, next) => {
  /*
    If the user does not provide a token in the Authorization header:
    status 401
    {
      "message": "Token required"
    }

    If the provided token does not verify:
    status 401
    {
      "message": "Token invalid"
    }

    Put the decoded token in the req object, to make life easier for middlewares downstream!
  */
  try {
    // const token = req.cookies.token
    const token = req.headers.authorization
    if (!token){
      return res.status(401).json({
        message: "Token required"
      })
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
      if(err){
        return res.status(401).json({
          message: "Token invalid"
        })
      }
      req.token = decoded

      next()
    })


  } catch (err) {
    next(err)
  }
}

const only = role_name => (req, res, next) => {
  /*
    If the user does not provide a token in the Authorization header with a role_name
    inside its payload matching the role_name passed to this function as its argument:
    status 403
    {
      "message": "This is not for you"
    }

    Pull the decoded token from the req object, to avoid verifying it again!
  */
 try {
   const decodedToken = req.token
   
   if(role_name !== decodedToken.role_name){
    return res.status(403).json({
      message: "This is not for you"
    })
   }
   next()
 } catch(err){
   next(err)
 }
}


const checkUsernameExists = async (req, res, next) => {
  /*
    If the username in req.body does NOT exist in the database
    status 401
    {
      "message": "Invalid credentials"
    }
  */
  try{
    const results = await find()
    const matchingUsernames = results.filter(users => 
      users.username === req.body.username)
    if(matchingUsernames.length === 0){
      return res.status(401).json({
        message: 'Invalid credentials'
      })
    }
    next()
  } catch(err){
    next(err)
  }
}


const validateRoleName = async (req, res, next) => {
  /*
    If the role_name in the body is valid, set req.role_name to be the trimmed string and proceed.

    If role_name is missing from req.body, or if after trimming it is just an empty string,
    set req.role_name to be 'student' and allow the request to proceed.

    If role_name is 'admin' after trimming the string:
    status 422
    {
      "message": "Role name can not be admin"
    }

    If role_name is over 32 characters after trimming the string:
    status 422
    {
      "message": "Role name can not be longer than 32 chars"
    }
  */

 
 try{
   
   if(!req.body.role_name || req.body.role_name.trim() === ''){
     req.role_name = 'student'
     return next()
   }


  if(req.body.role_name.trim() === 'admin'){
    return res.status(422).json({
      message: 'Role name can not be admin'
    })
  }

  if(req.body.role_name.trim().length > 32){
    return res.status(422).json({
      message: "Role name can not be longer than 32 chars"
    })
  }

  req.role_name = req.body.role_name.trim()
  next()

} catch(err){
  next(err)
}
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
