import Express, { json } from "express";
import User from "../services/mongodb/modules/users.js"
import bcrypt, { hash } from "bcrypt"
import Jwt from "jsonwebtoken";
// import isAdmin from "../middlewares/isAdmin";
import { body,validationResult } from "express-validator";


const router = Express.Router()

/*
  type:get
  path:/api/v1/auth/users
  params:none
  isProtected:true
*/

// router.get("/users",isAdmin,async (req,res)=>{
//   try {
//     const users = await User.find({})
//     res.json({users})
//   } catch (error) {
//     console.log(error.message)
//     res.status(500).json({users:[]})
//   }
// })

/*
  type:post
  path:/api/v1/auth/signup
  params:none
  isProtected:true
*/

router.post("/signup",
body('firstName').isLength({min:3}),
body('email').isEmail(),
body('password').isLength({min:6,max:10})
,async (req,res)=>{
  const {errors} = validationResult(req)
  if(errors.length > 0 ) return res.status(403).json({errors,message:"Bad request"})
  try {
    const {email,firstName,lastName,password,role="user"} = req.body
    
    const salt = await bcrypt.genSalt(10)
    const hashedpassword = await bcrypt.hash(password,salt)

    const user = new User({email,firstName,lastName,password:hashedpassword,role})
    await user.save()
    res.send("request is send")
  } catch (error) {
    console.log(error.message)
    res.status(500).json({users:[]})
  }
})

/*
  type:post
  path:/api/v1/auth/login
  params:none
  isProtected:true
*/

router.post("/login",async (req,res)=>{
  try {
    const {email,password} = req.body
    const user = await User.findOne({email})
    if (user){
      const isVerified  = await bcrypt.compare(password,user.password)
      if(isVerified){
        const {_id,role} = user
        const token = Jwt.sign({_id,role},process.env.JWT_SECERT,{expiresIn:"1h"})
        return res.json({token})
      }else{
        return res.json({token:null,message:"unathorised"})
      }
    }
    return res.json({token:null,message:"User doesn't exist"})
    
  } catch (error) {
    console.log(error.message)
    res.status(500).json({token:null})
  }
})



export default router