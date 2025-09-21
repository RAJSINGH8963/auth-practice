
const bcrypt = require("bcrypt");  

const User = require("../models/User");

require("dotenv").config();

const jwt = require("jsonwebtoken"); 
// signup route handler 

exports.signup  = async (req , res ) => {
    try{
    // get data 
    const {name , email , password , role } = req.body ; 

    // check if user alredy exist 
    const existingUser = await User.findOne({email});
    if(existingUser){
        return res.status(400).json({
            success:false , 
            message:"user alredy Exist " , 
        }); 
    }
    // secure password 
    let hashedPassword ; 
    try{
        hashedPassword = await bcrypt.hash(password , 10 ) ; 
    }
    catch(err){
         return res.status(500).json({
            success:false , 
            message:"error in hashing password Exist " , 
        }); 
    }

    // create entry for user 
    const user = await User.create({
        name,email,password:hashedPassword, role 
    })

    return res.status(200).json({
        success:true,
        message:"user created succesfully" , 
    })
    }catch(error){
       console.log(error);
       return res.status(500).json({
        success:false , 
        message:"user cannot be registered , please try again later "
       })
    }
}

exports.login = async (req , res ) => { 

    try{
    // data fetch
      const {email , password} = req.body ; 
    //   validation on email and password 
      if(!password || !email){
        return res.status(400).json({
            success:false, 
            message:'please fill all the details carefully '
        });
      }
    //   check for resigestered User 
      let user = await User.findOne({email});
    //   if not a registered found 
      if(!user){
        return res.status(300).json({
        success:false , 
        message:"user not found "
        });      
       }
     
    const payload = {
        email : user.email,
        id: user._id,
        role: user.role,
    };
    //   verify password  generate a JWT token 
    if (await bcrypt.compare(password,user.password) ){
        
         
    //   password correct 
         
         let token = jwt.sign(payload,process.env.JWT_SECRET,{
                     expiresIn : "2h",
                     });
         user.token = token ; 
         user.password = " " ; 
         user = user.toObject();
         user.token = token ; 
         
         const option = {
          expires : new Date( Date.now() + 3 * 24 * 60 * 60 * 1000),
          httpOnly:true , 
         }
         
         res.cookie("rajCookie" , token , option).status(200).json({
            success:true,
            token,
            user,
            message:"user Logged in successfully" , 
         });
    }else{
        // password do not match 
        return res.status(403).json({
            success:false , 
            message:"Password Incorrect",
        });
    }
    }catch(error){
       console.log(error);
       return res.status(500).json({
        success:false, 
        message:"login failer " 
       })
    }


};