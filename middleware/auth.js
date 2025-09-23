// auth , isStudent , isAdmin 

const jwt = require("jsonwebtoken"); 
require("dotenv").config();

exports.auth = (req , res , next ) => {
     try{
     //  expract JWT token 
     // pending other ways to fetch token 
     const token = req.body.token || req.cookies.token || req.header("Authorization").replace("Bearer" , ""); 
     if(!token || token === undefined ) return res.status(401).json({
      success:false , 
      message:"Token missing"
     });

     // verify the token 
    
     try{
          const decode = jwt.verify(token , process.env.JWT_SECRET);
          console.log(decode ); 
          // why this ? 
          req.user = decode ; 

     }catch(error){
          console.log(error);
          return res.status(401).json({
      
      success:false , 
      message:"Token is invalid "
     });
     }
      next();
      
     }catch(error){
        return  res.status(401).json({
      success:false , 
      message:"something went wrong , while verifying the token ", 
     });
     }
}


exports.isStudent = (req, res , next) => {
     try{
     if(req.user.role !== "Student"){
          return res.status(401).json({
               success: false , 
               message:'This is a protected route for students ',
          })
     }

       next();
     }catch(error){
      return  res.status(500).json({
      success:false , 
      message:"user role is not matching ", 
     });
     }
}

exports.isAdmin = (req, res , next) => {
     try{
          console.log(req.user)
     if(req.user.role !== "Admin"){
          return res.status(401).json({
               success: false , 
               message:'This is a protected route for admin ',
          })
     }

       next();
     }catch(error){
      return  res.status(500).json({
      success:false , 
      message:"user role is not matching ", 
     });
     }
}