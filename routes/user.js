const express = require("express"); 
const router = express.Router();

const {login , signup} = require("../controllers/Auth");
const {auth , isStudent , isAdmin } = require("../middleware/auth");

 router.post("/login" , login );
router.post("/signup" , signup); 

//  tsting protected route for single middleware 
router.get( "/test" , auth , (req , res ) => {
    res.json({
        success:true, 
        message:'Welcome to the Protected route for TESTS '
    })
})

// protected route 
router.get("/student" , auth , isStudent , (req , res) => {
    res.json({
        success:true,
        message:"Welcome to the Protected route for Student"
    })
} ); 

router.get("/admin" , auth , isAdmin , (req , res)=> {
    res.json({
        success:true,
        message:"Welcome o the Protected route for admin "
    })
})
module.exports = router ;  
// hello