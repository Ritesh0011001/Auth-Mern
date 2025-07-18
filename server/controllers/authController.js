import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import userMOdel from '../models/usermodel.js';




export const register = async (req,res) => {
  const {name,email,password} = req.body;

  if(!name || !email || !password){
    return res.json({success:false, message:'Missing Details'})
  }
  try {

    const existingUser = await userMOdel.findOne({email})

    if(existingUser){
      return res.json({success:false, message:'User already exists'})

    }

    const hashedPassword = await bcrypt.hash(password, 10)

    const user = new userMOdel({name, email, password:hashedPassword})

    await user.save()

    const token = jwt.sign({id: user._id},)
    
  } catch (error) {
    res.json({success:false,message:error.message})
    
  }
  
}