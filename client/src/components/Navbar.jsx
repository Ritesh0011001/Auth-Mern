import React, { useContext } from 'react'
import { assets  } from '../assets/assets'
import { useNavigate } from 'react-router-dom'
import { AppContext } from '../context/AppContext'

const Navbar = () => {

  const navigate = useNavigate()
  const {userData, backendUrl,setUserData,setIsLoggedin} = useContext(AppContext)




  return (
    <div className='w-full flex justify-between items-center =-4 sm:p-6 sm:px-24 absolute top-0'>

      <img src={assets.logo} alt="" className='w-28 sm:w-32' />

      <button onClick={()=>navigate('/login')}
       className='flex items-center gap-2 border border-gray-500 rounded-full px-6 py-2 text-gray-800 hover:bg-gray-100 transition-all cursor-pointer'>Login <img src={assets.arrow_icon} alt="" /></button>


    </div>
  )
}

export default Navbar
