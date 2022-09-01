import mongoose from "mongoose";

const ProductSchema = new mongoose.Schema({
  Name:{
    type:String,
    required:true
  },
  Price:{
    type:Number,
    required:true
  },
  Description:{
    type:String,
    required:true
  },
  cDate:{
    type:String,
    required:true
  },
  uDate:{
    type:String,
    required:true
  },
  _id:{
    type:String,
    required:true
  }
})
const Product = mongoose.model("Product",ProductSchema)
export default Product;