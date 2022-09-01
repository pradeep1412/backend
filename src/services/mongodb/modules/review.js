import mongoose from "mongoose";

const ReviewSchema = new mongoose.Schema({
  userId:{
    type:mongoose.Types.ObjectId,
    required:true
  },
  description:{
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
  },
  product_id:{
    type:String,
    required:true
  }
  

})
const Review = mongoose.model("Review",ReviewSchema)
export default Review;