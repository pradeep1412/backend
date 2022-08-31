import  Express, { json } from "express";
import dotenv from "dotenv"
import connectDB from "./services/mongodb/connectDB";
import cors from "cors"
import authRoutes from "./routes/authRoutes"

dotenv.config()

connectDB()

const app = Express()
app.use(cors())
app.use(Express.json())

app.use("/api/v1/auth",authRoutes)

const port = process.env.PORT || 3003

app.listen(port,(req,res)=>{
  console.log(`server listing at port ${port}`)
});