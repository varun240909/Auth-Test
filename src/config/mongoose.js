import mongoose from "mongoose";

const ConnectMongoose = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGO_URI, {
      dbName: "sandbox",
    });
    console.log(`Mongoose connected: ${conn.connection.host}`);
  } catch (err) {
    console.log("Error connecting to MongoDB:", err.message);
    process.exit(1);
  }
};

export default ConnectMongoose;
