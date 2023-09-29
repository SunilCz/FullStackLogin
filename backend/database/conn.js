import mongoose from "mongoose";
import ENV from '../config.js'

async function connect() {
    try {
        const uri = ENV.MONGO_URI;

        mongoose.set('strictQuery', true);
        const db = await mongoose.connect(uri
      );

        console.log("Database Connected");
        return db;
    } catch (error) {
        console.error("Error connecting to the database:", error);
        throw error; // Re-throw the error to handle it at a higher level if necessary
    }
}

export default connect;
