import express, { Request, Response } from 'express';
import dotenv from 'dotenv';
import connectDB from './config/connection';
import path from 'path';
import cookieParser = require('cookie-parser');
import errorHandler from './helpers/errorHandler';
import authRoutes from "./routes/userRoutes"
dotenv.config();

const app = express();
const PORT = process.env.PORT || 9000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({extended:true}));
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(cookieParser());



// Sample Route
app.get('/', (req: Request, res: Response) => {
    res.send('Hello, TypeScript with Express!');
});

app.use("/auth", authRoutes)

// error handler middleware
app.use(errorHandler);

// Server Listen
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
    connectDB()
});
