import express, { Express, Request, Response,NextFunction, Application } from "express";
import AuthRouter from "../routes/auth/AuthRoutes";
import Dbconnection from "../database/dbConnection";
import cors from "cors";
import cookieParser from "cookie-parser";
import { config } from "dotenv";
import session from "express-session";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import userModel from "../models/userModel";
import sendVerificationEmail from "../utils/sendVerificationEmail";
import UserRouter from "../routes/user/UserRoutes";
import { BadRequestError } from "../errors";
import crypto from "crypto";
import httpStatus from "http-status";
import organizationroute from "../routes/organization/organizationRoute";
config()

/**
 * Initializes the Express application.
 * @param none
 * @returns Express application instance.
 */
const app: Application = express();

const clienturl = "https://bilwills.vercel.app";

if (!clienturl) {
  throw new Error("CLIENT_LIVE_URL is not defined");
}


/**
 * Sets the origins allowed to send requests to the Express application.
 * @param none
 * @returns none
 */
const origin = ["http://localhost:3000", "https://bilwills.vercel.app"];

/**
 * Configures CORS settings for the Express application.
 * @param none
 * @returns none
 */
app.use(
  cors({
    origin: origin,
    credentials: true,
    methods: ["GET", "HEAD", "PUT", "PATCH", "POST", "DELETE"],
  })
);


app.use(cookieParser(process.env.JWT_SECRET_KEY));


/**
 * Parses JSON data for the Express application.
 * @param none
 * @returns none
 */
app.use(express.json());

/*
 * Parses cookies for the Express application.
 * @param none
 * @returns none
 */

/**
/**
 * Mounts the AuthRouter to the specified path.
 * @param none
 * @returns none
 */
app.use("/client/api/auth", AuthRouter);



app.use("/client/api/user", UserRouter);

app.use("/client/api/organization", organizationroute);
/**
 * Connects the Express application to the database.
 * @param app Express application instance.
 * @returns none
 */
Dbconnection(app);


/**
 * Exports the Express application instance.
 * @param none
 * @returns Express application instance.
 */
export default app;