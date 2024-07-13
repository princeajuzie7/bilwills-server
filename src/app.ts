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
const origin = ["http://localhost:3000", clienturl];

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
app.use(cookieParser(process.env.JWT_SECRET_KEY));


passport.serializeUser((user: any, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await userModel.findById(id);
    done(null, user);
  } catch (error) {
    done(error, null);
  }
});

const SessionSeceret = process.env.SESSION_SECERET;
if (!SessionSeceret) {
    throw new Error(
      "Session secret is not defined in environment variables."
    );
  
}



app.use(
  session({
    secret: "keyboard cat",
    resave: false,
    saveUninitialized: true,
    
  })
);


app.use(passport.initialize());
app.use(passport.session());

const ClientLiveUrl = process.env.CLIENT_LIVE_URL;
const ClientLocalUrl = process.env.CLIENT_LOCAL_URL;

if (!ClientLiveUrl || !ClientLocalUrl) {
  throw new BadRequestError(
    " Client Local URL must be specified in the configuration file."
  );
}
const origins =
  process.env.NODE_ENV === "production" ? ClientLiveUrl : ClientLocalUrl;

const clientID = process.env.OAUTH_CLIENT_ID;
const clientSecret = process.env.OAUTH__CLIENT_SECERET;

if (!clientID || !clientSecret) {
  throw new Error(
    "Google OAuth client ID and secret are not defined in environment variables."
  );
}

const ServertLiveUrl = process.env.SERVER_LIVE_URL;
const SeverLocalUrl = process.env.SERVER_PUBLIC_LOCAL_URL;

if (!ServertLiveUrl || !SeverLocalUrl) {
  throw new BadRequestError(
    " Client Local URL must be specified in the configuration file."
  );
}

passport.use(
  new GoogleStrategy(
    {
      clientID,
      clientSecret,
      callbackURL: "/client/api/auth/google/callback",
      scope: ["profile", "email"],
    },
    async (
      accessToken: string,
      refreshToken: string,
      profile: any,
      done: any
    ) => {
      console.log("Profile:", profile); // Log the profile object
      try {
        // Check if user already exists in the db based on the email
        let user = await userModel.findOne({ email: profile.emails[0].value });

        if (!user) {
          // If user does not exist, create a new user
             const verificationToken = crypto.randomBytes(40).toString("hex");
          user = await userModel.create({
            googleId: profile.id,
            username: profile.displayName,
            email: profile.emails[0].value,
            userdp: profile.photos[0].value,
            verificationToken: verificationToken,
          });

           await sendVerificationEmail({
             name: user?.username,
             email: user?.email,
             verificationToken: user?.verificationToken,
             origin: origins,
           });

        }

        return done(null, user);
      } catch (error) {
        return done(error, null);
      }
    }
  )
);

app.get(
  "/client/api/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get(
  "/client/api/auth/google/callback",
  passport.authenticate("google", {
    failureRedirect: "http://localhost:3000", // Redirect to a failure route
  }),
  (req: Request, res: Response) => {
    if (req.user) {
      res.redirect(`http://localhost:3000/auth/signup?newaccount=true`);
    } else {
      res.redirect(`http://localhost:3000`);
    }
  }
);


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