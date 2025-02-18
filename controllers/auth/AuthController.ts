import express, { Express, Request, Response, NextFunction } from "express";

import userModel from "../../models/userModel";
import * as jwt from "jsonwebtoken";
import { log } from "console";
import { BadRequestError, UnAuthorized } from "../../errors";
import crypto from "crypto";
import sendVerificationEmail from "../../utils/sendVerificationEmail";
import httpStatus, { BAD_REQUEST, OK } from "http-status";
import createTokenUser from "../../utils/createTokenUser";
import TokenModel from "../../models/TokenModel";
import { attachCookiesToResponse,createJWT } from "../../utils/jwt";
import sendPasswordResetToken from "../../utils/sendPasswordResetToken";
import createHash from "../../utils/createHash";
import passport from "passport";
import { Users } from "../../utils/createTokenUser";
interface Userbody {
  username: string;
  password: string;
  email: string;
}

interface ProviderSignupBody {
  provider: "google" | "github";
  email: string;
  password: string;
  username: string;
  type: "signup" | "login";
  userdp: string;
}

const ClientLiveUrl = process.env.CLIENT_LIVE_URL;
const ClientLocalUrl = process.env.CLIENT_LOCAL_URL;

if (!ClientLiveUrl || !ClientLocalUrl) {
  throw new BadRequestError(
    " Client Local URL must be specified in the configuration file."
  );
}
const origin =
  process.env.NODE_ENV === "production" ? ClientLiveUrl : ClientLocalUrl;

/**
 * Signs up a new user.
 * @param req - Express request object containing the username, email, and password.
 * @param res - Express response object used to send the success message or error response.
 * @param next - Express next function used to handle errors.
 * @returns A response with a success message and a status code of 201 (Created) if the user is created successfully, otherwise an error response.
 * @throws BadRequestError if the email already exists.
 * @throws UnAuthorized if the provided credentials are invalid.
 */
async function Signup(req: Request, res: Response, next: NextFunction) {
  console.log("auth controller hit successfully");
  const { username, email, password}: Userbody = req.body;

  try {

    
  const EmailAlreadyExist = await userModel.findOne({ email });

  if (EmailAlreadyExist ) {
    throw new UnAuthorized("Email already exist");
  }

  const verificationToken = crypto.randomBytes(40).toString("hex");
    const newUser = await userModel.create({
      username,
      email,
      password,
      verificationToken,
    });

 


    await sendVerificationEmail({
      name: newUser?.username,
      email: newUser?.email,
      verificationToken: newUser?.verificationToken,
      origin,
    });

    const user = await userModel.findOne({ email });

    if (!user) {
      console.log("incorrect email ");
      throw new UnAuthorized("invalid credentials");


    }

           const payload = {
             id: user._id,
             email: user.email,
           };

           const maxAge = 90 * 24 * 60 * 60 * 1000;

           const token = createJWT({ payload });

    const ispasswordCorrect = await user.comparePassword(password);
    console.log(ispasswordCorrect, "ispasswordCorrect");
    if (!ispasswordCorrect) {
      console.log("password incorrect");
      throw new UnAuthorized("invalid credentials");
    }

    res.status(httpStatus.CREATED).json({
      message: "Success! Please check your mail to verify your account",
      token,
    });

    log(newUser, "newUser");
  } catch (error: Error | any) {
    console.log(error);
    next(error);
  }
}


export async function SignupWithProvider(
  req: Request,
  res: Response,
  next: NextFunction
) {
  console.log("OAuth signup controller hit successfully");
  const { provider, username, email, password, type, userdp }: ProviderSignupBody =
    req.body;

  try {
    // Check if email already exists
    const existingUser = await userModel.findOne({ email });

    // If user exists but was created with a different provider
    if (existingUser && type === "login") {
      if (existingUser.provider !== provider) {
        throw new UnAuthorized(
          `Email already exists with ${existingUser.provider} authentication`
        );
      }
      // If user exists with same provider, we can update their details
      const token = createJWT({
        payload: {
          id: existingUser._id,
          email: existingUser.email,
        },
      });

      return res.status(httpStatus.OK).json({
        message: "Login successful",
        token,
      });
    }

    // Generate verification token
    const verificationToken = crypto.randomBytes(40).toString("hex");

    // Create new user
    const newUser = await userModel.create({
      username,
      email,
      password, // This is already hashed as sub+email from client
      verificationToken,
      provider,
      isVerified: provider === "google" || provider === "github", // Google emails are pre-verified
      userdp: userdp,
    });


    // Generate JWT token
    const token = createJWT({
      payload: {
        id: newUser._id,
        email: newUser.email,
      },
    });

    // Send response
    res.status(httpStatus.CREATED).json({
      message: "Account created successfully",
      token,
    });

    log(newUser, "newUser created with provider");
  } catch (error: any) {
    console.error("OAuth signup error:", error);
    next(error);
  }
}

/**
 * Verifies an email address by comparing the provided verification token with the stored token for the given email address.
 * If the tokens match, the user's email address is marked as verified and the function returns a response indicating success.
 * If the tokens do not match, or if the email address is not found, the function returns an error response.
 * @param req - Express request object
 * @param res - Express response object
 */

async function verifyEmail(req: Request, res: Response) {
  try {
    const {
      verificationToken,
      email,
    }: { verificationToken: string; email: string } = req.body;

    const user = await userModel.findOne({ email });
    if (!user) {
      throw new UnAuthorized("verification failed");
    }

    if (user.verificationToken !== verificationToken) {
      throw new UnAuthorized("verification failed");
    }

    user.isVerified = true;
    user.verified = new Date();
    user.verificationToken = "";

       await user.save();

    if (user.isVerified === true) {
         
      const tokenUser = createTokenUser(user as unknown as Users);
      let refreshToken = "";
      const existingToken = await TokenModel.findOne({ user: user._id });
  
      if (existingToken) {
        const { isValid } = existingToken;
        console.log("token existing");
  
        if (!isValid) {
          throw new UnAuthorized("invalid credentials");
        }
        refreshToken = existingToken.refreshToken;
  
        attachCookiesToResponse({ res, user: tokenUser, refreshToken });
        res.status(OK).json({ user: tokenUser });
        return;
      }
  
  
      refreshToken = crypto.randomBytes(40).toString("hex");
      const userAgent = req.headers["user-agent"];
      const ip = req.ip;
      const userToken: { refreshToken: string; ip: string | undefined; userAgent: string | undefined; user: unknown } = { refreshToken, ip, userAgent, user: user._id };
      await TokenModel.create(userToken);
      attachCookiesToResponse({ res, user: tokenUser, refreshToken });
       }
    


    return res.status(httpStatus.CREATED).json({
      message: "Email verified",
      isverified: user.isVerified,
      email: user.email,
    });
  } catch (error: Error | any) {
    return res.status(httpStatus.BAD_REQUEST).json({ message: error.message });
  }
}

/**
 * Signs in a user.
 * @param req - Express request object containing the email and password.
 * @param res - Express response object used to send the success message or error response.
 * @param next - Express next function used to handle errors.
 * @returns A response with a success message and a status code of 200 (OK) if the user is authenticated successfully, otherwise an error response.
 * @throws BadRequestError if the email or password is missing.
 * @throws UnAuthorized if the provided credentials are invalid.
 */
async function Signin(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    if (!req.body.email || !req.body.password) {
      throw new BadRequestError("Please provide email and password");
    }

    const { email, password }: { email: string; password: string } = req.body;

    const user = await userModel.findOne({ email });
    if (!user) {
      console.log("incorrect email ");
      throw new UnAuthorized("invalid credentials");
    }

    const ispasswordCorrect = await user.comparePassword(password);
    console.log(ispasswordCorrect, "ispasswordCorrect");
    if (!ispasswordCorrect) {
      console.log("password incorrect");
      
      throw new UnAuthorized("invalid credentials");
    }

    // if (!user.isVerified) {
    
    //   throw new UnAuthorized("Please verify your email first");
    // }
    
      const tokenUser = createTokenUser(user as unknown as Users);
    let refreshToken = "";
    const existingToken = await TokenModel.findOne({ user: user._id });

    if (existingToken) {
      const { isValid } = existingToken;
      console.log("token existing");

      if (!isValid) {
        throw new UnAuthorized("invalid credentials");
      }
      refreshToken = existingToken.refreshToken;

      attachCookiesToResponse({ res, user: tokenUser, refreshToken });

      
    const token = createJWT({
      payload: {
        id: user._id,
        email: user.email,
      },
    });

      
      res.status(OK).json({
        tokenUser: tokenUser,
        token: token,
        message: "logged in successfully",
      });
      return;
    }

    refreshToken = crypto.randomBytes(40).toString("hex");

    const token = createJWT({
      payload: {
        id: user._id,
        email: user.email,
      },
    });

    const userAgent = req.headers["user-agent"];
    const ip = req.ip;
    const userToken = { refreshToken, ip, userAgent, user: user._id };
    await TokenModel.create(userToken);
    attachCookiesToResponse({ res, user: tokenUser,  refreshToken });
    res
      .status(OK)
      .json({
        tokenUser: tokenUser,
        token: token,
        message: "logged in successfully",
      });
  } catch (error) {
    next(error);
  }
}

/**
 * ForgotPassword function is used to send a password reset token to the user's email address.
 * @param req - Express request object containing the user's email address.
 * @param res - Express response object used to send the success message.
 * @param next - Express next function used to handle errors.
 * @returns A response with a success message and a status code of 200 (OK).
 * @throws BadRequestError if the email does not exist.
 */
async function forgotPassword(req: Request, res: Response, next: NextFunction) {
  const { email } = req.body;

  try {
    const user = await userModel.findOne({ email });
    if (!user) {
      throw new BadRequestError("Email does not exist");
    }

    const passwordResetToken = crypto.randomBytes(70).toString("hex");
    await sendPasswordResetToken({
      passwordResetToken,
      username: user.username,
      email: user.email,
      origin: origin,
    });
    const tenminutes = 1000 * 60 * 10;
    const passwordRestTokenExipiry = new Date(Date.now() + tenminutes);
    user.passwordToken = createHash(passwordResetToken);
    user.passwordTokenExpiration = passwordRestTokenExipiry;
    await user.save();
    res.status(httpStatus.OK).json({
      message: "Link sent Sucesfully please check your email",
    });
  } catch (error) {
    next(error);
  }
}

/**
 * Verifies a password reset token.
 * @param req - Express request object containing the token.
 * @param res - Express response object used to send the success message.
 * @param next - Express next function used to handle errors.
 * @returns A response with a success message and a status code of 200 (OK) if the token is valid, otherwise an error response.
 * @throws UnAuthorized if the token is invalid or has expired.
 */
async function verifyPasswordResetToken(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  const { token } = req.body;

  if (!token) {
   res
      .status(httpStatus.BAD_REQUEST)
      .json({ message: "Token is required" });
        return
  }

  const encryptedToken = createHash(token);
  const currentDate = Date.now();

  try {
    const user = await userModel.findOne({
      passwordToken: encryptedToken,
      passwordTokenExpiration: { $gt: currentDate },
    });

    if (!user) {
       res
        .status(httpStatus.UNAUTHORIZED)
        .json({ message: "Invalid token or token expired" });
        return;
    }

    res.status(httpStatus.OK).json({ message: "Valid token" });
  } catch (error) {
    console.error("Error verifying password reset token:", error);
    res
      .status(httpStatus.INTERNAL_SERVER_ERROR)
      .json({ message: "An error occurred while verifying the token" });
  }
}


/**
 * Updates the user's password.
 * @param req - Express request object containing the new password, confirmation of the new password, and the token.
 * @param res - Express response object used to send the success message.
 * @param next - Express next function used to handle errors.
 * @returns A response with a success message and a status code of 200 (OK) if the password is updated successfully, otherwise an error response.
 * @throws BadRequestError if the new password is not provided.
 * @throws BadRequestError if the confirmation of the new password is not provided.
 * @throws BadRequestError if the token is invalid or expired.
 * @throws Error if there is an error updating the password.
 */
async function updatePassword(req: Request, res: Response, next: NextFunction) {
  try {
    if (!req.body.password || !req.body.confirmpassword) {
      throw new BadRequestError("New password is required");
    }

    const { password, confirmpassword, token } = req.body;

    const currentDate = new Date();

    const encryptedToken = createHash(token);

    const user = await userModel.findOne({
      passwordToken: encryptedToken,
      passwordTokenExpiration: { $gt: currentDate },
    });

    if (!user) {
      throw new BadRequestError("Token is invalid or expired");
    }

    if (
      user.passwordToken === createHash(token) &&
      user.passwordTokenExpiration > currentDate
    ) {
      user.password = password;
      user.passwordToken = "";
      user.passwordTokenExpiration = "";
      console.log("updated successfully");
      await user.save();
      return res.status(httpStatus.OK).json({
        message: "Password updated successfully",
      });
    }
  } catch (error: Error | any) {
    throw new Error(error);
  }
}



// async function GoogleAuth() {
//   console.log('google auth hit')
//   passport.authenticate("google", {scope: ["profile", "email"]});
// }

// async function GoogleAuthCallback(req:Request, res:Response) {
// passport.authenticate("google", {
//   failureRedirect: "http://localhost:3001", // Redirect to a failure route
// }),
//   (req: Request, res: Response) => {
//     if (req.user) {
//       res.redirect(`http://localhost:3000/addBusiness`);
//     } else {
//       res.redirect(`http://localhost:3000`);
//     }
//   };
// }

/**
 * Returns the currently authenticated user.
 * @param req - The Express request object.
 * @param res - The Express response object.
 * @returns The currently authenticated user, or an error response.
 */
function ShowCurrentUser(req: Request, res: Response) {
  return res.status(httpStatus.OK).json({ user: req.user });
}


function LogOut(req: Request, res: Response) {
  
  
}
export {
  Signup,
  Signin,
  verifyEmail,
  forgotPassword,
  updatePassword,
  verifyPasswordResetToken,
  ShowCurrentUser,
};
