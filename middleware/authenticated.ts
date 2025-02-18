import { isTokenValid, attachCookiesToResponse } from "../utils/jwt";
import { Request, Response, NextFunction } from "express";
import TokenSchema from "../models/TokenModel";
import { config } from "dotenv";
import { BadRequestError, UnAuthorized } from "../errors";
import jwt, { JwtPayload } from "jsonwebtoken";

config();
const secretKey: string = process.env.JWT_SECRET || "";

/**
 * Authenticates the user by checking the validity of the access token or refresh token.
 * If the access token is valid, it sets the user object in the request and returns.
 * If the refresh token is valid, it updates the refresh token in the database and sets the user object in the request.
 * If neither token is valid, it throws an UnAuthorized error.
 *
 * @param req - The Express request object containing the signed cookies.
 * @param res - The Express response object.
 * @param next - The Express next middleware function.
 * @returns void
 * @throws UnAuthorized - If authentication is invalid.
 */
export async function authenticated(
  req: Request | any,
  res: Response,
  next: NextFunction
): Promise<void> {
  const {
    refreshToken,
    accessToken,
  }: { refreshToken: string; accessToken: string } = req.signedCookies;


  const authHeader = req.headers.authorization; // Ensure this matches the cookie name in the browser

  if (!authHeader) {
    return next(new UnAuthorized("Unauthorized access"));
  }

  const token = authHeader.split(" ")[1];

  try {
    const decodedToken = isTokenValid(token) as JwtPayload;

    if (!decodedToken) {
      return next(new UnAuthorized("You are not logged in"));
    }

    req.user = decodedToken;

    next();
  } catch (error) {
    res.status(401).json({ message: "Invalid token" });
  }
}


export default authenticated;

