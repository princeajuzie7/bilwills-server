import express, { Express, Request, Response, NextFunction } from "express";
import httpStatus from "http-status";

import passport from "passport";
import userModel from "../../models/userModel";

/**
 * Returns the currently authenticated user.
 * @param req - The Express request object.
 * @param res - The Express response object.
 * @returns The currently authenticated user, or an error response.
 */
async function ShowCurrentUser(req: Request, res: Response) {
  const userId = req.user;

  try {
    const user = await userModel
      .findById(userId)
      .select({ password: 0, verificationToken : 0}); // Exclude password field

    return res.status(httpStatus.OK).json({ user });
  } catch (error) {
    return res
      .status(httpStatus.INTERNAL_SERVER_ERROR)
      .json({ error: "Internal server error" });
    
  }
}
export { ShowCurrentUser };

