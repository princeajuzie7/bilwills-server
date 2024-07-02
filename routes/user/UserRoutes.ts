import express from "express";
import { authenticated } from "../../middleware";
const UserRouter = express.Router()
import {ShowCurrentUser} from "../../controllers/users/UsersController"

UserRouter.route("/getactiveuser").get(authenticated, ShowCurrentUser);


export default UserRouter;