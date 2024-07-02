import express from "express";
import { teamSize, setupOrganization, setupTeam, inviteTeam } from "../../controllers/organization/OrganizationCont";
const organizationroute = express.Router();


organizationroute.route('/setuporganization').post(setupOrganization)

organizationroute.route('/teamsize').post(teamSize)

organizationroute.route('/setupteam').post(setupTeam)

organizationroute.route('/inviteteam').post(inviteTeam)

export default organizationroute;

