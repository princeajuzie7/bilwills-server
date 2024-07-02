import moongoose from "mongoose";

const Orgnaziation = new moongoose.Schema({
    name: {
      type: String,
    required: true
    },
    teamsize: {
        enum: ["team", "individual", "company"],
        required: true,
    },
    setupteam: {
        
  },
    image: {
      type: String,
      
    } 
})

const OrgnaziationModel =  moongoose.model("Orgnaziation", Orgnaziation)

export default OrgnaziationModel;
