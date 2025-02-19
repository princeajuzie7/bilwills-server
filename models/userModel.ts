import mongoose, { Document, Model } from "mongoose";
import bcrypt from "bcryptjs";
import validator from "validator";

type Provider = "google" | "github";
type SubscriptionTier = "free" | "pro" | "enterprise";
type Theme = "light" | "dark" | "system";
type AccountType = "user" | "admin";

interface UserDocument extends Document {
  // Basic Profile
  username: string;
  email: string;
  password: string;
  userdp: string;
  provider: Provider;
  accountType: AccountType;

  // Authentication
  verificationToken: string;
  isVerified: boolean;
  verified: Date;
  passwordToken?: string;
  passwordTokenExpiration: Date | string;

  // Subscription & Billing
  subscriptionTier: SubscriptionTier;
  subscriptionStatus: "active" | "cancelled" | "expired";
  subscriptionRenewalDate?: Date;
  billingAddress?: {
    line1: string;
    line2?: string;
    city: string;
    state: string;
    country: string;
    postalCode: string;
  };
  paymentMethods: Array<{
    type: "card" | "paypal";
    last4?: string;
    brand?: string;
    expiryMonth?: number;
    expiryYear?: number;
    isDefault: boolean;
  }>;

  // Usage & Limits
  monthlyDownloads: {
    count: number;
    limit: number;
    resetDate: Date;
  };
  totalDownloads: number;

  // Icons & Favorites
  favoriteIcons: Array<{
    iconId: mongoose.Schema.Types.ObjectId;
    dateAdded: Date;
    lastUsed: Date;
    customProperties?: {
      color?: string;
      size?: number;
      animation?: string;
    };
  }>;
  customIcons: Array<{
    iconId: mongoose.Schema.Types.ObjectId;
    name: string;
    dateCreated: Date;
    lastModified: Date;
  }>;

  // Settings & Preferences
  settings: {
    theme: Theme;
    emailNotifications: {
      marketing: boolean;
      updates: boolean;
      usage: boolean;
    };
    defaultIconProperties: {
      size: number;
      color: string;
      animation: string;
    };
    autoDownload: boolean;
    showPreviewAnimations: boolean;
    showDimensions: boolean;
  };

  // Usage History
  recentActivity: Array<{
    type: "download" | "favorite" | "create" | "modify";
    iconId: mongoose.Schema.Types.ObjectId;
    timestamp: Date;
    details?: Record<string, any>;
  }>;

  // API Access
  apiKeys: Array<{
    key: string;
    name: string;
    createdAt: Date;
    lastUsed: Date;
    permissions: string[];
  }>;

  comparePassword(userpassword: string): Promise<boolean>;
}

const emailValidator = (email: string) => {
  return /\S+@\S+\.\S+/.test(email);
};

const UserSchema = new mongoose.Schema<UserDocument>(
  {
    // Basic Profile
    username: {
      type: String,
      required: [true, "Please provide a username"],
      unique: true,
      trim: true,
    },
    email: {
      type: String,
      required: [true, "Please provide an email"],
      unique: true,
      validate: {
        validator: emailValidator,
        message: "Please provide a valid email",
      },
    },
    password: {
      type: String,
      required: [true, "Please provide a password"],
      minlength: 8,
    },
    accountType: {
      type: String,
      enum: ["user", "admin"],
      default:  "user"
    },
    userdp: {
      type: String,
      default: "",
    },
    provider: {
      type: String,
      enum: ["google", "github"],
    },

    // Authentication
    verificationToken: String,
    isVerified: {
      type: Boolean,
      default: false,
    },
    verified: Date,
    passwordToken: String,
    passwordTokenExpiration: Date,

    // Subscription & Billing
    subscriptionTier: {
      type: String,
      enum: ["free", "pro", "enterprise"],
      default: "free",
    },
    subscriptionStatus: {
      type: String,
      enum: ["active", "cancelled", "expired"],
      default: "active",
    },
    subscriptionRenewalDate: Date,
    billingAddress: {
      line1: String,
      line2: String,
      city: String,
      state: String,
      country: String,
      postalCode: String,
    },
    paymentMethods: [
      {
        type: {
          type: String,
          enum: ["card", "paypal"],
          required: true,
        },
        last4: String,
        brand: String,
        expiryMonth: Number,
        expiryYear: Number,
        isDefault: {
          type: Boolean,
          default: false,
        },
      },
    ],

    // Usage & Limits
    monthlyDownloads: {
      count: {
        type: Number,
        default: 0,
      },
      limit: {
        type: Number,
        default: 100,
      },
      resetDate: Date,
    },
    totalDownloads: {
      type: Number,
      default: 0,
    },

    // Icons & Favorites
    favoriteIcons: [
      {
        iconId: {
          type: mongoose.Schema.Types.ObjectId,
          ref: "Icon",
        },
        dateAdded: {
          type: Date,
          default: Date.now,
        },
        lastUsed: Date,
        customProperties: {
          color: String,
          size: Number,
          animation: String,
        },
      },
    ],
    customIcons: [
      {
        iconId: {
          type: mongoose.Schema.Types.ObjectId,
          ref: "Icon",
        },
        name: String,
        dateCreated: {
          type: Date,
          default: Date.now,
        },
        lastModified: Date,
      },
    ],

    // Settings & Preferences
    settings: {
      theme: {
        type: String,
        enum: ["light", "dark", "system"],
        default: "system",
      },
      emailNotifications: {
        marketing: {
          type: Boolean,
          default: true,
        },
        updates: {
          type: Boolean,
          default: true,
        },
        usage: {
          type: Boolean,
          default: true,
        },
      },
      defaultIconProperties: {
        size: {
          type: Number,
          default: 24,
        },
        color: {
          type: String,
          default: "#000000",
        },
        animation: {
          type: String,
          default: "none",
        },
      },
      autoDownload: {
        type: Boolean,
        default: false,
      },
      showPreviewAnimations: {
        type: Boolean,
        default: true,
      },
      showDimensions: {
        type: Boolean,
        default: true,
      },
    },

    // Usage History
    recentActivity: [
      {
        type: {
          type: String,
          enum: ["download", "favorite", "create", "modify"],
          required: true,
        },
        iconId: {
          type: mongoose.Schema.Types.ObjectId,
          ref: "Icon",
        },
        timestamp: {
          type: Date,
          default: Date.now,
        },
        details: mongoose.Schema.Types.Mixed,
      },
    ],

    // API Access
    apiKeys: [
      {
        key: String,
        name: String,
        createdAt: {
          type: Date,
          default: Date.now,
        },
        lastUsed: Date,
        permissions: [String],
      },
    ],
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// Password hashing middleware
UserSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();

  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error: any) {
    next(error);
  }
});

UserSchema.methods.comparePassword = async function (
  userPassword: string
): Promise<boolean> {
  const isMatch = await bcrypt.compare(userPassword, this.password);
  return isMatch;
};

export default mongoose.model<UserDocument>("usermodel", UserSchema);
