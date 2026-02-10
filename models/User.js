import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import {
  BadRequestError,
  NotFoundError,
  UnauthenticateError,
} from "../errors/index.js";

const userSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      match: [
        /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/,
        "Please fill a valid email",
      ],
    },
    password: {
      type: String,
    },
    name: {
      type: String,
      maxlength: 50,
      minlenght: 3,
    },
    login_pin: {
      type: String,
      maxlength: 4,
      minlength: 4,
    },
    phone_number: {
      type: String,
      match: [/^\d{10}$/, "Please fill a valid phone number"],
      unique: true,
      sparse: true,
    },
    date_of_birth: Date,
    biometricKey: String,
    gender: {
      type: String,
      enum: ["Male", "Female", "Other"],
    },
    wrong_pin_attempts: {
      type: Number,
      default: 0,
    },
    // wrong_pin_attempts keeps track of the number of consecutive incorrect login PIN attempts.
    blocked_until_pin: {
      type: Date,
      default: null,
    },
    wrong_password_attempts: {
      type: Number,
      default: 0,
    },
    blocked_until_password: {
      type: Date,
      default: null,
    },
    balance: {
      type: Number,
      default: 50000.0,
    },
  },
  { timestamps: true },
);

userSchema.pre("save", async function () {
  if (this.isModified("password")) {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
  }
});
// This middleware runs before saving a User document to the database. It checks if the password field has been modified (either during user creation or when updating the password). If it has been modified, it generates a salt and hashes the password using bcrypt, ensuring that the password is stored securely in the database.

// In a Mongoose middleware, this refers to the current document instance.

userSchema.pre("save", async function () {
  if (this.isModified("login_pin")) {
    const salt = await bcrypt.genSalt(10);
    this.login_pin = await bcrypt.hash(this.login_pin, salt);
  }
});

userSchema.statics.updatePin = async function (email, newPin) {
  try {
    const user = await this.findOne({ email });

    if (!user) {
      throw new NotFoundError("User not found");
    }

    const isSamePin = await bcrypt.compare(newPin, user.login_pin);
    if (isSamePin) {
      throw new BadRequestError("New PIN cannot be the same as the old PIN");
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPin = await bcrypt.hash(newPin, salt);

    await this.findOneAndUpdate(
      { email },
      { login_pin: hashedPin, wrong_pin_attempts: 0, blocked_until_pin: null },
    );

    return { success: true, message: "PIN updated successfully" };
  } catch (err) {
    console.log("Error in updating PIN: ", err);
    throw err;
  }
};

userSchema.statics.updatePassword = async function (email, newPassword) {
  try {
    const user = await this.findOne({ email });

    if (!user) {
      throw new NotFoundError("User not found");
    }

    const isSamePassword = await bcrypt.compare(newPassword, user.password);
    if (isSamePassword) {
      throw new BadRequestError(
        "New password cannot be the same as the old password",
      );
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    await this.findOneAndUpdate(
      { email },
      {
        password: hashedPassword,
        wrong_password_attempts: 0,
        blocked_until_password: null,
      },
    );
    return { success: true, message: "Password updated successfully" };
  } catch (err) {
    console.log("Error in updating password: ", err);
    throw err;
  }
};

userSchema.methods.comparePassword = async function (candidatePassword) {
  if (this.blocked_until_password && this.blocked_until_password > new Date()) {
    throw new UnauthenticateError(
      "Invalid login attempts exceeded. Please try after 30 minutes.",
    );
  }
  const isMatch = await bcrypt.compare(candidatePassword, this.password);
  if (!isMatch) {
    this.wrong_password_attempts += 1;
    if (this.wrong_password_attempts >= 3) {
      this.blocked_until_password = new Date(Date.now() + 30 * 60 * 1000); // Block for 30 minutes
      this.wrong_password_attempts = 0; // Reset attempts after blocking
    }
    await this.save();
  } else {
    this.wrong_password_attempts = 0; // Reset attempts on successful login
    this.blocked_until_password = null; // Clear block on successful login
    await this.save();
  }
  return isMatch;
};

userSchema.methods.comparePin = async function comparePin(candidatePin) {
  if (this.blocked_until_pin && this.blocked_until_pin > new Date()) {
    throw new UnauthenticateError(
      "Invalid PIN attempts exceeded. Please try after 30 minutes.",
    );
  }
  const hashedPin = this.login_pin;
  const isMatch = await bcrypt.compare(candidatePin, hashedPin);

  if (!isMatch) {
    this.wrong_pin_attempts += 1;
    if (this.wrong_pin_attempts >= 3) {
      this.blocked_until_pin = new Date(Date.now() + 30 * 60 * 1000); // Block for 30 minutes
      this.wrong_pin_attempts = 0; // Reset attempts after blocking
    }
    await this.save();
  } else {
    this.wrong_pin_attempts = 0; // Reset attempts on successful login
    this.blocked_until_pin = null; // Clear block on successful login
    await this.save();
  }
  return isMatch;
};
// The comparePin method checks if the user is currently blocked from entering their PIN due to too many failed attempts. If they are blocked, it throws an UnauthenticateError. If not, it compares the entered PIN with the hashed PIN stored in the database using bcrypt. If the PIN does not match, it increments the wrong_pin_attempts counter and checks if it has reached 3 attempts. If it has, it sets a block on the account for 30 minutes and resets the attempt counter. If the PIN matches, it resets the attempt counter and clears any existing block. Finally, it returns whether the entered PIN is correct or not.

userSchema.methods.createAccessToken = function () {
  return jwt.sign(
    { userId: this._id, name: this.name },
    process.env.JWT_SECRET,
    {
      expiresIn: process.env.ACCESS_TOKEN_EXPIRY,
    },
  );
};

userSchema.methods.createRefreshToken = function () {
  return jwt.sign(
    { userId: this._id, name: this.name },
    process.env.REFRESH_TOKEN_SECRET,
    {
      expiresIn: process.env.REFRESH_TOKEN_EXPIRY,
    },
  );
};
// The createAccessToken method generates a JWT access token that includes the user's ID and name in the payload. It uses a secret key defined in the environment variables and sets an expiration time for the token. The createRefreshToken method does the same but uses a different secret and expiration time, typically for refresh tokens.

// process.env is used to keep secrets and configuration out of source code, making your app secure, configurable, and production-ready.

const User = mongoose.model("User", userSchema);

export default User;
