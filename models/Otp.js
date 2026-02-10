import mongoose from "mongoose";
import bcrypt from "bcryptjs"; // Hashing library (used to securely store OTP).
import { mailSender } from "../services/mailSender"; // Your email service that actually sends the OTP.

// Defines how OTP data is stored in MongoDB.
const otpSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
  },
  // Email address to which OTP is sent.
  otp: {
    type: String,
    required: true,
  },
  // The OTP itself, stored as a hashed string for security.
  createdAt: {
    type: Date,
    default: Date.now,
    expires: 60 * 5,
  },
  // Timestamp of when the OTP was created. This field is used to automatically delete expired OTPs after 5 minutes.
  otp_type: {
    type: String,
    enum: ["phone", "email", "reset_password", "reset_pin"],
    required: true,
  },
  // The purpose of the OTP (e.g., "phone", "email", "reset_password", "reset_pin"). This helps in customizing the email content and also for any specific logic based on OTP type.
});

otpSchema.pre("save", async function (next) {
  if (this.isNew) {
    const salt = await bcrypt.genSalt(10);
    await sendVerificationMail(this.email, this.otp, this.otp_type);
    this.otp = await bcrypt.hash(this.otp, salt);
  }
  next();
});

// This middleware runs before saving an OTP document to the database. It checks if the document is new (i.e., being created for the first time). If it is new, it generates a salt and hashes the OTP using bcrypt, and then sends the OTP email using the mailSender function. Finally, it calls next() to proceed with saving the document.

otpSchema.methods.compareOTP = async function (enteredOtp) {
  return await bcrypt.compare(enteredOtp, this.otp);
};
// This method is added to the OTP schema to compare a user-entered OTP with the hashed OTP stored in the database. It uses bcrypt's compare function to check if the entered OTP matches the hashed OTP.

async function sendVerificationMail(email, otp, otp_type) {
  try {
    const mailResponse = await mailSender(email, otp, otp_type);
    console.log("Mail Response: ", mailResponse);
  } catch (err) {
    console.log("Error in sending OTP mail: ", err);
    throw err;
  }
}
// This function is responsible for sending the OTP email. It calls the mailSender function and logs the response. If there is an error in sending the email, it catches the error, logs it, and rethrows it.

const Otp = mongoose.model("Otp", otpSchema);

export default Otp;
// Finally, we create a Mongoose model named "Otp" using the defined schema and export it for use in other parts of the application.
