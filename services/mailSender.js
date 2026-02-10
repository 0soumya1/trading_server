import otpGenerator from "otp-generator"; // Generates a random OTP.
import nodemailer from "nodemailer"; // Sends emails via SMTP (Simple Mail Transfer Protocol).
import fs from "fs"; // Reads files from the filesystem.
import inlineCss from "inline-css"; // Converts CSS in <style> tags to inline CSS (important for email clients).

export const mailSender = async (email, otp, otp_type) => {
  let htmlContent = fs.readFileSync("otp_template.html", "utf8"); // Loads otp_template.html as a string.
  htmlContent = htmlContent.replace("TradingApp_otp", otp); // TradingApp_otp → actual OTP
  htmlContent = htmlContent.replace("TradingApp_otp2", otp_type); // TradingApp_otp2 → purpose like Login, Signup, Reset Password

  const options = { url: " " };

  htmlContent = await inlineCss(htmlContent, options);

  try {
    let transporter = nodemailer.createTransport({
      host: process.env.MAIL_HOST,
      port: process.env.MAIL_PORT,
      secure: false,
      auth: {
        user: process.env.MAIL_USER,
        pass: process.env.MAIL_PASS,
      },
    });

    let result = await transporter.sendMail({
      from: process.env.MAIL_FROM,
      to: email,
      subject: "TradingApp - OTP Verification",
      html: htmlContent,
    });
    return result;
  } catch (err) {
    console.log("Error in sending mail: ", err);
    throw err;
  }
};

// The mailSender function is responsible for sending an OTP email to the user. It reads an HTML template, replaces placeholders with the actual OTP and its purpose, inlines the CSS for better email client compatibility, and then uses nodemailer to send the email via SMTP. If there is an error during this process, it logs the error and rethrows it.

export const generateOTP = () => {
  const otp = otpGenerator.generate(6, {
    digits: true,
    lowerCaseAlphabets: false,
    upperCaseAlphabets: false,
    specialChars: false,
  });
  return otp;
};

// The generateOTP function creates a 6-digit numeric OTP using the otp-generator library. It specifies that the OTP should only contain digits and should not include any letters or special characters. The generated OTP is then returned as a string.
