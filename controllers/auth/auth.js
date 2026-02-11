import User from "../../models/User.js";
import { StatusCodes } from "http-status-codes";
import {
  BadRequestError,
  NotFoundError,
  UnauthenticateError,
} from "../../errors/index.js";
import jwt from "jsonwebtoken";

const register = async (req, res) => {
  const { email, password, register_token } = req.body;
  if (!email || !password || !register_token) {
    throw new BadRequestError("Please provide all values");
  }

  const user = await User.findOne({ email });
  if (user) {
    throw new BadRequestError("User already exists");
  }

  try {
    const payload = jwt.verify(register_token, process.env.REGISTER_SECRET);
    if (payload.email !== email) {
      throw new BadRequestError("Invalid registration token");
    }

    const newUser = await User.create({ email, password });
    const access_token = newUser.createAccessToken();
    const refresh_token = newUser.createRefreshToken();
    res.status(StatusCodes.CREATED).json({
      user: { email: newUser.email, userId: newUser.id },
      tokens: { access_token, refresh_token },
    });
  } catch (err) {
    console.error(err);
    throw new BadRequestError("Invalid Body");
  }
};

// The register function handles user registration. It first checks if the required fields (email, password, and register_token) are provided in the request body. If any of these fields are missing, it throws a BadRequestError. Then it checks if a user with the provided email already exists in the database. If such a user exists, it throws another BadRequestError indicating that the user already exists.

// If the email is unique, it proceeds to verify the registration token using JWT. The token is expected to contain the email in its payload, and if the email in the token does not match the provided email, it throws a BadRequestError indicating an invalid registration token.

// If the token is valid, it creates a new user with the provided email and password. After successfully creating the user, it generates an access token and a refresh token for the new user and sends a response with the user's email, user ID, and the generated tokens. If there is any error during this process (such as an invalid token), it catches the error, logs it, and throws a BadRequestError indicating an invalid body.

const login = async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    throw new BadRequestError("Please provide all values");
  }

  const user = await User.findOne({ email });
  if (!user) {
    throw new UnauthenticateError("Invalid Credentials");
  }

  const isPasswordCorrect = await user.comparePassword(password);
  if (!isPasswordCorrect) {
    let message;
    if (
      user.blocked_until_password &&
      user.blocked_until_password > new Date()
    ) {
      const remainingMinutes = Math.ceil(
        (user.blocked_until_password - new Date()) / (1000 * 60),
      );
      message = `Your account is blocked for password. Please try again after ${remainingMinutes} minutes.`;
    } else {
      const attemptsRemaining = 3 - user.wrong_password_attempts;
      message =
        attemptsRemaining > 0
          ? `Invalid password. You have ${attemptsRemaining} attempts remaining `
          : "Invalid login attempts exceeded. Please try after 30 minutes.";
    }
    throw new UnauthenticateError(message);
  }

  const access_token = user.createAccessToken();
  const refresh_token = user.createRefreshToken();

  let phone_exist = false;
  let login_pin_exist = false;

  if (user.phone) {
    phone_exist = true;
  }
  if (user.login_pin) {
    login_pin_exist = true;
  }
  res.status(StatusCodes.OK).json({
    user: {
      name: user.name,
      email: user.email,
      userId: user.id,
      phone_exist,
      login_pin_exist,
    },
    tokens: { access_token, refresh_token },
  });
};

// The login function handles user authentication. It first checks if the email and password are provided in the request body. If either of these fields is missing, it throws a BadRequestError. Then it looks up the user in the database using the provided email. If no user is found, it throws an UnauthenticateError indicating invalid credentials.

// If the user is found, it calls the comparePassword method on the user instance to check if the provided password matches the stored hashed password. If the password is incorrect, it checks if the user is currently blocked from logging in due to too many failed attempts. If the user is blocked, it calculates the remaining block time and includes that information in the error message. If the user is not blocked, it calculates how many login attempts are remaining before the account gets blocked and includes that in the error message. Finally, it throws an UnauthenticateError with the appropriate message.

// If the password is correct, it generates an access token and a refresh token for the user. It also checks if the user's phone number and login PIN exist and includes that information in the response. Finally, it sends a response with the user's name, email, user ID, and token information.

const refreshToken = async (req, res) => {
  const { type, refresh_token } = req.body;
  if (!type || !["socket", "app"].includes(type) || !refresh_token) {
    throw new BadRequestError("Invalid body");
  }
  try {
    let accessToken, newRefreshToken;
    if (type === "socket") {
      ({ accessToken, newRefreshToken } = await generateRefreshTokens(
        refresh_token,
        process.env.REFRESH_SCOKET_TOKEN_SECRET,
        process.env.REFRESH_SCOKET_TOKEN_EXPIRY,
        process.env.SOCKET_TOKEN_SECRET,
        process.env.SOCKET_TOKEN_EXPIRY,
      ));
    } else if (type === "app") {
      ({ accessToken, newRefreshToken } = await generateRefreshTokens(
        refresh_token,
        process.env.REFRESH_TOKEN_SECRET,
        process.env.REFRESH_SOCKET_TOKEN_EXPIRY,
        process.env.JWT_SECRET,
        process.env.ACCESS_TOKEN_EXPIRY,
      ));
    }
    res
      .status(StatusCodes.OK)
      .json({ access_token: accessToken, refresh_token: newRefreshToken });
  } catch (err) {
    console.error("Error in refresh token endpoint: ", err);
    throw new UnauthenticateError("Invalid token");
  }
};

async function generateRefreshTokens(
  token,
  refresh_secret,
  refresh_expiry,
  access_secret,
  access_expiry,
) {
  try {
    const payload = jwt.verify(token, refresh_secret);
    const user = await User.findById(payload.userId);
    if (!user) {
      throw new NotFoundError("User not found");
    }
    const access_token = jwt.sign({ userId: payload.userId }, access_secret, {
      expiresIn: access_expiry,
    });
    const newRefreshToken = jwt.sign(
      { userId: payload.userId },
      refresh_secret,
      { expiresIn: refresh_expiry },
    );
    return { access_token, newRefreshToken };
  } catch (err) {
    console.error("Error in generating refresh token: ", err);
    throw new UnauthenticateError("Invalid refresh token");
  }
}

const logout = async (req, res) => {
  const accessToken = req.headers.authorization?.split(" ")[1];
  const decodedToken = jwt.decode(accessToken, process.env.JWT_SECRET);
  const userId = decodedToken?.userId;
  await User.updateOne({ _id: userId }, { $unset: { biometricKey: 1 } });
  res.status(StatusCodes.OK).json({ message: "Logged out successfully" });
};

export { register, login, logout, refreshToken };
