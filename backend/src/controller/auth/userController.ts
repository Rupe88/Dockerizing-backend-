import asyncHandler from 'express-async-handler';
import { Request, Response } from 'express';
import User, { IUser } from '../../model/auth/userModel';
import generateToken from '../../helpers/generateToken';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import Token from '../../model/auth/tokenModel';
import crypto from 'crypto';
import sendEmail from '../../service/sendEmail';
import { hashToken } from '../../helpers/hashToken';
// import sendEmail from '../../service/sendEmail';
require("dotenv").config();

interface AuthenticatedRequest extends Request {
  user?: IUser;
}

// Register User
export const registerUser = asyncHandler(async (req: Request, res: Response):Promise<void> => {
  const { name, email, password } = req.body;

  // validation
  if (!name || !email || !password) {
     res.status(400).json({ message: 'All fields are required' })
     return;
  }

  if (password.length < 6) {
     res.status(400).json({ message: 'Password must be at least 6 characters' });
     return

  }

  // Check if user already exists
  const userExists = await User.findOne({ email });
  if (userExists) {
     res.status(400).json({ message: 'User already exists' });
     return
  }



 // Create new user
const user = await User.create({ name, email, password });

// Generate JWT token for user session
const jwtToken = generateToken(user._id);

// Set cookie with JWT token
res.cookie('token', jwtToken, {
  path: '/',
  httpOnly: true,
  maxAge: 30 * 24 * 60 * 60 * 1000,
  sameSite: 'none',
  secure: false,
});

if (user) {
  const { _id, name, email, role, photo, bio, isVerified } = user;

  // Generate email verification token
  let token = await Token.findOne({ userId: user._id });
  if (token) await token.deleteOne();

  const verificationToken = crypto.randomBytes(64).toString('hex') + user._id;
  const hashedToken = hashToken(verificationToken);

  // Save the verification token
  await new Token({
    userId: user._id,
    verificationToken: hashedToken,
    createdAt: Date.now(),
    expiresAt: Date.now() + 24 * 60 * 60 * 1000, // 24 hours expiration
  }).save();

  // Send verification email
  const verificationLink = `${process.env.CLIENT_URL}/verify-email/${verificationToken}`;
  await sendEmail({
    subject: 'Email Verification - AuthKit',
    send_to: user.email,
    send_from: process.env.USER_EMAIL!,
    reply_to: 'noreply@gmail.com',
    template: 'emailVerification',
    name: user.name,
    link: verificationLink,
  });

  res.status(201).json({ _id, name, email, role, photo, bio, isVerified, token: jwtToken });
}

});

// User Login
export const loginUser = asyncHandler(async (req: Request, res: Response):Promise<void> => {
  const { email, password } = req.body;

  if (!email || !password) {
     res.status(400).json({ message: 'All fields are required' });
     return
  }

  const userExists = await User.findOne({ email });
  if (!userExists) {
     res.status(404).json({ message: 'User not found, sign up!' });
     return
  }


  const token = generateToken(userExists._id);
  const { _id, name, role, photo, bio, isVerified } = userExists;

  res.cookie('token', token, {
    path: '/',
    httpOnly: true,
    maxAge: 30 * 24 * 60 * 60 * 1000,
    sameSite: 'none',
    secure: true,
  });

  res.status(200).json({ _id, name, email, role, photo, bio, isVerified, token });
});

// Logout User
export const logoutUser = asyncHandler(async (req: Request, res: Response) => {
  res.clearCookie('token', {
    httpOnly: true,
    sameSite: 'none',
    secure: true,
    path: '/',
  });
  res.status(200).json({ message: 'User logged out' });
});

// Get User
export const getUser = asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
  const user = await User.findById(req.user?._id).select('-password');
  if (user) {
    res.status(200).json(user);
  } else {
    res.status(404).json({ message: 'User not found' });
  }
});

// Update User
export const updateUser = asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
  const user = await User.findById(req.user?._id);
  if (user) {
    user.name = req.body.name || user.name;
    user.bio = req.body.bio || user.bio;
    user.photo = req.body.photo || user.photo;

    const updated = await user.save();
    res.status(200).json(updated);
  } else {
    res.status(404).json({ message: 'User not found' });
  }
});

// Login Status
export const userLoginStatus = asyncHandler(async (req: Request, res: Response):Promise<void> => {
  const token = req.cookies.token;
  if (!token) {
     res.status(401).json({ message: 'Not authorized, please login!' });
     return
  }

  const decoded = jwt.verify(token, process.env.JWT_SECRET as string);
  res.status(200).json(Boolean(decoded));
});

// Verify Email
export const verifyEmail = asyncHandler(async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  const user = await User.findById(req.user?._id);
  if (!user) {
    res.status(404).json({ message: 'User not found' });
    return;
  }

  if (user.isVerified) {
    res.status(400).json({ message: 'User is already verified' });
    return;
  }

  let token = await Token.findOne({ userId: user._id });
  if (token) await token.deleteOne();

  const verificationToken = crypto.randomBytes(64).toString('hex') + user._id;
  const hashedToken = hashToken(verificationToken);

  await new Token({
    userId: user._id,
    verificationToken: hashedToken,
    createdAt: Date.now(),
    expiresAt: Date.now() + 24 * 60 * 60 * 1000,
  }).save();

  const verificationLink = `${process.env.CLIENT_URL}/verify-email/${verificationToken}`;
  await sendEmail({
    subject: 'Email Verification - AuthKit',
    send_to: user.email,
    send_from: process.env.USER_EMAIL!,
    reply_to: 'noreply@gmail.com',
    template: 'emailVerification',
    name: user.name,
    link: verificationLink,
  });

  res.json({ message: 'Email sent' });
});


export const verifyUser = asyncHandler(async (req: Request, res: Response): Promise<void> => {
  const { verificationToken } = req.params;
  const hashedToken = hashToken(verificationToken);

  console.log("Verification token received:", verificationToken);
  console.log("Hashed token for comparison:", hashedToken);

  // Find token in database
  const userToken = await Token.findOne({
    verificationToken: hashedToken,
    expiresAt: { $gt: Date.now() },
  });

  if (!userToken) {
    console.log("Token not found or expired.");
    res.status(400).json({ message: 'Invalid or expired verification token' });
    return;
  }

  // Find user by token's userId
  const user = await User.findById(userToken.userId);
  if (user && !user.isVerified) {
    user.isVerified = true;
    await user.save();
    await Token.findByIdAndDelete(userToken._id); // Remove token
    console.log("User verified successfully and token deleted.");
    res.status(200).json({ message: 'User verified' });
  } else {
    console.log("User is already verified or not found.");
    res.status(400).json({ message: 'User is already verified or not found' });
  }
});


  

// Forgot Password
export const forgotPassword = asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const { email } = req.body;
    if (!email) {
      res.status(400).json({ message: 'Email is required' });
      return;
    }
  
    const user = await User.findOne({ email });
    if (!user) {
      res.status(404).json({ message: 'User not found' });
      return;
    }
  
    let token = await Token.findOne({ userId: user._id });
    if (token) await token.deleteOne();
  
    const passwordResetToken = crypto.randomBytes(64).toString('hex') + user._id;
    const hashedToken = hashToken(passwordResetToken);
  
    await new Token({
      userId: user._id,
      passwordResetToken: hashedToken,
      createdAt: Date.now(),
      expiresAt: Date.now() + 60 * 60 * 1000,
    }).save();
  
    const resetLink = `${process.env.CLIENT_URL}/reset-password/${passwordResetToken}`;
    await sendEmail({
      subject: 'Password Reset - AuthKit',
      send_to: user.email,
      send_from: process.env.USER_EMAIL!,
      reply_to: 'noreply@gmail.com',
      template: 'forgotPassword',
      name: user.name,
      link: resetLink,
    });
  
    res.json({ message: 'Email sent' });
  });
  
// Reset Password
export const resetPassword = asyncHandler(async (req: Request, res: Response): Promise<void> => {
  const { resetPasswordToken } = req.params;
  const { password } = req.body;
  
  if (!password) {
    res.status(400).json({ message: 'Password is required' });
    return;
  }

  const hashedToken = hashToken(resetPasswordToken);
  const userToken = await Token.findOne({ passwordResetToken: hashedToken, expiresAt: { $gt: Date.now() } });

  if (!userToken) {
    res.status(400).json({ message: 'Invalid or expired reset token' });
    return;
  }

  const user = await User.findById(userToken.userId);
  if (user) {
    user.password = await bcrypt.hash(password, 10); // Hashing the password
    await user.save();
    res.status(200).json({ message: 'Password reset successfully' });
  }
});


// Change Password
export const changePassword = asyncHandler(async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword) {
    res.status(400).json({ message: 'All fields are required' });
    return;
  }

  const user = await User.findById(req.user?._id);
  if (user && await bcrypt.compare(currentPassword, user.password)) {
    user.password = await bcrypt.hash(newPassword, 10); // Hashing the new password
    await user.save();
    res.status(200).json({ message: 'Password changed successfully' });
  } else {
    res.status(400).json({ message: 'Invalid password!' });
  }
});

