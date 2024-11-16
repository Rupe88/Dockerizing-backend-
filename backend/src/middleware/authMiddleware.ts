import asyncHandler from 'express-async-handler';
import jwt, { JwtPayload } from 'jsonwebtoken';
import { Request, Response, NextFunction } from 'express';
import User, { IUser } from '../model/auth/userModel';

interface DecodedToken extends JwtPayload {
  id: string;
}

// Extend Express Request type to include user
declare module 'express-serve-static-core' {
  interface Request {
    user?: IUser;
  }
}

// Protect middleware
export const protect = asyncHandler(async (req: Request, res: Response, next: NextFunction) => {
  try {
    // check if user is logged in
    const token = req.cookies.token;

    if (!token) {
      // 401 Unauthorized
      res.status(401).json({ message: 'Not authorized, please login!' });
      return;
    }

    // verify the token
    const decoded = jwt.verify(token, process.env.JWT_SECRET as string) as DecodedToken;

    // get user details from the token ----> exclude password
    const user = await User.findById(decoded.id).select('-password');

    // check if user exists
    if (!user) {
      res.status(404).json({ message: 'User not found!' });
      return;
    }

    // set user details in the request object
    req.user = user;

    next();
  } catch (error) {
    // 401 Unauthorized
    res.status(401).json({ message: 'Not authorized, token failed!' });
  }
});

// Admin middleware
export const adminMiddleware = asyncHandler(async (req: Request, res: Response, next: NextFunction) => {
  if (req.user && req.user.role === 'admin') {
    next();
    return;
  }
  res.status(403).json({ message: 'Only admins can do this!' });
});

// Creator middleware
export const creatorMiddleware = asyncHandler(async (req: Request, res: Response, next: NextFunction) => {
  if (req.user && (req.user.role === 'creator' || req.user.role === 'admin')) {
    next();
    return;
  }
  res.status(403).json({ message: 'Only creators can do this!' });
});

// Verified middleware
export const verifiedMiddleware = asyncHandler(async (req: Request, res: Response, next: NextFunction) => {
  if (req.user && req.user.isVerified) {
    next();
    return;
  }
  res.status(403).json({ message: 'Please verify your email address!' });
});
