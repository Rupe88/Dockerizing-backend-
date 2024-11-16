import asyncHandler from "express-async-handler";
import { Request, Response } from "express";
import User, { IUser } from "../../model/auth/userModel"; 

// Define an interface for the request with user ID parameter
interface RequestWithId extends Request {
  params: {
    id: string;
  };
}

// Delete a user
export const deleteUser = asyncHandler(async (req: RequestWithId, res: Response): Promise<void> => {
  const { id } = req.params;

  try {
    const user = await User.findByIdAndDelete(id);
    if (!user) {
      res.status(404).json({ message: "User not found" });
      return;
    }
    res.status(200).json({ message: "User deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: "Cannot Delete User" });
  }
});

// Get all users
export const getAllUsers = asyncHandler(async (req: Request, res: Response): Promise<void> => {
  try {
    const users = await User.find({});
    if (!users || users.length === 0) {
      res.status(404).json({ message: "No users found" });
      return;
    }
    res.status(200).json(users);
  } catch (error) {
    res.status(500).json({ message: "Cannot get users" });
  }
});
