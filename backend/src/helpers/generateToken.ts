import jwt from 'jsonwebtoken';
require("dotenv").config();


// Use user id to generate token
const generateToken = (id: string): string => {
  // Ensure the token is returned to the client
  return jwt.sign({ id }, process.env.JWT_SECRET as string, {
    expiresIn: '20d',
  });
};

export default generateToken;
