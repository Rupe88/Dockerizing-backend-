import mongoose, { Document, Schema } from 'mongoose';

// Define Token Interface
export interface IToken extends Document {
  userId: mongoose.Types.ObjectId;
  verificationToken: string;
  passwordResetToken: string;
  createdAt: Date;
  expiresAt: Date;
}

// Token Schema
const TokenSchema: Schema<IToken> = new Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  verificationToken: {
    type: String,
    default: "",
  },
  passwordResetToken: {
    type: String,
    default: "",
  },
  createdAt: {
    type: Date,
    required: true,
    default: Date.now,
  },
  expiresAt: {
    type: Date,
    required: true,
  },
});

// Create Token Model
const Token = mongoose.model<IToken>('Token', TokenSchema);
export default Token;
