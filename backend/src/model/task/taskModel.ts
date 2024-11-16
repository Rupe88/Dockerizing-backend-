import mongoose, { Document, Schema } from 'mongoose';

// Define Task Interface
export interface ITask extends Document {
  title: string;
  description: string;
  dueDate: Date;
  status: 'active' | 'inactive';
  completed: boolean;
  priority: 'low' | 'medium' | 'high';
  user: mongoose.Types.ObjectId;
  createdAt: Date;
  updatedAt: Date;
}

// Task Schema
const TaskSchema: Schema<ITask> = new Schema(
  {
    title: {
      type: String,
      required: [true, "Please provide a title"],
      unique: true,
    },
    description: {
      type: String,
      default: "No description",
    },
    dueDate: {
      type: Date,
      default: Date.now,
    },
    status: {
      type: String,
      enum: ["active", "inactive"],
      default: "active",
    },
    completed: {
      type: Boolean,
      default: false,
    },
    priority: {
      type: String,
      enum: ["low", "medium", "high"],
      default: "low",
    },
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
  },
  { timestamps: true }
);

// Create Task Model
const TaskModel = mongoose.model<ITask>('Task', TaskSchema);
export default TaskModel;
