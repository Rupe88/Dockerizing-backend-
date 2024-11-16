import { Request, Response, NextFunction } from 'express';

// Error Handler Middleware
const errorHandler = (err: Error, req: Request, res: Response, next: NextFunction) => {
  // Check if response headers have already been sent to the client
  if (res.headersSent) {
    // If true, pass the error to the next error-handling middleware
    return next(err);
  }

  // Set the status code of the response
  const statusCode = res.statusCode && res.statusCode >= 400 ? res.statusCode : 500;
  res.status(statusCode);

  // Log error stack trace to the console if not in production --> for debugging
  if (process.env.NODE_ENV !== 'production') {
    console.error(err.stack);
  }

  res.json({
    message: err.message,
    stack: process.env.NODE_ENV === 'production' ? null : err.stack,
  });
};

export default errorHandler;
