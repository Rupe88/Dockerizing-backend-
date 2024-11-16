import nodemailer from 'nodemailer';
import path from 'path';
import dotenv from 'dotenv';
import ejs from 'ejs';

dotenv.config();

interface EmailOptions {
  subject: string;
  send_to: string;
  send_from: string;
  reply_to: string;
  template: string;
  name: string;
  link: string;
}

const sendEmail = async ({
  subject,
  send_to,
  send_from,
  reply_to,
  template,
  name,
  link,
}: EmailOptions): Promise<void> => {
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    host: 'smtp.gmail.com',
    port: 587,
    secure: false,
    auth: {
      user: process.env.USER_EMAIL as string,
      pass: process.env.EMAIL_PASS as string,
    },
  });

  // Path to the EJS template
  const templatePath = path.join(__dirname, '../views', `${template}.ejs`);

  // Render the EJS template with variables `name` and `link`
  const htmlContent = await ejs.renderFile(templatePath, { name, link });

  const mailOptions = {
    from: send_from,
    to: send_to,
    replyTo: reply_to,
    subject: subject,
    html: htmlContent, // Use rendered HTML content
  };

  try {
    const info = await transporter.sendMail(mailOptions);
    console.log('Message sent: %s', info.messageId);
  } catch (error) {
    console.error('Error sending email:', error);
    throw error;
  }
};

export default sendEmail;
