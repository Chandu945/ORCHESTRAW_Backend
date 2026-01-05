import { Injectable, InternalServerErrorException, Logger } from '@nestjs/common';
import * as nodemailer from 'nodemailer';
import * as fs from 'fs';
import * as hbs from 'handlebars';
import path from 'path';

@Injectable()
export class MailService {
  private readonly logger= new Logger(MailService.name);
  private transporter: nodemailer.Transporter;

  constructor() {
    this.initTransporter();
  }

  private async initTransporter() {
    // Generate test SMTP service account from ethereal.email
    try{
    const testAccount = await nodemailer.createTestAccount();

    this.transporter = nodemailer.createTransport({
      host: 'smtp.gmail.com',
      port: 465,
      secure: true,
      auth: {
        user: process.env.MAIL_USER,
        pass: process.env.MAIL_PASS,
      },
    });
      this.logger.log(`Mail Service initialized with test account: ${testAccount}`);
  }catch(err){
      this.logger.error('Failed to initialize SMTP:',err);
      throw new InternalServerErrorException('Mail service initialization failed');
    }
  }

  //  Load + compile .hbs templates
  private renderTemplate (templatePath: string, context: any={}){
    try{
      const filePath=path.join(
        process.cwd(),
      'src',
      'mail',
      'templates',
      templatePath,
        // __dirname,'templates',templateFile
        );
      const templateSource = fs.readFileSync(filePath,'utf8');
      const compiledTemplate = hbs.compile(templateSource);
      return compiledTemplate(context);
    }
    catch(err){
      this.logger.error('Template loading error:',err);
      throw new InternalServerErrorException('Failed to load email template');
    }
  }

  private async sendMail(to: string, subject: string, html: string){
      try{
        const info = await this.transporter.sendMail({
          from: '"No Reply" <noreply@example.com',
          to,
          subject,
          html,
        });
        //this.logger.log(`Email sent: ${info.messageId}`);
        //this. logger.log(`Preview URL: ${nodemailer.getTestMessageUrl(info)}`);
      }catch(error){
        this.logger.error('Mail sending error:',error);
        throw new InternalServerErrorException('Unable to send email');
      }
  }
  
  // Send Otp Confirmation
  async sendUserConfirmation(email: string, otp: string) {
    const html= this.renderTemplate('otp/otp.hbs',{otp});
    await this.sendMail(email, 'Confirm Your Email',html);
  }

  // Send Password Reset Otp
  async sendPasswordReset(email: string, otp: string) {
    const html = this.renderTemplate('otp/otp.hbs',{otp});
    await this.sendMail(email, 'Reset Your Password', html);
  }

  // Send Band Account OTP (Email Verification or Password Reset)
  async sendBandOtpEmail(email: string, otp: string) {
    const html = this.renderTemplate('otp/otp.hbs', { otp });
    await this.sendMail(email, 'Band Account Verification', html);
  }

  // Send Welcome Email
  // async sendWelcomeEmail(email:string){
  //   const html = this.renderTemplate('welcome/Welcome.hbs',{});
  //   await this.sendMail(email, 'Welcome! Email Verified', html);
  // }
}
