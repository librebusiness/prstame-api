import { config } from 'dotenv';
import { createTransport } from 'nodemailer';
config();

const {
    MAIL_TRANSPORTER_HOST,
    MAIL_TRANSPORTER_PORT,
    MAIL_AUTH_USER,
    MAIL_AUTH_PASSWORD
} = process.env;

export const transporterConfig: any = {
    host: MAIL_TRANSPORTER_HOST,
    port: +(MAIL_TRANSPORTER_PORT || ''),
    secure: true,
    auth: {
        user: MAIL_AUTH_USER,
        pass: MAIL_AUTH_PASSWORD,
    },
}

export const sendHtmlEmail = (payload: { from: string, to: string, subject: string, html: string }) => {
	const transporter = createTransport(transporterConfig);
	return transporter.sendMail({
        from: payload.from,
        to: payload.to,
        subject: payload.subject,
        html: payload.html
    });
}

export const sendEmail = (payload: { from: string, to: string, subject: string, text: string }) => {
	const transporter = createTransport(transporterConfig);
	const { from, to, subject, text } = payload;
	return transporter.sendMail({ from, to, subject, text });
}