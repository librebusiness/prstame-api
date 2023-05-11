import { config } from 'dotenv';
import { sendHtmlEmail } from './base.mailer';
config();

const {
	MAIL_BUTTON_HOST
} = process.env;

export const sendPasswordRecoveryEmail = (payload: { to: string, _id: string, update_token: string }) => {
	const { to, _id, update_token } = payload;
	return sendHtmlEmail({
		from: '"Otoniel Reyes Galay" <otoniel@otonielreyes.com>',
		to,
		subject: "Password recovery",
		html: `To change your password click the link bellow.<br/>
        <a href="${MAIL_BUTTON_HOST}/auth/restore-password/${_id}/${update_token}">Reset my password now</a>
        `
	});
}

export const sendEmailConfirmEmail = (payload: { to: string, _id: string, confirmation_token: string }) => {
	const { to, _id, confirmation_token } = payload;
	return sendHtmlEmail({
		from: '"Otoniel Reyes Galay" <otoniel@otonielreyes.com>',
		to,
		subject: "Email address confirmation",
		html: `To confirm your email address click the link bellow.<br/>
        <a href="${MAIL_BUTTON_HOST}/user/confirm-email/${_id}/${confirmation_token}">Confirm my email now</a>
        `
	});
}

export const sendEmailChangeConfirmEmail = (payload: { to: string, _id: string, confirmation_token: string }) => {
	const { to, _id, confirmation_token } = payload;
	return sendHtmlEmail({
		from: '"Otoniel Reyes Galay" <otoniel@otonielreyes.com>',
		to,
		subject: "Email address change confirmation",
		html: `To change and confirm your new email address click the link bellow.<br/>
        <a href="${MAIL_BUTTON_HOST}/user/change-email/${_id}/${confirmation_token}">Confirm my email now</a>
        `
	});
}

export const sendWelcomeEmail = (to: string) => {
	return sendHtmlEmail({
		from: '"Otoniel Reyes Galay" <otoniel@otonielreyes.com>',
		to,
		subject: "Welcome to Prstame",
		html: `<h1>Welcome to Prstame</h1>
		<p>It's a pleasure to have you here with us.</p>
		<p>If you need something, just email me. I'll be pleased to help.</p>
		`
	});
}