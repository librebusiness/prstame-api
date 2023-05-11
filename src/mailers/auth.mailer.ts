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