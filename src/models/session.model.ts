import { Schema, model } from 'mongoose';

export const SessionSchema = new Schema({
	user_id: String,
	date: { type: Date, default: Date.now },
	expires: Date,
	emailUpdateRequestToken: String,
	emailConfirmationRequestToken: String,
	passwordUpdateRequestToken: String,
	targetEmail: String,
});

export const Session = model('Session', SessionSchema);
