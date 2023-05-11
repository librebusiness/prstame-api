import { Schema, model } from 'mongoose';

export const SessionSchema = new Schema({
	user_id: String,
	date: { type: Date, default: Date.now },
	expires: Date,
	emailUpdateRequestToken: String,
	passwordUpdateRequestToken: String,
});

export const Session = model('Session', SessionSchema);
