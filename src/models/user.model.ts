import { Schema, model } from 'mongoose';

export const UserSchema = new Schema({
    name: String,
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    api_token: { type: String, unique: true },
    referred: { type: String },
    emailConfirmed: { type: Boolean, default: false },
});

export const User = model('User', UserSchema);