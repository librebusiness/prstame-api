import { Schema, model } from 'mongoose';

export const UserSchema = new Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    api_token: { type: String, unique: true },
});

export const User = model('User', UserSchema);