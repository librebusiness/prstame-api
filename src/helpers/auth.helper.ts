import { sign } from 'jsonwebtoken';
import { config } from 'dotenv';
config();

const {
	JWT_SECRET
} = process.env;

export const generateToken = (length = 32): string => {
	const source = 'ZXCVBNMASDFGHJKLQWERTYUIOP1234567890';
	const token = [];
	for (let i = 0; i < length; i++) {
		token.push(source[Math.floor(Math.random() * source.length)]);
	}
	return token.join('');
}

export const createAuthToken = (user: any): string => {
	return sign({
        user_id: user._id,
        email: user.email,
    }, JWT_SECRET as any as string, { expiresIn: '30d' });
}
