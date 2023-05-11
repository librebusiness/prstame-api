export const generateToken = (length = 32): string => {
	const source = 'ZXCVBNMASDFGHJKLQWERTYUIOP1234567890';
	const token = [];
	for (let i = 0; i < length; i++) {
		token.push(source[Math.floor(Math.random() * source.length)]);
	}
	return token.join('');
}