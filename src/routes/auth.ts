import express, { Request, Response, Router } from 'express';
import { User } from '../models/user';
import { hash } from 'bcrypt';
import { sign } from 'jsonwebtoken';

export const auth = express();

export const authRouter = Router();

authRouter.post('/login', (req: Request, res: Response) => {
    const { email, password } = req.body;
    if (email && password) {
        User.findOne({ email }).then(user => {
            if (user) {
                hash(password, 10).then(encrypted => {
                    if (encrypted == user.password) {
                        const { JWT_SECRET } = process.env;
                        const token = sign({
                            user_id: user._id,
                            email: user.email,
                        }, JWT_SECRET as any as string, { expiresIn: '30d' });
                        const { password, ...data} = user;
                        const payload = {
                            token,
                            code: 201,
                            message: 'User authenticated',
                            data,
                        };
                        res.status(201).json(payload);
                    } else {
                        res.status(403).json({ code: 403, message: 'Wrong password.'});
                    }
                })
            } else {
                res.status(404).json({ code: 404, message: 'User not found' });
            }
        })
    } else {
        res.status(500).json({ code: 500, message: 'Invalid data provided' });
    }
});

authRouter.post('/signup', (req: Request, res: Response) => {
    const { email, password } = req.body;
    if (email && password) {
        hash(password, 10).then(encrypted => {
            if (encrypted) {
                const data: {email: string, password:string} = {
                    email,
                    password: encrypted
                };
    
                const user = new User(data);
                user.save().then(
                    () => {
                        res.status(201).json({ code: 201, message: 'User created.' });
                    },
                    (error) => {
                        res.status(500).json({ code: 500, message: error.message });
                    }
                )
            } else {
                res.status(500).json({ code: 500, message: 'Couldn\'t encrypt data' });
            }
        }).catch(error => {
            res.status(500).json({ code: 500, message: error.message });
        });
    } else {
        res.status(500).json({ code: 500, message: 'Invalid data provided' });
    }
});

auth.use('/', authRouter);