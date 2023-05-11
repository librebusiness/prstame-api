import express, { Request, Response, Router } from 'express';
import { hash, compare } from 'bcrypt';
import { sign } from 'jsonwebtoken';
import { createTransport } from 'nodemailer';
import { config } from 'dotenv';
import { sendPasswordRecoveryEmail } from '../mailers/auth.mailer';
import { Session } from '../models/session.model';
import { User } from '../models/user.model';
import { generateToken } from '../helpers/auth.helper';
config();

const {
    JWT_SECRET
} = process.env;

export const authController = express();

export const authRouter = Router();

authRouter.post('/signup', (req: Request, res: Response) => {
    const { email, password } = req.body;
    if (email && password) {
        hash(password, 10).then(encrypted => {
            if (encrypted) {
                const data: {email: string, password: string, api_token: string} = {
                    email,
                    password: encrypted,
                    api_token: generateToken(64),
                };

                const user = new User(data);
                user.save().then(
                    (data) => {
                        const session = new Session({ user_id: user._id });
                        session.save();
                        const token = sign({
                            user_id: user._id,
                            email: user.email,
                        }, JWT_SECRET as any as string, { expiresIn: '30d' });
                        const { password, ...userData} = (user as any)._doc;
                        const payload = {
                            token,
                            code: 201,
                            message: 'User created',
                            data: userData,
                        };
                        res.status(201).json(payload);
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

authRouter.post('/login', (req: Request, res: Response) => {
    const { email, password } = req.body;
    if (email && password) {
        User.findOne({ email }).then(user => {
            if (user) {
                compare(password, user.password).then(result => {
                    if (result) {
                        const token = sign({
                            user_id: user._id,
                            email: user.email,
                        }, JWT_SECRET as any as string, { expiresIn: '30d' });
                        const { password, ...data} = (user as any)._doc;
                        const payload = {
                            token,
                            code: 201,
                            message: 'User authenticated',
                            data,
                        };
                        res.status(201).json(payload);
                    } else {
                        res.status(400).json({
                            code: 400,
                            message: 'Wrong password.'
                        });
                    }
                },
                (error) => {
                    res.status(403).json({ code: 403, message: error.message });
                });
            } else {
                res.status(404).json({ code: 404, message: 'User not found' });
            }
        });
    } else {
        res.status(500).json({ code: 500, message: 'Invalid data provided' });
    }
});

authRouter.post('/forgot-password', (req: Request, res: Response) => {
    const update_token = generateToken();
    if (req.body.email) {
        User.findOne({ email: req.body.email }).then(user => {
            if (user) {
                const { _id } = (user as any)._doc;
                Session.updateOne({ user_id: _id }, {
                    passwordUpdateRequestToken: update_token,
                    date: new Date(),
                    expires: new Date(Date.now() + (1000*60*60))
                }).then((count) => {
                    if (count) {
                        sendPasswordRecoveryEmail({
                            to: req.body.email,
                            _id,
                            update_token
                        }).then(() => {
                            res.status(201).json({
                                code: 201,
                                message: 'Password recovery request created.'
                            });
                        }).catch(error => {
                            res.status(500).json({
                                code: 500,
                                message: error.message,
                            });
                        });
                    } else {
                        res.status(500).json({
                            code: 500,
                            message: 'Can\'t save the request'
                        });
                    }
                });
            }
        }).catch(error => {
            res.status(404).json({
                code: 404,
                message: 'User not found'
            });
        })
    } else {
        res.status(400).json({
            code: 400,
            message: 'No email provided'
        });
    }
});

authRouter.post('/password-reset', (req: Request, res: Response) => {
    if (req.body.password && req.body._id && req.body.token) {
        Session.findOne({
            user_id: req.body._id,
            passwordUpdateRequestToken: req.body.token
        }).then(session => {
            if (session) {
                if (new Date < new Date(`${session.expires}`)) {
                    Session.updateOne({ user_id: req.body._id }, {
                        expires: new Date(),
                        passwordUpdateRequestToken: '',
                    });
                    hash(req.body.password, 10).then(password => {
                        User.updateOne({ _id: req.body._id }, {
                            password
                        }).then(async (count) => {
                            if (count) {
                                const user = await User.findOne({ _id: req.body._id });
                                if (!user) {
                                    return res.status(500).json({
                                        code: 500,
                                        message: 'Password updated'
                                    });
                                }
                                const token = sign({
                                    user_id: req.body._id,
                                    email: user.email,
                                }, JWT_SECRET as any as string, { expiresIn: '30d' });
                                const { password, ...data} = user;
                                const payload = {
                                    token,
                                    code: 201,
                                    message: 'Password updated',
                                    data,
                                };
                                res.status(201).json(payload);
                            } else {
                                res.status(500).json({
                                    code: 500,
                                    message: 'Password unchanged'
                                })
                            }
                        }).catch(error => {
                            res.status(500).json({
                                code: 500,
                                message: error.message,
                            });
                        });
                    }).catch(error => {
                        res.status(500).json({
                            code: 500,
                            message: error.message,
                        });
                    });
                } else {
                    res.status(400).json({
                        code: 400,
                        message: 'Expired token'
                    });
                }
            } else {
                res.status(400).json({
                    code: 400,
                    message: 'Bad request'
                });
            }
        })
    } else {
        res.status(400).json({
            code: 400,
            message: 'Bad request'
        });
    }
});

authController.use('/', authRouter);