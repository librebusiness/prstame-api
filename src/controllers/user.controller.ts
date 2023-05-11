import express, { Request, Response, Router } from 'express';
import { hash, compare } from 'bcrypt';
import { config } from 'dotenv';
import { User } from '../models/user.model';
import { Session } from '../models/session.model';
import { sendEmailChangeConfirmEmail, sendEmailConfirmEmail } from '../mailers/auth.mailer';
import { generateToken } from '../helpers/auth.helper';
import { requiresAuthentication } from '../middleware/auth.middleware';
config();

export const userController = express();

export const userRouter = Router();

userRouter.post('/update-password', requiresAuthentication, (req: Request, res: Response) => {
    if (req.body.password && req.body.oldPassword) {
        User.findOne({ _id: (req as any).user.user_id }).then(user => {
            if (user) {
                compare(req.body.oldPassword, user.password).then(result => {
                    if (result) {
                        hash(req.body.password, 10).then(password => {
                            User.updateOne({ _id: (req as any).user.user_id }, { password }).then(() => {
                                res.json({
                                    code: 201,
                                    message: 'Password Updated'
                                });
                            }).catch(error => {
                                res.json({
                                    code: 500,
                                    message: error.message,
                                });
                            });
                        }).catch(error => {
                            res.json({
                                code: 500,
                                message: error.message,
                            });
                        });
                    } else {
                        res.json({
                            code: 400,
                            message: 'Old password doesn\'t match'
                        });
                    }
                });
            } else {
                res.json({
                    code: 404,
                    message: 'User not found'
                });
            }
        },
        (error) => {
            res.status(403).json({ code: 403, message: error.message });
        });
    } else {
        res.json({
            code: 400,
            message: 'Missing password',
        });
    }
});

userRouter.post('/confirm-email', requiresAuthentication, (req: Request, res: Response) => {
    const confirmation_token = generateToken();
    User.findOne({ _id: (req as any).user.user_id }).then(async (user) => {
        const session = await Session.updateOne({ user_id: (req as any).user.user_id }, {
            emailConfirmationRequestToken: confirmation_token,
        });
        if (user) {
            sendEmailConfirmEmail({
                to: (req as any).user.email,
                _id: (req as any).user.user_id,
                confirmation_token
            }).then(() => {
                res.status(201).json({
                    code: 201,
                    message: 'Check your inbox to confirm your email.'
                });
            }).catch(error => {
                res.status(500).json({
                    code: 500,
                    message: error.message,
                });
            })
        } else {
            res.json({
                code: 404,
                message: 'User not found'
            });
        }
    },
    (error) => {
        res.status(403).json({ code: 403, message: error.message });
    });
});

userRouter.post('/confirm-email/:id', (req: Request, res: Response) => {
    const _id = req.params.id;
    if (req.body.confirmation_token) {
        Session.updateOne({ user_id: _id, emailConfirmationRequestToken: req.body.confirmation_token }, {
            emailConfirmationRequestToken: null,
        }).then(count => {
            if (count) {
                User.updateOne({ _id }, {
                    emailConfirmed: true,
                }).then(updated => {
                    if (updated) {
                        res.status(201).json({
                            code: 201,
                            message: 'Email confirmed'
                        });
                    }
                });
            } else {
                res.status(404).json({
                    code: 404,
                    message: 'Invalid confirmation'
                });
            }
        },
        (error) => {
            res.status(403).json({ code: 403, message: error.message });
        });
    } else {
        res.json({
            code: 400,
            message: 'Missing confirmation token',
        });
    }
});

userRouter.post('/update-email', requiresAuthentication, (req: Request, res: Response) => {
    if (req.body.email) {
        const _id = (req as any).user.user_id;
        const confirmation_token = generateToken();
        Session.updateOne({ user_id: _id }, {
            emailUpdateRequestToken: confirmation_token,
            targetEmail: req.body.email,
        }).then(count => {
            if (count) {
                sendEmailChangeConfirmEmail({ to: req.body.email, _id, confirmation_token }).then(() => {
                    res.status(201).json({
                        code: 201,
                        message: 'Check your email to confirm the change'
                    });
                }).catch(error => {
                    res.status(400).json({ code: 403, message: error.message });
                });
            } else {
                res.json({
                    code: 404,
                    message: 'Invalid request'
                });
            }
        },
        (error) => {
            res.status(400).json({ code: 403, message: error.message });
        });
    } else {
        res.json({
            code: 400,
            message: 'Missing email',
        });
    }
});

userRouter.post('/update-email/:id', (req: Request, res: Response) => {
    const _id = req.params.id;
    if (req.body.confirmation_token) {
        const confirmation_token = req.body.confirmation_token;
        Session.updateOne({
            user_id: _id,
            emailUpdateRequestToken: confirmation_token
        }, { emailUpdateRequestToken: null }).then(async count => {
            const session = await Session.findOne({ user_id: _id });
            if (!session) {
                return res.status(400).json({
                    code: 400,
                    message: 'Invalid request.'
                });
            }
            if (count) {
                User.updateOne({ _id }, { emailConfirmed: true, email: session.targetEmail }).then((updated) => {
                    if (updated) {
                        res.status(201).json({
                            code: 201,
                            message: 'Email updated'
                        });
                    } else {
                        res.status(500).json({
                            code: 500,
                            message: 'Email unchanged'
                        });
                    }
                }).catch(error => {
                    res.status(400).json({ code: 403, message: error.message });
                });
            } else {
                res.status(400).json({
                    code: 400,
                    message: 'Invalid request.'
                });
            }
        },
        (error) => {
            res.status(400).json({ code: 403, message: error.message });
        });
    } else {
        res.json({
            code: 400,
            message: 'Missing confirmation token',
        });
    }
});

userRouter.get('/profile', requiresAuthentication, (req: Request, res: Response) => {
    const _id = (req as any).user.user_id;
    User.findOne({ _id }).then(user => {
        if (user) {
            const { password, ...data } = (user as any)._doc;
            res.json({
                code: 200,
                data
            });
        } else {
            res.status(400).json({
                code: 400,
                message: 'Bad request'
            });
        }
    }).catch(error => {
        res.status(500).json({
            code: 500,
            message: error.message
        });
    });
});

userRouter.post('/profile', requiresAuthentication, (req: Request, res: Response) => {
    const _id = (req as any).user.user_id;
    const payload = {
        name: req.body.name,
    };
    User.updateOne({ _id }, payload).then(async (count) => {
        if (count) {
            const user = await User.findOne({ _id });
            if (!user) {
                return res.json({
                    code: 200,
                    message: 'User profiled updated.'
                });
            }
            const { password, ...data } = (user as any)._doc;
            res.json({
                code: 200,
                message: 'User profiled updated.',
                data
            });
        } else {
            res.status(400).json({
                code: 400,
                message: 'Bad request'
            });
        }
    }).catch(error => {
        res.status(500).json({
            code: 500,
            message: error.message
        });
    });
});

userController.use('/', userRouter);