import express, { Request, Response, Router } from 'express';
import { hash, compare } from 'bcrypt';
import { config } from 'dotenv';
import { User } from '../models/user.model';
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
})

userController.use('/', userRouter);