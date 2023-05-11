import { NextFunction, Request, Response } from "express";
import { User } from "../models/user.model";
import { verify } from "jsonwebtoken";

export function requiresAuthentication(req: Request, res: Response, next: NextFunction) {
    const token = req.body['access-token'] || req.query['access-token'] || req.headers['x-access-token'] || req.headers['authorization']?.slice(6);

    if (!token) {
        return res.status(403).json({ code: 403, message: 'Missing access token.' });
    }

    try {
        const { JWT_SECRET } = process.env;
        if (JWT_SECRET) {
            const decoded = verify(token, JWT_SECRET);
            (req as any).user = decoded;
        } else {
            return res.status(500).json({ code: 500, message: 'Misconfiguration' });
        }
    } catch (err: any) {
        return res.status(403).json({ code: 403, message: err.message });
    }

    return next();
}

export function requiresAuthorization(level: number | string) {
    return function (req: Request, res: Response, next: NextFunction) {
        next();
    }
}

export function requiresAPIToken(req: Request, res: Response, next: NextFunction) {
    const token = req.header('x-api-token');
    if (token) {
        User.findOne({ api_token: token }).then(
            user => {
                if (user) {
                    (req as any).user = user;
                    next();
                } else {
                    res.status(403).json({ message: 'Invalid api token.', code: 403 });
                }
            },
            error => {
                res.status(403).json({ message: error.message, code: 403 });
            }
        );
    } else {
        res.status(403).json({ message: 'Missing api token.', code: 403 });
    }
}