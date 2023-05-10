import express, { NextFunction, Request, Response, json } from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import logger from 'morgan';
import createHttpError from 'http-errors';
import helmet from 'helmet';
import mongoose from 'mongoose';
import { config } from 'dotenv';

import { auth } from './routes/auth';

config();

export const app = express();

const mongoUrl: string | undefined = process.env.MONGO_URL;

if (mongoUrl) {
    mongoose.connect(mongoUrl).then(
        () => {
            console.log('Connected to MongoDB');
        },
        (reason) => {
            console.log('Error connecting to MongoDB: ', reason.message);
        }
    )
}

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(cors());
app.use(logger('dev'));
app.use(json());
app.use(helmet());

app.use('/auth', auth);

app.use('/', (req: Request, res: Response) => {
    res.send('Welcome!');
});

app.use((req: Request, res: Response, next: NextFunction) => {
    next(createHttpError(404));
});

app.use((err: any, req: Request, res: Response, next: NextFunction) => {
    res.locals.message = err.message;
    res.locals.error = req.app.get('env') === 'development' ? err : {};

    res.status(err.status || 500);
    res.json({
        success: false,
        message: err.message
    });
});
