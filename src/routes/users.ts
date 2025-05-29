/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */

import express, { Request, Response, NextFunction } from 'express';
const router = express.Router();
export default router;

import fetch from '../fetch';

import dotenv from '@dotenvx/dotenvx';
if (process.env.NODE_ENV !== 'production'){
    dotenv.config()
}
const GRAPH_ME_ENDPOINT = process.env.GRAPH_API_ENDPOINT + "v1.0/me";

// custom middleware to check auth state
function isAuthenticated(req: Request, res: Response, next: NextFunction) {
    if (!req.session.isAuthenticated) {
        return res.redirect('/auth/signin'); // redirect to sign-in route
    }

    next();
};

router.get('/id',
    isAuthenticated, // check if user is authenticated
    async function (req, res, next) {
        res.render('id', { idTokenClaims: req.session.account.idTokenClaims });
    }
);

router.get('/profile',
    isAuthenticated, // check if user is authenticated
    async function (req, res, next) {
        try {
            if (!req.session.accessToken){
                throw Error('Access Token is required for the Profile to be seen. Please create Token in advance.')
            }
            const graphResponse = await fetch(GRAPH_ME_ENDPOINT, req.session.accessToken);
            res.render('profile', { profile: graphResponse });
        } catch (error) {
            next(error);
        }
    }
);
