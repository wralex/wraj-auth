#!/usr/bin/env node

/**
 * Module dependencies.
 */

import app from '../app';
import Debug from 'debug';
const debug = Debug('msal:server');
import http from 'node:http';

import { AddressInfo } from 'node:net';
import dotenv from '@dotenvx/dotenvx';
if (process.env.NODE_ENV !== 'production'){
    dotenv.config()
}

/**
 * Get port from environment and store in Express.
 */
const port = normalizePort(process.env.PORT ?? '3000');
app.set('port', port);

/**
 * Create HTTP server.
 */
const server = http.createServer(app);

server.on('error', onError);
server.on('listening', onListening);

/**
 * Listen on provided port, on all network interfaces.
 */
server.listen(port);

/**
 * Normalize a port into a number, string, or false.
 */
function normalizePort(val: string | number) {
    const port = parseInt(val.toString(), 10);

    if (isNaN(port)) {
        // named pipe
        return val;
    }

    if (port >= 0) {
        // port number
        return port;
    }

    return false;
}

/**
 * Event listener for HTTP server "error" event.
 */

function onError(error: NodeJS.ErrnoException) {
    if (error.syscall !== 'listen') {
        throw error;
    }

    const bind = typeof port === 'string'
        ? 'Pipe ' + port
        : 'Port ' + port;

    // handle specific listen errors with friendly messages
    switch (error.code) {
        case 'EACCES':
            console.error(bind + ' requires elevated privileges');
            process.exit(1);
        case 'EADDRINUSE':
            console.error(bind + ' is already in use');
            process.exit(1);
        default:
            throw error;
    }
}

/**
 * Event listener for HTTP server "listening" event.
 */
function onListening() {
    const addr = server.address() as AddressInfo;
    const bind = typeof addr === 'string'
        ? addr
        : addr.port;
    debug('Listening on http://localhost:' + bind);
    console.log('Listening on http://localhost:' + bind);
}
