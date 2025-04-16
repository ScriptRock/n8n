import { Container } from '@n8n/di';
import express from 'express';
import { Logger } from 'n8n-core';
import jwt from 'jsonwebtoken';

import { AuthService } from './auth/auth.service';
import { JwtSsoHandler } from './auth/jwt-sso.handler';
import { UserService } from './services/user.service';
import { EventService } from './events/event.service';
import { PostHogClient } from './posthog';

export function setupEmbeddedAuthRouter(app: express.Application, restEndpoint: string): void {
	const logger = Container.get(Logger);
	logger.info('Setting up custom embedded auth router');

	// Manual route for embedded authentication
	// This is a workaround for the controller not being properly registered
	app.post(`/${restEndpoint}/auth/embedded-auth`, express.json(), async (req, res) => {
		logger.info('Custom embedded auth endpoint called');

		try {
			const token = req.body?.token;

			if (!token) {
				logger.error('No token provided in embedded auth request');
				res.status(400).json({
					status: 'error',
					message: 'No authentication token provided',
				});
				return;
			}

			logger.debug(`Token received, length: ${token.length}`);
			logger.debug(`Token preview: ${token.substring(0, 20)}...`);

			// Basic token structure check
			try {
				const decoded = jwt.decode(token, { complete: true });
				logger.debug(`Token header: ${JSON.stringify(decoded?.header)}`);
				if (decoded?.payload) {
					logger.debug(
						`Token payload preview: ${JSON.stringify(decoded.payload).substring(0, 100)}...`,
					);
				}
			} catch (err) {
				logger.warn(`Unable to decode token structure: ${err.message}`);
			}

			const jwtSsoHandler = Container.get(JwtSsoHandler);
			const authService = Container.get(AuthService);
			const userService = Container.get(UserService);
			const eventService = Container.get(EventService);
			const postHog = Container.has(PostHogClient) ? Container.get(PostHogClient) : undefined;

			// Log secret debug info
			const secret = process.env.N8N_SSO_SHARED_SECRET || '';
			if (secret) {
				logger.info(
					`Using JWT shared secret from env var (length: ${secret.length}, starts with: ${secret.substring(0, 3)}***)`,
				);
			} else {
				logger.warn('N8N_SSO_SHARED_SECRET not set in environment');
			}

			logger.info('Processing JWT token for embedded authentication');
			const user = await jwtSsoHandler.handleEmbedAuth(token);

			logger.info(`User authenticated successfully: ${user.email} (ID: ${user.id})`);

			// Issue cookie for session
			logger.debug('Issuing auth cookie');
			// @ts-ignore - browserId might not be present in this request
			authService.issueCookie(res, user, req.browserId);

			logger.debug('Emitting user-logged-in event');
			eventService.emit('user-logged-in', {
				user,
				authenticationMethod: 'embed',
			});

			logger.info('Embedded auth successful, returning user data');
			const publicUser = await userService.toPublic(user, { posthog: postHog, withScopes: true });
			res.json(publicUser);
		} catch (error) {
			logger.error('Embedded auth failed', {
				error,
				message: error instanceof Error ? error.message : 'Unknown error',
				stack: error instanceof Error ? error.stack : undefined,
			});
			res.status(401).json({
				status: 'error',
				message: 'Authentication failed',
			});
		}
	});

	logger.info('Custom embedded auth router setup complete');
}
