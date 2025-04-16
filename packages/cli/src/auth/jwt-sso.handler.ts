import { GlobalConfig } from '@n8n/config';
import { Container, Service } from '@n8n/di';
import { randomBytes } from 'crypto';
import jwt from 'jsonwebtoken';
import { Logger } from 'n8n-core';

import { AuthIdentity, AuthProviderType } from '@/databases/entities/auth-identity';
import { User } from '@/databases/entities/user';
import { AuthIdentityRepository } from '@/databases/repositories/auth-identity.repository';
import { ProjectRepository } from '@/databases/repositories/project.repository';
import { ProjectRelationRepository } from '@/databases/repositories/project-relation.repository';
import { UserRepository } from '@/databases/repositories/user.repository';
import { AuthError } from '@/errors/response-errors/auth.error';
import { JwtService } from '@/services/jwt.service';
import { ProjectService, TeamProjectOverQuotaError } from '@/services/project.service.ee';

interface EmbedJwtPayload {
	sub: string;
	email: string;
	name: string;
	org_id: number;
	iat: number;
	exp: number;
	nbf?: number; // Not Before (if present in JWT v5)
}

@Service()
export class JwtSsoHandler {
	private readonly sharedSecret: string;

	constructor(
		private readonly userRepository: UserRepository,
		private readonly authIdentityRepository: AuthIdentityRepository,
		private readonly jwtService: JwtService,
		private readonly logger: Logger,
		private readonly globalConfig: GlobalConfig,
	) {
		// Try to get the secret from environment directly first
		this.sharedSecret = process.env.N8N_SSO_SHARED_SECRET || '';

		if (!this.sharedSecret) {
			// Fall back to config system
			this.sharedSecret = this.globalConfig.auth.sso.embedJwtSecret;
		}

		if (!this.sharedSecret) {
			this.logger.warn('N8N_SSO_SHARED_SECRET not set. JWT SSO will not function correctly.');
		} else {
			this.logger.info(
				`JWT SSO shared secret loaded (length: ${this.sharedSecret.length}, first 3 chars: ${this.sharedSecret.substring(0, 3)}***)`,
			);
			// Optionally add this debug line with the full secret for testing, but REMOVE BEFORE PRODUCTION
			// this.logger.debug(`Raw secret for testing: "${this.sharedSecret}"`);
		}
	}

	async handleEmbedAuth(token: string): Promise<User> {
		try {
			this.logger.info('Handling embedded authentication with JWT token');

			if (!this.sharedSecret) {
				this.logger.error('N8N_SSO_SHARED_SECRET is not set, cannot verify JWT');
				throw new AuthError('Server configuration error: Missing shared secret');
			}

			// Verify JWT with shared secret
			this.logger.debug('Verifying JWT token');
			this.logger.debug(`Token preview: ${token.substring(0, 20)}...`);

			// First decode without verification to check claims
			const decoded = jwt.decode(token, { complete: true });
			this.logger.debug(`Token header: ${JSON.stringify(decoded?.header)}`);
			if (decoded?.payload) {
				this.logger.debug(
					`Token payload preview: ${JSON.stringify(decoded.payload).substring(0, 100)}...`,
				);
			}

			let payload: EmbedJwtPayload;

			try {
				// Now verify with the secret
				payload = jwt.verify(token, this.sharedSecret) as EmbedJwtPayload;
				this.logger.info('JWT token verified successfully', {
					sub: payload.sub,
					email: payload.email,
					name: payload.name,
					org_id: payload.org_id,
				});
			} catch (error) {
				// If verification fails, log the error and re-throw
				this.logger.error(`JWT verification failed: ${error.message}`);
				throw error;
			}

			// Check if user already exists
			this.logger.debug(`Checking if user exists with email: ${payload.email}`);
			let user = await this.userRepository.findOne({
				where: { email: payload.email },
				relations: ['authIdentities'],
			});

			let isNewUser = false;
			if (user) {
				this.logger.info(`User found: ${user.email} (ID: ${user.id})`);
				// User exists, ensure they have an 'email' auth identity for embed
				const hasEmbedIdentity = user.authIdentities?.some(
					(identity) => identity.providerId === 'embed' && identity.providerType === 'email',
				);

				if (!hasEmbedIdentity) {
					this.logger.info(`Creating 'embed' auth identity for existing user: ${user.email}`);
					// Create auth identity for existing user
					await this.createAuthIdentity(user, payload);
				} else {
					this.logger.info(`User already has 'embed' auth identity`);
				}
			} else {
				this.logger.info(`User not found, creating new user with email: ${payload.email}`);
				// Create new user with embed identity
				user = await this.createUserWithIdentity(payload);
				isNewUser = true;
			}

			// Handle project setup for the user
			try {
				const projectService = Container.get(ProjectService);

				// First check if user already has any projects
				const userProjects = await projectService.getProjectRelationsForUser(user);
				if (userProjects.length > 0) {
					this.logger.info(
						`User ${user.email} already has access to ${userProjects.length} projects`,
					);
					return user;
				}

				// Try to set up an organization-based project if we have an org_id
				if (payload.org_id) {
					try {
						this.logger.info(
							`Setting up organization project for organization ID: ${payload.org_id}`,
						);

						// Get or create a project for this organization
						const projectId = await this.getOrCreateOrgProject(payload.org_id, user);

						// Add the user to the project if they're not already added
						if (!userProjects.some((pr) => pr.projectId === projectId)) {
							this.logger.info(`Adding user ${user.email} to organization project ${projectId}`);
							// Use editor role as the minimum viable role to work with workflows
							await projectService.addUser(projectId, user.id, 'project:editor');
							this.logger.info(
								`User ${user.email} successfully added to organization project ${projectId}`,
							);
							return user;
						} else {
							this.logger.info(
								`User ${user.email} already belongs to organization project ${projectId}`,
							);
							return user;
						}
					} catch (error) {
						if (error instanceof TeamProjectOverQuotaError) {
							this.logger.warn(
								`Team project quota exceeded, falling back to personal project: ${error.message}`,
							);
						} else {
							this.logger.error(`Failed to setup organization project: ${error.message}`, {
								error,
							});
						}
						// Continue to personal project fallback
					}
				} else {
					this.logger.warn('No organization ID found in JWT token, using personal project instead');
				}

				// Fallback: Create or use personal project
				this.logger.info(`Setting up personal project for user: ${user.email}`);
				let personalProject = await projectService.getPersonalProject(user);

				if (personalProject) {
					this.logger.info(
						`User ${user.email} already has a personal project: ${personalProject.id}`,
					);
				} else {
					this.logger.info(
						`No personal project found for user ${user.email}, creating one manually`,
					);

					try {
						// Try to create a project manually with a personal type
						await this.createManualPersonalProject(user);

						// Check if it was created successfully
						personalProject = await projectService.getPersonalProject(user);
						if (personalProject) {
							this.logger.info(
								`Created personal project for user ${user.email}: ${personalProject.id}`,
							);
						} else {
							this.logger.warn(`Failed to verify personal project creation for user ${user.email}`);
						}
					} catch (error) {
						this.logger.error(`Failed to create personal project manually: ${error.message}`, {
							error,
						});
					}
				}
			} catch (error) {
				this.logger.error(`Failed to setup any project for user: ${error.message}`, { error });
				// Don't fail authentication if project setup fails
				// We'll just log the error and continue
			}

			this.logger.info(`Authentication successful for user: ${user.email} (ID: ${user.id})`);
			return user;
		} catch (error) {
			this.logger.error('Failed to authenticate with JWT token', {
				error,
				message: error instanceof Error ? error.message : 'Unknown error',
				stack: error instanceof Error ? error.stack : undefined,
			});

			if (error instanceof jwt.JsonWebTokenError) {
				this.logger.error(`JWT Error: ${error.message}`);
			}

			throw new AuthError('Invalid or expired JWT token');
		}
	}

	private async createAuthIdentity(user: User, payload: EmbedJwtPayload): Promise<void> {
		this.logger.debug(`Creating auth identity for user: ${user.email}`);

		const identity = new AuthIdentity();
		identity.providerId = 'embed';
		identity.providerType = 'email' as AuthProviderType;
		identity.user = user;
		identity.userId = user.id;

		await this.authIdentityRepository.save(identity);
		this.logger.debug(`Auth identity created successfully for user: ${user.email}`);
	}

	/**
	 * Gets or creates an organization project based on the org_id from the JWT payload
	 */
	private async getOrCreateOrgProject(orgId: number, creatorUser: User): Promise<string> {
		try {
			this.logger.debug(`Looking for existing project for organization ID: ${orgId}`);

			// Try to find an existing project for this organization
			const projectRepository = Container.get(ProjectRepository);
			const existingProject = await projectRepository.findOne({
				where: { name: `Organization ${orgId}` },
			});

			if (existingProject) {
				this.logger.info(
					`Found existing project for organization ID ${orgId}: ${existingProject.id}`,
				);
				return existingProject.id;
			}

			// Create a new project for this organization if it doesn't exist
			this.logger.info(`Creating new project for organization ID: ${orgId}`);
			const projectService = Container.get(ProjectService);

			const newProject = await projectService.createTeamProject(creatorUser, {
				name: `Organization ${orgId}`,
				icon: { value: '👥', type: 'emoji' },
			});

			this.logger.info(`Created new project for organization ID ${orgId}: ${newProject.id}`);
			return newProject.id;
		} catch (error) {
			this.logger.error(`Failed to get or create organization project: ${error.message}`);
			throw error;
		}
	}

	/**
	 * Manually creates a personal project for a user
	 */
	private async createManualPersonalProject(user: User): Promise<void> {
		try {
			this.logger.debug(`Manually creating personal project for user: ${user.email}`);

			// Get database connection to create project directly
			const projectRepository = Container.get(ProjectRepository);
			const projectRelationRepository = Container.get(ProjectRelationRepository);

			// Create a personal project
			const project = projectRepository.create({
				name: `Personal Project (${user.email})`,
				type: 'personal',
			});

			// Save the project
			const savedProject = await projectRepository.save(project);
			this.logger.info(`Created personal project with ID: ${savedProject.id}`);

			// Create the relation between user and project with personal owner role
			const relation = projectRelationRepository.create({
				userId: user.id,
				projectId: savedProject.id,
				role: 'project:personalOwner',
			});

			await projectRelationRepository.save(relation);
			this.logger.info(`Created personal project relation for user ${user.email}`);
		} catch (error) {
			this.logger.error(`Failed to create personal project: ${error.message}`, { error });
			throw error;
		}
	}

	private async createUserWithIdentity(payload: EmbedJwtPayload): Promise<User> {
		this.logger.debug(`Creating new user with email: ${payload.email}`);

		// Create new user
		const user = new User();
		user.email = payload.email;
		user.firstName = payload.name.split(' ')[0] || '';
		user.lastName = payload.name.split(' ').slice(1).join(' ') || '';
		user.password = randomBytes(24).toString('hex'); // Random secure password

		// Set all users to global:owner to ensure they can access personal projects
		user.role = 'global:owner';

		// Settings to avoid welcome stuff
		user.settings = {
			userActivated: true,
			userActivatedAt: 1743142541906,
			easyAIWorkflowOnboarded: true,
			npsSurvey: { waitingForResponse: true, ignoredCount: 2, lastShownAt: 1744686406744 },
		};

		this.logger.debug(
			`Saving user with name: ${user.firstName} ${user.lastName}, email: ${user.email}, role: ${user.role}`,
		);
		const savedUser = await this.userRepository.save(user);
		this.logger.info(`New user created with ID: ${savedUser.id}, email: ${savedUser.email}`);

		// Create auth identity
		await this.createAuthIdentity(savedUser, payload);

		return savedUser;
	}
}
