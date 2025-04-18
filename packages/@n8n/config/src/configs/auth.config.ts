import { Config, Env, Nested } from '../decorators';

@Config
class CookieConfig {
	/** This sets the `Secure` flag on n8n auth cookie */
	@Env('N8N_SECURE_COOKIE')
	secure: boolean = true;

	/** This sets the `Samesite` flag on n8n auth cookie */
	@Env('N8N_SAMESITE_COOKIE')
	samesite: 'strict' | 'lax' | 'none' = 'lax';
}

@Config
class SsoConfig {
	/** Shared secret for JWT-based SSO from host application */
	@Env('N8N_SSO_SHARED_SECRET')
	embedJwtSecret: string = '';
}

@Config
export class AuthConfig {
	@Nested
	cookie: CookieConfig;

	@Nested
	sso: SsoConfig;
}
