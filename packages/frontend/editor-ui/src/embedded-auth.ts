import type { AxiosError } from 'axios';
import { useAuthStore } from '@/stores/auth.store';
import { useRootStore } from '@/stores/root.store';
import { useUIStore } from '@/stores/ui.store';
import { useUsersStore } from '@/stores/users.store';
import { useSettingsStore } from '@/stores/settings.store';
import axios from 'axios';
import { jwtDecode } from 'jwt-decode';

// Extend Window interface to support embedded mode flag
declare global {
	interface Window {
		__embedded?: boolean;
		__embeddedAuthPending?: boolean;
		__embeddedAuthReloaded?: boolean;
	}
}

interface EmbeddedAuthMessage {
	type: 'auth';
	token: string;
}

interface JwtPayload {
	sub?: string;
	email?: string;
	// Add other expected payload fields if needed
}

/**
 * Initialize listener for embedded authentication via postMessage
 */
/**
 * Skip welcome screens and setup pages for embedded mode
 */
function skipSetupScreens(): void {
	console.log('n8n: Skipping welcome screens and setup pages for embedded mode');

	// Mark setup flags as completed
	try {
		// Set localStorage flags to skip onboarding/welcome screens
		const setupFlags = [
			'userSetupCompleted',
			'personalizeRecommendationsCompleted',
			'welcomeScreenSeen',
			'onboardingCallCompleted',
			'firstWorkflowCreated',
			'firstNodeCreated',
			'firstWorkflowRunCompleted',
		];

		setupFlags.forEach((flag) => {
			localStorage.setItem(flag, 'true');
		});

		console.log('n8n: Setup flags set to skip welcome screens');
	} catch (error) {
		console.warn('n8n: Failed to set setup flags:', error);
	}
}

// IIFE to inject blocking CSS if needed
(function injectEmbeddedBlockerIfNeeded() {
	const isIframe = window.self !== window.top;
	const styleId = 'embedded-auth-blocker-style';
	const styleElement = document.getElementById(styleId);

	// Only inject if in iframe and blocker is not already present
	if (isIframe && !styleElement) {
		console.log('n8n: Injecting app blocker CSS (iframe detected)');
		const newStyleElement = document.createElement('style');
		newStyleElement.id = styleId;
		newStyleElement.innerHTML = `
			/* Hide main app container */
			#app {
				display: none !important;
			}
			/* Show a simple loading spinner instead */
			body:before {
				content: '';
				position: fixed;
				top: 50%;
				left: 50%;
				width: 50px;
				height: 50px;
				margin-top: -25px;
				margin-left: -25px;
				border: 5px solid #ccc;
				border-top-color: #4489fe;
				border-radius: 50%;
				animation: spin 1s linear infinite;
				z-index: 999999;
			}
			@keyframes spin {
				to { transform: rotate(360deg); }
			}
		`;
		document.head.appendChild(newStyleElement);
	}
})();

export function initEmbeddedAuth(): void {
	console.log('n8n: Initializing embedded auth message listener');

	// Skip welcome screens for embedded mode
	skipSetupScreens();

	// Set embedded mode flag to true
	window.__embedded = true;
	console.log('n8n: Set embedded mode flag');

	window.addEventListener('message', async (event) => {
		console.log('n8n: Received postMessage event', {
			origin: event.origin,
			isFromParent: event.source === window.parent,
			hasData: !!event.data,
		});

		if (event.source !== window.parent) {
			console.log('n8n: Ignoring message - not from parent window');
			return;
		}

		const message = event.data as EmbeddedAuthMessage;
		console.log('n8n: Processing message', {
			messageType: message?.type,
			hasToken: !!message?.token,
			tokenPreview: message?.token ? `${message.token.substring(0, 10)}...` : null,
		});

		if (!message || message.type !== 'auth' || !message.token) {
			console.log('n8n: Ignoring message - not an auth message or missing token');
			return;
		}

		// --- Authenticate and Reload Flow ---
		try {
			console.log('n8n: Processing authentication request via postMessage');

			// Authenticate with the token
			console.log('n8n: Making API request to /rest/auth/embedded-auth');
			const response = await axios.post(
				'/rest/auth/embedded-auth',
				{ token: message.token },
				{ headers: { 'Content-Type': 'application/json' } },
			);

			if (response.data && response.data.id) {
				console.log('n8n: API Auth successful', { userId: response.data.id });

				// Remove the blocker CSS *before* reloading
				const styleElement = document.getElementById('embedded-auth-blocker-style');
				if (styleElement) {
					console.log('n8n: Removing app blocker CSS before reload');
					styleElement.remove();
				}
				const appElement = document.getElementById('app');
				if (appElement) {
					// Ensure app is visible before reload (might cause flash)
					appElement.style.display = 'block';
					appElement.style.visibility = 'visible';
				}

				// Trigger reload for session commit if this hasn't happened already
				if (window.self !== window.top && !window.__embeddedAuthReloaded) {
					window.__embeddedAuthReloaded = true;
					console.log('n8n: Triggering reload now...');
					window.location.replace(window.location.href);
					// Execution stops here due to reload
				} else {
					// This case might occur if the message is somehow received after a reload
					// or if not in an iframe. Ensure blocker is gone.
					console.log('n8n: Auth successful, no reload needed (already reloaded or not iframe).');
					const styleElement = document.getElementById('embedded-auth-blocker-style');
					if (styleElement) styleElement.remove();
					const appElement = document.getElementById('app');
					if (appElement) {
						appElement.style.display = 'block';
						appElement.style.visibility = 'visible';
					}
				}
			} else {
				// Handle API error
				console.error('n8n: Embedded auth API call failed', response);
				window.parent.postMessage({ type: 'auth-error', error: 'API call failed' }, '*');
			}
		} catch (error) {
			// Handle network/axios error
			console.error('n8n: Embedded authentication failed:', (error as AxiosError).message, error);
			window.parent.postMessage({ type: 'auth-error', error: (error as AxiosError).message }, '*');
		}
		// --- End New User Flow ---
	});
}
