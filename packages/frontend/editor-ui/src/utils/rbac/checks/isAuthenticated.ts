import { useUsersStore } from '@/stores/users.store';
import type { RBACPermissionCheck, AuthenticatedPermissionOptions } from '@/types/rbac';

export const isAuthenticated: RBACPermissionCheck<AuthenticatedPermissionOptions> = (options) => {
	if (options?.bypass?.()) {
		return true;
	}

	// Bypass auth check in embedded mode if the app blocker style is present
	if (
		typeof window !== 'undefined' &&
		window.self !== window.top &&
		document.getElementById('embedded-auth-blocker-style')
	) {
		return true;
	}

	const usersStore = useUsersStore();
	return !!usersStore.currentUser;
};
