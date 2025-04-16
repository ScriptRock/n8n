import { defineStore } from 'pinia';
import { computed, ref } from 'vue';
import type { IUser } from '@/Interface';

export type AuthenticationType = 'email' | 'ldap' | 'saml' | 'embed';

export const useAuthStore = defineStore('auth', () => {
	const currentUser = ref<IUser | null>(null);
	const authenticatedWith = ref<AuthenticationType>('email');

	const isAuthenticated = computed(() => currentUser.value !== null);

	function setCurrentUser(user: IUser | null) {
		currentUser.value = user;
	}

	function setAuthenticatedWith(type: AuthenticationType) {
		authenticatedWith.value = type;
	}

	return {
		currentUser,
		authenticatedWith,
		isAuthenticated,
		setCurrentUser,
		setAuthenticatedWith,
	};
});
