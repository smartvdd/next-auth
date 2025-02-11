import type { AuthConfig } from "@auth/core";
import type { ProviderId } from "@auth/core/providers";
import type { Session } from "@auth/core/types";
/** Configure the {@link SvelteKitAuth} method. */
export interface SvelteKitAuthConfig extends Omit<AuthConfig, "raw"> {
}
declare global {
    namespace App {
        interface Locals {
            auth(): Promise<Session | null>;
            /** @deprecated Use `auth` instead. */
            getSession(): Promise<Session | null>;
            signIn: <Redirect extends boolean = true>(
            /** Provider to sign in to */
            provider?: ProviderId, // See: https://github.com/microsoft/TypeScript/issues/29729
            options?: FormData | ({
                /** The URL to redirect to after signing in. By default, the user is redirected to the current page. */
                redirectTo?: string;
                /** If set to `false`, the `signIn` method will return the URL to redirect to instead of redirecting automatically. */
                redirect?: Redirect;
            } & Record<string, any>), authorizationParams?: string[][] | Record<string, string> | string | URLSearchParams) => Promise<Redirect extends false ? any : never>;
            signOut: <Redirect extends boolean = true>(options?: {
                /** The URL to redirect to after signing out. By default, the user is redirected to the current page. */
                redirectTo?: string;
                /** If set to `false`, the `signOut` method will return the URL to redirect to instead of redirecting automatically. */
                redirect?: Redirect;
            }) => Promise<Redirect extends false ? any : never>;
        }
        interface PageData {
            session?: Session | null;
        }
    }
}
declare module "$env/dynamic/private" {
    const AUTH_SECRET: string;
    const AUTH_SECRET_1: string;
    const AUTH_SECRET_2: string;
    const AUTH_SECRET_3: string;
    const AUTH_TRUST_HOST: string;
    const VERCEL: string;
}
//# sourceMappingURL=types.d.ts.map