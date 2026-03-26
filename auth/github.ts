import {
  decodeBase64Url,
  encodeBase64Url,
} from "jsr:@std/encoding@1.0.10/base64url";
import {
  deleteCookie,
  getCookies,
  setCookie,
} from "jsr:@std/http@1.0.25/cookie";
import {
  parseSignedCookie,
  signCookie,
  verifySignedCookie,
} from "jsr:@std/http@1.0.25/unstable-signed-cookie";
import { route } from "jsr:@std/http@1.0.25/unstable-route";
import { OAuthApp } from "npm:octokit@5.0.3";

import type { AuthProvider, AuthProviderOptions } from "../types.ts";

type Routes = "getCallback" | "getLogin" | "postLogout";

/**
 * Options for {@link AuthGitHub}.
 * Extends Octokit `OAuthApp` options with LumeCMS-specific fields.
 */
export type AuthGitHubOptions = ConstructorParameters<typeof OAuthApp>[0] & {
  /**
   * Secret used to HMAC-sign the session cookie.
   * If omitted, the cookie is unsigned.
   */
  authSecret?: string;
};

/**
 * Session data emitted via the "authentication" event.
 *
 * Fires after the user's GitHub identity is confirmed. Note that this is
 * **authentication** (who you are), not **authorization** (what you can
 * do). Callers should still verify the user is permitted to access CMS
 * features.
 *
 * Dispatched after successful authentication (both on initial callback
 * and when reading an existing session cookie).
 */
export type AuthGitHubSession = {
  user: {
    email: string | null;
    login: string;
    name: string | null;
  };
  authentication: {
    token: string;
    tokenType: "oauth";
  };
};

/**
 * GitHub OAuth authentication provider for LumeCMS.
 *
 * Implements the GitHub OAuth web flow: redirects unauthenticated users to
 * GitHub, exchanges the code for a token, and stores the session in a signed
 * HttpOnly cookie mapped to a configured CMS user.
 *
 * Auth routes are fixed at `{basePath}/auth/oauth/github/callback` and are
 * not configurable.
 *
 * @remarks
 * **Setting up a GitHub App:**
 * 1. Go to GitHub → Settings → Developer settings → GitHub Apps → New GitHub App.
 * 2. Set "Callback URL" to `{your-site}/auth/oauth/github/callback`
 *  (e.g. `http://127.0.0.1:8000/auth/oauth/github/callback` for local dev).
 * 3. Enable "Request user authorization (OAuth) during installation".
 * 4. Disable "Webhook".
 * 5. Under "Where can this GitHub App be installed?", select **"Any account"**
 *  (If left on "Only on this account", other users will get a 404 error when logging in).
 * 6. Create the App, then copy the **Client ID** and generate a **Client Secret**.
 * 7. Store **Client ID** as `GITHUB_CLIENT_ID` and **Client Secret** as
 * `GITHUB_CLIENT_SECRET` to use with `Deno.env.get()` as shown below.
 *
 * @example
 * ```ts
 * cms.auth(
 *   { myusername: { password: "" } },
 *   new AuthGitHub({
 *     authSecret: Deno.env.get("AUTH_SECRET"),
 *     clientId: Deno.env.get("GITHUB_CLIENT_ID"),
 *     clientSecret: Deno.env.get("GITHUB_CLIENT_SECRET"),
 *   }),
 * );
 * ```
 */
export default class AuthGitHub extends EventTarget implements AuthProvider {
  fetch: (request: Request) => Response | Promise<Response>;
  options: AuthProviderOptions | undefined;

  #client: InstanceType<typeof OAuthApp>;
  #encoder = new TextEncoder();
  #decoder = new TextDecoder();
  #secretKeyPromise: Promise<CryptoKey> | undefined;
  #cookieName = "auth_session";
  #cookieAttributes: Parameters<typeof deleteCookie>[2] = {
    httpOnly: true,
    secure: true,
    partitioned: true,
    path: "/",
  };
  #routes = {
    getCallback: {
      method: "GET",
      pattern: new URLPattern({ pathname: "*/auth/oauth/github/callback" }),
      handler: this.#handleGetCallback.bind(this),
    },
    getLogin: {
      method: "GET",
      pattern: new URLPattern({ pathname: "*/auth/login" }),
      handler: this.#handleGetLogin.bind(this),
    },
    postLogout: {
      method: "POST",
      pattern: new URLPattern({ pathname: "*/auth/logout" }),
      handler: this.logout.bind(this),
    },
  } as const;

  constructor(options: AuthGitHubOptions) {
    super();
    if (options.authSecret) {
      this.#secretKeyPromise = crypto.subtle.importKey(
        "raw",
        this.#encoder.encode(options.authSecret),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign", "verify"],
      );
    }

    this.#client = new OAuthApp({
      clientType: "github-app",
      ...options,
    });

    this.fetch = route(
      Object.values(this.#routes),
      () => new Response("Not found", { status: 404 }),
    );
  }

  /**
   * Register a listener for authentication events.
   *
   * The "authentication" event fires with `CustomEvent<AuthGitHubSession>`
   * whenever a user is successfully authenticated (either via callback
   * or when reading an existing session cookie).
   *
   * @example
   * ```ts
   * auth.addEventListener("authentication", (ev) => {
   *   console.log("Authenticated as:", ev.detail.user.login);
   * });
   * ```
   */
  override addEventListener(
    type: "authentication",
    listener:
      | EventListenerObject
      | (((ev: CustomEvent<AuthGitHubSession>) => any) | null),
    options?: boolean | AddEventListenerOptions,
  ): void;
  override addEventListener(
    ...[type, listener, options]: Parameters<EventTarget["addEventListener"]>
  ) {
    return super.addEventListener(type, listener, options);
  }

  /**
   * Called by LumeCMS to pass the provider options (users, basePath, etc.).
   */
  init(options: AuthProviderOptions) {
    this.options = options;
  }

  /**
   * Checks if the request is already authenticated via session cookie.
   *
   * Returns the username if valid, otherwise redirects to GitHub OAuth.
   * Fires an "authentication" event when a valid session is found.
   */
  async login(request: Request): Promise<Response | string> {
    this.#assertOptions();

    const username = await this.#getUsername(request.headers);
    if (username && this.options.users.has(username)) {
      return username;
    }

    return this.#handleGetLogin(request);
  }

  async #handleGetLogin(request: Request): Promise<Response> {
    this.#assertOptions();

    const username = await this.#getUsername(request.headers);

    const requestUrl = new URL(request.url);
    let referrerUrl: URL | null = null;
    if (request.headers.has("referer")) {
      try {
        referrerUrl = new URL(request.headers.get("referer")!);
      } catch { /* empty */ }
    }
    const candidateReturnUrl = this.#isRoute("getLogin", requestUrl)
      ? referrerUrl
      : requestUrl;
    const isValidReturnUrl = candidateReturnUrl &&
      this.#isSameOrigin(requestUrl, candidateReturnUrl) &&
      !this.#isRoute("getLogin", candidateReturnUrl);
    const baseUrl = new URL(this.options.basePath || "/", requestUrl.origin);
    // URL where to return once authenticated
    const returnUrl = (isValidReturnUrl ? candidateReturnUrl : baseUrl)
      .toString();
    const basePath = baseUrl.pathname.length > 1 ? baseUrl.pathname : "";
    const callbackUrl = new URL(
      basePath + this.#routes.getCallback.pattern.pathname.slice(1),
      requestUrl.origin,
    );
    callbackUrl.searchParams.set("redirect_uri", returnUrl);

    const gitHubUrl = new URL(
      this.#client.getWebFlowAuthorizationUrl({
        redirectUrl: callbackUrl.href,
      }).url,
    );

    // If already authenticated, force a prompt to switch account
    if (username) {
      gitHubUrl.searchParams.set("prompt", "select_account");
    }

    const headers = new Headers({ location: gitHubUrl.toString() });
    return new Response(null, {
      headers,
      status: 302,
    });
  }

  /**
   * Clears the session cookie to log the user out.
   */
  async logout(_request: Request): Promise<Response> {
    const headers = new Headers();
    deleteCookie(headers, this.#cookieName, this.#cookieAttributes);
    return new Response(null, {
      headers,
      status: 204,
    });
  }

  async #getUsername(headers: Headers): Promise<string | undefined> {
    const cookies = getCookies(headers);

    if (!cookies[this.#cookieName]) {
      return;
    }

    let maybeSignedValue = cookies[this.#cookieName];

    if (this.#secretKeyPromise) {
      const isValidCookie = await verifySignedCookie(
        maybeSignedValue,
        await this.#secretKeyPromise,
      );

      if (!isValidCookie) {
        // Not authenticated
        return;
      }

      maybeSignedValue = parseSignedCookie(maybeSignedValue);
    }

    let session;

    try {
      session = JSON.parse(
        this.#decoder.decode(decodeBase64Url(maybeSignedValue)),
      );
    } catch { /* empty */ }

    // Could ignore the cookie cached value and verify each time with GitHub
    // const { data: { user } } = await this.#client.checkToken({ token: value.authentication.token });

    // Or use the cookie cached value
    const { user } = session ?? {};

    // Authenticated as
    const username = user?.login;

    if (username) {
      this.dispatchEvent(
        new CustomEvent<AuthGitHubSession>("authentication", {
          detail: session,
        }),
      );
    }

    return username;
  }

  async #handleGetCallback(request: Request): Promise<Response> {
    this.#assertOptions();

    const requestUrl = new URL(request.url);
    const { searchParams } = requestUrl;

    if (searchParams.has("error")) {
      throw new Error(
        `[${this.constructor.name}] ${searchParams.get("error")} ${
          searchParams.get("error_description")
        }`,
      );
    }

    if (!searchParams.has("code")) {
      throw new Error(
        `[${this.constructor.name}] "code" parameter is required`,
      );
    }

    const { authentication } = await this.#client.createToken({
      code: searchParams.get("code") ?? "",
      state: searchParams.get("state") ?? undefined,
    });
    const userClient = await this.#client.getUserOctokit({
      token: authentication.token,
      scopes: ["read:user"],
    });
    const { data: user } = await userClient.request("GET /user");

    const unsafeRedirect = searchParams.get("redirect_uri");
    let safeRedirect;
    if (unsafeRedirect) {
      try {
        const redirectUrl = new URL(unsafeRedirect);
        if (this.#isSameOrigin(requestUrl, redirectUrl)) {
          safeRedirect = redirectUrl.pathname + redirectUrl.search +
            redirectUrl.hash;
        }
      } catch { /* empty */ }
    }

    const headers = new Headers({
      location: safeRedirect ??
        (this.options.basePath || "/"),
    });

    const session: AuthGitHubSession = {
      user: {
        login: user.login,
        email: user.email,
        name: user.name,
      },
      authentication: {
        // expiresAt: authentication.expiresAt,
        // refreshToken: authentication.refreshToken,
        // refreshTokenExpiresAt: authentication.refreshTokenExpiresAt,
        token: authentication.token,
        tokenType: authentication.tokenType,
      },
    };

    let value = encodeBase64Url(this.#encoder.encode(JSON.stringify(session)));

    if (this.#secretKeyPromise) {
      value = await signCookie(value, await this.#secretKeyPromise);
    }

    setCookie(headers, {
      ...this.#cookieAttributes,
      name: this.#cookieName,
      value,
      sameSite: "Lax",
      expires: "expiresAt" in authentication
        ? new Date(authentication.expiresAt as string)
        : undefined,
    });

    this.dispatchEvent(
      new CustomEvent<AuthGitHubSession>("authentication", { detail: session }),
    );

    return new Response(null, {
      headers,
      status: 302,
    });
  }

  #isSameOrigin(url: URL, another: URL): boolean {
    return url.origin === another.origin;
  }

  #isRoute(routeName: Routes, url: URL): boolean {
    return this.#routes[routeName].pattern.test(url);
  }

  #assertOptions(): asserts this is { options: AuthProviderOptions } {
    if (!this.options) {
      throw new Error("AuthProvider not initialized");
    }
  }
}
