/**
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import {
    AsgardeoAuthException,
    AsgardeoSPAClient,
    AuthClientConfig,
    BasicUserInfo,
    FetchResponse,
    Hooks,
    HttpRequestConfig,
    SPAUtils,
    SignInConfig
} from "@brionmario-experimental/asgardeo-auth-spa";
import { SPACustomGrantConfig } from "@brionmario-experimental/asgardeo-auth-spa/src/models/request-custom-grant";
import React, {
    FunctionComponent,
    MutableRefObject,
    PropsWithChildren,
    ReactNode,
    createContext,
    useContext,
    useEffect,
    useMemo,
    useRef,
    useState
} from "react";
import { AuthParams, ReactConfig } from ".";
import AuthAPI from "./api";
import { AuthContextInterface, AuthReactConfig, AuthStateInterface } from "./models";

/**
 * Default `AuthReactConfig` config.
 */
const defaultConfig: Partial<ReactConfig> = {
    disableAutoSignIn: true,
    disableTrySignInSilently: true
};

/**
 * Authentication Context to hold global states in react components.
 */
const AuthContext = createContext<AuthContextInterface>(null);

interface AuthProviderPropsInterface {
    config: AuthReactConfig;
    fallback?: ReactNode;
    getAuthParams?: () => Promise<AuthParams>;
    onSignOut?: () => void;
    plugin?: AsgardeoSPAClient;
}

const AuthProvider: FunctionComponent<PropsWithChildren<AuthProviderPropsInterface>> = (
    props: PropsWithChildren<AuthProviderPropsInterface>
) => {
    const { children, config: passedConfig, fallback, getAuthParams, onSignOut, plugin } = props;
    const AuthClient: AuthAPI = useMemo(() => {
        return new AuthAPI(plugin);
    }, [ plugin ]);

    const [ state, dispatch ] = useState<AuthStateInterface>(AuthClient.getState());
    const [ initialized, setInitialized ] = useState(false);

    const _config = useMemo(
        (): AuthReactConfig => ({ ...defaultConfig, ...passedConfig }), [ passedConfig ]
    );

    const signIn = async(
        config?: SignInConfig,
        authorizationCode?: string,
        sessionState?: string,
        authState?: string,
        callback?: (response: BasicUserInfo) => void,
        tokenRequestConfig?: {
            params: Record<string, unknown>
        }
    ): Promise<BasicUserInfo> => {
        console.log('REACT SDK:::authenticate.tsx -> Passed in config', _config);
        
        const ___config = await AuthClient.getConfigData();
        
        console.log('REACT SDK:::authenticate.tsx -> Config from AuthClient', ___config);
        
        if (!___config || Object.keys(___config).length === 0) {
            console.log('REACT SDK:::authenticate.tsx -> Config not found in storage. Re-Initializing...', _config);
            await AuthClient.init(_config);
        }

        try {
            setError(null);
            return await AuthClient.signIn(
                dispatch,
                state,
                config,
                authorizationCode,
                sessionState,
                authState,
                callback,
                tokenRequestConfig
            );
        } catch (error) {
            return Promise.reject(error);
        }
    };
    const signOut = (callback?: (response: boolean) => void): Promise<boolean> => {
        return AuthClient.signOut(dispatch, state, callback);
    };
    const getBasicUserInfo = () => AuthClient.getBasicUserInfo();
    const httpRequest = (config: HttpRequestConfig) => AuthClient.httpRequest(config);
    const httpRequestAll = (configs: HttpRequestConfig[]) => AuthClient.httpRequestAll(configs);
    const requestCustomGrant = (
        config: SPACustomGrantConfig,
        callback?: (response: BasicUserInfo | FetchResponse<any>) => void
    ) => AuthClient.requestCustomGrant(config, callback, dispatch);
    const revokeAccessToken = () => AuthClient.revokeAccessToken(dispatch);
    const getOIDCServiceEndpoints = () => AuthClient.getOIDCServiceEndpoints();
    const getHttpClient = () => AuthClient.getHttpClient();
    const getDecodedIDPIDToken = () => AuthClient.getDecodedIDPIDToken();
    const getDecodedIDToken = () => AuthClient.getDecodedIDToken();
    const getAccessToken = () => AuthClient.getAccessToken();
    const refreshAccessToken = () => AuthClient.refreshAccessToken();
    const isAuthenticated = () => AuthClient.isAuthenticated();
    const enableHttpHandler = () => AuthClient.enableHttpHandler();
    const disableHttpHandler = () => AuthClient.disableHttpHandler();
    const getIDToken = () => AuthClient.getIDToken();
    const updateConfig = (config: Partial<AuthClientConfig<AuthReactConfig>>) => AuthClient.updateConfig(config);
    const on = (hook: Hooks, callback: (response?: any) => void, id?: string): Promise<void> => {
        if (hook === Hooks.CustomGrant) {
            return AuthClient.on(hook, callback, id);
        }

        return AuthClient.on(hook, callback);
    };
    const trySignInSilently = (
        additionalParams?: Record<string, string | boolean>,
        tokenRequestConfig?: { params: Record<string, unknown> }
    ) => AuthClient.trySignInSilently(state, dispatch, additionalParams, tokenRequestConfig);
    
    const [ error, setError ] = useState<AsgardeoAuthException>();
    const initializationRef: MutableRefObject<boolean> = useRef(false);
    const reRenderCheckRef: MutableRefObject<boolean> = useRef(false);

    useEffect(() => {
        // Prevent multiple initializations
        if (initializationRef.current) {
            return;
        }
    
        // Mark as initialized to prevent re-runs
        initializationRef.current = true;
    
        // Prevent initialization if already authenticated
        if (state.isAuthenticated) {
            return;
        }
    
        let isMounted = true;
    
        const initializeAuth = async () => {
            try {
                const initResult = await AuthClient.init(_config);
    
                if (isMounted) {
                    setInitialized(initResult);
                    await checkIsAuthenticated();
                }
            } catch (error) {
                console.error('Authentication initialization failed:', error);
            }
        };
    
        initializeAuth();
    
        // Cleanup function
        return () => {
            isMounted = false;
            initializationRef.current = false;
        };
    }, [_config]);

    /**
     * Try signing in when the component is mounted.
     */
    useEffect(() => {
        // More robust handling of Strict Mode re-renders
        const mountId = Math.random().toString(36).substring(7);
        console.log(`AuthProvider mount: ${mountId}`);

        // React 18.x Strict.Mode has a new check for `Ensuring reusable state` to facilitate an upcoming react feature.
        // https://reactjs.org/docs/strict-mode.html#ensuring-reusable-state
        // This will remount all the useEffects to ensure that there are no unexpected side effects.
        // When react remounts the signIn hook of the AuthProvider, it will cause a race condition. Hence, we have to
        // prevent the re-render of this hook as suggested in the following discussion.
        // https://github.com/reactwg/react-18/discussions/18#discussioncomment-795623
        if (reRenderCheckRef.current) {
            console.log(`Skipping re-render for mount: ${mountId}`);
            return;
        }

        reRenderCheckRef.current = true;

        const performAuthentication = async () => {
            try {
                let isSignedOut = false;

                // Register sign-out hook with proper error handling
                const unsubscribeSignOut = await on(Hooks.SignOut, () => {
                    isSignedOut = true;
                    onSignOut?.();
                });

                // Skip if already authenticated
                if (state.isAuthenticated) {
                    return;
                }

                // Handle redirect callback
                if (!_config.skipRedirectCallback) {
                    const authParams = getAuthParams 
                        ? await getAuthParams() 
                        : null;

                    const url = new URL(location.href);

                    // More comprehensive redirect handling
                    const shouldHandleRedirect = 
                        SPAUtils.hasAuthSearchParamsInURL() ||
                        (new URL(url.origin + url.pathname).toString() === 
                        new URL(_config?.signInRedirectURL).toString()) ||
                        authParams?.authorizationCode ||
                        url.searchParams.get("error");

                    if (shouldHandleRedirect) {
                        try {
                            await signIn(
                                { callOnlyOnRedirect: true }, 
                                authParams?.authorizationCode, 
                                authParams?.sessionState,
                                authParams?.state
                            );
                            setError(null);
                        } catch (error) {
                            if (error && Object.prototype.hasOwnProperty.call(error, "code")) {
                                setError(error as AsgardeoAuthException);
                            }
                        }
                    }
                }

                // Additional authentication checks
                if (AuthClient.getState().isAuthenticated) {
                    return;
                }

                // Auto sign-in if session is active and not disabled
                if (!_config.disableAutoSignIn && await AuthClient.isSessionActive()) {
                    await signIn();
                }  

                // Silent sign-in handling
                if (!(_config.disableTrySignInSilently || isSignedOut)) {
                    try {
                        await trySignInSilently();
                        setError(null);
                    } catch (error) {
                        if (error && Object.prototype.hasOwnProperty.call(error, "code")) {
                            setError(error as AsgardeoAuthException);
                        }
                    }
                }

                // Ensure loading state is updated
                dispatch({ ...state, isLoading: false });

                // Return unsubscribe function for cleanup
                return () => {
                    // unsubscribeSignOut?.();
                };
            } catch (error) {
                console.error('Authentication process error:', error);
                dispatch({ ...state, isLoading: false });
            }
        };

        const cleanupPromise = performAuthentication();

        return () => {
            cleanupPromise.then(cleanup => cleanup?.());
        };
    }, [_config]);

    /**
     * Check if the user is authenticated and update the state.isAuthenticated value.
     */
    const checkIsAuthenticated = async () => {
        const isAuthenticatedState = await AuthClient.isAuthenticated();        

        if (isAuthenticatedState) {
            const response = await AuthClient.getBasicUserInfo();

            if (response) {
                const stateToUpdate ={
                    allowedScopes: response.allowedScopes,
                    displayName: response.displayName,
                    email: response.email,
                    isAuthenticated: true,
                    isLoading: false,
                    isSigningOut: false,
                    sub: response.sub,
                    username: response.username
                };

                AuthClient.updateState(stateToUpdate);
                dispatch({ ...state, ...stateToUpdate });

                return;
            }

            AuthClient.updateState({ ...state, isAuthenticated: isAuthenticatedState, isLoading: false });
            dispatch({ ...state, isAuthenticated: isAuthenticatedState, isLoading: false });
        }
    };

    /**
     * Render state and special case actions
     */
    return (
            <AuthContext.Provider
                value={ {
                    disableHttpHandler,
                    enableHttpHandler,
                    getAccessToken,
                    getBasicUserInfo,
                    getDecodedIDPIDToken,
                    getDecodedIDToken,
                    getHttpClient,
                    getIDToken,
                    getOIDCServiceEndpoints,
                    httpRequest,
                    httpRequestAll,
                    isAuthenticated,
                    on,
                    refreshAccessToken,
                    requestCustomGrant,
                    revokeAccessToken,
                    signIn,
                    signOut,
                    state,
                    trySignInSilently,
                    updateConfig,
                    error
                } }
            >
                { initialized ? children : fallback ?? null }
            </AuthContext.Provider>
    );
};

const useAuthContext = (): AuthContextInterface => {
    return useContext(AuthContext);
};

export { AuthProvider, useAuthContext };
