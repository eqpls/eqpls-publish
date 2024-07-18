const Auth = {};

Auth._endpoint = new Keycloak({
	url: 'https://example.com/auth',
	realm: 'eqpls',
	clientId: 'openid'
});

Auth.init =(resultHandler, errorHandler)=> {
	try {
		Auth._endpoint.onAuthSuccess =()=> {
			Auth.getTokens((tokens)=>{
				let authHeader = `Bearer ${tokens.accessToken}`;
				Auth.RestHeaders = {
					"Content-Type": "application/json; charset=utf-8",
					"Accept": "application/json; charset=utf-8",
					"Authorization": authHeader,
					"Realm": "admin"
				}
				if (resultHandler) { resultHandler(Auth); }
			});
		};
		Auth._endpoint.onAuthError =()=> {
			console.error('failed to initialize keycloak:', e);
			if (errorHandler) { errorHandler(e); }
		};
		Auth.authentication = Auth._endpoint.init({
			onLoad: 'login-required'
		});
	} catch (e) {
		console.error('failed to initialize keycloak:', e);
		if (errorHandler) { errorHandler(e); }
	}
};

Auth.getTokens =(resultHandler, errorHandler)=> {
	if (Auth.authentication) {
		let tokens = {
			realm: Auth._endpoint.realm,
			accessToken: Auth._endpoint.token,
			refreshToken: Auth._endpoint.refreshToken
		};
		if (resultHandler) { resultHandler(tokens); }
		return tokens;
	} else {
		console.error('could not find any auth information');
		if (errorHandler) { errorHandler(e); }
		return null;
	}
};