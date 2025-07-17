import React, { useCallback, useEffect } from 'react';
import { parse } from 'query-string';
import { useAuthContext } from 'context';
import { User } from 'types';
import { useHistory } from 'react-router-dom';

type OktaCallbackResponse = {
  token: string;
  user: User;
};

export const OktaCallback: React.FC = () => {
  const { login } = useAuthContext();
  const history = useHistory();

  const handleOktaCallback = useCallback(async () => {
    const { code, state } = parse(window.location.search);

    if (!code || !state) {
      console.error('Missing OAuth parameters');
      history.push('/');
      return;
    }

    try {
      const response = await fetch(
        `${process.env.REACT_APP_API_URL}/auth/okta-callback`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({
            code,
            state
          })
        }
      );

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'OAuth callback failed');
      }

      const data: OktaCallbackResponse = await response.json();

      await login(data.token);

      localStorage.setItem('token', data.token);
      localStorage.removeItem('nonce');
      sessionStorage.removeItem('oauth_state');
      sessionStorage.removeItem('pkce_code_verifier');

      history.push('/');
    } catch (e) {
      console.error(e);
      history.push('/');
    }
  }, [history, login]);

  useEffect(() => {
    handleOktaCallback();
  }, [handleOktaCallback]);

  return <div>Loading...</div>;
};
