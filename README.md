## OIDC Extended

An extension to the ERPNext Social Login authentication method (OIDC) that incorporates new features designed to meet the needs of enterprises.

Features:

- Group to Role/Role Profile mapping: maps the received *groups* as token claim to ERPNext roles or role profiles.
- Customizable claim names.
- Specify the default role for the users that haven't logged in yet.
- Automatically creates users from trusted identity providers even if signup is disabled in the site.

![image](screenshots/Screenshot%202025-11-08%20at%2003.56.24.png)

#### *Social Login Key* Configuration

This app extends the functionality of Social Login Key, that is why it is important to configure the latter correctly to get this app work properly. Below is a simple functional configuration for Social Login Key module, which can be imported directly as a document in ERPNext.

```json
{
    "name": "microsoft",
    "enable_social_login": 1,
    "social_login_provider": "Custom",
    "client_id": "{{ client_id }}",
    "provider_name": "microsoft",
    "client_secret": "{{ client_secret }}",
    "icon": "",
    "base_url": "https://login.microsoftonline.com/{{ tenant_id }}",
    "authorize_url": "/oauth2/v2.0/authorize",
    "access_token_url": "/oauth2/v2.0/token",
    "redirect_url": "/api/method/oidc_extended.callback.custom/microsoft",
    "api_endpoint": "https://graph.microsoft.com/v1.0/me",
    "custom_base_url": 1,
    "auth_url_data": "{\"response_type\": \"code\", \"scope\": \"openid profile email\"}",
    "user_id_property": "userPrincipalName",
    "doctype": "Social Login Key"
}
```

Notes:

- The last part of your `redirect_url` must match the name of the identity provider.
- Replace the `{{ variable }}`s with real values.

#### License

MIT
