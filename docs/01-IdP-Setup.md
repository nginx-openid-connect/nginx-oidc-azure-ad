# How To Configure Amazon Cognito for NGINX Plus OIDC Integration

Take the following steps to create a new application of Amazon Cognito for integrating with NGINX Plus.

> **Note:**
>
> The following procedure reflects the Cognito GUI at the time of publication, but the GUI is subject to change. Use this guide as a reference and adapt to the current Cognito GUI as necessary.

- [Create a new User Pool](#create-a-new-user-pool)
- [Create a user](#create-a-user)
- [Create a domain](#create-a-domain)
- [Create or Edit a new Application](#create-or-edit-a-new-application)

## Create a new User Pool

1. Log in to your AWS account, open the [AWS Management Console](https://console.aws.amazon.com), and navigate to the Cognito dashboard (you can, for example, click **`Cognito`** in the **Security, Identity, & Compliance** section of the **Services** drop‑down menu).

2. On the Cognito dashboard, click **Manage User Pools** to open the **Your User Pools** window. Click the **`Create a user pool`**  button or the highlighted phrase.
   ![](./img/cognito-user-pools.png)

3. Configure **sign-in experience** as the following example:
   ![](./img/cognito-user-pool-step-01-sign-in.png)

4. Configure **security requirements** as the following example:

   > Note: Select `No MFA` for your quick testing. Otherwise configure multi-factor authentication.

   ![](./img/cognito-user-pool-step-02-security.png)

5. Configure **sign-up experience** as the following example:

   > Note: select additional required attributes such as `preferred_username` because it is used for **NGINX Dev Portal**.

   ![](./img/cognito-user-pool-step-03-sign-up.png)

6. Configure **message delivery** as the following example:
   ![](./img/cognito-user-pool-step-04-message-delivery.png)

7. **Integrate your app** as the following example:

   > Note: You can create your app either in this step or [after creating](#create-a-new-application) a user pool.

   ![](./img/cognito-user-pool-step-05-integrate-app.png)

   - Option 1. Check `Generate a client secret` if you want to **disable PKCE**

   - Option 2. Check `Don't generate a client secret` if you want to **enable PKCE**
     ![](./img/cognito-user-pool-step-05-initial-app-client.png)

8. Review and create a user pool:

   ![](./img/cognito-user-pool-step-06-review-and-create.png)

9. Click **`Create user pool`** button:

   ![](./img/cognito-user-pool-step-06-create-button.png)

## Create a user

1. Select a user pool (`nginx-oidc-user-pool`) that you created:

   ![](./img/cognito-user-pool-step-07-created.png)

2. In the tab of Users, click `Create user` button:

   ![](./img/cognito-users-01-create.png)

3. Add a user name that you want to create:

   > Note: Select `Don't send an invitation` for your quick testing to create dummy email address.

   ![](./img/cognito-users-02-create.png)

## Create a domain

1. Select a **Create Cognito domain** in the list after selecting the tab of **App Integration**:

   ![](./img/cognito-app-integration-01-domain.png)

2. Type a domain prefix in the **Domain prefix** field under **Cognito domain** (in this guide, `my-nginx-plus-oidc`). Click the **`Create Cognito domain`** button:

   ![](./img/cognito-app-integration-02-domain.png)

3. Check if your domain is created:
   ![](./img/cognito-app-integration-03-domain.png)

## Create or Edit a new Application

1. Select the tab of **App Integration** in the user pool:

   ![](./img/cognito-app-integration-tab.png)

2. Scroll down from the tab of **App integration**, and select **Create app client** button

   ![](./img/cognito-app-client-create-button.png)

3. Enter a name of app (in this guide, `nginx-oidc-app` for **non-PKCE**, `nginx-odic-app-pkce` for **PKCE**) in the **App client name** field. Make sure that you choose one of the following options.

   - Option 1. Check `Generate a client secret` if you want to **disable PKCE**
     ![](./img/cognito-app-client-non-pkce-01.png)

   - Option 2. Check `Don't generate a client secret` if you want to **enable PKCE**
     ![](./img/cognito-user-pool-step-05-initial-app-client.png)

4. Find **Hosted UI settings** after scrolling down, and perform the following steps:

   ![](./img/cognito-app-client-host-UI-settings.png)

   - 4.1 In the sections of **Allowed callback URLs** and **Allowed sign-out URLs**, type the URI of the NGINX Plus instance including the port number, and ending in **`/_codexch`** for callback URL and **`/_logout`** for sign-out URL as follows.

     - **Allowed callback URLs**: `https://nginx.cognito.test:443/_codexch`.
     - **Allowed sign-out URLs**: `https://nginx.cognito.test:443/_logout`.

     > **Notes:**
     >
     > - For production, we strongly recommend that you use SSL/TLS (port 443).
     > - The port number is mandatory even when you’re using the default port for HTTP (80) or HTTPS (443). But it it isn't needed if you use NGINX ACM.

   - 4.2 In the **OAuth 2.0 grant types** section, click the **Authorization code grant** checkbox.

   - 4.3 In the **OpenID Connect scopes**, click the **email, openid**, and **profile** checkboxes.

   - 4.4 Click the **`Save changes`** button.

5. Check the **App client list** in the tab of **App integration** under the user pool of **nginx-oidc-user-pool** to see TWO applications (#1 for non-PKCE, #2 for PKCE) are created.

   ![](./img/cognito-app-client-list.png)

6. Click one of app clients to note **Client ID** and **Client secret** for configuring NGINX Plus.

   - Option 1. Copy and note **Client ID** and **Client secret** for non-PKCE application.
     ![](./img/cognito-app-details-non-pkce.png)

   - Option 2. Copy and note only **Client ID** for PKCE application.
     ![](./img/cognito-app-details-pkce.png)
