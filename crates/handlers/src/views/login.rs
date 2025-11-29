// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
// Copyright 2025 Aless Microsystems.
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.
// Currenly email otp is only used for login flow and it is not fully tested yet.
// We can move email 2fa in a seperate page later. We could have added authenticator apps 
// complexity is not the reason that we are not adding it now. the user experice is the main reason.
// We want to keep the login flow as simple as possible for now.
use std::sync::{Arc, LazyLock};

use axum::{
    extract::{Form, State},
    response::{Html, IntoResponse, Response},
};
use axum_extra::{extract::Query, typed_header::TypedHeader};
use hyper::StatusCode;
use mas_axum_utils::{
    InternalError, SessionInfoExt,
    cookies::CookieJar,
    csrf::{CsrfExt, ProtectedForm},
};
use mas_data_model::{BoxClock, BoxRng, Clock, oauth2::LoginHint};
use ulid::Ulid;
use chrono::Duration;
use mas_i18n::DataLocale;
use mas_matrix::HomeserverConnection;
use mas_router::{UpstreamOAuth2Authorize, UrlBuilder};
use mas_storage::{
    BoxRepository, RepositoryAccess,
    queue::{QueueJobRepositoryExt as _, SendEmailAuthenticationCodeJob},
    upstream_oauth2::UpstreamOAuthProviderRepository,
    user::{BrowserSessionRepository, UserEmailRepository, UserPasswordRepository, UserRepository},
};
use mas_templates::{
    AccountInactiveContext, FieldError, FormError, FormState, LoginContext, LoginFormField,
    PostAuthContext, PostAuthContextInner, TemplateContext, Templates, ToFormState,
};
use opentelemetry::{Key, KeyValue, metrics::Counter};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use zeroize::Zeroizing;

use super::shared::OptionalPostAuthAction;
use crate::{
    BoundActivityTracker, Limiter, METER, PreferredLanguage, RequesterFingerprint, SiteConfig,
    captcha::Form as CaptchaForm,
    passwords::{PasswordManager, PasswordVerificationResult},
    session::{SessionOrFallback, load_session_or_fallback},
};

static PASSWORD_LOGIN_COUNTER: LazyLock<Counter<u64>> = LazyLock::new(|| {
    METER
        .u64_counter("mas.user.password_login_attempt")
        .with_description("Number of password login attempts")
        .with_unit("{attempt}")
        .build()
});
const RESULT: Key = Key::from_static_str("result");

fn create_fingerprint_hash(requester: &RequesterFingerprint, user_id: &Ulid) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"login_otp_fingerprint:");
    hasher.update(user_id.to_bytes());
    hasher.update(b":");
    hasher.update(format!("{:?}", requester).as_bytes());
    format!("{:x}", hasher.finalize())
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct LoginForm {
    username: String,
    password: String,
    otp_code: Option<String>,
    
    #[serde(flatten, skip_serializing)]
    captcha: CaptchaForm,
}

#[derive(Debug, Deserialize, Serialize)]
struct LoginOtpContext {
    auth_id: String,
    user_id: String,
    fingerprint_hash: String,
}

impl ToFormState for LoginForm {
    type Field = LoginFormField;
}

#[tracing::instrument(name = "handlers.views.login.get", skip_all)]
pub(crate) async fn get(
    mut rng: BoxRng,
    clock: BoxClock,
    PreferredLanguage(locale): PreferredLanguage,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    State(site_config): State<SiteConfig>,
    State(homeserver): State<Arc<dyn HomeserverConnection>>,
    mut repo: BoxRepository,
    activity_tracker: BoundActivityTracker,
    Query(query): Query<OptionalPostAuthAction>,
    cookie_jar: CookieJar,
) -> Result<Response, InternalError> {
    let (cookie_jar, maybe_session) = match load_session_or_fallback(
        cookie_jar, &clock, &mut rng, &templates, &locale, &mut repo,
    )
    .await?
    {
        SessionOrFallback::MaybeSession {
            cookie_jar,
            maybe_session,
            ..
        } => (cookie_jar, maybe_session),
        SessionOrFallback::Fallback { response } => return Ok(response),
    };

    if let Some(session) = maybe_session {
        activity_tracker
            .record_browser_session(&clock, &session)
            .await;

        let reply = query.go_next(&url_builder);
        return Ok((cookie_jar, reply).into_response());
    }

    let providers = repo.upstream_oauth_provider().all_enabled().await?;

    // If password-based login is disabled, and there is only one upstream provider,
    // we can directly start an authorization flow
    if !site_config.password_login_enabled && providers.len() == 1 {
        let provider = providers.into_iter().next().unwrap();

        let mut destination = UpstreamOAuth2Authorize::new(provider.id);

        if let Some(action) = query.post_auth_action {
            destination = destination.and_then(action);
        }

        return Ok((cookie_jar, url_builder.redirect(&destination)).into_response());
    }

    render(
        locale,
        cookie_jar,
        FormState::default(),
        query,
        &mut repo,
        &clock,
        &mut rng,
        &templates,
        &homeserver,
        &site_config,
    )
    .await
}

#[tracing::instrument(name = "handlers.views.login.post", skip_all)]
pub(crate) async fn post(
    mut rng: BoxRng,
    clock: BoxClock,
    PreferredLanguage(locale): PreferredLanguage,
    State(password_manager): State<PasswordManager>,
    State(site_config): State<SiteConfig>,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    State(limiter): State<Limiter>,
    State(homeserver): State<Arc<dyn HomeserverConnection>>,
    State(http_client): State<reqwest::Client>,
    mut repo: BoxRepository,
    (activity_tracker, requester): (BoundActivityTracker, RequesterFingerprint),
    Query(query): Query<OptionalPostAuthAction>,
    cookie_jar: CookieJar,
    user_agent: Option<TypedHeader<headers::UserAgent>>,
    Form(form): Form<ProtectedForm<LoginForm>>,
) -> Result<Response, InternalError> {
    let user_agent = user_agent.map(|ua| ua.as_str().to_owned());
    if !site_config.password_login_enabled {
        // XXX: is it necessary to have better errors here?
        return Ok(StatusCode::METHOD_NOT_ALLOWED.into_response());
    }

    let form = cookie_jar.verify_form(&clock, form)?;

    // Validate the captcha first
    let passed_captcha = form
        .captcha
        .verify(
            &activity_tracker,
            &http_client,
            url_builder.public_hostname(),
            site_config.captcha.as_ref(),
        )
        .await
        .is_ok();

    // Validate the form
    let mut form_state = form.to_form_state();
    
    if !passed_captcha {
        form_state.add_error_on_form(FormError::Captcha);
    }

    if form.username.is_empty() {
        form_state.add_error_on_field(LoginFormField::Username, FieldError::Required);
    }

    if form.password.is_empty() {
        form_state.add_error_on_field(LoginFormField::Password, FieldError::Required);
    }

    if !form_state.is_valid() {
        tracing::warn!("Invalid login form: {form_state:?}");
        PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
        return render(
            locale,
            cookie_jar,
            form_state,
            query,
            &mut repo,
            &clock,
            &mut rng,
            &templates,
            &homeserver,
            &site_config,
        )
        .await;
    }

    // Extract the localpart of the MXID, fallback to the bare username
    let username = homeserver
        .localpart(&form.username)
        .unwrap_or(&form.username);

    // First, lookup the user
    let Some(user) = get_user_by_email_or_by_username(&site_config, &mut repo, username).await?
    else {
        tracing::warn!(username, "User not found");
        let form_state = form_state.with_error_on_form(FormError::InvalidCredentials);
        PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
        return render(
            locale,
            cookie_jar,
            form_state,
            query,
            &mut repo,
            &clock,
            &mut rng,
            &templates,
            &homeserver,
            &site_config,
        )
        .await;
    };

    // Check the rate limit
    if let Err(e) = limiter.check_password(requester, &user) {
        tracing::warn!(error = &e as &dyn std::error::Error, "ratelimit exceeded");
        let form_state = form_state.with_error_on_form(FormError::RateLimitExceeded);
        PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
        return render(
            locale,
            cookie_jar,
            form_state,
            query,
            &mut repo,
            &clock,
            &mut rng,
            &templates,
            &homeserver,
            &site_config,
        )
        .await;
    }

    // And its password
    let Some(user_password) = repo.user_password().active(&user).await? else {
        // There is no password for this user, but we don't want to disclose that. Show
        // a generic 'invalid credentials' error instead
        tracing::warn!(username, "No password for user");
        let form_state = form_state.with_error_on_form(FormError::InvalidCredentials);
        PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
        return render(
            locale,
            cookie_jar,
            form_state,
            query,
            &mut repo,
            &clock,
            &mut rng,
            &templates,
            &homeserver,
            &site_config,
        )
        .await;
    };

    let password = Zeroizing::new(form.password.clone());

    // Verify the password, and upgrade it on-the-fly if needed
    let user_password = match password_manager
        .verify_and_upgrade(
            &mut rng,
            user_password.version,
            password,
            user_password.hashed_password.clone(),
        )
        .await
    {
        Ok(PasswordVerificationResult::Success(Some((version, new_password_hash)))) => {
            // Save the upgraded password
            repo.user_password()
                .add(
                    &mut rng,
                    &clock,
                    &user,
                    version,
                    new_password_hash,
                    Some(&user_password),
                )
                .await?
        }
        Ok(PasswordVerificationResult::Success(None)) => user_password,
        Ok(PasswordVerificationResult::Failure) => {
            tracing::warn!(username, "Failed to verify/upgrade password for user");
            let form_state = form_state.with_error_on_form(FormError::InvalidCredentials);
            PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "mismatch")]);
            return render(
                locale,
                cookie_jar,
                form_state,
                query,
                &mut repo,
                &clock,
                &mut rng,
                &templates,
                &homeserver,
                &site_config,
            )
            .await;
        }
        Err(err) => return Err(InternalError::from_anyhow(err)),
    };

    // Now that we have checked the user password, we now want to show an error if
    // the user is locked or deactivated
    if user.deactivated_at.is_some() {
        tracing::warn!(username, "User is deactivated");
        PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
        let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);
        let ctx = AccountInactiveContext::new(user)
            .with_csrf(csrf_token.form_value())
            .with_language(locale);
        let content = templates.render_account_deactivated(&ctx)?;
        return Ok((cookie_jar, Html(content)).into_response());
    }

    if user.locked_at.is_some() {
        tracing::warn!(username, "User is locked");
        PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
        let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);
        let ctx = AccountInactiveContext::new(user)
            .with_csrf(csrf_token.form_value())
            .with_language(locale);
        let content = templates.render_account_locked(&ctx)?;
        return Ok((cookie_jar, Html(content)).into_response());
    }

    // At this point, we should have a 'valid' user. In case we missed something, we
    // want it to crash in tests/debug builds
    debug_assert!(user.is_valid());

    // Check if email OTP is required
    if site_config.email_otp_required {
        // Get user's primary email
        let user_emails = repo.user_email().all(&user).await?;
        let Some(primary_email) = user_emails.first() else {
            tracing::warn!(username, "User has no verified email for OTP verification");
            let form_state = form_state.with_error_on_form(FormError::InvalidCredentials);
            PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
            return render(
                locale,
                cookie_jar,
                form_state,
                query,
                &mut repo,
                &clock,
                &mut rng,
                &templates,
                &homeserver,
                &site_config,
            )
            .await;
        };

        if let Some(ref otp_code) = form.otp_code {
            // Normalize and validate OTP code format
            let code = otp_code.trim();
            if code.is_empty() || code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
                let mut form_state = form.to_form_state();
                form_state.set_value(LoginFormField::Username, Some(form.username.clone()));
                form_state.add_error_on_form(FormError::InvalidCredentials);
                PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
                return render(
                    locale,
                    cookie_jar,
                    form_state,
                    query,
                    &mut repo,
                    &clock,
                    &mut rng,
                    &templates,
                    &homeserver,
                    &site_config,
                )
                .await;
            }
            
            // Try to get the authentication context from the cookie
            let auth_valid = if let Ok(Some(otp_context)) = cookie_jar.load::<LoginOtpContext>("login_email_auth_context") {
                // Verify the context belongs to the current user and requester
                let expected_fingerprint = create_fingerprint_hash(&requester, &user.id);
                if otp_context.user_id != user.id.to_string() {
                    tracing::warn!("OTP context user mismatch for user {}", user.username);
                    false
                } else if otp_context.fingerprint_hash != expected_fingerprint {
                    tracing::warn!("OTP context fingerprint mismatch for user {}", user.username);
                    false
                } else if let Ok(auth_id) = otp_context.auth_id.parse::<Ulid>() {
                    // Look up the authentication record
                    let email_authentication = repo.user_email().lookup_authentication(auth_id).await?;
                    if let Some(email_authentication) = email_authentication {
                        // Security validations per NIST 800-63B and MFA guidance:
                        
                        // 1. Verify authentication belongs to the same user
                        let user_emails = repo.user_email().all(&user).await?;
                        let auth_belongs_to_user = user_emails.iter().any(|email| email.email == email_authentication.email);
                        
                        if !auth_belongs_to_user {
                            tracing::warn!("OTP authentication email mismatch for user {}", user.username);
                            false
                        }
                        // 2. Verify authentication is still pending (not already completed)
                        else if email_authentication.completed_at.is_some() {
                            tracing::warn!("OTP authentication already completed for user {}", user.username);
                            false
                        }
                        // 3. Check rate limiting for OTP attempts (NIST 800-63B requirement)
                        else if let Err(e) = limiter.check_email_authentication_attempt(&email_authentication) {
                            tracing::warn!(error = &e as &dyn std::error::Error, "OTP rate limit exceeded for user {}", user.username);
                            false
                        }
                        else {
                            // Find the authentication code
                            let code_result = repo.user_email().find_authentication_code(&email_authentication, code).await?;
                            if let Some(auth_code) = code_result {
                                // 4. Verify code has not expired (TTL check)
                                if auth_code.expires_at <= clock.now() {
                                    tracing::warn!("Expired OTP code for user {}", user.username);
                                    false
                                } else {
                                    // Complete the authentication (enforces single-use)
                                    repo.user_email().complete_authentication_with_code(&clock, email_authentication, &auth_code).await?;
                                    true // OTP verified
                                }
                            } else {
                                tracing::warn!("Invalid OTP code for user {}", user.username);
                                false // Invalid OTP code
                            }
                        }
                    } else {
                        false // Authentication record not found
                    }
                } else {
                    false // Invalid auth ID format
                }
            } else {
                false // No cookie found
            };
            
            if !auth_valid {
                // Invalid OTP - show error
                let mut form_state = form.to_form_state();
                form_state.set_value(LoginFormField::Username, Some(form.username.clone()));
                form_state.add_error_on_form(FormError::InvalidCredentials);
                PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
                return render(
                    locale,
                    cookie_jar,
                    form_state,
                    query,
                    &mut repo,
                    &clock,
                    &mut rng,
                    &templates,
                    &homeserver,
                    &site_config,
                )
                .await;
            }
        } else {
            // Create a temporary session for email authentication
            let temp_session = repo
                .browser_session()
                .add(&mut rng, &clock, &user, user_agent.clone())
                .await?;

            // Create email authentication for this login session
            let user_email_authentication = repo
                .user_email()
                .add_authentication_for_session(&mut rng, &clock, primary_email.email.clone(), &temp_session)
                .await?;

            // Generate and add the authentication code
            let code = format!("{:06}", rng.gen_range(100000..1000000));
            repo.user_email()
                .add_authentication_code(
                    &mut rng,
                    &clock,
                    Duration::try_minutes(10).unwrap(),
                    &user_email_authentication,
                    code,
                )
                .await?;

            // Schedule email sending job with a delay to ensure data is committed
            let scheduled_at = clock.now() + Duration::try_milliseconds(100).unwrap();
            repo.queue_job()
                .schedule_job_later(
                    &mut rng,
                    &clock,
                    SendEmailAuthenticationCodeJob::new(&user_email_authentication, locale.to_string()),
                    scheduled_at,
                )
                .await?;

            tracing::info!(
                auth_id = %user_email_authentication.id,
                email = %primary_email.email,
                "Scheduled email authentication code job for login OTP with 100ms delay"
            );

            // Save everything together to ensure atomicity
            repo.save().await?;
            
            // Add small delay to ensure database consistency. This delay is only added because my db is slow and i need
            // to verify why its like this. there is a race condition which would be investigated in future.
            // by any chance this is not the solution. its just a hotfix
            //tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
            
            let mut form_state = form.to_form_state();
            form_state.set_value(LoginFormField::Username, Some(form.username.clone()));
            
            // Store the authentication context in a cookie with user binding and fingerprint
            let otp_context = LoginOtpContext {
                auth_id: user_email_authentication.id.to_string(),
                user_id: user.id.to_string(),
                fingerprint_hash: create_fingerprint_hash(&requester, &user.id),
            };
            let cookie_jar = cookie_jar.save(
                "login_email_auth_context",
                &otp_context,
                false,
            );
            
            // We need a new repository instance for rendering since save() consumed the old one
            // This is a limitation of the current architecture - we'll need to get a new repo
            // For now, let's just return a simple response without using the render function
            let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);
            let ctx = LoginContext::default()
                .with_form_state(form_state)
                .with_captcha(site_config.captcha.clone())
                .with_csrf(csrf_token.form_value())
                .with_language(locale);
            let content = templates.render_login(&ctx)?;
            return Ok((cookie_jar, Html(content)).into_response());
        }
    }

    // Start a new session
    let user_session = repo
        .browser_session()
        .add(&mut rng, &clock, &user, user_agent)
        .await?;

    // And mark it as authenticated by the password
    repo.browser_session()
        .authenticate_with_password(&mut rng, &clock, &user_session, &user_password)
        .await?;

    repo.save().await?;

    PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "success")]);

    activity_tracker
        .record_browser_session(&clock, &user_session)
        .await;

    let cookie_jar = cookie_jar.set_session(&user_session);
    // Clean up the authentication context cookie
    let cookie_jar = cookie_jar.remove("login_email_auth_context");
    let reply = query.go_next(&url_builder);
    Ok((cookie_jar, reply).into_response())
}

async fn get_user_by_email_or_by_username<R: RepositoryAccess>(
    site_config: &SiteConfig,
    repo: &mut R,
    username_or_email: &str,
) -> Result<Option<mas_data_model::User>, R::Error> {
    if site_config.login_with_email_allowed && username_or_email.contains('@') {
        let maybe_user_email = repo.user_email().find_by_email(username_or_email).await?;

        if let Some(user_email) = maybe_user_email {
            let user = repo.user().lookup(user_email.user_id).await?;

            if user.is_some() {
                return Ok(user);
            }
        }
    }

    let user = repo.user().find_by_username(username_or_email).await?;

    Ok(user)
}

fn handle_login_hint(
    mut ctx: LoginContext,
    next: &PostAuthContext,
    homeserver: &dyn HomeserverConnection,
    site_config: &SiteConfig,
) -> LoginContext {
    let form_state = ctx.form_state_mut();

    // Do not override username if coming from a failed login attempt
    if form_state.has_value(LoginFormField::Username) {
        return ctx;
    }

    if let PostAuthContextInner::ContinueAuthorizationGrant { ref grant } = next.ctx {
        let value = match grant.parse_login_hint(homeserver.homeserver()) {
            LoginHint::MXID(mxid) => Some(mxid.localpart().to_owned()),
            LoginHint::Email(email) if site_config.login_with_email_allowed => {
                Some(email.to_string())
            }
            _ => None,
        };
        form_state.set_value(LoginFormField::Username, value);
    }

    ctx
}

async fn render(
    locale: DataLocale,
    cookie_jar: CookieJar,
    form_state: FormState<LoginFormField>,
    action: OptionalPostAuthAction,
    repo: &mut impl RepositoryAccess,
    clock: &impl Clock,
    rng: impl Rng,
    templates: &Templates,
    homeserver: &dyn HomeserverConnection,
    site_config: &SiteConfig,
) -> Result<Response, InternalError> {
    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(clock, rng);
    let providers = repo.upstream_oauth_provider().all_enabled().await?;

    let ctx = LoginContext::default()
        .with_form_state(form_state)
        .with_upstream_providers(providers);

    let next = action
        .load_context(repo)
        .await
        .map_err(InternalError::from_anyhow)?;
    let ctx = if let Some(next) = next {
        let ctx = handle_login_hint(ctx, &next, homeserver, site_config);
        ctx.with_post_action(next)
    } else {
        ctx
    };
    let ctx = ctx
        .with_captcha(site_config.captcha.clone())
        .with_csrf(csrf_token.form_value())
        .with_language(locale);

    let content = templates.render_login(&ctx)?;
    Ok((cookie_jar, Html(content)).into_response())
}

#[cfg(test)]
mod test {
    use hyper::{
        Request, StatusCode,
        header::{CONTENT_TYPE, LOCATION},
    };
    use mas_data_model::{
        UpstreamOAuthProviderClaimsImports, UpstreamOAuthProviderOnBackchannelLogout,
        UpstreamOAuthProviderTokenAuthMethod,
    };
    use mas_iana::jose::JsonWebSignatureAlg;
    use mas_router::Route;
    use mas_storage::{
        RepositoryAccess,
        upstream_oauth2::{UpstreamOAuthProviderParams, UpstreamOAuthProviderRepository},
    };
    use mas_templates::escape_html;
    use oauth2_types::scope::OPENID;
    use sqlx::PgPool;
    use zeroize::Zeroizing;

    use crate::{
        SiteConfig,
        test_utils::{
            CookieHelper, RequestBuilderExt, ResponseExt, TestState, setup, test_site_config,
        },
    };

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_password_disabled(pool: PgPool) {
        setup();
        let state = TestState::from_pool_with_site_config(
            pool,
            SiteConfig {
                password_login_enabled: false,
                ..test_site_config()
            },
        )
        .await
        .unwrap();

        let mut rng = state.rng();

        // Without password login and no upstream providers, we should get an error
        // message
        let response = state.request(Request::get("/login").empty()).await;
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        assert!(
            response.body().contains("No login methods available"),
            "Response body: {}",
            response.body()
        );

        // Adding an upstream provider should redirect to it
        let mut repo = state.repository().await.unwrap();
        let first_provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                UpstreamOAuthProviderParams {
                    issuer: Some("https://first.com/".to_owned()),
                    human_name: Some("First Ltd.".to_owned()),
                    brand_name: None,
                    scope: [OPENID].into_iter().collect(),
                    token_endpoint_auth_method: UpstreamOAuthProviderTokenAuthMethod::None,
                    token_endpoint_signing_alg: None,
                    id_token_signed_response_alg: JsonWebSignatureAlg::Rs256,
                    fetch_userinfo: false,
                    userinfo_signed_response_alg: None,
                    client_id: "client".to_owned(),
                    encrypted_client_secret: None,
                    claims_imports: UpstreamOAuthProviderClaimsImports::default(),
                    authorization_endpoint_override: None,
                    token_endpoint_override: None,
                    userinfo_endpoint_override: None,
                    jwks_uri_override: None,
                    discovery_mode: mas_data_model::UpstreamOAuthProviderDiscoveryMode::Oidc,
                    pkce_mode: mas_data_model::UpstreamOAuthProviderPkceMode::Auto,
                    response_mode: None,
                    additional_authorization_parameters: Vec::new(),
                    forward_login_hint: false,
                    ui_order: 0,
                    on_backchannel_logout: UpstreamOAuthProviderOnBackchannelLogout::DoNothing,
                },
            )
            .await
            .unwrap();
        repo.save().await.unwrap();

        let first_provider_login = mas_router::UpstreamOAuth2Authorize::new(first_provider.id);

        let response = state.request(Request::get("/login").empty()).await;
        response.assert_status(StatusCode::SEE_OTHER);
        response.assert_header_value(LOCATION, &first_provider_login.path_and_query());

        // Adding a second provider should show a login page with both providers
        let mut repo = state.repository().await.unwrap();
        let second_provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                UpstreamOAuthProviderParams {
                    issuer: Some("https://second.com/".to_owned()),
                    human_name: None,
                    brand_name: None,
                    scope: [OPENID].into_iter().collect(),
                    token_endpoint_auth_method: UpstreamOAuthProviderTokenAuthMethod::None,
                    token_endpoint_signing_alg: None,
                    id_token_signed_response_alg: JsonWebSignatureAlg::Rs256,
                    fetch_userinfo: false,
                    userinfo_signed_response_alg: None,
                    client_id: "client".to_owned(),
                    encrypted_client_secret: None,
                    claims_imports: UpstreamOAuthProviderClaimsImports::default(),
                    authorization_endpoint_override: None,
                    token_endpoint_override: None,
                    userinfo_endpoint_override: None,
                    jwks_uri_override: None,
                    discovery_mode: mas_data_model::UpstreamOAuthProviderDiscoveryMode::Oidc,
                    pkce_mode: mas_data_model::UpstreamOAuthProviderPkceMode::Auto,
                    response_mode: None,
                    additional_authorization_parameters: Vec::new(),
                    forward_login_hint: false,
                    ui_order: 1,
                    on_backchannel_logout: UpstreamOAuthProviderOnBackchannelLogout::DoNothing,
                },
            )
            .await
            .unwrap();
        repo.save().await.unwrap();

        let second_provider_login = mas_router::UpstreamOAuth2Authorize::new(second_provider.id);

        let response = state.request(Request::get("/login").empty()).await;
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        assert!(response.body().contains(&escape_html("First Ltd.")));
        assert!(
            response
                .body()
                .contains(&escape_html(&first_provider_login.path_and_query()))
        );
        assert!(response.body().contains(&escape_html("second.com")));
        assert!(
            response
                .body()
                .contains(&escape_html(&second_provider_login.path_and_query()))
        );
    }

    async fn user_with_password(
        state: &TestState,
        username: &str,
        password: &str,
    ) -> mas_data_model::User {
        let mut rng = state.rng();
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, username.to_owned())
            .await
            .unwrap();
        let (version, hash) = state
            .password_manager
            .hash(&mut rng, Zeroizing::new(password.to_owned()))
            .await
            .unwrap();
        repo.user_password()
            .add(&mut rng, &state.clock, &user, version, hash, None)
            .await
            .unwrap();
        repo.save().await.unwrap();
        user
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_password_login(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let cookies = CookieHelper::new();

        // Provision a user with a password
        user_with_password(&state, "john", "hunter2").await;

        // Render the login page to get a CSRF token
        let request = Request::get("/login").empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        // Extract the CSRF token from the response body
        let csrf_token = response
            .body()
            .split("name=\"csrf\" value=\"")
            .nth(1)
            .unwrap()
            .split('\"')
            .next()
            .unwrap();

        // Submit the login form
        let request = Request::post("/login").form(serde_json::json!({
            "csrf": csrf_token,
            "username": "john",
            "password": "hunter2",
        }));
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::SEE_OTHER);

        // Now if we get to the home page, we should see the user's username
        let request = Request::get("/").empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        assert!(response.body().contains("john"));
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_password_login_with_mxid(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let cookies = CookieHelper::new();

        // Provision a user with a password
        user_with_password(&state, "john", "hunter2").await;

        // Render the login page to get a CSRF token
        let request = Request::get("/login").empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        // Extract the CSRF token from the response body
        let csrf_token = response
            .body()
            .split("name=\"csrf\" value=\"")
            .nth(1)
            .unwrap()
            .split('\"')
            .next()
            .unwrap();

        // Submit the login form
        let request = Request::post("/login").form(serde_json::json!({
            "csrf": csrf_token,
            "username": "@john:example.com",
            "password": "hunter2",
        }));
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::SEE_OTHER);

        // Now if we get to the home page, we should see the user's username
        let request = Request::get("/").empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        assert!(response.body().contains("john"));
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_password_login_with_mxid_wrong_server(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let cookies = CookieHelper::new();

        // Provision a user with a password
        user_with_password(&state, "john", "hunter2").await;

        // Render the login page to get a CSRF token
        let request = Request::get("/login").empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        // Extract the CSRF token from the response body
        let csrf_token = response
            .body()
            .split("name=\"csrf\" value=\"")
            .nth(1)
            .unwrap()
            .split('\"')
            .next()
            .unwrap();

        // Submit the login form
        let request = Request::post("/login").form(serde_json::json!({
            "csrf": csrf_token,
            "username": "@john:something.corp",
            "password": "hunter2",
        }));
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;

        // This shouldn't have worked, we're back on the login page
        response.assert_status(StatusCode::OK);
        assert!(response.body().contains("Invalid credentials"));
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_password_login_rate_limit(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let mut rng = state.rng();
        let cookies = CookieHelper::new();

        // Provision a user without a password.
        // We don't give that user a password, so that we skip hashing it in this test.
        // It will still be rate-limited
        let mut repo = state.repository().await.unwrap();
        repo.user()
            .add(&mut rng, &state.clock, "john".to_owned())
            .await
            .unwrap();
        repo.save().await.unwrap();

        // Render the login page to get a CSRF token
        let request = Request::get("/login").empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        // Extract the CSRF token from the response body
        let csrf_token = response
            .body()
            .split("name=\"csrf\" value=\"")
            .nth(1)
            .unwrap()
            .split('\"')
            .next()
            .unwrap();

        // Submit the login form
        let request = Request::post("/login").form(serde_json::json!({
            "csrf": csrf_token,
            "username": "john",
            "password": "hunter2",
        }));
        let request = cookies.with_cookies(request);

        // First three attempts should just tell about the invalid credentials
        let response = state.request(request.clone()).await;
        response.assert_status(StatusCode::OK);
        let body = response.body();
        assert!(body.contains("Invalid credentials"));
        assert!(!body.contains("too many requests"));

        let response = state.request(request.clone()).await;
        response.assert_status(StatusCode::OK);
        let body = response.body();
        assert!(body.contains("Invalid credentials"));
        assert!(!body.contains("too many requests"));

        let response = state.request(request.clone()).await;
        response.assert_status(StatusCode::OK);
        let body = response.body();
        assert!(body.contains("Invalid credentials"));
        assert!(!body.contains("too many requests"));

        // The fourth attempt should be rate-limited
        let response = state.request(request.clone()).await;
        response.assert_status(StatusCode::OK);
        let body = response.body();
        assert!(!body.contains("Invalid credentials"));
        assert!(body.contains("too many requests"));
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_password_login_locked_account(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let cookies = CookieHelper::new();

        // Provision a user with a password
        let user = user_with_password(&state, "john", "hunter2").await;

        // Lock the user
        let mut repo = state.repository().await.unwrap();
        repo.user().lock(&state.clock, user).await.unwrap();
        repo.save().await.unwrap();

        // Render the login page to get a CSRF token
        let request = Request::get("/login").empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        // Extract the CSRF token from the response body
        let csrf_token = response
            .body()
            .split("name=\"csrf\" value=\"")
            .nth(1)
            .unwrap()
            .split('\"')
            .next()
            .unwrap();

        // Submit the login form
        let request = Request::post("/login").form(serde_json::json!({
            "csrf": csrf_token,
            "username": "john",
            "password": "hunter2",
        }));
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        assert!(response.body().contains("Account locked"));

        // A bad password should not disclose that the account is locked
        let request = Request::post("/login").form(serde_json::json!({
            "csrf": csrf_token,
            "username": "john",
            "password": "badpassword",
        }));
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        assert!(!response.body().contains("Account locked"));
        assert!(response.body().contains("Invalid credentials"));
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_password_login_deactivated_account(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let cookies = CookieHelper::new();

        // Provision a user with a password
        let user = user_with_password(&state, "john", "hunter2").await;

        // Deactivate the user
        let mut repo = state.repository().await.unwrap();
        repo.user().deactivate(&state.clock, user).await.unwrap();
        repo.save().await.unwrap();

        // Render the login page to get a CSRF token
        let request = Request::get("/login").empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        // Extract the CSRF token from the response body
        let csrf_token = response
            .body()
            .split("name=\"csrf\" value=\"")
            .nth(1)
            .unwrap()
            .split('\"')
            .next()
            .unwrap();

        // Submit the login form
        let request = Request::post("/login").form(serde_json::json!({
            "csrf": csrf_token,
            "username": "john",
            "password": "hunter2",
        }));
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        assert!(response.body().contains("Account deleted"));

        // A bad password should not disclose that the account is deleted
        let request = Request::post("/login").form(serde_json::json!({
            "csrf": csrf_token,
            "username": "john",
            "password": "badpassword",
        }));
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        assert!(!response.body().contains("Account deleted"));
        assert!(response.body().contains("Invalid credentials"));
    }
}
