// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::sync::{Arc, LazyLock};

use anyhow::Context as _;
use axum::{
    extract::{Path, State},
    response::{Html, IntoResponse, Response},
};
use axum_extra::TypedHeader;
use chrono::Duration;
use mas_axum_utils::{InternalError, SessionInfoExt as _, cookies::CookieJar};
use mas_data_model::{BoxClock, BoxRng, SiteConfig};
use mas_matrix::HomeserverConnection;
use mas_router::{PostAuthAction, UrlBuilder};
use mas_storage::{
    BoxRepository,
    queue::{ProvisionUserJob, QueueJobRepositoryExt as _},
    user::UserEmailFilter,
};
use mas_matrix::ProvisionRequest;
use mas_templates::{RegisterStepsEmailInUseContext, TemplateContext as _, Templates};
use opentelemetry::metrics::Counter;
use ulid::Ulid;

use super::super::cookie::UserRegistrationSessions;
use crate::{
    BoundActivityTracker, METER, PreferredLanguage, views::shared::OptionalPostAuthAction,
};

static PASSWORD_REGISTER_COUNTER: LazyLock<Counter<u64>> = LazyLock::new(|| {
    METER
        .u64_counter("mas.user.password_registration")
        .with_description("Number of password registrations")
        .with_unit("{registration}")
        .build()
});

#[tracing::instrument(
    name = "handlers.views.register.steps.finish.get",
    fields(user_registration.id = %id),
    skip_all,
)]
pub(crate) async fn get(
    mut rng: BoxRng,
    clock: BoxClock,
    mut repo: BoxRepository,
    activity_tracker: BoundActivityTracker,
    user_agent: Option<TypedHeader<headers::UserAgent>>,
    State(url_builder): State<UrlBuilder>,
    State(homeserver): State<Arc<dyn HomeserverConnection>>,
    State(templates): State<Templates>,
    State(site_config): State<SiteConfig>,
    PreferredLanguage(lang): PreferredLanguage,
    cookie_jar: CookieJar,
    Path(id): Path<Ulid>,
) -> Result<Response, InternalError> {
    let user_agent = user_agent.map(|ua| ua.as_str().to_owned());
    let registration = repo
        .user_registration()
        .lookup(id)
        .await?
        .context("User registration not found")
        .map_err(InternalError::from_anyhow)?;

    // If the registration is completed, we can go to the registration destination
    // XXX: this might not be the right thing to do? Maybe an error page would be
    // better?
    if registration.completed_at.is_some() {
        let post_auth_action: Option<PostAuthAction> = registration
            .post_auth_action
            .map(serde_json::from_value)
            .transpose()?;

        return Ok((
            cookie_jar,
            OptionalPostAuthAction::from(post_auth_action).go_next(&url_builder),
        )
            .into_response());
    }

    // Make sure the registration session hasn't expired
    // XXX: this duration is hard-coded, could be configurable
    if clock.now() - registration.created_at > Duration::minutes(10) {
        return Err(InternalError::from_anyhow(anyhow::anyhow!(
            "Registration session has expired"
        )));
    }

    // Check that this registration belongs to this browser
    let registrations = UserRegistrationSessions::load(&cookie_jar);
    if !registrations.contains(&registration) {
        // XXX: we should have a better error screen here
        return Err(InternalError::from_anyhow(anyhow::anyhow!(
            "Could not find the registration in the browser cookies, Check that cookies are enabled."
        )));
    }

    // Let's perform last minute checks on the registration, especially to avoid
    // race conditions where multiple users register with the same username or email
    // address

    if repo.user().exists(&registration.username).await? {
        // XXX: this could have a better error message, but as this is unlikely to
        // happen, we're fine with a vague message for now
        return Err(InternalError::from_anyhow(anyhow::anyhow!(
            "Username is already taken"
        )));
    }

    if !homeserver
        .is_localpart_available(&registration.username)
        .await
        .map_err(InternalError::from_anyhow)?
    {
        return Err(InternalError::from_anyhow(anyhow::anyhow!(
            "Username is not available"
        )));
    }

    // Check if the registration token is required and was provided
    let registration_token = if site_config.registration_token_required {
        if let Some(registration_token_id) = registration.user_registration_token_id {
            let registration_token = repo
                .user_registration_token()
                .lookup(registration_token_id)
                .await?
                .context("Could not load the registration token")
                .map_err(InternalError::from_anyhow)?;

            if !registration_token.is_valid(clock.now()) {
                // XXX: the registration token isn't valid anymore, we should
                // have a better error in this case?
                return Err(InternalError::from_anyhow(anyhow::anyhow!(
                    "Registration token used is no longer valid"
                )));
            }

            Some(registration_token)
        } else {
            // Else redirect to the registration token page
            return Ok((
                cookie_jar,
                url_builder.redirect(&mas_router::RegisterToken::new(registration.id)),
            )
                .into_response());
        }
    } else {
        None
    };

    // If there is an email authentication, we need to check that the email
    // address was verified. If there is no email authentication attached, we
    // need to make sure the server doesn't require it
    let email_authentication = if let Some(email_authentication_id) =
        registration.email_authentication_id
    {
        let email_authentication = repo
            .user_email()
            .lookup_authentication(email_authentication_id)
            .await?
            .context("Could not load the email authentication")
            .map_err(InternalError::from_anyhow)?;

        // Check that the email authentication has been completed
        if email_authentication.completed_at.is_none() {
            return Ok((
                cookie_jar,
                url_builder.redirect(&mas_router::RegisterVerifyEmail::new(id)),
            )
                .into_response());
        }

        // Check that the email address isn't already used
        // It is important to do that here, as we we're not checking during the
        // registration, because we don't want to disclose whether an email is
        // already being used or not before we verified it
        if repo
            .user_email()
            .count(UserEmailFilter::new().for_email(&email_authentication.email))
            .await?
            > 0
        {
            let action = registration
                .post_auth_action
                .map(serde_json::from_value)
                .transpose()?;

            let ctx = RegisterStepsEmailInUseContext::new(email_authentication.email, action)
                .with_language(lang);

            return Ok((
                cookie_jar,
                Html(templates.render_register_steps_email_in_use(&ctx)?),
            )
                .into_response());
        }

        Some(email_authentication)
    } else if site_config.password_registration_email_required {
        // This could only happen in theory during a configuration change
        return Err(InternalError::from_anyhow(anyhow::anyhow!(
            "Server requires an email address to complete the registration, but no email authentication was attached to the user registration"
        )));
    } else {
        None
    };

    // Check that the display name is set
    if registration.display_name.is_none() {
        return Ok((
            cookie_jar,
            url_builder.redirect(&mas_router::RegisterDisplayName::new(registration.id)),
        )
            .into_response());
    }

    // Everything is good, let's complete the registration
    let registration = repo
        .user_registration()
        .complete(&clock, registration)
        .await?;

    // If we used a registration token, we need to mark it as used
    if let Some(registration_token) = registration_token {
        repo.user_registration_token()
            .use_token(&clock, registration_token)
            .await?;
    }

    // Consume the registration session
    let cookie_jar = registrations
        .consume_session(&registration)?
        .save(cookie_jar, &clock);

    // Now we can start the user creation
    let user = repo
        .user()
        .add(&mut rng, &clock, registration.username)
        .await?;
    // Also create a browser session which will log the user in
    let user_session = repo
        .browser_session()
        .add(&mut rng, &clock, &user, user_agent)
        .await?;

    if let Some(email_authentication) = email_authentication {
        repo.user_email()
            .add(&mut rng, &clock, &user, email_authentication.email)
            .await?;
    }

    if let Some(password) = registration.password {
        let user_password = repo
            .user_password()
            .add(
                &mut rng,
                &clock,
                &user,
                password.version,
                password.hashed_password,
                None,
            )
            .await?;

        repo.browser_session()
            .authenticate_with_password(&mut rng, &clock, &user_session, &user_password)
            .await?;

        PASSWORD_REGISTER_COUNTER.add(1, &[]);
    }

    if let Some(terms_url) = registration.terms_url {
        repo.user_terms()
            .accept_terms(&mut rng, &clock, &user, terms_url)
            .await?;
    }
    // Provision synchronously before DB commit to avoid split-brain state.
    // If provisioning fails, the transaction rolls back and no user is created in MAS.
    // This eliminates the need for manual cleanup when Synapse provisioning fails.
    let emails = repo
        .user_email()
        .all(&user)
        .await?
        .into_iter()
        .map(|email| email.email)
        .collect();
    let mut request = ProvisionRequest::new(user.username.clone(), user.sub.clone())
        .set_emails(emails);
    
    if let Some(display_name) = registration.display_name {
        request = request.set_displayname(display_name);
    }
    
    // Provision with retries
    for attempt in 1..=3 {
        match homeserver.provision_user(&request).await {
            Ok(_) => break,
            Err(e) if attempt < 3 => {
                tracing::warn!("Provision attempt {} failed: {}", attempt, e);
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
            Err(e) => return Err(InternalError::from_anyhow(e)),
        }
    }

    // Sync devices after user provisioning (empty device list for new user)
    for attempt in 1..=3 {
        match homeserver.sync_devices(&user.username, std::collections::HashSet::new()).await {
            Ok(_) => break,
            Err(e) if attempt < 3 => {
                tracing::warn!("Device sync attempt {} failed: {}", attempt, e);
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
            Err(e) => return Err(InternalError::from_anyhow(e)),
        }
    }

    repo.save().await?;

    activity_tracker
        .record_browser_session(&clock, &user_session)
        .await;

    let post_auth_action: Option<PostAuthAction> = registration
        .post_auth_action
        .map(serde_json::from_value)
        .transpose()?;

    // Login the user with the session we just created
    let cookie_jar = cookie_jar.set_session(&user_session);

    return Ok((
        cookie_jar,
        OptionalPostAuthAction::from(post_auth_action).go_next(&url_builder),
    )
        .into_response());
}
