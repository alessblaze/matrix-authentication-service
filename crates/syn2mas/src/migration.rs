// Copyright 2024 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

//! # Migration
//!
//! This module provides the high-level logic for performing the Synapse-to-MAS
//! database migration.
//!
//! This module does not implement any of the safety checks that should be run
//! *before* the migration.

use std::{pin::pin, time::Instant};

use chrono::{DateTime, Utc};
use compact_str::CompactString;
use futures_util::{SinkExt, StreamExt as _, TryFutureExt, TryStreamExt as _};
use mas_storage::Clock;
use opentelemetry::{KeyValue, metrics::Counter};
use rand::{RngCore, SeedableRng};
use thiserror::Error;
use thiserror_ext::ContextInto;
use tokio_util::sync::PollSender;
use tracing::{Instrument as _, Level, info};
use ulid::Ulid;
use uuid::{NonNilUuid, Uuid};

use crate::{
    HashMap, ProgressCounter, RandomState, SynapseReader,
    mas_writer::{
        self, MasNewCompatAccessToken, MasNewCompatRefreshToken, MasNewCompatSession,
        MasNewEmailThreepid, MasNewUnsupportedThreepid, MasNewUpstreamOauthLink, MasNewUser,
        MasNewUserPassword, MasWriteBuffer, MasWriter,
    },
    progress::Progress,
    synapse_reader::{
        self, ExtractLocalpartError, FullUserId, SynapseAccessToken, SynapseDevice,
        SynapseExternalId, SynapseRefreshableTokenPair, SynapseThreepid, SynapseUser,
    },
    telemetry::{
        K_ENTITY, METER, V_ENTITY_DEVICES, V_ENTITY_EXTERNAL_IDS,
        V_ENTITY_NONREFRESHABLE_ACCESS_TOKENS, V_ENTITY_REFRESHABLE_TOKEN_PAIRS,
        V_ENTITY_THREEPIDS, V_ENTITY_USERS,
    },
};

#[derive(Debug, Error, ContextInto)]
pub enum Error {
    #[error("error when reading synapse DB ({context}): {source}")]
    Synapse {
        source: synapse_reader::Error,
        context: String,
    },
    #[error("error when writing to MAS DB ({context}): {source}")]
    Mas {
        source: mas_writer::Error,
        context: String,
    },
    #[error("failed to extract localpart of {user:?}: {source}")]
    ExtractLocalpart {
        source: ExtractLocalpartError,
        user: FullUserId,
    },
    #[error("channel closed")]
    ChannelClosed,

    #[error("task failed ({context}): {source}")]
    Join {
        source: tokio::task::JoinError,
        context: String,
    },

    #[error("user {user} was not found for migration but a row in {table} was found for them")]
    MissingUserFromDependentTable { table: String, user: FullUserId },
    #[error(
        "missing a mapping for the auth provider with ID {synapse_id:?} (used by {user} and maybe other users)"
    )]
    MissingAuthProviderMapping {
        /// `auth_provider` ID of the provider in Synapse, for which we have no
        /// mapping
        synapse_id: String,
        /// a user that is using this auth provider
        user: FullUserId,
    },
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy)]
    struct UserFlags: u8 {
        const IS_SYNAPSE_ADMIN = 0b0000_0001;
        const IS_DEACTIVATED = 0b0000_0010;
        const IS_GUEST = 0b0000_0100;
        const IS_APPSERVICE = 0b0000_1000;
    }
}

impl UserFlags {
    const fn is_deactivated(self) -> bool {
        self.contains(UserFlags::IS_DEACTIVATED)
    }

    const fn is_guest(self) -> bool {
        self.contains(UserFlags::IS_GUEST)
    }

    const fn is_synapse_admin(self) -> bool {
        self.contains(UserFlags::IS_SYNAPSE_ADMIN)
    }

    const fn is_appservice(self) -> bool {
        self.contains(UserFlags::IS_APPSERVICE)
    }
}

#[derive(Debug, Clone, Copy)]
struct UserInfo {
    mas_user_id: Option<NonNilUuid>,
    flags: UserFlags,
}

struct MigrationState {
    /// The server name we're migrating from
    server_name: String,

    /// Lookup table from user localpart to that user's infos
    users: HashMap<CompactString, UserInfo>,

    /// Mapping of MAS user ID + device ID to a MAS compat session ID.
    devices_to_compat_sessions: HashMap<(NonNilUuid, CompactString), Uuid>,

    /// A mapping of Synapse external ID providers to MAS upstream OAuth 2.0
    /// provider ID
    provider_id_mapping: std::collections::HashMap<String, Uuid>,
}

/// Performs a migration from Synapse's database to MAS' database.
///
/// # Panics
///
/// - If there are more than `usize::MAX` users
///
/// # Errors
///
/// Errors are returned under the following circumstances:
///
/// - An underlying database access error, either to MAS or to Synapse.
/// - Invalid data in the Synapse database.
#[allow(clippy::implicit_hasher, clippy::too_many_lines)]
pub async fn migrate(
    mut synapse: SynapseReader<'_>,
    mas: MasWriter,
    server_name: String,
    clock: &dyn Clock,
    rng: &mut impl RngCore,
    provider_id_mapping: std::collections::HashMap<String, Uuid>,
    progress: &Progress,
) -> Result<(), Error> {
    let counts = synapse.count_rows().await.into_synapse("counting users")?;

    let approx_total_counter = METER
        .u64_counter("syn2mas.entity.approx_total")
        .with_description("Approximate number of entities of this type to be migrated")
        .build();
    let migrated_otel_counter = METER
        .u64_counter("syn2mas.entity.migrated")
        .with_description("Number of entities of this type that have been migrated so far")
        .build();
    let skipped_otel_counter = METER
        .u64_counter("syn2mas.entity.skipped")
        .with_description("Number of entities of this type that have been skipped so far")
        .build();

    approx_total_counter.add(
        counts.users as u64,
        &[KeyValue::new(K_ENTITY, V_ENTITY_USERS)],
    );
    approx_total_counter.add(
        counts.devices as u64,
        &[KeyValue::new(K_ENTITY, V_ENTITY_DEVICES)],
    );
    approx_total_counter.add(
        counts.threepids as u64,
        &[KeyValue::new(K_ENTITY, V_ENTITY_THREEPIDS)],
    );
    approx_total_counter.add(
        counts.external_ids as u64,
        &[KeyValue::new(K_ENTITY, V_ENTITY_EXTERNAL_IDS)],
    );
    // assume 1 refreshable access token per refresh token.
    let approx_nonrefreshable_access_tokens = counts.access_tokens - counts.refresh_tokens;
    approx_total_counter.add(
        approx_nonrefreshable_access_tokens as u64,
        &[KeyValue::new(
            K_ENTITY,
            V_ENTITY_NONREFRESHABLE_ACCESS_TOKENS,
        )],
    );
    approx_total_counter.add(
        counts.refresh_tokens as u64,
        &[KeyValue::new(K_ENTITY, V_ENTITY_REFRESHABLE_TOKEN_PAIRS)],
    );

    let state = MigrationState {
        server_name,
        // We oversize the hashmaps, as the estimates are innaccurate, and we would like to avoid
        // reallocations.
        users: HashMap::with_capacity_and_hasher(counts.users * 9 / 8, RandomState::default()),
        devices_to_compat_sessions: HashMap::with_capacity_and_hasher(
            counts.devices * 9 / 8,
            RandomState::default(),
        ),
        provider_id_mapping,
    };

    let progress_counter = progress.migrating_data(V_ENTITY_USERS, counts.users);
    let (mas, state) = migrate_users(
        &mut synapse,
        mas,
        state,
        rng,
        progress_counter,
        migrated_otel_counter.clone(),
        skipped_otel_counter.clone(),
    )
    .await?;

    let progress_counter = progress.migrating_data(V_ENTITY_THREEPIDS, counts.threepids);
    let (mas, state) = migrate_threepids(
        &mut synapse,
        mas,
        rng,
        state,
        progress_counter,
        migrated_otel_counter.clone(),
        skipped_otel_counter.clone(),
    )
    .await?;

    let progress_counter = progress.migrating_data(V_ENTITY_EXTERNAL_IDS, counts.external_ids);
    let (mas, state) = migrate_external_ids(
        &mut synapse,
        mas,
        rng,
        state,
        progress_counter,
        migrated_otel_counter.clone(),
        skipped_otel_counter.clone(),
    )
    .await?;

    let progress_counter = progress.migrating_data(
        V_ENTITY_NONREFRESHABLE_ACCESS_TOKENS,
        counts.access_tokens - counts.refresh_tokens,
    );
    let (mas, state) = migrate_unrefreshable_access_tokens(
        &mut synapse,
        mas,
        clock,
        rng,
        state,
        progress_counter,
        migrated_otel_counter.clone(),
        skipped_otel_counter.clone(),
    )
    .await?;

    let progress_counter =
        progress.migrating_data(V_ENTITY_REFRESHABLE_TOKEN_PAIRS, counts.refresh_tokens);
    let (mas, state) = migrate_refreshable_token_pairs(
        &mut synapse,
        mas,
        clock,
        rng,
        state,
        progress_counter,
        migrated_otel_counter.clone(),
        skipped_otel_counter.clone(),
    )
    .await?;

    let progress_counter = progress.migrating_data("devices", counts.devices);
    let (mas, _state) = migrate_devices(
        &mut synapse,
        mas,
        rng,
        state,
        progress_counter,
        migrated_otel_counter.clone(),
        skipped_otel_counter.clone(),
    )
    .await?;

    synapse
        .finish()
        .await
        .into_synapse("failed to close Synapse reader")?;

    mas.finish(progress)
        .await
        .into_mas("failed to finalise MAS database")?;

    Ok(())
}

#[tracing::instrument(skip_all, level = Level::INFO)]
async fn migrate_users(
    synapse: &mut SynapseReader<'_>,
    mut mas: MasWriter,
    mut state: MigrationState,
    rng: &mut impl RngCore,
    progress_counter: ProgressCounter,
    migrated_otel_counter: Counter<u64>,
    skipped_otel_counter: Counter<u64>,
) -> Result<(MasWriter, MigrationState), Error> {
    let start = Instant::now();
    let otel_kv = [KeyValue::new(K_ENTITY, V_ENTITY_USERS)];

    let (tx, mut rx) = tokio::sync::mpsc::channel::<SynapseUser>(10 * 1024 * 1024);

    // create a new RNG seeded from the passed RNG so that we can move it into the
    // spawned task
    let mut rng = rand_chacha::ChaChaRng::from_rng(rng).expect("failed to seed rng");
    let task = tokio::spawn(
        async move {
            let mut user_buffer = MasWriteBuffer::new(&mas, MasWriter::write_users);
            let mut password_buffer = MasWriteBuffer::new(&mas, MasWriter::write_passwords);

            while let Some(user) = rx.recv().await {
                // Handling an edge case: some AS users may have invalid localparts containing
                // extra `:` characters. These users are ignored and a warning is logged.
                if user.appservice_id.is_some()
                    && user
                        .name
                        .0
                        .strip_suffix(&format!(":{}", state.server_name))
                        .is_some_and(|localpart| localpart.contains(':'))
                {
                    tracing::warn!("AS user {} has invalid localpart, ignoring!", user.name.0);
                    continue;
                }

                let (mas_user, mas_password_opt) =
                    transform_user(&user, &state.server_name, &mut rng)?;

                let mut flags = UserFlags::empty();
                if bool::from(user.admin) {
                    flags |= UserFlags::IS_SYNAPSE_ADMIN;
                }
                if bool::from(user.deactivated) {
                    flags |= UserFlags::IS_DEACTIVATED;
                }
                if bool::from(user.is_guest) {
                    flags |= UserFlags::IS_GUEST;
                }
                if user.appservice_id.is_some() {
                    flags |= UserFlags::IS_APPSERVICE;

                    skipped_otel_counter.add(1, &otel_kv);
                    progress_counter.increment_skipped();

                    // Special case for appservice users: we don't insert them into the database
                    // We just record the user's information in the state and continue
                    state.users.insert(
                        CompactString::new(&mas_user.username),
                        UserInfo {
                            mas_user_id: None,
                            flags,
                        },
                    );
                    continue;
                }

                state.users.insert(
                    CompactString::new(&mas_user.username),
                    UserInfo {
                        mas_user_id: Some(mas_user.user_id),
                        flags,
                    },
                );

                user_buffer
                    .write(&mut mas, mas_user)
                    .await
                    .into_mas("writing user")?;

                if let Some(mas_password) = mas_password_opt {
                    password_buffer
                        .write(&mut mas, mas_password)
                        .await
                        .into_mas("writing password")?;
                }

                migrated_otel_counter.add(1, &otel_kv);
                progress_counter.increment_migrated();
            }

            user_buffer
                .finish(&mut mas)
                .await
                .into_mas("writing users")?;
            password_buffer
                .finish(&mut mas)
                .await
                .into_mas("writing passwords")?;

            Ok((mas, state))
        }
        .instrument(tracing::info_span!("ingest_task")),
    );

    // In case this has an error, we still want to join the task, so we look at the
    // error later
    let res = synapse
        .read_users()
        .map_err(|e| e.into_synapse("reading users"))
        .forward(PollSender::new(tx).sink_map_err(|_| Error::ChannelClosed))
        .inspect_err(|e| tracing::error!(error = e as &dyn std::error::Error))
        .await;

    let (mas, state) = task.await.into_join("user write task")??;

    res?;

    info!(
        "users migrated in {:.1}s",
        Instant::now().duration_since(start).as_secs_f64()
    );

    Ok((mas, state))
}

#[tracing::instrument(skip_all, level = Level::INFO)]
async fn migrate_threepids(
    synapse: &mut SynapseReader<'_>,
    mut mas: MasWriter,
    rng: &mut impl RngCore,
    state: MigrationState,
    progress_counter: ProgressCounter,
    migrated_otel_counter: Counter<u64>,
    skipped_otel_counter: Counter<u64>,
) -> Result<(MasWriter, MigrationState), Error> {
    let start = Instant::now();
    let otel_kv = [KeyValue::new(K_ENTITY, V_ENTITY_THREEPIDS)];

    let mut email_buffer = MasWriteBuffer::new(&mas, MasWriter::write_email_threepids);
    let mut unsupported_buffer = MasWriteBuffer::new(&mas, MasWriter::write_unsupported_threepids);
    let mut users_stream = pin!(synapse.read_threepids());

    while let Some(threepid_res) = users_stream.next().await {
        let SynapseThreepid {
            user_id: synapse_user_id,
            medium,
            address,
            added_at,
        } = threepid_res.into_synapse("reading threepid")?;
        let created_at: DateTime<Utc> = added_at.into();

        // HACK(matrix.org): for some reason, m.org has threepids for the :vector.im
        // server. We skip just skip them.
        if synapse_user_id.0.ends_with(":vector.im") {
            continue;
        }

        let username = synapse_user_id
            .extract_localpart(&state.server_name)
            .into_extract_localpart(synapse_user_id.clone())?
            .to_owned();
        let Some(user_infos) = state.users.get(username.as_str()).copied() else {
            // HACK(matrix.org): we seem to have many threepids for unknown users
            if state.users.contains_key(username.to_lowercase().as_str()) {
                tracing::warn!(mxid = %synapse_user_id, "Threepid found in the database matching an MXID with the wrong casing");
                continue;
            }

            return Err(Error::MissingUserFromDependentTable {
                table: "user_threepids".to_owned(),
                user: synapse_user_id,
            });
        };

        let Some(mas_user_id) = user_infos.mas_user_id else {
            progress_counter.increment_skipped();
            skipped_otel_counter.add(1, &otel_kv);
            continue;
        };

        if medium == "email" {
            email_buffer
                .write(
                    &mut mas,
                    MasNewEmailThreepid {
                        user_id: mas_user_id,
                        user_email_id: Uuid::from(Ulid::from_datetime_with_source(
                            created_at.into(),
                            rng,
                        )),
                        email: address,
                        created_at,
                    },
                )
                .await
                .into_mas("writing email")?;
        } else {
            unsupported_buffer
                .write(
                    &mut mas,
                    MasNewUnsupportedThreepid {
                        user_id: mas_user_id,
                        medium,
                        address,
                        created_at,
                    },
                )
                .await
                .into_mas("writing unsupported threepid")?;
        }

        migrated_otel_counter.add(1, &otel_kv);
        progress_counter.increment_migrated();
    }

    email_buffer
        .finish(&mut mas)
        .await
        .into_mas("writing email threepids")?;
    unsupported_buffer
        .finish(&mut mas)
        .await
        .into_mas("writing unsupported threepids")?;

    info!(
        "third-party IDs migrated in {:.1}s",
        Instant::now().duration_since(start).as_secs_f64()
    );

    Ok((mas, state))
}

/// # Parameters
///
/// - `provider_id_mapping`: mapping from Synapse `auth_provider` ID to UUID of
///   the upstream provider in MAS.
#[tracing::instrument(skip_all, level = Level::INFO)]
async fn migrate_external_ids(
    synapse: &mut SynapseReader<'_>,
    mut mas: MasWriter,
    rng: &mut impl RngCore,
    state: MigrationState,
    progress_counter: ProgressCounter,
    migrated_otel_counter: Counter<u64>,
    skipped_otel_counter: Counter<u64>,
) -> Result<(MasWriter, MigrationState), Error> {
    let start = Instant::now();
    let otel_kv = [KeyValue::new(K_ENTITY, V_ENTITY_EXTERNAL_IDS)];

    let mut write_buffer = MasWriteBuffer::new(&mas, MasWriter::write_upstream_oauth_links);
    let mut extids_stream = pin!(synapse.read_user_external_ids());

    while let Some(extid_res) = extids_stream.next().await {
        let SynapseExternalId {
            user_id: synapse_user_id,
            auth_provider,
            external_id: subject,
        } = extid_res.into_synapse("reading external ID")?;
        let username = synapse_user_id
            .extract_localpart(&state.server_name)
            .into_extract_localpart(synapse_user_id.clone())?
            .to_owned();
        let Some(user_infos) = state.users.get(username.as_str()).copied() else {
            return Err(Error::MissingUserFromDependentTable {
                table: "user_external_ids".to_owned(),
                user: synapse_user_id,
            });
        };

        let Some(mas_user_id) = user_infos.mas_user_id else {
            progress_counter.increment_skipped();
            skipped_otel_counter.add(1, &otel_kv);
            continue;
        };

        let Some(&upstream_provider_id) = state.provider_id_mapping.get(&auth_provider) else {
            return Err(Error::MissingAuthProviderMapping {
                synapse_id: auth_provider,
                user: synapse_user_id,
            });
        };

        // To save having to store user creation times, extract it from the ULID
        // This gives millisecond precision — good enough.
        let user_created_ts = Ulid::from(mas_user_id.get()).datetime();

        let link_id: Uuid = Ulid::from_datetime_with_source(user_created_ts, rng).into();

        write_buffer
            .write(
                &mut mas,
                MasNewUpstreamOauthLink {
                    link_id,
                    user_id: mas_user_id,
                    upstream_provider_id,
                    subject,
                    created_at: user_created_ts.into(),
                },
            )
            .await
            .into_mas("failed to write upstream link")?;

        migrated_otel_counter.add(1, &otel_kv);
        progress_counter.increment_migrated();
    }

    write_buffer
        .finish(&mut mas)
        .await
        .into_mas("writing upstream links")?;

    info!(
        "upstream links (external IDs) migrated in {:.1}s",
        Instant::now().duration_since(start).as_secs_f64()
    );

    Ok((mas, state))
}

/// Migrate devices from Synapse to MAS (as compat sessions).
///
/// In order to get the right session creation timestamps, the access tokens
/// must counterintuitively be migrated first, with the ULIDs passed in as
/// `devices`.
///
/// This is because only access tokens store a timestamp that in any way
/// resembles a creation timestamp.
#[tracing::instrument(skip_all, level = Level::INFO)]
async fn migrate_devices(
    synapse: &mut SynapseReader<'_>,
    mut mas: MasWriter,
    rng: &mut impl RngCore,
    mut state: MigrationState,
    progress_counter: ProgressCounter,
    migrated_otel_counter: Counter<u64>,
    skipped_otel_counter: Counter<u64>,
) -> Result<(MasWriter, MigrationState), Error> {
    let start = Instant::now();
    let otel_kv = [KeyValue::new(K_ENTITY, V_ENTITY_DEVICES)];

    let (tx, mut rx) = tokio::sync::mpsc::channel(10 * 1024 * 1024);

    // create a new RNG seeded from the passed RNG so that we can move it into the
    // spawned task
    let mut rng = rand_chacha::ChaChaRng::from_rng(rng).expect("failed to seed rng");
    let task = tokio::spawn(
        async move {
            let mut write_buffer = MasWriteBuffer::new(&mas, MasWriter::write_compat_sessions);

            while let Some(device) = rx.recv().await {
                let SynapseDevice {
                    user_id: synapse_user_id,
                    device_id,
                    display_name,
                    last_seen,
                    ip,
                    user_agent,
                } = device;
                let username = synapse_user_id
                    .extract_localpart(&state.server_name)
                    .into_extract_localpart(synapse_user_id.clone())?
                    .to_owned();
                let Some(user_infos) = state.users.get(username.as_str()).copied() else {
                    return Err(Error::MissingUserFromDependentTable {
                        table: "devices".to_owned(),
                        user: synapse_user_id,
                    });
                };

                let Some(mas_user_id) = user_infos.mas_user_id else {
                    progress_counter.increment_skipped();
                    skipped_otel_counter.add(1, &otel_kv);
                    continue;
                };

                if user_infos.flags.is_deactivated()
                    || user_infos.flags.is_guest()
                    || user_infos.flags.is_appservice()
                {
                    continue;
                }

                let session_id = *state
                    .devices_to_compat_sessions
                    .entry((mas_user_id, CompactString::new(&device_id)))
                    .or_insert_with(||
                // We don't have a creation time for this device (as it has no access token),
                // so use now as a least-evil fallback.
                Ulid::with_source(&mut rng).into());
                let created_at = Ulid::from(session_id).datetime().into();

                // As we're using a real IP type in the MAS database, it is possible
                // that we encounter invalid IP addresses in the Synapse database.
                // In that case, we should ignore them, but still log a warning.
                // One special case: Synapse will record '-' as IP in some cases, we don't want
                // to log about those
                let last_active_ip = ip.filter(|ip| ip != "-").and_then(|ip| {
                    ip.parse()
                        .map_err(|e| {
                            tracing::warn!(
                                error = &e as &dyn std::error::Error,
                                mxid = %synapse_user_id,
                                %device_id,
                                %ip,
                                "Failed to parse device IP, ignoring"
                            );
                        })
                        .ok()
                });

                write_buffer
                    .write(
                        &mut mas,
                        MasNewCompatSession {
                            session_id,
                            user_id: mas_user_id,
                            device_id: Some(device_id),
                            human_name: display_name,
                            created_at,
                            is_synapse_admin: user_infos.flags.is_synapse_admin(),
                            last_active_at: last_seen.map(DateTime::from),
                            last_active_ip,
                            user_agent,
                        },
                    )
                    .await
                    .into_mas("writing compat sessions")?;

                migrated_otel_counter.add(1, &otel_kv);
                progress_counter.increment_migrated();
            }

            write_buffer
                .finish(&mut mas)
                .await
                .into_mas("writing compat sessions")?;

            Ok((mas, state))
        }
        .instrument(tracing::info_span!("ingest_task")),
    );

    // In case this has an error, we still want to join the task, so we look at the
    // error later
    let res = synapse
        .read_devices()
        .map_err(|e| e.into_synapse("reading devices"))
        .forward(PollSender::new(tx).sink_map_err(|_| Error::ChannelClosed))
        .inspect_err(|e| tracing::error!(error = e as &dyn std::error::Error))
        .await;

    let (mas, state) = task.await.into_join("device write task")??;

    res?;

    info!(
        "devices migrated in {:.1}s",
        Instant::now().duration_since(start).as_secs_f64()
    );

    Ok((mas, state))
}

/// Migrates unrefreshable access tokens (those without an associated refresh
/// token). Some of these may be deviceless.
#[tracing::instrument(skip_all, level = Level::INFO)]
#[allow(clippy::too_many_arguments)]
async fn migrate_unrefreshable_access_tokens(
    synapse: &mut SynapseReader<'_>,
    mut mas: MasWriter,
    clock: &dyn Clock,
    rng: &mut impl RngCore,
    mut state: MigrationState,
    progress_counter: ProgressCounter,
    migrated_otel_counter: Counter<u64>,
    skipped_otel_counter: Counter<u64>,
) -> Result<(MasWriter, MigrationState), Error> {
    let start = Instant::now();
    let otel_kv = [KeyValue::new(
        K_ENTITY,
        V_ENTITY_NONREFRESHABLE_ACCESS_TOKENS,
    )];

    let (tx, mut rx) = tokio::sync::mpsc::channel(10 * 1024 * 1024);

    let now = clock.now();
    // create a new RNG seeded from the passed RNG so that we can move it into the
    // spawned task
    let mut rng = rand_chacha::ChaChaRng::from_rng(rng).expect("failed to seed rng");
    let task = tokio::spawn(
        async move {
            let mut write_buffer = MasWriteBuffer::new(&mas, MasWriter::write_compat_access_tokens);
            let mut deviceless_session_write_buffer =
                MasWriteBuffer::new(&mas, MasWriter::write_compat_sessions);

            while let Some(token) = rx.recv().await {
                let SynapseAccessToken {
                    user_id: synapse_user_id,
                    device_id,
                    token,
                    valid_until_ms,
                    last_validated,
                } = token;
                let username = synapse_user_id
                    .extract_localpart(&state.server_name)
                    .into_extract_localpart(synapse_user_id.clone())?
                    .to_owned();
                let Some(user_infos) = state.users.get(username.as_str()).copied() else {
                    return Err(Error::MissingUserFromDependentTable {
                        table: "access_tokens".to_owned(),
                        user: synapse_user_id,
                    });
                };

                let Some(mas_user_id) = user_infos.mas_user_id else {
                    progress_counter.increment_skipped();
                    skipped_otel_counter.add(1, &otel_kv);
                    continue;
                };

                if user_infos.flags.is_deactivated()
                    || user_infos.flags.is_guest()
                    || user_infos.flags.is_appservice()
                {
                    progress_counter.increment_skipped();
                    skipped_otel_counter.add(1, &otel_kv);
                    continue;
                }

                // It's not always accurate, but last_validated is *often* the creation time of
                // the device If we don't have one, then use the current time as a
                // fallback.
                let created_at = last_validated.map_or_else(|| now, DateTime::from);

                let session_id = if let Some(device_id) = device_id {
                    // Use the existing device_id if this is the second token for a device
                    *state
                        .devices_to_compat_sessions
                        .entry((mas_user_id, CompactString::new(&device_id)))
                        .or_insert_with(|| {
                            Uuid::from(Ulid::from_datetime_with_source(created_at.into(), &mut rng))
                        })
                } else {
                    // If this is a deviceless access token, create a deviceless compat session
                    // for it (since otherwise we won't create one whilst migrating devices)
                    let deviceless_session_id =
                        Uuid::from(Ulid::from_datetime_with_source(created_at.into(), &mut rng));

                    deviceless_session_write_buffer
                        .write(
                            &mut mas,
                            MasNewCompatSession {
                                session_id: deviceless_session_id,
                                user_id: mas_user_id,
                                device_id: None,
                                human_name: None,
                                created_at,
                                is_synapse_admin: false,
                                last_active_at: None,
                                last_active_ip: None,
                                user_agent: None,
                            },
                        )
                        .await
                        .into_mas("failed to write deviceless compat sessions")?;

                    deviceless_session_id
                };

                let token_id =
                    Uuid::from(Ulid::from_datetime_with_source(created_at.into(), &mut rng));

                write_buffer
                    .write(
                        &mut mas,
                        MasNewCompatAccessToken {
                            token_id,
                            session_id,
                            access_token: token,
                            created_at,
                            expires_at: valid_until_ms.map(DateTime::from),
                        },
                    )
                    .await
                    .into_mas("writing compat access tokens")?;

                migrated_otel_counter.add(1, &otel_kv);
                progress_counter.increment_migrated();
            }
            write_buffer
                .finish(&mut mas)
                .await
                .into_mas("writing compat access tokens")?;
            deviceless_session_write_buffer
                .finish(&mut mas)
                .await
                .into_mas("writing deviceless compat sessions")?;

            Ok((mas, state))
        }
        .instrument(tracing::info_span!("ingest_task")),
    );

    // In case this has an error, we still want to join the task, so we look at the
    // error later
    let res = synapse
        .read_unrefreshable_access_tokens()
        .map_err(|e| e.into_synapse("reading tokens"))
        .forward(PollSender::new(tx).sink_map_err(|_| Error::ChannelClosed))
        .inspect_err(|e| tracing::error!(error = e as &dyn std::error::Error))
        .await;

    let (mas, state) = task.await.into_join("token write task")??;

    res?;

    info!(
        "non-refreshable access tokens migrated in {:.1}s",
        Instant::now().duration_since(start).as_secs_f64()
    );

    Ok((mas, state))
}

/// Migrates (access token, refresh token) pairs.
/// Does not migrate non-refreshable access tokens.
#[tracing::instrument(skip_all, level = Level::INFO)]
#[allow(clippy::too_many_arguments)]
async fn migrate_refreshable_token_pairs(
    synapse: &mut SynapseReader<'_>,
    mut mas: MasWriter,
    clock: &dyn Clock,
    rng: &mut impl RngCore,
    mut state: MigrationState,
    progress_counter: ProgressCounter,
    migrated_otel_counter: Counter<u64>,
    skipped_otel_counter: Counter<u64>,
) -> Result<(MasWriter, MigrationState), Error> {
    let start = Instant::now();
    let otel_kv = [KeyValue::new(K_ENTITY, V_ENTITY_REFRESHABLE_TOKEN_PAIRS)];

    let mut token_stream = pin!(synapse.read_refreshable_token_pairs());
    let mut access_token_write_buffer =
        MasWriteBuffer::new(&mas, MasWriter::write_compat_access_tokens);
    let mut refresh_token_write_buffer =
        MasWriteBuffer::new(&mas, MasWriter::write_compat_refresh_tokens);

    while let Some(token_res) = token_stream.next().await {
        let SynapseRefreshableTokenPair {
            user_id: synapse_user_id,
            device_id,
            access_token,
            refresh_token,
            valid_until_ms,
            last_validated,
        } = token_res.into_synapse("reading Synapse refresh token")?;

        let username = synapse_user_id
            .extract_localpart(&state.server_name)
            .into_extract_localpart(synapse_user_id.clone())?
            .to_owned();
        let Some(user_infos) = state.users.get(username.as_str()).copied() else {
            return Err(Error::MissingUserFromDependentTable {
                table: "refresh_tokens".to_owned(),
                user: synapse_user_id,
            });
        };

        let Some(mas_user_id) = user_infos.mas_user_id else {
            progress_counter.increment_skipped();
            skipped_otel_counter.add(1, &otel_kv);
            continue;
        };

        if user_infos.flags.is_deactivated()
            || user_infos.flags.is_guest()
            || user_infos.flags.is_appservice()
        {
            progress_counter.increment_skipped();
            skipped_otel_counter.add(1, &otel_kv);
            continue;
        }

        // It's not always accurate, but last_validated is *often* the creation time of
        // the device If we don't have one, then use the current time as a
        // fallback.
        let created_at = last_validated.map_or_else(|| clock.now(), DateTime::from);

        // Use the existing device_id if this is the second token for a device
        let session_id = *state
            .devices_to_compat_sessions
            .entry((mas_user_id, CompactString::new(&device_id)))
            .or_insert_with(|| Uuid::from(Ulid::from_datetime_with_source(created_at.into(), rng)));

        let access_token_id = Uuid::from(Ulid::from_datetime_with_source(created_at.into(), rng));
        let refresh_token_id = Uuid::from(Ulid::from_datetime_with_source(created_at.into(), rng));

        access_token_write_buffer
            .write(
                &mut mas,
                MasNewCompatAccessToken {
                    token_id: access_token_id,
                    session_id,
                    access_token,
                    created_at,
                    expires_at: valid_until_ms.map(DateTime::from),
                },
            )
            .await
            .into_mas("writing compat access tokens")?;
        refresh_token_write_buffer
            .write(
                &mut mas,
                MasNewCompatRefreshToken {
                    refresh_token_id,
                    session_id,
                    access_token_id,
                    refresh_token,
                    created_at,
                },
            )
            .await
            .into_mas("writing compat refresh tokens")?;

        migrated_otel_counter.add(1, &otel_kv);
        progress_counter.increment_migrated();
    }

    access_token_write_buffer
        .finish(&mut mas)
        .await
        .into_mas("writing compat access tokens")?;

    refresh_token_write_buffer
        .finish(&mut mas)
        .await
        .into_mas("writing compat refresh tokens")?;

    info!(
        "refreshable token pairs migrated in {:.1}s",
        Instant::now().duration_since(start).as_secs_f64()
    );

    Ok((mas, state))
}

fn transform_user(
    user: &SynapseUser,
    server_name: &str,
    rng: &mut impl RngCore,
) -> Result<(MasNewUser, Option<MasNewUserPassword>), Error> {
    let username = user
        .name
        .extract_localpart(server_name)
        .into_extract_localpart(user.name.clone())?
        .to_owned();

    let user_id = Uuid::from(Ulid::from_datetime_with_source(
        DateTime::<Utc>::from(user.creation_ts).into(),
        rng,
    ))
    .try_into()
    .expect("ULID generation lead to a nil UUID, this is a bug!");

    let new_user = MasNewUser {
        user_id,
        username,
        created_at: user.creation_ts.into(),
        locked_at: user.locked.then_some(user.creation_ts.into()),
        deactivated_at: bool::from(user.deactivated).then_some(user.creation_ts.into()),
        can_request_admin: bool::from(user.admin),
        is_guest: bool::from(user.is_guest),
    };

    let mas_password = user
        .password_hash
        .clone()
        .map(|password_hash| MasNewUserPassword {
            user_password_id: Uuid::from(Ulid::from_datetime_with_source(
                DateTime::<Utc>::from(user.creation_ts).into(),
                rng,
            )),
            user_id: new_user.user_id,
            hashed_password: password_hash,
            created_at: new_user.created_at,
        });

    Ok((new_user, mas_password))
}
