// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::process::ExitCode;

use clap::Parser;
use figment::Figment;
use mas_config::{ConfigurationSectionExt, DatabaseConfig};
use tracing::info_span;

use crate::util::{database_connection_from_config, run_migrations};

#[derive(Parser, Debug)]
pub(super) struct Options {
    #[command(subcommand)]
    subcommand: Subcommand,
}

#[derive(Parser, Debug)]
enum Subcommand {
    /// Run database migrations
    Migrate,
}

impl Options {
    pub async fn run(self, figment: &Figment) -> anyhow::Result<ExitCode> {
        let _span = info_span!("cli.database.migrate").entered();
        let config =
            DatabaseConfig::extract_or_default(figment).map_err(anyhow::Error::from_boxed)?;
        let mut conn = database_connection_from_config(&config).await?;

        // Run pending migrations
        run_migrations(&mut conn).await?;

        Ok(ExitCode::SUCCESS)
    }
}
