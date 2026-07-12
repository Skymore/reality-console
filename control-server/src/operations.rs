//! Minimal, fail-closed command-line surface for controller backup operations.

use crate::backup::{
    create_backup, restore_backup, verify_backup, CreateBackupOptions, ExternalEncryptionContract,
    RecoveryMode, RestoreBaseline, RestoreOptions,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::io::Write as _;
use std::path::PathBuf;
use thiserror::Error;

/// Runs an operator command and writes a redacted JSON result.
///
/// # Errors
///
/// Returns [`OperationCliError`] for malformed arguments, failed validation, or failed output.
pub fn run_operation_command<I>(arguments: I) -> Result<(), OperationCliError>
where
    I: IntoIterator<Item = OsString>,
{
    let arguments = arguments
        .into_iter()
        .map(|argument| {
            argument
                .into_string()
                .map_err(|_| OperationCliError::NonUnicodeArgument)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let Some(command) = arguments.first().map(String::as_str) else {
        return Err(OperationCliError::Usage);
    };
    match command {
        "backup" => run_backup_command(&arguments[1..]),
        "restore" => run_restore_command(&arguments[1..]),
        _ => Err(OperationCliError::Usage),
    }
}

fn run_backup_command(arguments: &[String]) -> Result<(), OperationCliError> {
    let Some(command) = arguments.first().map(String::as_str) else {
        return Err(OperationCliError::Usage);
    };
    match command {
        "create" => {
            let parsed = ParsedArguments::new(&arguments[1..])?;
            parsed.ensure_only(
                &["database", "destination", "external-encryption-contract"],
                &[],
            )?;
            let report = create_backup(&CreateBackupOptions {
                source_database: PathBuf::from(parsed.required_value("database")?),
                destination: PathBuf::from(parsed.required_value("destination")?),
                external_encryption: ExternalEncryptionContract::new(
                    parsed.required_value("external-encryption-contract")?,
                )?,
            })?;
            write_json(&report)
        }
        "verify" => {
            let parsed = ParsedArguments::new(&arguments[1..])?;
            parsed.ensure_only(&["backup"], &[])?;
            let report = verify_backup(PathBuf::from(parsed.required_value("backup")?).as_path())?;
            write_json(&report)
        }
        _ => Err(OperationCliError::Usage),
    }
}

fn run_restore_command(arguments: &[String]) -> Result<(), OperationCliError> {
    let parsed = ParsedArguments::new(arguments)?;
    parsed.ensure_only(
        &["backup", "destination", "current-database"],
        &["recovery-mode", "dry-run", "no-local-history"],
    )?;
    if !parsed.has_flag("recovery-mode") {
        return Err(OperationCliError::RecoveryModeRequired);
    }
    let baseline = match (
        parsed.optional_value("current-database"),
        parsed.has_flag("no-local-history"),
    ) {
        (Some(path), false) => RestoreBaseline::CurrentDatabase(PathBuf::from(path)),
        (None, true) => RestoreBaseline::NoLocalHistory,
        _ => return Err(OperationCliError::BaselineRequired),
    };
    let report = restore_backup(&RestoreOptions {
        backup: PathBuf::from(parsed.required_value("backup")?),
        destination: PathBuf::from(parsed.required_value("destination")?),
        baseline,
        recovery_mode: RecoveryMode::Explicit,
        dry_run: parsed.has_flag("dry-run"),
    })?;
    write_json(&report)
}

fn write_json(value: &impl Serialize) -> Result<(), OperationCliError> {
    let mut output = std::io::stdout().lock();
    serde_json::to_writer_pretty(&mut output, value)?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(())
}

struct ParsedArguments {
    values: BTreeMap<String, String>,
    flags: BTreeSet<String>,
}

impl ParsedArguments {
    fn new(arguments: &[String]) -> Result<Self, OperationCliError> {
        let mut values = BTreeMap::new();
        let mut flags = BTreeSet::new();
        let mut index = 0;
        while index < arguments.len() {
            let Some(name) = arguments[index].strip_prefix("--") else {
                return Err(OperationCliError::Usage);
            };
            if name.is_empty() || values.contains_key(name) || flags.contains(name) {
                return Err(OperationCliError::DuplicateArgument);
            }
            if arguments
                .get(index + 1)
                .is_some_and(|value| !value.starts_with("--"))
            {
                values.insert(name.to_string(), arguments[index + 1].clone());
                index += 2;
            } else {
                flags.insert(name.to_string());
                index += 1;
            }
        }
        Ok(Self { values, flags })
    }

    fn ensure_only(
        &self,
        allowed_values: &[&str],
        allowed_flags: &[&str],
    ) -> Result<(), OperationCliError> {
        if self
            .values
            .keys()
            .any(|name| !allowed_values.contains(&name.as_str()))
            || self
                .flags
                .iter()
                .any(|name| !allowed_flags.contains(&name.as_str()))
        {
            return Err(OperationCliError::Usage);
        }
        Ok(())
    }

    fn required_value(&self, name: &'static str) -> Result<&str, OperationCliError> {
        self.optional_value(name)
            .ok_or(OperationCliError::MissingArgument(name))
    }

    fn optional_value(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(String::as_str)
    }

    fn has_flag(&self, name: &str) -> bool {
        self.flags.contains(name)
    }
}

/// Redacted command-line failures. Argument values are intentionally omitted.
#[derive(Debug, Error)]
pub enum OperationCliError {
    #[error(
        "usage: control-server backup create --database PATH --destination DIR \
         --external-encryption-contract ID | control-server backup verify --backup DIR | \
         control-server restore --backup DIR --destination DIR --recovery-mode \
         (--current-database PATH | --no-local-history) [--dry-run]"
    )]
    Usage,
    #[error("command arguments must be valid UTF-8")]
    NonUnicodeArgument,
    #[error("an option was supplied more than once")]
    DuplicateArgument,
    #[error("required option --{0} is missing")]
    MissingArgument(&'static str),
    #[error("restore requires the explicit --recovery-mode flag")]
    RecoveryModeRequired,
    #[error("restore requires exactly one of --current-database or --no-local-history")]
    BaselineRequired,
    #[error(transparent)]
    Backup(#[from] crate::backup::BackupError),
    #[error("operator JSON output failed")]
    Json(#[from] serde_json::Error),
    #[error("operator output failed")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restore_requires_explicit_mode_and_one_baseline() {
        let without_mode = vec![
            "--backup".to_string(),
            "backup".to_string(),
            "--destination".to_string(),
            "restore".to_string(),
            "--no-local-history".to_string(),
        ];
        assert!(matches!(
            run_restore_command(&without_mode),
            Err(OperationCliError::RecoveryModeRequired)
        ));

        let conflicting = vec![
            "--backup".to_string(),
            "backup".to_string(),
            "--destination".to_string(),
            "restore".to_string(),
            "--recovery-mode".to_string(),
            "--no-local-history".to_string(),
            "--current-database".to_string(),
            "current.sqlite3".to_string(),
        ];
        assert!(matches!(
            run_restore_command(&conflicting),
            Err(OperationCliError::BaselineRequired)
        ));
    }

    #[test]
    fn parser_rejects_unknown_and_duplicate_options() {
        let duplicate = vec![
            "--backup".to_string(),
            "one".to_string(),
            "--backup".to_string(),
            "two".to_string(),
        ];
        assert!(matches!(
            ParsedArguments::new(&duplicate),
            Err(OperationCliError::DuplicateArgument)
        ));

        let unknown = ParsedArguments::new(&["--secret".to_string(), "value".to_string()]).unwrap();
        assert!(matches!(
            unknown.ensure_only(&["backup"], &[]),
            Err(OperationCliError::Usage)
        ));
    }
}
