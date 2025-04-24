pub mod allow_access;
pub mod pay_for_access;
pub mod register_webhook;

/// Job ID for the admin function to permanently allow an IP/CIDR or AccountId.
pub const ALLOW_ACCESS_JOB_ID: u64 = 0;

/// Job ID for users to pay (e.g., with tokens) for temporary access.
pub const PAY_FOR_ACCESS_JOB_ID: u64 = 1;

/// Job ID for users/admins to register a webhook URL for notifications.
pub const REGISTER_WEBHOOK_JOB_ID: u64 = 2;
