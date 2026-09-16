//! See [`MigrationSyncFactorReaper`].

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Duration, Utc};
use turnkey_client::generated::external::activity::v1::Activity;
use turnkey_client::generated::external::data::v1::{Policy, Timestamp, User};

use super::super::error::TurnkeyApiError;
use super::super::policies::UserRole;
use super::sync_factor_policy::policy_bound_user;
use super::{MigrationContext, MigrationOutcome, TurnkeyMigration};

const ACTIVITIES_PAGE_SIZE: usize = 100;
const ACTIVITIES_PAGE_HARD_LIMIT: usize = 50;
const MAX_SYNC_FACTOR_USERS: usize = 25;
const MAX_SYNC_FACTOR_USER_AGE: Duration = Duration::days(365);

/// Removes stale Sync Factor users and the policies that belong to them.
///
/// A sync factor is stale when it has not voted in the last year, or it falls
/// outside the 25 most-recently-active sync factors. The current sync factor is
/// always retained and counts toward the cap. This also repairs partial prior
/// cleanup attempts by removing policies without users and users without a
/// policy.
///
/// Reads use the current sync factor. Deleting policies before users requires a
/// main factor and makes a partial failure recoverable: a subsequent run sees a
/// user without a policy and removes it.
pub(super) struct MigrationSyncFactorReaper;

#[async_trait::async_trait]
impl TurnkeyMigration for MigrationSyncFactorReaper {
    fn id(&self) -> &'static str {
        "sync_factor_reaper"
    }

    fn description(&self) -> &'static str {
        "Remove stale sync factors and orphaned sync factor policies."
    }

    async fn run(
        &self,
        ctx: &MigrationContext<'_>,
    ) -> Result<MigrationOutcome, TurnkeyApiError> {
        let now = Utc::now();
        let users = ctx
            .api
            .get_users(ctx.suborganization_id, ctx.sync_factor)
            .await?;
        if !users
            .iter()
            .any(|user| UserRole::classify(&user.user_name) == UserRole::SyncFactor)
        {
            return Ok(MigrationOutcome::Skipped);
        }
        let policies = ctx
            .api
            .get_policies(ctx.suborganization_id, ctx.sync_factor)
            .await?;
        let current_user_id = ctx
            .api
            .whoami_sync_factor_user_id(ctx.suborganization_id, ctx.sync_factor)
            .await?;
        let activity_scan = scan_last_activity(ctx, now).await?;
        let plan = plan(
            &users,
            &policies,
            &activity_scan.last_activity_by_user_id,
            activity_scan.complete,
            &current_user_id,
            now,
        )?;

        if plan.is_empty() {
            return Ok(MigrationOutcome::Skipped);
        }

        let Some(main_factor) = ctx.main_factor else {
            return Ok(MigrationOutcome::MainFactorRequired);
        };

        // Policies are intentionally removed first. If user deletion then fails,
        // the next run identifies the remaining user as one without a policy.
        if !plan.policy_ids.is_empty() {
            ctx.api
                .delete_policies(
                    ctx.suborganization_id,
                    plan.policy_ids.clone(),
                    main_factor,
                )
                .await?;
        }
        if !plan.user_ids.is_empty() {
            ctx.api
                .delete_users(
                    ctx.suborganization_id,
                    plan.user_ids.clone(),
                    main_factor,
                )
                .await?;
        }

        Ok(MigrationOutcome::Applied {
            details: vec![format!(
                "removed {} stale sync factor users and {} policies",
                plan.user_ids.len(),
                plan.policy_ids.len(),
            )],
        })
    }
}

struct ActivityScan {
    last_activity_by_user_id: HashMap<String, DateTime<Utc>>,
    complete: bool,
}

async fn scan_last_activity(
    ctx: &MigrationContext<'_>,
    now: DateTime<Utc>,
) -> Result<ActivityScan, TurnkeyApiError> {
    let cutoff = now - MAX_SYNC_FACTOR_USER_AGE;
    let mut last_activity_by_user_id = HashMap::new();
    let mut before_activity_id: Option<String> = None;

    for _ in 0..ACTIVITIES_PAGE_HARD_LIMIT {
        let activities = ctx
            .api
            .get_activities(
                ctx.suborganization_id,
                ctx.sync_factor,
                before_activity_id.as_deref(),
            )
            .await?;
        let page_len = activities.len();

        if page_len == 0 {
            return Ok(ActivityScan {
                last_activity_by_user_id,
                complete: true,
            });
        }

        let mut oldest: Option<DateTime<Utc>> = None;
        for activity in &activities {
            let created_at = parse_timestamp(activity.created_at.as_ref(), "activity")?;
            oldest = Some(oldest.map_or(created_at, |oldest| oldest.min(created_at)));
            record_votes(activity, created_at, &mut last_activity_by_user_id)?;
        }

        if oldest.is_some_and(|timestamp| timestamp < cutoff)
            || page_len < ACTIVITIES_PAGE_SIZE
        {
            return Ok(ActivityScan {
                last_activity_by_user_id,
                complete: true,
            });
        }

        let cursor = activities
            .last()
            .map(|activity| activity.id.clone())
            .filter(|id| !id.is_empty())
            .ok_or_else(|| {
                TurnkeyApiError::Client(
                    "list_activities returned an empty cursor".into(),
                )
            })?;
        before_activity_id = Some(cursor);
    }

    crate::warn!(
        "sync_factor_reaper activity scan reached page limit={ACTIVITIES_PAGE_HARD_LIMIT}; age cleanup is disabled"
    );
    Ok(ActivityScan {
        last_activity_by_user_id,
        complete: false,
    })
}

fn record_votes(
    activity: &Activity,
    activity_created_at: DateTime<Utc>,
    last_activity_by_user_id: &mut HashMap<String, DateTime<Utc>>,
) -> Result<(), TurnkeyApiError> {
    for vote in &activity.votes {
        let voted_at = match vote.created_at.as_ref() {
            Some(timestamp) => parse_timestamp(Some(timestamp), "vote")?,
            None => activity_created_at,
        };
        last_activity_by_user_id
            .entry(vote.user_id.clone())
            .and_modify(|previous| *previous = (*previous).max(voted_at))
            .or_insert(voted_at);
    }
    Ok(())
}

fn parse_timestamp(
    timestamp: Option<&Timestamp>,
    resource: &str,
) -> Result<DateTime<Utc>, TurnkeyApiError> {
    let timestamp = timestamp.ok_or_else(|| {
        TurnkeyApiError::Client(format!(
            "Turnkey {resource} is missing its created_at timestamp"
        ))
    })?;
    let seconds = timestamp.seconds.parse::<i64>().map_err(|_| {
        TurnkeyApiError::Client(format!(
            "Turnkey {resource} has an invalid created_at seconds value"
        ))
    })?;
    let nanos = timestamp.nanos.parse::<u32>().map_err(|_| {
        TurnkeyApiError::Client(format!(
            "Turnkey {resource} has an invalid created_at nanos value"
        ))
    })?;
    DateTime::from_timestamp(seconds, nanos).ok_or_else(|| {
        TurnkeyApiError::Client(format!(
            "Turnkey {resource} has an out-of-range created_at timestamp"
        ))
    })
}

#[derive(Debug, PartialEq, Eq)]
struct ReaperPlan {
    policy_ids: Vec<String>,
    user_ids: Vec<String>,
}

impl ReaperPlan {
    const fn is_empty(&self) -> bool {
        self.policy_ids.is_empty() && self.user_ids.is_empty()
    }
}

fn plan(
    users: &[User],
    policies: &[Policy],
    last_activity_by_user_id: &HashMap<String, DateTime<Utc>>,
    activity_scan_complete: bool,
    current_user_id: &str,
    now: DateTime<Utc>,
) -> Result<ReaperPlan, TurnkeyApiError> {
    let mut sync_factor_users: Vec<(&User, DateTime<Utc>)> = users
        .iter()
        .filter(|user| UserRole::classify(&user.user_name) == UserRole::SyncFactor)
        .map(|user| {
            let last_activity = last_activity_by_user_id
                .get(&user.user_id)
                .copied()
                .map_or_else(
                    || parse_timestamp(user.created_at.as_ref(), "sync factor user"),
                    Ok,
                );
            last_activity.map(|last_activity| (user, last_activity))
        })
        .collect::<Result<_, _>>()?;
    sync_factor_users.sort_unstable_by(|(_, left), (_, right)| right.cmp(left));

    let current_user_count = sync_factor_users
        .iter()
        .filter(|(user, _)| user.user_id == current_user_id)
        .count();
    if current_user_count != 1 {
        return Err(TurnkeyApiError::Consistency);
    }

    let max_other_users = MAX_SYNC_FACTOR_USERS.saturating_sub(1);
    let cutoff = now - MAX_SYNC_FACTOR_USER_AGE;
    let known_policy_users: HashSet<&str> =
        policies.iter().filter_map(policy_bound_user).collect();
    let known_user_ids: HashSet<&str> =
        users.iter().map(|user| user.user_id.as_str()).collect();

    let mut stale_user_ids = HashSet::new();
    for (index, (user, last_activity)) in sync_factor_users
        .iter()
        .filter(|(user, _)| user.user_id != current_user_id)
        .enumerate()
    {
        let stale_by_count = index >= max_other_users;
        let stale_by_age = activity_scan_complete && *last_activity < cutoff;
        let missing_policy = !known_policy_users.contains(user.user_id.as_str());
        if stale_by_count || stale_by_age || missing_policy {
            stale_user_ids.insert(user.user_id.as_str());
        }
    }

    let mut policy_ids: Vec<String> = policies
        .iter()
        .filter(|policy| {
            policy_bound_user(policy).is_some_and(|user_id| {
                stale_user_ids.contains(user_id) || !known_user_ids.contains(user_id)
            })
        })
        .map(|policy| policy.policy_id.clone())
        .collect();
    policy_ids.sort_unstable();
    policy_ids.dedup();

    let mut user_ids: Vec<String> =
        stale_user_ids.into_iter().map(str::to_string).collect();
    user_ids.sort_unstable();
    Ok(ReaperPlan {
        policy_ids,
        user_ids,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const CURRENT_ID: &str = "11111111-1111-1111-1111-111111111111";
    const STALE_ID: &str = "22222222-2222-2222-2222-222222222222";
    const FRESH_ID: &str = "33333333-3333-3333-3333-333333333333";

    fn user(id: &str, created_at: i64) -> User {
        serde_json::from_value(json!({
            "userId": id,
            "userName": format!("sync_factor_user_{id}"),
            "createdAt": { "seconds": created_at.to_string(), "nanos": "0" },
        }))
        .unwrap()
    }

    fn policy(id: &str, user_id: &str) -> Policy {
        serde_json::from_value(json!({
            "policyId": id,
            "policyName": "sync factor policy",
            "effect": "EFFECT_ALLOW",
            "notes": "",
            "consensus": format!("approvers.any(user, user.id == '{user_id}')"),
        }))
        .unwrap()
    }

    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(2_000_000_000, 0).unwrap()
    }

    #[test]
    fn preserves_current_user_and_removes_an_old_user_with_its_policy() {
        let plan = plan(
            &[
                user(CURRENT_ID, 1_999_000_000),
                user(STALE_ID, 1_000_000_000),
            ],
            &[
                policy("policy-current", CURRENT_ID),
                policy("policy-stale", STALE_ID),
            ],
            &HashMap::new(),
            true,
            CURRENT_ID,
            now(),
        )
        .unwrap();

        assert_eq!(plan.user_ids, [STALE_ID]);
        assert_eq!(plan.policy_ids, ["policy-stale"]);
    }

    #[test]
    fn retains_a_user_with_a_recent_vote_even_when_it_was_created_long_ago() {
        let mut last_activity = HashMap::new();
        last_activity.insert(STALE_ID.to_string(), now() - Duration::days(1));
        let plan = plan(
            &[
                user(CURRENT_ID, 1_999_000_000),
                user(STALE_ID, 1_000_000_000),
            ],
            &[
                policy("policy-current", CURRENT_ID),
                policy("policy-fresh", STALE_ID),
            ],
            &last_activity,
            true,
            CURRENT_ID,
            now(),
        )
        .unwrap();

        assert!(plan.is_empty());
    }

    #[test]
    fn removes_orphan_policies_and_users_without_a_policy() {
        let plan = plan(
            &[
                user(CURRENT_ID, 1_999_000_000),
                user(FRESH_ID, 1_999_000_000),
            ],
            &[
                policy("policy-current", CURRENT_ID),
                policy("policy-orphan", STALE_ID),
            ],
            &HashMap::new(),
            true,
            CURRENT_ID,
            now(),
        )
        .unwrap();

        assert_eq!(plan.user_ids, [FRESH_ID]);
        assert_eq!(plan.policy_ids, ["policy-orphan"]);
    }

    #[test]
    fn keeps_only_twenty_five_sync_factors_including_current_user() {
        let users: Vec<User> = std::iter::once(user(CURRENT_ID, 1_999_999_999))
            .chain((0..25).map(|index| {
                let id = format!("00000000-0000-0000-0000-{index:012}");
                user(&id, 1_999_999_999 - index)
            }))
            .collect();
        let policies: Vec<Policy> = users
            .iter()
            .map(|user| policy(&format!("policy-{}", user.user_id), &user.user_id))
            .collect();

        let plan =
            plan(&users, &policies, &HashMap::new(), true, CURRENT_ID, now()).unwrap();

        assert_eq!(plan.user_ids.len(), 1);
        assert_eq!(plan.user_ids[0], "00000000-0000-0000-0000-000000000024");
    }
}
