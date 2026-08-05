//! See [`MigrationSyncFactorPolicy`]

use std::collections::HashSet;

use turnkey_client::generated::external::data::v1::{Policy, User};
use turnkey_client::generated::immutable::activity::v1::{
    CreatePolicyIntentV3, UpdatePolicyIntentV2,
};
use turnkey_client::generated::immutable::common::v1::Effect;

use super::super::error::TurnkeyApiError;
use super::super::policies::{
    sync_factor_policy_consensus, sync_factor_policy_name, UserRole,
    SYNC_FACTOR_POLICY_CONDITION, SYNC_FACTOR_POLICY_NOTES,
};
use super::{MigrationContext, MigrationOutcome, TurnkeyMigration};

/// Ensures every sync factor user in the Turnkey account has an up-to-date and
/// correct policy, as defined in <https://docs.toolsforhumanity.com/world-app/backup/components#turnkey-user-setup>.
///
/// This migration will:
/// 1. identify all sync factor users and ensure they have the right policy (either create or update).
/// 2. identify stale sync factor policies assigned to orphaned users and remove them.
///
/// # Why?
/// This migration is necessary because in the past Sync Factors were registered with
/// a policy that lacked certain permissions (e.g. delete sub-organization) and it
/// also used `activity.type` conditions instead of `resource` + `action`.
///
/// # Main Factor
/// If operations need to be executed, this migration REQUIRES a Main Factor.
pub(super) struct MigrationSyncFactorPolicy;

#[async_trait::async_trait]
impl TurnkeyMigration for MigrationSyncFactorPolicy {
    fn id(&self) -> &'static str {
        "sync_factor_policy"
    }

    fn description(&self) -> &'static str {
        "Ensure every sync factor has the correct policy to perform all housekeeping operations."
    }

    async fn run(
        &self,
        ctx: &MigrationContext<'_>,
    ) -> Result<MigrationOutcome, TurnkeyApiError> {
        let users = ctx
            .api
            .get_users(ctx.suborganization_id, ctx.sync_factor)
            .await?;

        let policies = ctx
            .api
            .get_policies(ctx.suborganization_id, ctx.sync_factor)
            .await?;

        let actions = plan(&users, &policies);
        if actions.is_empty() {
            crate::info!(
                "sync_factor_policy skipped: all sync factors have the correct policy"
            );
            return Ok(MigrationOutcome::Skipped);
        }

        let Some(main_factor) = ctx.main_factor else {
            return Ok(MigrationOutcome::MainFactorRequired);
        };

        let mut details = Vec::with_capacity(actions.len());
        for action in actions {
            match action {
                PolicyAction::Create { user_name, intent } => {
                    ctx.api
                        .create_policy(ctx.suborganization_id, intent, main_factor)
                        .await?;
                    details.push(format!("created policy for {user_name}"));
                }
                PolicyAction::Update { user_name, intent } => {
                    ctx.api
                        .update_policy(ctx.suborganization_id, intent, main_factor)
                        .await?;
                    details.push(format!("updated policy for {user_name}"));
                }
                PolicyAction::Delete { policy_id } => {
                    ctx.api
                        .delete_policy(ctx.suborganization_id, &policy_id, main_factor)
                        .await?;
                    details
                        .push(format!("deleted stale sync factor policy {policy_id}"));
                }
            }
        }
        Ok(MigrationOutcome::Applied { details })
    }
}

/// A change needed to reconcile the sub-org's sync factor policies.
enum PolicyAction {
    /// No policy is bound to the user; create one.
    Create {
        user_name: String,
        intent: CreatePolicyIntentV3,
    },
    /// A policy exists but its condition/effect drifted; update it.
    ///
    /// This is the expected "happy path". Before ~Aug 2026, Sync Factor
    /// user were created with a different policy.
    Update {
        user_name: String,
        intent: UpdatePolicyIntentV2,
    },
    /// A sync factor policy is assigned to a user that no longer exists; delete it.
    ///
    /// NOTE: Only sync factor user policies are targeted.
    Delete { policy_id: String },
}

/// Computes the set of policy changes from the sub-org's users and policies (pure).
fn plan(users: &[User], policies: &[Policy]) -> Vec<PolicyAction> {
    let mut actions = Vec::new();

    // Add or fix the policy for each sync factor user.
    for user in users {
        match UserRole::classify(&user.user_name) {
            UserRole::SyncFactor => {}
            UserRole::Main | UserRole::BreakGlass => continue,
            UserRole::Unexpected => {
                crate::warn!(
                    "Consistency Warning! sub-org has a user that is not main, sync, or break-glass"
                );
                continue;
            }
        }

        if let Some(action) = plan_for_sync_factor(user, policies) {
            actions.push(action);
        }
    }

    // Delete stale policies, i.e. policies bound to a user that no longer exists in the org
    let current_user_ids: HashSet<&str> =
        users.iter().map(|user| user.user_id.as_str()).collect();
    for policy in policies {
        if let Some(bound_user_id) = policy_bound_user(policy) {
            if !current_user_ids.contains(bound_user_id) {
                actions.push(PolicyAction::Delete {
                    policy_id: policy.policy_id.clone(),
                });
            }
        }
    }

    actions
}

/// Decides the change (if any) for a single sync factor user.
fn plan_for_sync_factor(user: &User, policies: &[Policy]) -> Option<PolicyAction> {
    let Some(consensus) = sync_factor_policy_consensus(&user.user_id) else {
        crate::error!(
            "sync_factor_policy: sync factor has a malformed user_id; skipping to avoid policy-language injection"
        );
        return None;
    };

    let bound: Vec<&Policy> = policies
        .iter()
        .filter(|policy| is_policy_for(policy, &user.user_id))
        .collect();

    if bound.len() > 1 {
        // Sync Factor Users should never have more than one policy assigned, this is
        // a soft consistency issue.
        crate::warn!(
            "sync_factor_policy: sync factor has multiple policies; keeping all"
        );
    }

    if bound.iter().any(|policy| is_up_to_date(policy)) {
        return None;
    }

    let action = bound.first().map_or_else(
        || PolicyAction::Create {
            user_name: user.user_name.clone(),
            intent: create_intent(&user.user_id, &consensus),
        },
        |policy| PolicyAction::Update {
            user_name: user.user_name.clone(),
            intent: update_intent(&policy.policy_id, &user.user_id, &consensus),
        },
    );
    Some(action)
}

/// Whether `policy` is the policy bound to `user_id`.
fn is_policy_for(policy: &Policy, user_id: &str) -> bool {
    policy_bound_user(policy) == Some(user_id)
}

/// Determines if a Turnkey's [`Policy`] consensus matches **exactly** for a single user,
/// regardless of the effect or any other conditions which the policy would apply.
///
/// The match is strict: any other consensus shape is ignored.
fn policy_bound_user(policy: &Policy) -> Option<&str> {
    const PREFIX: &str = "approvers.any(user, user.id == '";
    const SUFFIX: &str = "')";

    let consensus = policy.consensus.as_deref()?;
    let inner = consensus.strip_prefix(PREFIX)?.strip_suffix(SUFFIX)?;
    // A well-formed id has no additional quotes, rejecting quotes rules out
    // anything with more clauses
    if inner.contains('\'') {
        return None;
    }
    Some(inner)
}

/// Whether an existing bound policy already matches the desired state.
///
/// NOTE: The policy name is ignored as it's only a convenience label, i.e.
/// a wrong label will not trigger a policy update.
fn is_up_to_date(policy: &Policy) -> bool {
    policy.effect == Effect::Allow
        && policy.condition.as_deref() == Some(SYNC_FACTOR_POLICY_CONDITION)
}

fn create_intent(user_id: &str, consensus: &str) -> CreatePolicyIntentV3 {
    CreatePolicyIntentV3 {
        policy_name: sync_factor_policy_name(user_id),
        effect: Effect::Allow,
        condition: Some(SYNC_FACTOR_POLICY_CONDITION.to_string()),
        consensus: Some(consensus.to_string()),
        notes: SYNC_FACTOR_POLICY_NOTES.to_string(),
    }
}

fn update_intent(
    policy_id: &str,
    user_id: &str,
    consensus: &str,
) -> UpdatePolicyIntentV2 {
    UpdatePolicyIntentV2 {
        policy_id: policy_id.to_string(),
        policy_name: Some(sync_factor_policy_name(user_id)),
        policy_effect: Some(Effect::Allow),
        policy_condition: Some(SYNC_FACTOR_POLICY_CONDITION.to_string()),
        policy_consensus: Some(consensus.to_string()),
        policy_notes: Some(SYNC_FACTOR_POLICY_NOTES.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::turnkey::policies::{
        AUTH_USER_MAIN_USERNAME, BREAK_GLASS_USERNAME, SYNC_FACTOR_USERNAME_PREFIX,
    };
    use serde_json::json;

    /// A valid Turnkey-style user id (UUID).
    const SYNC_USER_ID: &str = "11111111-2222-3333-4444-555555555555";

    fn user_from_json(value: serde_json::Value) -> User {
        serde_json::from_value(value).unwrap()
    }

    fn policy_from_json(value: serde_json::Value) -> Policy {
        serde_json::from_value(value).unwrap()
    }

    fn sync_user(user_id: &str) -> User {
        user_from_json(json!({
            "userId": user_id,
            "userName": format!("{SYNC_FACTOR_USERNAME_PREFIX}abcd1234"),
        }))
    }

    /// A bound policy for `user_id` carrying an arbitrary `condition`.
    fn user_policy(user_id: &str, condition: &str) -> Policy {
        policy_from_json(json!({
            "policyId": format!("policy-{user_id}"),
            "policyName": sync_factor_policy_name(user_id),
            "effect": "EFFECT_ALLOW",
            "notes": "",
            "consensus": sync_factor_policy_consensus(user_id)
                .expect("test user id is valid"),
            "condition": condition,
        }))
    }

    #[test]
    fn creates_policy_when_sync_factor_has_none() {
        let users = vec![sync_user(SYNC_USER_ID)];

        let actions = plan(&users, &[]);

        assert_eq!(actions.len(), 1);
        let PolicyAction::Create { intent, .. } = &actions[0] else {
            panic!("expected Create, got a different action");
        };
        assert_eq!(intent.effect, Effect::Allow);
        assert_eq!(
            intent.condition.as_deref(),
            Some(SYNC_FACTOR_POLICY_CONDITION)
        );
        assert_eq!(intent.consensus, sync_factor_policy_consensus(SYNC_USER_ID));
    }

    /// A real legacy policy (bound to the user, `EFFECT_ALLOW`) whose condition uses
    /// version-specific `activity.type == …` clauses must be reconciled to the
    /// canonical `resource` + `action` policy — updated in place, never duplicated.
    ///
    /// The expected result is hardcoded (not derived from the constants) so a stray
    /// change to the canonical policy is caught here.
    #[test]
    fn updates_policy_with_legacy_activity_type_condition() {
        let legacy_condition =
            "activity.type == 'ACTIVITY_TYPE_DELETE_AUTHENTICATORS' \
             || activity.type == 'ACTIVITY_TYPE_DELETE_PRIVATE_KEYS' \
             || activity.type == 'ACTIVITY_TYPE_DELETE_OAUTH_PROVIDERS' \
             || activity.type == 'ACTIVITY_TYPE_DELETE_API_KEYS' \
             || activity.type == 'ACTIVITY_TYPE_DELETE_SUB_ORGANIZATION' \
             || activity.type == 'ACTIVITY_TYPE_DELETE_USERS'";
        let users = vec![sync_user(SYNC_USER_ID)];
        let policies = vec![user_policy(SYNC_USER_ID, legacy_condition)];

        let actions = plan(&users, &policies);

        assert_eq!(actions.len(), 1);
        let PolicyAction::Update { intent, .. } = &actions[0] else {
            panic!("expected Update, got a different action");
        };
        assert_eq!(
            intent.policy_id,
            "policy-11111111-2222-3333-4444-555555555555"
        );
        assert_eq!(
            intent.policy_name.as_deref(),
            Some("sync_factor_policy_11111111-2222-3333-4444-555555555555")
        );
        assert_eq!(intent.policy_effect, Some(Effect::Allow));
        assert_eq!(
            intent.policy_condition.as_deref(),
            Some(
                "activity.action == 'DELETE' && (activity.resource == 'CREDENTIAL' \
                 || activity.resource == 'PRIVATE_KEY' || activity.resource == \
                 'ORGANIZATION' || activity.resource == 'USER')"
            )
        );
        assert_eq!(
            intent.policy_consensus.as_deref(),
            Some(
                "approvers.any(user, user.id == \
                 '11111111-2222-3333-4444-555555555555')"
            )
        );
    }

    #[test]
    fn skips_when_policy_is_already_correct() {
        let users = vec![sync_user(SYNC_USER_ID)];
        let policies = vec![user_policy(SYNC_USER_ID, SYNC_FACTOR_POLICY_CONDITION)];

        assert!(plan(&users, &policies).is_empty());
    }

    #[test]
    fn flips_effect_when_policy_denies() {
        let users = vec![sync_user(SYNC_USER_ID)];
        let mut denying = user_policy(SYNC_USER_ID, SYNC_FACTOR_POLICY_CONDITION);
        denying.effect = Effect::Deny;

        let actions = plan(&users, &[denying]);

        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], PolicyAction::Update { .. }));
    }

    #[test]
    fn ignores_main_and_break_glass_users() {
        let users = vec![
            user_from_json(json!({
                "userId": "22222222-2222-2222-2222-222222222222",
                "userName": AUTH_USER_MAIN_USERNAME,
            })),
            user_from_json(json!({
                "userId": "33333333-3333-3333-3333-333333333333",
                "userName": BREAK_GLASS_USERNAME,
            })),
        ];

        assert!(plan(&users, &[]).is_empty());
    }

    #[test]
    fn ignores_unexpected_user() {
        let users = vec![user_from_json(json!({
            "userId": "44444444-4444-4444-4444-444444444444",
            "userName": "some_unexpected_user",
        }))];

        assert!(plan(&users, &[]).is_empty());
    }

    /// A malformed user id must never be embedded in a policy: injecting a quote
    /// could break out of the consensus string literal.
    #[test]
    fn skips_sync_factor_with_malformed_user_id() {
        let users = vec![sync_user("bad' || approvers.any(user, true) || 'x")];

        assert!(plan(&users, &[]).is_empty());
    }

    #[test]
    fn matches_only_the_users_own_policy() {
        // A correct policy exists, but it is bound to a *different* (existing) user,
        // so it neither satisfies SYNC_USER_ID nor counts as stale.
        let other = "99999999-9999-9999-9999-999999999999";
        let users = vec![sync_user(SYNC_USER_ID), sync_user(other)];
        let policies = vec![user_policy(other, SYNC_FACTOR_POLICY_CONDITION)];

        let actions = plan(&users, &policies);

        // Only SYNC_USER_ID needs a policy; `other`'s is correct and not stale.
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], PolicyAction::Create { .. }));
    }

    #[test]
    fn plans_each_sync_factor_independently() {
        let second = "66666666-7777-8888-9999-000000000000";
        let users = vec![sync_user(SYNC_USER_ID), sync_user(second)];
        // Only the first user already has a correct policy.
        let policies = vec![user_policy(SYNC_USER_ID, SYNC_FACTOR_POLICY_CONDITION)];

        let actions = plan(&users, &policies);

        assert_eq!(actions.len(), 1);
        let PolicyAction::Create { intent, .. } = &actions[0] else {
            panic!("expected Create for the second sync factor");
        };
        assert_eq!(intent.consensus, sync_factor_policy_consensus(second));
    }

    #[test]
    fn prunes_policy_bound_to_absent_user() {
        // A live sync factor with a correct policy, plus a leftover policy bound to
        // a user id no longer in the org.
        let gone = "99999999-9999-9999-9999-999999999999";
        let users = vec![sync_user(SYNC_USER_ID)];
        let policies = vec![
            user_policy(SYNC_USER_ID, SYNC_FACTOR_POLICY_CONDITION),
            user_policy(gone, SYNC_FACTOR_POLICY_CONDITION),
        ];

        let actions = plan(&users, &policies);

        assert_eq!(actions.len(), 1);
        let PolicyAction::Delete { policy_id } = &actions[0] else {
            panic!("expected Delete, got a different action");
        };
        assert_eq!(policy_id, &format!("policy-{gone}"));
    }

    #[test]
    fn keeps_policy_bound_to_existing_non_sync_user() {
        // A policy bound to the main user (which exists) is not pruned, even though
        // main is not a sync factor.
        let main_id = "22222222-2222-2222-2222-222222222222";
        let users = vec![user_from_json(json!({
            "userId": main_id,
            "userName": AUTH_USER_MAIN_USERNAME,
        }))];
        let policies = vec![user_policy(main_id, SYNC_FACTOR_POLICY_CONDITION)];

        assert!(plan(&users, &policies).is_empty());
    }

    /// A policy carrying an arbitrary `consensus`, for exercising consensus
    /// matching in isolation (condition/effect are irrelevant to the match).
    fn policy_with_consensus(policy_id: &str, consensus: &str) -> Policy {
        policy_from_json(json!({
            "policyId": policy_id,
            "policyName": "some-policy",
            "effect": "EFFECT_ALLOW",
            "notes": "",
            "consensus": consensus,
            "condition": "activity.action == 'DELETE'",
        }))
    }

    /// The migration only treats a policy as a sync factor's when its consensus is
    /// *exactly* `approvers.any(user, user.id == '<id>')`. Every other shape in the
    /// Turnkey policy language must be ignored, so we never update or prune an
    /// unrelated policy. See <https://docs.turnkey.com/features/policies/language>.
    #[test]
    fn policy_bound_user_matches_only_the_exact_single_user_consensus() {
        let ours = policy_with_consensus(
            "p",
            "approvers.any(user, user.id == '4b894565-fa11-42fc-b813-5bf4ea3d53f9')",
        );
        assert_eq!(
            policy_bound_user(&ours),
            Some("4b894565-fa11-42fc-b813-5bf4ea3d53f9")
        );

        for consensus in [
            // Tag-based membership.
            "approvers.any(user, user.tags.contains('some-tag'))",
            // Threshold / count.
            "approvers.count() >= 2",
            // Two users OR-ed (opens with our prefix but is not a lone user).
            "approvers.any(user, user.id == 'a') || approvers.any(user, user.id == 'b')",
            // Credential-based.
            "credentials.any(credential, credential.type == 'CREDENTIAL_TYPE_API_KEY')",
            // Negation of our form.
            "!approvers.any(user, user.id == 'a')",
            // Our form with an extra trailing clause.
            "approvers.any(user, user.id == 'a') && approvers.count() >= 1",
            // Filter rather than any.
            "approvers.filter(user, user.id == 'a').count() >= 1",
        ] {
            assert_eq!(
                policy_bound_user(&policy_with_consensus("p", consensus)),
                None,
                "unexpectedly matched consensus: {consensus}"
            );
        }
    }

    #[test]
    fn does_not_touch_policy_with_unrecognized_consensus() {
        // A live sync factor (already correct) plus a policy whose consensus is not
        // one of ours. The latter must be neither updated nor pruned.
        let users = vec![sync_user(SYNC_USER_ID)];
        let policies = vec![
            user_policy(SYNC_USER_ID, SYNC_FACTOR_POLICY_CONDITION),
            policy_with_consensus(
                "p-tag",
                "approvers.any(user, user.tags.contains('some-tag'))",
            ),
        ];

        assert!(plan(&users, &policies).is_empty());
    }
}
