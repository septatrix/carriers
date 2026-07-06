//! Tests for the sqlx-backed store, membership roles, and the moderation queue.

use std::sync::Arc;

use carriers_core::member::{MemberProvider, SqliteMemberProvider};
use carriers_core::store::Store;

#[tokio::test]
async fn subscribers_and_posting_only_members() {
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    let provider = SqliteMemberProvider::new(store);

    // A subscriber (receives + is a member) and a posting-only member (member, not subscriber).
    provider
        .add("dev", "Alice@Example.com", true)
        .await
        .unwrap();
    provider.add("dev", "bot@example.net", false).await.unwrap();

    // Both are members; only alice is a subscriber / recipient.
    assert!(provider
        .is_member("dev", "alice@example.com")
        .await
        .unwrap());
    assert!(provider.is_member("dev", "bot@example.net").await.unwrap());
    assert!(provider
        .is_subscriber("dev", "alice@example.com")
        .await
        .unwrap());
    assert!(!provider
        .is_subscriber("dev", "bot@example.net")
        .await
        .unwrap());
    assert_eq!(
        provider.recipients("dev").await.unwrap(),
        vec!["alice@example.com".to_string()]
    );

    // Re-adding with a different role updates it (idempotent upsert).
    provider.add("dev", "bot@example.net", true).await.unwrap();
    assert!(provider
        .is_subscriber("dev", "bot@example.net")
        .await
        .unwrap());

    provider.remove("dev", "alice@example.com").await.unwrap();
    assert!(!provider
        .is_member("dev", "alice@example.com")
        .await
        .unwrap());
}

#[tokio::test]
async fn record_message_deduplicates() {
    let store = Store::open_in_memory().await.unwrap();

    assert!(
        store.record_message("dev", "<a@x>").await.unwrap(),
        "first sighting is new"
    );
    assert!(
        !store.record_message("dev", "<a@x>").await.unwrap(),
        "second is a duplicate"
    );
    // Same id, different list is independent.
    assert!(store.record_message("ops", "<a@x>").await.unwrap());
}

#[tokio::test]
async fn bounces_disable_delivery_then_enable_restores_it() {
    let store = Store::open_in_memory().await.unwrap();
    store
        .add_member("dev", "alice@example.com", true)
        .await
        .unwrap();

    // threshold 5.0, hard weight 3.0: one hard bounce is below threshold, two crosses it.
    assert_eq!(
        store
            .record_bounce("dev", "alice@example.com", 3.0, 5.0)
            .await
            .unwrap(),
        Some(false),
        "first hard bounce does not yet disable"
    );
    assert!(
        store
            .subscribers("dev")
            .await
            .unwrap()
            .contains(&"alice@example.com".to_string()),
        "still a deliverable recipient"
    );

    assert_eq!(
        store
            .record_bounce("dev", "alice@example.com", 3.0, 5.0)
            .await
            .unwrap(),
        Some(true),
        "second hard bounce crosses the threshold and disables delivery"
    );
    assert!(
        store.subscribers("dev").await.unwrap().is_empty(),
        "bounce-disabled address is no longer a delivery recipient"
    );

    // A bounce for a non-member is a no-op.
    assert_eq!(
        store
            .record_bounce("dev", "stranger@nowhere.example", 3.0, 5.0)
            .await
            .unwrap(),
        None
    );

    // Re-enabling clears the score and restores delivery.
    assert!(store
        .enable_member("dev", "alice@example.com")
        .await
        .unwrap());
    assert_eq!(
        store.subscribers("dev").await.unwrap(),
        vec!["alice@example.com".to_string()]
    );
    let members = store.all_members("dev").await.unwrap();
    assert_eq!(members[0].bounce_score, 0.0);
    assert!(!members[0].bounce_disabled);
}

#[tokio::test]
async fn moderation_queue_enqueue_get_delete() {
    let store = Store::open_in_memory().await.unwrap();

    let id = store
        .enqueue_held(
            "dev",
            "sender@evil.example",
            "helo.example",
            "203.0.113.7",
            Some("mallory@evil.example"),
            Some("please moderate me"),
            b"From: mallory@evil.example\r\n\r\nbody",
        )
        .await
        .unwrap();

    let held = store.held_messages(Some("dev")).await.unwrap();
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].id, id);
    assert_eq!(held[0].subject.as_deref(), Some("please moderate me"));

    let full = store.get_held(id).await.unwrap().unwrap();
    assert_eq!(full.mail_from, "sender@evil.example");
    assert_eq!(full.remote_ip, "203.0.113.7");
    assert!(full.raw.starts_with(b"From: mallory"));

    assert!(store.delete_held(id).await.unwrap());
    assert!(store.get_held(id).await.unwrap().is_none());
    assert!(store.held_messages(None).await.unwrap().is_empty());
}
