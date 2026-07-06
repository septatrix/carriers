//! Tests for the sqlx-backed store and membership provider.

use std::sync::Arc;

use carriers_core::member::{MemberProvider, SqliteMemberProvider};
use carriers_core::store::Store;

#[tokio::test]
async fn membership_add_remove_query() {
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    let provider = SqliteMemberProvider::new(store);

    assert!(!provider
        .is_member("dev", "alice@example.com")
        .await
        .unwrap());

    provider.add("dev", "Alice@Example.com").await.unwrap();
    provider.add("dev", "bob@example.net").await.unwrap();
    // Idempotent + case-insensitive.
    provider.add("dev", "alice@example.com").await.unwrap();

    assert!(provider
        .is_member("dev", "alice@example.com")
        .await
        .unwrap());
    assert_eq!(
        provider.recipients("dev").await.unwrap(),
        vec![
            "alice@example.com".to_string(),
            "bob@example.net".to_string()
        ]
    );

    provider.remove("dev", "alice@example.com").await.unwrap();
    assert!(!provider
        .is_member("dev", "alice@example.com")
        .await
        .unwrap());
    assert_eq!(
        provider.recipients("dev").await.unwrap(),
        vec!["bob@example.net".to_string()]
    );
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
