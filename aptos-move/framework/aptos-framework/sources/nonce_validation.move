module aptos_framework::nonce_validation {
    use aptos_std::table::{Self, Table};
    use aptos_std::timestamp;
    use aptos_std::big_ordered_map::{Self, BigOrderedMap};
    use aptos_std::aptos_hash::sip_hash_from_value;
    use aptos_std::error;
    friend aptos_framework::genesis;
    friend aptos_framework::transaction_validation;

    const NUM_BUCKETS: u64 = 50000;

    // Max expiration time for orderless txns.
    // We will advertise to the community that max expiration time for orderless txns is 60 seconds.
    // Adding a 5 second slack here as the client's time and the blockchain's time may drift.
    const MAX_EXPIRATION_TIME: u64 = 65;

    // Each time we check if an (address, nonce) pair can be inserted into nonce history,
    // we try to initially garbage collect expired nonces in the bucket. This is a limit on the number of nonces
    // we try to garbage collect in a single call.
    const MAX_ENTRIES_GARBAGE_COLLECTED_PER_CALL: u64 = 5;

    // Nonce history resource does not exist.
    const E_NONCE_HISTORY_DOES_NOT_EXIST: u64 = 1001;

    // An orderless transaction is a transaction that doesn't have a sequence number.
    // Orderless transactions instead contain a nonce to prevent replay attacks.
    // If the incoming transaction has the same (address, nonce) pair as a previous unexpired transaction, it is rejected.
    // The nonce history is used to store the list of (address, nonce, txn expiration time) values of all unexpired transactions.
    // The nonce history is used in the transaction validation process to check if the incoming transaction is valid.
    struct NonceHistory has key {
        // Key = sip_hash(NonceKey) % NUM_BUCKETS
        // Value = Bucket
        nonce_table: Table<u64, Bucket>,
        // Used to facilitate prefill the nonce_table with empty buckets
        // one by one using `add_nonce_bucket` method.
        // This is the next_key to prefill with an empty bucket
        next_key: u64,
    }

    // The bucket stores (address, nonce, txn expiration time) tuples.
    // All the entries in the bucket contain the same hash(address, nonce) % NUM_BUCKETS.
    // The first big ordered map in the bucket stores (expiration time, address, nonce) -> true.
    // The second big ordered map in the bucket stores (address, nonce) -> expiration time.
    // Both the maps store the same data, just in a different format.
    // As the key in the first big ordered map starts with expiration time, it's easy to figure out which
    // entries have expired at the current time. The first big ordered map helps with easy garbage collection.
    // The second big ordered map helps with checking if the given (address, nonce) pair exists in the bucket.
    struct Bucket has store {
        // The first big ordered map in the bucket stores (expiration time, address, nonce) -> true.
        nonces_ordered_by_exp_time: BigOrderedMap<NonceKeyWithExpTime, bool>,
        // The second big ordered map in the bucket stores (address, nonce) -> expiration time.
        nonce_to_exp_time_map: BigOrderedMap<NonceKey, u64>,
    }

    struct NonceKeyWithExpTime has copy, drop, store {
        txn_expiration_time: u64,
        sender_address: address,
        nonce: u64,
    }

    struct NonceKey has copy, drop, store {
        sender_address: address,
        nonce: u64,
    }

    public(friend) fun initialize(aptos_framework: &signer) {
        initialize_nonce_table(aptos_framework);
    }

    public entry fun initialize_nonce_table(aptos_framework: &signer) {
        if (!exists<NonceHistory>(@aptos_framework)) {
            let table = table::new();
            let nonce_history = NonceHistory {
                nonce_table: table,
                next_key: 0,
            };
            move_to<NonceHistory>(aptos_framework, nonce_history);
        };
    }

    fun empty_bucket(): Bucket {
        let bucket = Bucket {
            nonces_ordered_by_exp_time: big_ordered_map::new_with_config(0, 0, true),
            nonce_to_exp_time_map: big_ordered_map::new_with_config(0, 0, true),
        };

        // Initiating big ordered maps with 5 pre-allocated storage slots.
        // (expiration time, address, nonce) is together 48 bytes.
        // A 4 KB storage slot can store 80+ such tuples.
        // The 5 slots should be more than enough for the current use case.
        bucket.nonces_ordered_by_exp_time.allocate_spare_slots(5);
        bucket.nonce_to_exp_time_map.allocate_spare_slots(5);
        bucket
    }

    // This method is used to prefill the nonce_table with empty buckets one by one.
    public entry fun add_nonce_buckets(count: u64) acquires NonceHistory {
        assert!(exists<NonceHistory>(@aptos_framework), error::invalid_state(E_NONCE_HISTORY_DOES_NOT_EXIST));
        let nonce_history = &mut NonceHistory[@aptos_framework];
        for (i in 0..count) {
            if (nonce_history.next_key <= NUM_BUCKETS) {
                if (!nonce_history.nonce_table.contains(nonce_history.next_key)) {
                    nonce_history.nonce_table.add(
                        nonce_history.next_key,
                        empty_bucket()
                    );
                };
                nonce_history.next_key = nonce_history.next_key + 1;
            }
        }
    }

    // Returns true if the input (address, nonce) pair doesn't exist in the nonce history, and inserted into nonce history successfully.
    // Returns false if the input (address, nonce) pair already exists in the nonce history.
    public(friend) fun check_and_insert_nonce(
        sender_address: address,
        nonce: u64,
        txn_expiration_time: u64,
    ): bool acquires NonceHistory {
        assert!(exists<NonceHistory>(@aptos_framework), error::invalid_state(E_NONCE_HISTORY_DOES_NOT_EXIST));
        let nonce_history = &mut NonceHistory[@aptos_framework];
        let nonce_key = NonceKey {
            sender_address,
            nonce,
        };
        let nonce_key_with_exp_time = NonceKeyWithExpTime {
            txn_expiration_time,
            sender_address,
            nonce,
        };
        let bucket_index = sip_hash_from_value(&nonce_key) % NUM_BUCKETS;
        let current_time = timestamp::now_seconds();
        if (!nonce_history.nonce_table.contains(bucket_index)) {
            nonce_history.nonce_table.add(
                bucket_index,
                empty_bucket()
            );
        };
        let bucket = table::borrow_mut(&mut nonce_history.nonce_table, bucket_index);

        let existing_exp_time = bucket.nonce_to_exp_time_map.borrow_optional(&nonce_key);
        if (existing_exp_time.is_some()) {
            let existing_exp_time = existing_exp_time.extract();

            // If the existing (address, nonce) pair has not expired, return false.
            if (existing_exp_time >= current_time) {
                return false;
            };

            // If the existing (address, nonce) pair has expired, garbage collect it.
            bucket.nonce_to_exp_time_map.remove(&nonce_key);
            bucket.nonces_ordered_by_exp_time.remove(&NonceKeyWithExpTime {
                txn_expiration_time: existing_exp_time,
                sender_address,
                nonce,
            });
        };

        // Garbage collect upto MAX_ENTRIES_GARBAGE_COLLECTED_PER_CALL expired nonces in the bucket.
        let i = 0;
        while (i < MAX_ENTRIES_GARBAGE_COLLECTED_PER_CALL) {
            if (!bucket.nonces_ordered_by_exp_time.is_empty()) {
                let (front_k, _) = bucket.nonces_ordered_by_exp_time.borrow_front();
                if (front_k.txn_expiration_time < current_time) {
                    bucket.nonces_ordered_by_exp_time.pop_front();
                    bucket.nonce_to_exp_time_map.remove(&NonceKey {
                        sender_address: front_k.sender_address,
                        nonce: front_k.nonce,
                    });
                } else {
                    break;
                }
            } else {
                break;
            };
            i = i + 1;
        };

        // Insert the (address, nonce) pair in the bucket.
        bucket.nonces_ordered_by_exp_time.add(nonce_key_with_exp_time, true);
        bucket.nonce_to_exp_time_map.add(nonce_key, txn_expiration_time);
        true
    }

    // Returns true if the input (address, nonce) pair doesn't exist in the nonce history.
    // Returns false if the input (address, nonce) pair already exists in the nonce history.
    public(friend) fun check_nonce(
        sender_address: address,
        nonce: u64,
    ): bool acquires NonceHistory {
        assert!(exists<NonceHistory>(@aptos_framework), error::invalid_state(E_NONCE_HISTORY_DOES_NOT_EXIST));
        let nonce_key = NonceKey {
            sender_address,
            nonce,
        };
        let bucket_index = sip_hash_from_value(&nonce_key) % NUM_BUCKETS;
        let nonce_history = &NonceHistory[@aptos_framework];
        if (nonce_history.nonce_table.contains(bucket_index)) {
            let bucket = table::borrow(&nonce_history.nonce_table, bucket_index);
            let existing_exp_time = bucket.nonce_to_exp_time_map.borrow_optional(&nonce_key);
            if (existing_exp_time.is_some()) {
                let existing_exp_time = existing_exp_time.extract();
                if (existing_exp_time >= timestamp::now_seconds()) {
                    return false;
                };
            };
        };
        true
    }

    #[test(fx = @aptos_framework)]
    public entry fun nonce_history_test(fx: signer) acquires NonceHistory {
        initialize_nonce_table(&fx);
        timestamp::set_time_has_started_for_testing(&fx);
        let begin_time = timestamp::now_seconds();

        assert!(check_and_insert_nonce(@0x5, 1234, begin_time + 50));
        assert!(!check_and_insert_nonce(@0x5, 1234, begin_time + 51));
        assert!(!check_nonce(@0x5, 1234));
        assert!(check_nonce(@0x5, 1235));

        timestamp::fast_forward_seconds(30);
        assert!(!check_and_insert_nonce(@0x5, 1234, begin_time + 85));
        assert!(check_and_insert_nonce(@0x5, 1235, begin_time + 85));

        timestamp::fast_forward_seconds(21);
        // (@0x5, 1234) has expired.
        // (@0x5, 1235) is still valid.
        assert!(check_nonce(@0x5, 1234));
        assert!(!check_nonce(@0x5, 1235));

        // Reinsert (0x5, 1234) after it has expired should work.
        assert!(check_and_insert_nonce(@0x5, 1234, begin_time + 100));
        assert!(!check_and_insert_nonce(@0x5, 1235, begin_time + 100));
    }
}
