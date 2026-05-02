// @generated automatically by Diesel CLI.

diesel::table! {
    contract_signature_slots (id) {
        id -> Nullable<Integer>,
        contract_id -> Text,
        slot_name -> Nullable<Text>,
        slot_order -> Integer,
        is_filled -> Bool,
    }
}

diesel::table! {
    contract_signatures (id) {
        id -> Integer,
        contract_id -> Text,
        verification_code -> Text,
        signature_hash -> Text,
        public_key -> Text,
        signed_at -> Text,
        signer_name -> Nullable<Text>,
        client_ip -> Nullable<Text>,
        user_agent -> Nullable<Text>,
        content_hash -> Text,
        slot_id -> Nullable<Integer>,
    }
}

diesel::table! {
    contracts (id) {
        id -> Nullable<Text>,
        customer_id -> Text,
        contract_type -> Text,
        title -> Text,
        content -> Text,
        created_at -> Text,
        expires_at -> Nullable<Text>,
        status -> Text,
        required_signatures -> Integer,
        completed_signatures -> Integer,
        final_hash -> Nullable<Text>,
    }
}

diesel::table! {
    customer (id) {
        id -> Nullable<Text>,
        name -> Text,
        address -> Nullable<Text>,
        currency -> Nullable<Text>,
        is_active -> Nullable<Bool>,
    }
}

diesel::table! {
    invoices (id) {
        id -> Nullable<Text>,
        serial_no -> Integer,
        customer_id -> Text,
        due_date -> Nullable<Text>,
        status -> Nullable<Text>,
        payment_made -> Nullable<Text>,
        line_charges -> Nullable<Text>,
        after_line_items -> Nullable<Text>,
        memo -> Nullable<Text>,
    }
}

diesel::table! {
    jwt_tokens (id) {
        id -> Integer,
        user_id -> Integer,
        token_hash -> Text,
        expires_at -> Text,
        created_at -> Text,
        revoked -> Bool,
    }
}

diesel::table! {
    refresh_tokens (id) {
        id -> Integer,
        user_id -> Integer,
        token_hash -> Text,
        expires_at -> Text,
        created_at -> Text,
        revoked -> Bool,
    }
}

diesel::table! {
    user (id) {
        id -> Integer,
        name -> Text,
        email -> Text,
        address -> Text,
        tax_id -> Text,
        password -> Text,
    }
}

diesel::joinable!(contract_signature_slots -> contracts (contract_id));
diesel::joinable!(contract_signatures -> contracts (contract_id));
diesel::joinable!(contracts -> customer (customer_id));
diesel::joinable!(invoices -> customer (customer_id));
diesel::joinable!(jwt_tokens -> user (user_id));
diesel::joinable!(refresh_tokens -> user (user_id));

diesel::allow_tables_to_appear_in_same_query!(
    contract_signature_slots,
    contract_signatures,
    contracts,
    customer,
    invoices,
    jwt_tokens,
    refresh_tokens,
    user,
);
