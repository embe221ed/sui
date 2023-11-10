(function() {var implementors = {
"sui_indexer":[["impl&lt;__DB: Backend&gt; QueryableByName&lt;__DB&gt; for <a class=\"struct\" href=\"sui_indexer/models/network_metrics/struct.DBMoveCallMetrics.html\" title=\"struct sui_indexer::models::network_metrics::DBMoveCallMetrics\">DBMoveCallMetrics</a><span class=\"where fmt-newline\">where\n    <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.i64.html\">i64</a>: FromSql&lt;BigInt, __DB&gt;,\n    <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/string/struct.String.html\" title=\"struct alloc::string::String\">String</a>: FromSql&lt;Text, __DB&gt;,</span>"],["impl&lt;__DB: Backend&gt; QueryableByName&lt;__DB&gt; for <a class=\"struct\" href=\"sui_indexer/models/network_metrics/struct.DBNetworkMetrics.html\" title=\"struct sui_indexer::models::network_metrics::DBNetworkMetrics\">DBNetworkMetrics</a><span class=\"where fmt-newline\">where\n    <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.f64.html\">f64</a>: FromSql&lt;Double, __DB&gt;,\n    <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.i64.html\">i64</a>: FromSql&lt;BigInt, __DB&gt;,</span>"],["impl&lt;__DB: Backend&gt; QueryableByName&lt;__DB&gt; for <a class=\"struct\" href=\"sui_indexer/models/checkpoint_metrics/struct.Tps.html\" title=\"struct sui_indexer::models::checkpoint_metrics::Tps\">Tps</a><span class=\"where fmt-newline\">where\n    <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.f64.html\">f64</a>: FromSql&lt;Float8, __DB&gt;,</span>"],["impl&lt;__DB: Backend&gt; QueryableByName&lt;__DB&gt; for <a class=\"struct\" href=\"sui_indexer/models_v2/address_metrics/struct.StoredAddressMetrics.html\" title=\"struct sui_indexer::models_v2::address_metrics::StoredAddressMetrics\">StoredAddressMetrics</a><span class=\"where fmt-newline\">where\n    <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.i64.html\">i64</a>: FromSql&lt;BigInt, __DB&gt;,</span>"],["impl&lt;__DB: Backend&gt; QueryableByName&lt;__DB&gt; for <a class=\"struct\" href=\"sui_indexer/models/objects/struct.Object.html\" title=\"struct sui_indexer::models::objects::Object\">Object</a><span class=\"where fmt-newline\">where\n    <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.i64.html\">i64</a>: FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema/objects/columns/struct.epoch.html\" title=\"struct sui_indexer::schema::objects::columns::epoch\">epoch</a>&gt;, __DB&gt; + FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema/objects/columns/struct.checkpoint.html\" title=\"struct sui_indexer::schema::objects::columns::checkpoint\">checkpoint</a>&gt;, __DB&gt; + FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema/objects/columns/struct.version.html\" title=\"struct sui_indexer::schema::objects::columns::version\">version</a>&gt;, __DB&gt; + FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema/objects/columns/struct.storage_rebate.html\" title=\"struct sui_indexer::schema::objects::columns::storage_rebate\">storage_rebate</a>&gt;, __DB&gt;,\n    <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/string/struct.String.html\" title=\"struct alloc::string::String\">String</a>: FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema/objects/columns/struct.object_id.html\" title=\"struct sui_indexer::schema::objects::columns::object_id\">object_id</a>&gt;, __DB&gt; + FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema/objects/columns/struct.object_digest.html\" title=\"struct sui_indexer::schema::objects::columns::object_digest\">object_digest</a>&gt;, __DB&gt; + FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema/objects/columns/struct.previous_transaction.html\" title=\"struct sui_indexer::schema::objects::columns::previous_transaction\">previous_transaction</a>&gt;, __DB&gt; + FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema/objects/columns/struct.object_type.html\" title=\"struct sui_indexer::schema::objects::columns::object_type\">object_type</a>&gt;, __DB&gt;,\n    <a class=\"enum\" href=\"sui_indexer/models/owners/enum.OwnerType.html\" title=\"enum sui_indexer::models::owners::OwnerType\">OwnerType</a>: FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema/objects/columns/struct.owner_type.html\" title=\"struct sui_indexer::schema::objects::columns::owner_type\">owner_type</a>&gt;, __DB&gt;,\n    <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/option/enum.Option.html\" title=\"enum core::option::Option\">Option</a>&lt;<a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/string/struct.String.html\" title=\"struct alloc::string::String\">String</a>&gt;: FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema/objects/columns/struct.owner_address.html\" title=\"struct sui_indexer::schema::objects::columns::owner_address\">owner_address</a>&gt;, __DB&gt;,\n    <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/option/enum.Option.html\" title=\"enum core::option::Option\">Option</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.i64.html\">i64</a>&gt;: FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema/objects/columns/struct.initial_shared_version.html\" title=\"struct sui_indexer::schema::objects::columns::initial_shared_version\">initial_shared_version</a>&gt;, __DB&gt;,\n    <a class=\"enum\" href=\"sui_indexer/models/objects/enum.ObjectStatus.html\" title=\"enum sui_indexer::models::objects::ObjectStatus\">ObjectStatus</a>: FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema/objects/columns/struct.object_status.html\" title=\"struct sui_indexer::schema::objects::columns::object_status\">object_status</a>&gt;, __DB&gt;,\n    <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.bool.html\">bool</a>: FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema/objects/columns/struct.has_public_transfer.html\" title=\"struct sui_indexer::schema::objects::columns::has_public_transfer\">has_public_transfer</a>&gt;, __DB&gt;,\n    <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;<a class=\"struct\" href=\"sui_indexer/models/objects/struct.NamedBcsBytes.html\" title=\"struct sui_indexer::models::objects::NamedBcsBytes\">NamedBcsBytes</a>&gt;: FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema/objects/columns/struct.bcs.html\" title=\"struct sui_indexer::schema::objects::columns::bcs\">bcs</a>&gt;, __DB&gt;,</span>"],["impl&lt;__DB: Backend&gt; QueryableByName&lt;__DB&gt; for <a class=\"struct\" href=\"sui_indexer/models_v2/objects/struct.StoredObject.html\" title=\"struct sui_indexer::models_v2::objects::StoredObject\">StoredObject</a><span class=\"where fmt-newline\">where\n    <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u8.html\">u8</a>&gt;: FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema_v2/objects/columns/struct.object_id.html\" title=\"struct sui_indexer::schema_v2::objects::columns::object_id\">object_id</a>&gt;, __DB&gt; + FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema_v2/objects/columns/struct.object_digest.html\" title=\"struct sui_indexer::schema_v2::objects::columns::object_digest\">object_digest</a>&gt;, __DB&gt; + FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema_v2/objects/columns/struct.serialized_object.html\" title=\"struct sui_indexer::schema_v2::objects::columns::serialized_object\">serialized_object</a>&gt;, __DB&gt;,\n    <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.i64.html\">i64</a>: FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema_v2/objects/columns/struct.object_version.html\" title=\"struct sui_indexer::schema_v2::objects::columns::object_version\">object_version</a>&gt;, __DB&gt; + FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema_v2/objects/columns/struct.checkpoint_sequence_number.html\" title=\"struct sui_indexer::schema_v2::objects::columns::checkpoint_sequence_number\">checkpoint_sequence_number</a>&gt;, __DB&gt;,\n    <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.i16.html\">i16</a>: FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema_v2/objects/columns/struct.owner_type.html\" title=\"struct sui_indexer::schema_v2::objects::columns::owner_type\">owner_type</a>&gt;, __DB&gt;,\n    <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/option/enum.Option.html\" title=\"enum core::option::Option\">Option</a>&lt;<a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u8.html\">u8</a>&gt;&gt;: FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema_v2/objects/columns/struct.owner_id.html\" title=\"struct sui_indexer::schema_v2::objects::columns::owner_id\">owner_id</a>&gt;, __DB&gt; + FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema_v2/objects/columns/struct.df_name.html\" title=\"struct sui_indexer::schema_v2::objects::columns::df_name\">df_name</a>&gt;, __DB&gt; + FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema_v2/objects/columns/struct.df_object_id.html\" title=\"struct sui_indexer::schema_v2::objects::columns::df_object_id\">df_object_id</a>&gt;, __DB&gt;,\n    <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/option/enum.Option.html\" title=\"enum core::option::Option\">Option</a>&lt;<a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/string/struct.String.html\" title=\"struct alloc::string::String\">String</a>&gt;: FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema_v2/objects/columns/struct.object_type.html\" title=\"struct sui_indexer::schema_v2::objects::columns::object_type\">object_type</a>&gt;, __DB&gt; + FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema_v2/objects/columns/struct.coin_type.html\" title=\"struct sui_indexer::schema_v2::objects::columns::coin_type\">coin_type</a>&gt;, __DB&gt; + FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema_v2/objects/columns/struct.df_object_type.html\" title=\"struct sui_indexer::schema_v2::objects::columns::df_object_type\">df_object_type</a>&gt;, __DB&gt;,\n    <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/option/enum.Option.html\" title=\"enum core::option::Option\">Option</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.i64.html\">i64</a>&gt;: FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema_v2/objects/columns/struct.coin_balance.html\" title=\"struct sui_indexer::schema_v2::objects::columns::coin_balance\">coin_balance</a>&gt;, __DB&gt;,\n    <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/option/enum.Option.html\" title=\"enum core::option::Option\">Option</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.i16.html\">i16</a>&gt;: FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema_v2/objects/columns/struct.df_kind.html\" title=\"struct sui_indexer::schema_v2::objects::columns::df_kind\">df_kind</a>&gt;, __DB&gt;,</span>"],["impl&lt;__DB: Backend&gt; QueryableByName&lt;__DB&gt; for <a class=\"struct\" href=\"sui_indexer/models_v2/move_call_metrics/struct.QueriedMoveMetrics.html\" title=\"struct sui_indexer::models_v2::move_call_metrics::QueriedMoveMetrics\">QueriedMoveMetrics</a><span class=\"where fmt-newline\">where\n    <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.i64.html\">i64</a>: FromSql&lt;BigInt, __DB&gt;,\n    <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u8.html\">u8</a>&gt;: FromSql&lt;Binary, __DB&gt;,\n    <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/string/struct.String.html\" title=\"struct alloc::string::String\">String</a>: FromSql&lt;Text, __DB&gt;,</span>"],["impl&lt;__DB: Backend&gt; QueryableByName&lt;__DB&gt; for <a class=\"struct\" href=\"sui_indexer/models_v2/objects/struct.StoredDeletedObject.html\" title=\"struct sui_indexer::models_v2::objects::StoredDeletedObject\">StoredDeletedObject</a><span class=\"where fmt-newline\">where\n    <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u8.html\">u8</a>&gt;: FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema_v2/objects/columns/struct.object_id.html\" title=\"struct sui_indexer::schema_v2::objects::columns::object_id\">object_id</a>&gt;, __DB&gt;,</span>"],["impl&lt;__DB: Backend&gt; QueryableByName&lt;__DB&gt; for <a class=\"struct\" href=\"sui_indexer/models/addresses/struct.DBAddressStats.html\" title=\"struct sui_indexer::models::addresses::DBAddressStats\">DBAddressStats</a><span class=\"where fmt-newline\">where\n    <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.i64.html\">i64</a>: FromSql&lt;BigInt, __DB&gt;,</span>"],["impl&lt;__DB: Backend&gt; QueryableByName&lt;__DB&gt; for <a class=\"struct\" href=\"sui_indexer/models_v2/tx_indices/struct.TxDigest.html\" title=\"struct sui_indexer::models_v2::tx_indices::TxDigest\">TxDigest</a><span class=\"where fmt-newline\">where\n    <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u8.html\">u8</a>&gt;: FromSql&lt;Bytea, __DB&gt;,</span>"],["impl&lt;__DB: Backend&gt; QueryableByName&lt;__DB&gt; for <a class=\"struct\" href=\"sui_indexer/models_v2/objects/struct.CoinBalance.html\" title=\"struct sui_indexer::models_v2::objects::CoinBalance\">CoinBalance</a><span class=\"where fmt-newline\">where\n    <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/string/struct.String.html\" title=\"struct alloc::string::String\">String</a>: FromSql&lt;Text, __DB&gt;,\n    <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.i64.html\">i64</a>: FromSql&lt;BigInt, __DB&gt;,</span>"],["impl&lt;__DB: Backend&gt; QueryableByName&lt;__DB&gt; for <a class=\"struct\" href=\"sui_indexer/models/transaction_index/struct.Recipient.html\" title=\"struct sui_indexer::models::transaction_index::Recipient\">Recipient</a><span class=\"where fmt-newline\">where\n    <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.i64.html\">i64</a>: FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema/recipients/columns/struct.id.html\" title=\"struct sui_indexer::schema::recipients::columns::id\">id</a>&gt;, __DB&gt; + FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema/recipients/columns/struct.checkpoint_sequence_number.html\" title=\"struct sui_indexer::schema::recipients::columns::checkpoint_sequence_number\">checkpoint_sequence_number</a>&gt;, __DB&gt; + FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema/recipients/columns/struct.epoch.html\" title=\"struct sui_indexer::schema::recipients::columns::epoch\">epoch</a>&gt;, __DB&gt;,\n    <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/string/struct.String.html\" title=\"struct alloc::string::String\">String</a>: FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema/recipients/columns/struct.transaction_digest.html\" title=\"struct sui_indexer::schema::recipients::columns::transaction_digest\">transaction_digest</a>&gt;, __DB&gt; + FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema/recipients/columns/struct.sender.html\" title=\"struct sui_indexer::schema::recipients::columns::sender\">sender</a>&gt;, __DB&gt; + FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema/recipients/columns/struct.recipient.html\" title=\"struct sui_indexer::schema::recipients::columns::recipient\">recipient</a>&gt;, __DB&gt;,</span>"],["impl&lt;__DB: Backend&gt; QueryableByName&lt;__DB&gt; for <a class=\"struct\" href=\"sui_indexer/models_v2/network_metrics/struct.RowCountEstimation.html\" title=\"struct sui_indexer::models_v2::network_metrics::RowCountEstimation\">RowCountEstimation</a><span class=\"where fmt-newline\">where\n    <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.i64.html\">i64</a>: FromSql&lt;BigInt, __DB&gt;,</span>"],["impl&lt;__DB: Backend&gt; QueryableByName&lt;__DB&gt; for <a class=\"struct\" href=\"sui_indexer/models_v2/tx_indices/struct.TxSequenceNumber.html\" title=\"struct sui_indexer::models_v2::tx_indices::TxSequenceNumber\">TxSequenceNumber</a><span class=\"where fmt-newline\">where\n    <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.i64.html\">i64</a>: FromSql&lt;BigInt, __DB&gt;,</span>"],["impl&lt;__DB: Backend&gt; QueryableByName&lt;__DB&gt; for <a class=\"struct\" href=\"sui_indexer/models_v2/transactions/struct.StoredTransaction.html\" title=\"struct sui_indexer::models_v2::transactions::StoredTransaction\">StoredTransaction</a><span class=\"where fmt-newline\">where\n    <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.i64.html\">i64</a>: FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema_v2/transactions/columns/struct.tx_sequence_number.html\" title=\"struct sui_indexer::schema_v2::transactions::columns::tx_sequence_number\">tx_sequence_number</a>&gt;, __DB&gt; + FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema_v2/transactions/columns/struct.checkpoint_sequence_number.html\" title=\"struct sui_indexer::schema_v2::transactions::columns::checkpoint_sequence_number\">checkpoint_sequence_number</a>&gt;, __DB&gt; + FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema_v2/transactions/columns/struct.timestamp_ms.html\" title=\"struct sui_indexer::schema_v2::transactions::columns::timestamp_ms\">timestamp_ms</a>&gt;, __DB&gt;,\n    <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u8.html\">u8</a>&gt;: FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema_v2/transactions/columns/struct.transaction_digest.html\" title=\"struct sui_indexer::schema_v2::transactions::columns::transaction_digest\">transaction_digest</a>&gt;, __DB&gt; + FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema_v2/transactions/columns/struct.raw_transaction.html\" title=\"struct sui_indexer::schema_v2::transactions::columns::raw_transaction\">raw_transaction</a>&gt;, __DB&gt; + FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema_v2/transactions/columns/struct.raw_effects.html\" title=\"struct sui_indexer::schema_v2::transactions::columns::raw_effects\">raw_effects</a>&gt;, __DB&gt;,\n    <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;<a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/option/enum.Option.html\" title=\"enum core::option::Option\">Option</a>&lt;<a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u8.html\">u8</a>&gt;&gt;&gt;: FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema_v2/transactions/columns/struct.object_changes.html\" title=\"struct sui_indexer::schema_v2::transactions::columns::object_changes\">object_changes</a>&gt;, __DB&gt; + FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema_v2/transactions/columns/struct.balance_changes.html\" title=\"struct sui_indexer::schema_v2::transactions::columns::balance_changes\">balance_changes</a>&gt;, __DB&gt; + FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema_v2/transactions/columns/struct.events.html\" title=\"struct sui_indexer::schema_v2::transactions::columns::events\">events</a>&gt;, __DB&gt;,\n    <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.i16.html\">i16</a>: FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema_v2/transactions/columns/struct.transaction_kind.html\" title=\"struct sui_indexer::schema_v2::transactions::columns::transaction_kind\">transaction_kind</a>&gt;, __DB&gt; + FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema_v2/transactions/columns/struct.success_command_count.html\" title=\"struct sui_indexer::schema_v2::transactions::columns::success_command_count\">success_command_count</a>&gt;, __DB&gt;,</span>"],["impl&lt;__DB: Backend&gt; QueryableByName&lt;__DB&gt; for <a class=\"struct\" href=\"sui_indexer/models/transactions/struct.Transaction.html\" title=\"struct sui_indexer::models::transactions::Transaction\">Transaction</a><span class=\"where fmt-newline\">where\n    <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.i64.html\">i64</a>: FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema/transactions/columns/struct.id.html\" title=\"struct sui_indexer::schema::transactions::columns::id\">id</a>&gt;, __DB&gt; + FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema/transactions/columns/struct.transaction_count.html\" title=\"struct sui_indexer::schema::transactions::columns::transaction_count\">transaction_count</a>&gt;, __DB&gt; + FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema/transactions/columns/struct.gas_object_sequence.html\" title=\"struct sui_indexer::schema::transactions::columns::gas_object_sequence\">gas_object_sequence</a>&gt;, __DB&gt; + FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema/transactions/columns/struct.gas_budget.html\" title=\"struct sui_indexer::schema::transactions::columns::gas_budget\">gas_budget</a>&gt;, __DB&gt; + FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema/transactions/columns/struct.total_gas_cost.html\" title=\"struct sui_indexer::schema::transactions::columns::total_gas_cost\">total_gas_cost</a>&gt;, __DB&gt; + FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema/transactions/columns/struct.computation_cost.html\" title=\"struct sui_indexer::schema::transactions::columns::computation_cost\">computation_cost</a>&gt;, __DB&gt; + FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema/transactions/columns/struct.storage_cost.html\" title=\"struct sui_indexer::schema::transactions::columns::storage_cost\">storage_cost</a>&gt;, __DB&gt; + FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema/transactions/columns/struct.storage_rebate.html\" title=\"struct sui_indexer::schema::transactions::columns::storage_rebate\">storage_rebate</a>&gt;, __DB&gt; + FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema/transactions/columns/struct.non_refundable_storage_fee.html\" title=\"struct sui_indexer::schema::transactions::columns::non_refundable_storage_fee\">non_refundable_storage_fee</a>&gt;, __DB&gt; + FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema/transactions/columns/struct.gas_price.html\" title=\"struct sui_indexer::schema::transactions::columns::gas_price\">gas_price</a>&gt;, __DB&gt;,\n    <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/string/struct.String.html\" title=\"struct alloc::string::String\">String</a>: FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema/transactions/columns/struct.transaction_digest.html\" title=\"struct sui_indexer::schema::transactions::columns::transaction_digest\">transaction_digest</a>&gt;, __DB&gt; + FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema/transactions/columns/struct.sender.html\" title=\"struct sui_indexer::schema::transactions::columns::sender\">sender</a>&gt;, __DB&gt; + FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema/transactions/columns/struct.transaction_kind.html\" title=\"struct sui_indexer::schema::transactions::columns::transaction_kind\">transaction_kind</a>&gt;, __DB&gt; + FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema/transactions/columns/struct.gas_object_id.html\" title=\"struct sui_indexer::schema::transactions::columns::gas_object_id\">gas_object_id</a>&gt;, __DB&gt; + FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema/transactions/columns/struct.gas_object_digest.html\" title=\"struct sui_indexer::schema::transactions::columns::gas_object_digest\">gas_object_digest</a>&gt;, __DB&gt; + FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema/transactions/columns/struct.transaction_effects_content.html\" title=\"struct sui_indexer::schema::transactions::columns::transaction_effects_content\">transaction_effects_content</a>&gt;, __DB&gt;,\n    <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/option/enum.Option.html\" title=\"enum core::option::Option\">Option</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.i64.html\">i64</a>&gt;: FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema/transactions/columns/struct.checkpoint_sequence_number.html\" title=\"struct sui_indexer::schema::transactions::columns::checkpoint_sequence_number\">checkpoint_sequence_number</a>&gt;, __DB&gt; + FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema/transactions/columns/struct.timestamp_ms.html\" title=\"struct sui_indexer::schema::transactions::columns::timestamp_ms\">timestamp_ms</a>&gt;, __DB&gt;,\n    <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.bool.html\">bool</a>: FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema/transactions/columns/struct.execution_success.html\" title=\"struct sui_indexer::schema::transactions::columns::execution_success\">execution_success</a>&gt;, __DB&gt;,\n    <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u8.html\">u8</a>&gt;: FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema/transactions/columns/struct.raw_transaction.html\" title=\"struct sui_indexer::schema::transactions::columns::raw_transaction\">raw_transaction</a>&gt;, __DB&gt;,\n    <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/option/enum.Option.html\" title=\"enum core::option::Option\">Option</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.bool.html\">bool</a>&gt;: FromSql&lt;SqlTypeOf&lt;<a class=\"struct\" href=\"sui_indexer/schema/transactions/columns/struct.confirmed_local_execution.html\" title=\"struct sui_indexer::schema::transactions::columns::confirmed_local_execution\">confirmed_local_execution</a>&gt;, __DB&gt;,</span>"],["impl&lt;__DB: Backend&gt; QueryableByName&lt;__DB&gt; for <a class=\"struct\" href=\"sui_indexer/models_v2/events/struct.StoredEvent.html\" title=\"struct sui_indexer::models_v2::events::StoredEvent\">StoredEvent</a><span class=\"where fmt-newline\">where\n    <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.i64.html\">i64</a>: FromSql&lt;BigInt, __DB&gt;,\n    <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u8.html\">u8</a>&gt;: FromSql&lt;Bytea, __DB&gt;,\n    <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;<a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/option/enum.Option.html\" title=\"enum core::option::Option\">Option</a>&lt;<a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u8.html\">u8</a>&gt;&gt;&gt;: FromSql&lt;Array&lt;Nullable&lt;Bytea&gt;&gt;, __DB&gt;,\n    <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/string/struct.String.html\" title=\"struct alloc::string::String\">String</a>: FromSql&lt;Text, __DB&gt;,</span>"]]
};if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()