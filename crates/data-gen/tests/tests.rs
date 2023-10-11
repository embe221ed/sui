// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

pub const TEST_DIR: &str = "tests";
use data_gen::run_test;

datatest_stable::harness!(run_test, TEST_DIR, r".*\.(mvir|move)$");
