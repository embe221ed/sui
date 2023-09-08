// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
import { useNavigate } from 'react-router-dom';
import { AccountGroup } from './AccountGroup';
import Overlay from '../../../components/overlay';
import { type AccountType } from '_src/background/accounts/Account';
import { useAccountGroups } from '_src/ui/app/hooks/useAccountGroups';

export function ManageAccountsPage() {
	const navigate = useNavigate();
	const groupedAccounts = useAccountGroups();

	return (
		<Overlay showModal title="Manage Accounts" closeOverlay={() => navigate('/home')}>
			<div className="flex flex-col gap-4 flex-1">
				{Object.entries(groupedAccounts).map(([type, accountGroups]) =>
					Object.entries(accountGroups).map(([key, accounts]) => {
						return (
							<AccountGroup
								key={`${type}-${key}`}
								accounts={accounts}
								accountSource={key}
								type={type as AccountType}
							/>
						);
					}),
				)}
			</div>
		</Overlay>
	);
}
